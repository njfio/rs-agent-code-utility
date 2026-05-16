//! End-to-end test: mount a workspace with a real `.rs` file, wait for the
//! writer-drain to commit, then `Index.FindSymbol` and expect a real match.
//!
//! Companion to `tests/wire_round_trip.rs` (which covers the lifecycle and
//! the read-only `Daemon.*`/`Session.*`/`Workspace.*` verbs without indexing).

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-daemon"))
}

async fn wait_for_socket(path: &std::path::Path, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "socket {} did not appear within {:?}",
                path.display(),
                timeout
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn round_trip(
    stream: &mut UnixStream,
    id: &str,
    method: &str,
    params: Value,
) -> anyhow::Result<Value> {
    let req = json!({ "id": id, "method": method, "params": params });
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.flush().await?;

    let mut buf = Vec::new();
    let (rd, _wr) = stream.split();
    let mut reader = BufReader::new(rd);
    let n = tokio::time::timeout(Duration::from_secs(8), reader.read_until(b'\n', &mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to {method}"))??;
    anyhow::ensure!(n > 0, "EOF before response to {method}");
    Ok(serde_json::from_slice(&buf)?)
}

/// Poll `Index.FindSymbol` until the writer has caught up (workspace just
/// started indexing). Returns the first non-empty match list, or the last
/// (empty) response after the deadline.
async fn poll_for_match(
    stream: &mut UnixStream,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<Value> {
    let deadline = Instant::now() + timeout;
    let mut next_id: u64 = 100;
    loop {
        next_id += 1;
        let resp = round_trip(
            stream,
            &next_id.to_string(),
            "Index.FindSymbol",
            json!({ "name": name }),
        )
        .await?;
        let matches = resp["result"]["matches"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if !matches.is_empty() {
            return Ok(resp);
        }
        if Instant::now() >= deadline {
            return Ok(resp);
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn writer_indexes_and_find_symbol_returns_match() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Seed the workspace with a single Rust file before mounting so the
    // initial walk picks it up.
    std::fs::write(
        workspace.path().join("lib.rs"),
        "pub fn build_index() {}\npub struct WidgetIndex;\n",
    )?;

    let socket_path = if cfg!(target_os = "macos") {
        home_dir
            .path()
            .join("Library")
            .join("Caches")
            .join("rts")
            .join("default.sock")
    } else {
        runtime_dir.path().join("rts").join("default.sock")
    };

    let mut cmd = Command::new(daemon_bin());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn()?;
    let _kill = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;

    let mount = round_trip(
        &mut stream,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount should succeed: {mount:?}");

    // Poll FindSymbol — the writer task is asynchronous; the symbol should
    // appear within a few hundred ms.
    let resp = poll_for_match(&mut stream, "build_index", Duration::from_secs(5)).await?;
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !matches.is_empty(),
        "expected at least one match for `build_index`; got {resp:?}"
    );
    let m = &matches[0];
    assert_eq!(m["qualified_name"], "build_index");
    assert_eq!(m["kind"], "fn");
    assert!(
        m["file"]
            .as_str()
            .map(|f| f.ends_with("lib.rs"))
            .unwrap_or(false),
        "match file should end in `lib.rs`; got {:?}",
        m["file"]
    );

    // The struct should be findable too.
    let widget_resp = poll_for_match(&mut stream, "WidgetIndex", Duration::from_secs(5)).await?;
    let widget_matches = widget_resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        widget_matches.iter().any(|m| m["kind"] == "struct"),
        "expected a `struct` kind match for WidgetIndex; got {widget_resp:?}"
    );

    // Filter test: `kind=fn` should drop the struct match for `WidgetIndex`.
    let filtered = round_trip(
        &mut stream,
        "200",
        "Index.FindSymbol",
        json!({ "name": "WidgetIndex", "kind": "fn" }),
    )
    .await?;
    let filtered_matches = filtered["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        filtered_matches.is_empty(),
        "WidgetIndex filtered to kind=fn should yield no matches; got {filtered_matches:?}"
    );

    // Negative: an unknown name returns an empty list (not an error).
    let nothing = round_trip(
        &mut stream,
        "300",
        "Index.FindSymbol",
        json!({ "name": "no_such_symbol_ever" }),
    )
    .await?;
    assert!(
        nothing["result"]["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "expected empty matches for unknown symbol; got {nothing:?}"
    );

    Ok(())
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// v0.4.1: `Index.FindSymbol.limit` parameter.
///
/// Verifies:
/// - `limit` caps the returned `matches` array and sets `truncated: true`.
/// - `limit` above the count returns everything with `truncated: false`.
/// - `limit: 0` is rejected with INVALID_PARAMS.
/// - `limit: 5000` (above MAX_LIMIT 4096) is rejected with INVALID_PARAMS.
#[tokio::test(flavor = "current_thread")]
async fn find_symbol_limit_param_caps_results() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Seed with 8 distinct top-level functions so pattern="*" returns
    // a known-cardinality candidate pool.
    let mut src = String::new();
    for i in 0..8 {
        src.push_str(&format!("pub fn limit_test_fn_{i:02}() {{}}\n"));
    }
    std::fs::write(workspace.path().join("lib.rs"), src)?;

    let socket_path = if cfg!(target_os = "macos") {
        home_dir
            .path()
            .join("Library")
            .join("Caches")
            .join("rts")
            .join("default.sock")
    } else {
        runtime_dir.path().join("rts").join("default.sock")
    };

    let mut cmd = Command::new(daemon_bin());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn()?;
    let _kill = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;

    let mount = round_trip(
        &mut stream,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount should succeed: {mount:?}");

    // Wait for indexing to complete via a known-name poll.
    let _ = poll_for_match(&mut stream, "limit_test_fn_00", Duration::from_secs(5)).await?;

    // Case 1: limit=3 caps the matches and sets truncated=true.
    let capped = round_trip(
        &mut stream,
        "10",
        "Index.FindSymbol",
        json!({ "pattern": "limit_test_fn_*", "limit": 3 }),
    )
    .await?;
    let matches = capped["result"]["matches"].as_array().cloned().unwrap();
    assert_eq!(matches.len(), 3, "limit=3 should return 3 matches");
    assert_eq!(
        capped["result"]["truncated"], true,
        "truncated should be true when matches > limit"
    );

    // Case 2: limit=100 (above the count) returns all 8 with truncated=false.
    let uncapped = round_trip(
        &mut stream,
        "11",
        "Index.FindSymbol",
        json!({ "pattern": "limit_test_fn_*", "limit": 100 }),
    )
    .await?;
    let uc_matches = uncapped["result"]["matches"].as_array().cloned().unwrap();
    assert_eq!(uc_matches.len(), 8, "limit=100 should return all 8 matches");
    assert_eq!(
        uncapped["result"]["truncated"], false,
        "truncated should be false when matches <= limit"
    );

    // Case 3: limit omitted → default 256, returns all 8.
    let default_limit = round_trip(
        &mut stream,
        "12",
        "Index.FindSymbol",
        json!({ "pattern": "limit_test_fn_*" }),
    )
    .await?;
    assert_eq!(
        default_limit["result"]["matches"]
            .as_array()
            .map(|a| a.len())
            .unwrap(),
        8,
        "default limit should return all 8 matches"
    );

    // Case 4: limit=0 → INVALID_PARAMS.
    let zero = round_trip(
        &mut stream,
        "13",
        "Index.FindSymbol",
        json!({ "pattern": "limit_test_fn_*", "limit": 0 }),
    )
    .await?;
    assert!(zero["error"].is_object(), "limit=0 should error: {zero:?}");

    // Case 5: limit=5000 (above MAX_LIMIT 4096) → INVALID_PARAMS.
    let oversize = round_trip(
        &mut stream,
        "14",
        "Index.FindSymbol",
        json!({ "pattern": "limit_test_fn_*", "limit": 5000 }),
    )
    .await?;
    assert!(
        oversize["error"].is_object(),
        "limit=5000 should error: {oversize:?}"
    );

    Ok(())
}

/// v0.5.2: `Index.FindSymbol.doc_contains` filter.
///
/// Verifies:
/// - `doc_contains: "frob"` keeps matches whose doc mentions "frob"
/// - case-insensitive match
/// - symbols with no doc are filtered out
/// - missing `doc_contains` field preserves pre-v0.5.2 behavior
#[tokio::test(flavor = "current_thread")]
async fn find_symbol_doc_contains_filter() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Three functions:
    //   - frob_one: doc mentions "FROBNICATION"  (uppercase needle test)
    //   - frob_two: doc mentions "frobnication"  (lowercase match)
    //   - bare:    no doc at all
    std::fs::write(
        workspace.path().join("lib.rs"),
        "/// FROBNICATION primary entry point.\npub fn frob_one() {}\n\n/// secondary frobnication path.\npub fn frob_two() {}\n\npub fn bare() {}\n",
    )?;

    let socket_path = if cfg!(target_os = "macos") {
        home_dir
            .path()
            .join("Library")
            .join("Caches")
            .join("rts")
            .join("default.sock")
    } else {
        runtime_dir.path().join("rts").join("default.sock")
    };

    let mut cmd = Command::new(daemon_bin());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn()?;
    let _kill = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;

    let mount = round_trip(
        &mut stream,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount: {mount:?}");

    let _ = poll_for_match(&mut stream, "frob_one", Duration::from_secs(5)).await?;

    // Case 1: doc_contains case-insensitive — matches both frob_*.
    let filtered = round_trip(
        &mut stream,
        "10",
        "Index.FindSymbol",
        json!({ "pattern": "frob_*", "doc_contains": "frobnication" }),
    )
    .await?;
    let matches = filtered["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        matches.len(),
        2,
        "expected 2 matches (both frob_* have frobnication in docs): {matches:?}"
    );
    for m in &matches {
        assert!(
            m["doc"]
                .as_str()
                .map(|d| d.to_lowercase().contains("frobnication"))
                .unwrap_or(false),
            "every kept match should contain `frobnication` in doc: {m:?}"
        );
    }

    // Case 2: doc_contains with no matches — empty array.
    let nomatch = round_trip(
        &mut stream,
        "11",
        "Index.FindSymbol",
        json!({ "pattern": "frob_*", "doc_contains": "no_such_word_anywhere" }),
    )
    .await?;
    assert!(
        nomatch["result"]["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "no_such_word should yield no matches: {nomatch:?}"
    );

    // Case 3: undocumented symbol filtered out.
    let bare_filter = round_trip(
        &mut stream,
        "12",
        "Index.FindSymbol",
        json!({ "name": "bare", "doc_contains": "anything" }),
    )
    .await?;
    assert!(
        bare_filter["result"]["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "undocumented symbol must be filtered out: {bare_filter:?}"
    );

    // Case 4: no doc_contains preserves old behavior — bare appears.
    let unfiltered = round_trip(
        &mut stream,
        "13",
        "Index.FindSymbol",
        json!({ "name": "bare" }),
    )
    .await?;
    assert!(
        !unfiltered["result"]["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(true),
        "without filter, undocumented symbol should still appear: {unfiltered:?}"
    );

    // Case 5 (v0.5.2): when the filter rejects ALL candidates, the
    // response should still include `pre_filter_count` so the agent
    // can distinguish "filter dropped N candidates" from "nothing
    // matched the pattern".
    let all_rejected = round_trip(
        &mut stream,
        "14",
        "Index.FindSymbol",
        json!({ "pattern": "frob_*", "doc_contains": "no_such_word_at_all" }),
    )
    .await?;
    assert_eq!(
        all_rejected["result"]["matches"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        0,
        "no-match filter should yield empty matches"
    );
    let pre_count = all_rejected["result"]["pre_filter_count"]
        .as_u64()
        .expect("pre_filter_count should be present when filter is active");
    assert!(
        pre_count >= 2,
        "pre_filter_count should report the candidate pool (>=2 frob_* names): got {pre_count}, response: {all_rejected:?}"
    );

    // Case 6: when no filter is active, pre_filter_count should be
    // ABSENT (back-compat wire shape).
    let no_filter = round_trip(
        &mut stream,
        "15",
        "Index.FindSymbol",
        json!({ "pattern": "frob_*" }),
    )
    .await?;
    assert!(
        no_filter["result"]["pre_filter_count"].is_null(),
        "pre_filter_count should be absent when no filter active: {no_filter:?}"
    );

    Ok(())
}
