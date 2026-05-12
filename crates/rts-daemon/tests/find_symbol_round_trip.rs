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
            anyhow::bail!("socket {} did not appear within {:?}", path.display(), timeout);
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
        let matches = resp["result"]["matches"].as_array().cloned().unwrap_or_default();
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
        home_dir.path().join("Library").join("Caches").join("rts").join("default.sock")
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
        m["file"].as_str().map(|f| f.ends_with("lib.rs")).unwrap_or(false),
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
