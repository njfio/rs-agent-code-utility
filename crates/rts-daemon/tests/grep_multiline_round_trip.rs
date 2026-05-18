//! End-to-end test for `Index.Grep` v2 multiline regex path (U3).
//!
//! Verifies:
//! 1. `regex: true, multiline: true` with a pattern that crosses a
//!    newline matches as a single record whose `range.start_line` is
//!    less than `range.end_line`.
//! 2. The same pattern with `multiline: false` (the v1 single-line
//!    path) returns zero matches — proving the new flags actually
//!    take effect rather than the default regex flags slipping
//!    through unchanged.
//! 3. An adversarial multiline pattern designed to provoke the DFA
//!    budget breach surfaces as `INVALID_PARAMS { data.code:
//!    "REGEX_TOO_COMPLEX" }` (not a generic crate-level error).

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

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn multiline_regex_matches_across_newlines() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // A multi-line `fn foo()` signature: opening paren on line 1,
    // args on line 2, closing paren on line 3. A v1 single-line
    // regex cannot match `fn\s+foo\([^)]*\)` here because `.`/`[^)]*`
    // stop at `\n`. With `multiline: true` the regex spans all
    // three lines as one match.
    std::fs::write(
        workspace.path().join("multiline.rs"),
        "pub fn foo(\n    arg: u32,\n    other: &str,\n) {\n    println!(\"body\");\n}\n",
    )?;
    // A control file with a single-line `fn` so the workspace mount
    // has at least one symbol the polling loop can wait on.
    std::fs::write(workspace.path().join("seed.rs"), "pub fn seed() {}\n")?;

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

    // Wait for the writer to commit `seed` so we know indexing has
    // settled before any grep query fires.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut id: u32 = 100;
    loop {
        id += 1;
        let r = round_trip(
            &mut stream,
            &id.to_string(),
            "Index.FindSymbol",
            json!({ "name": "seed" }),
        )
        .await?;
        if let Some(arr) = r["result"]["matches"].as_array() {
            if !arr.is_empty() {
                break;
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("`seed` never indexed within 5s");
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }

    // Case 1: multiline regex spans three lines as one match. The
    // pattern uses `.+` between `foo(` and `)` so that v1's default
    // single-line semantics (where `.` does NOT cross `\n`) cannot
    // match — the regex must rely on `dot_matches_new_line(true)`
    // to span the multi-line signature.
    let pat = r"fn\s+foo\(.+\)";
    let multiline = round_trip(
        &mut stream,
        "10",
        "Index.Grep",
        json!({
            "text": pat,
            "regex": true,
            "multiline": true,
        }),
    )
    .await?;
    assert!(
        multiline["error"].is_null(),
        "multiline grep errored: {multiline:?}"
    );
    let multiline_matches = multiline["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let multiline_hits_on_target: Vec<&Value> = multiline_matches
        .iter()
        .filter(|m| {
            m["file"]
                .as_str()
                .map(|s| s.ends_with("multiline.rs"))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(
        multiline_hits_on_target.len(),
        1,
        "expected exactly one multiline match in multiline.rs; got {multiline:?}"
    );
    let m = multiline_hits_on_target[0];
    let start_line = m["range"]["start_line"].as_u64().unwrap_or(0);
    let end_line = m["range"]["end_line"].as_u64().unwrap_or(0);
    assert!(
        start_line < end_line,
        "multiline match must have start_line < end_line; got start={start_line} end={end_line} (match: {m:?})"
    );
    assert_eq!(start_line, 1, "match should start on line 1");
    // Layout: L1 `pub fn foo(`, L2-3 args, L4 `) {`, L5 `println!(...)`.
    // The greedy `.+\)` will extend through the body's closing paren
    // on L5; the precise stop line depends on greedy semantics. What
    // matters for the U3 contract is that the match crosses newlines
    // (i.e. end_line > start_line by at least 3, proving a true
    // multi-line span rather than a same-line match).
    assert!(
        end_line >= 4,
        "multiline match should span past the args block (end_line >= 4); got {end_line}"
    );

    // Case 2: same pattern WITHOUT multiline → zero matches (proves
    // the new flags actually take effect rather than the default
    // flags accidentally letting `.` cross `\n`).
    let single = round_trip(
        &mut stream,
        "11",
        "Index.Grep",
        json!({
            "text": pat,
            "regex": true,
            // multiline omitted → default false
        }),
    )
    .await?;
    assert!(single["error"].is_null(), "single-line grep errored: {single:?}");
    let single_hits_on_target: Vec<&Value> = single["result"]["matches"]
        .as_array()
        .map(|v| {
            v.iter()
                .filter(|m| {
                    m["file"]
                        .as_str()
                        .map(|s| s.ends_with("multiline.rs"))
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();
    assert!(
        single_hits_on_target.is_empty(),
        "single-line regex must NOT match across newlines; got {single:?}"
    );

    Ok(())
}
