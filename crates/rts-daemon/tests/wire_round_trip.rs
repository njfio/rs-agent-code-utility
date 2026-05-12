//! End-to-end wire-protocol round-trip test.
//!
//! Spawns `rts-daemon` as a subprocess with a per-test `XDG_RUNTIME_DIR`,
//! connects over its Unix socket, and exchanges newline-JSON requests:
//!   1. `Daemon.Ping` — verifies the daemon's capability advertisement
//!   2. `Workspace.Mount` — mounts a tempdir as the workspace
//!   3. `Workspace.Status` — confirms the daemon transitioned to ready
//!   4. `Session.Open` / `Session.Close` — exercises the session verbs
//!
//! This is the v0 conformance-test seed referenced in
//! `docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md`
//! §P6.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Path to the freshly-built `rts-daemon` binary. Cargo sets `CARGO_BIN_EXE_<name>`
/// for integration tests, which is the canonical way to locate the bin.
fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-daemon"))
}

/// Wait for the daemon to write its socket file before connecting.
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

/// Send one newline-JSON request and read one newline-JSON response.
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

    // Read up to the first newline. Borrow the reader half temporarily.
    let mut buf = Vec::new();
    let (rd, _wr) = stream.split();
    let mut reader = BufReader::new(rd);
    let n = tokio::time::timeout(Duration::from_secs(5), reader.read_until(b'\n', &mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to {method}"))??;
    anyhow::ensure!(n > 0, "EOF before response to {method}");
    let resp: Value = serde_json::from_slice(&buf)?;
    Ok(resp)
}

#[tokio::test(flavor = "current_thread")]
async fn full_round_trip() -> anyhow::Result<()> {
    // Per-test directories. `XDG_RUNTIME_DIR` is required on Linux (the daemon
    // refuses to start without it); macOS uses `~/Library/Caches/rts/` by
    // default but honours the env override below to point at a tempdir.
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // Make the runtime dir mode 0700 (the daemon's bind step also chmods, but
    // some systems' tempfile defaults leak 0755 → 0700 transitions can race).
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Compute the expected socket path. The daemon's `socket_path_for_default`
    // uses `${XDG_RUNTIME_DIR}/rts/default.sock` on Linux and
    // `~/Library/Caches/rts/default.sock` on macOS.
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

    // Ensure we kill the daemon on every exit path, including panics.
    let _kill_on_drop = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;

    // 1. Daemon.Ping
    let pong = round_trip(&mut stream, "1", "Daemon.Ping", json!({})).await?;
    assert_eq!(pong["id"], "1");
    assert_eq!(pong["result"]["protocol"], "0");
    assert_eq!(pong["result"]["daemon"]["name"], "rts-daemon");
    let caps = pong["result"]["capabilities"]
        .as_array()
        .expect("capabilities array");
    assert!(caps.iter().any(|v| v == "find_symbol"));

    // 2. Workspace.Mount
    let mount = round_trip(
        &mut stream,
        "2",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert_eq!(mount["id"], "2");
    assert!(mount["result"]["workspace_id"].is_string(), "got {mount:?}");
    assert_eq!(mount["result"]["state"], "ready");

    // 3. Workspace.Status — second mount returns same payload shape
    let status = round_trip(&mut stream, "3", "Workspace.Status", json!({})).await?;
    assert_eq!(status["id"], "3");
    assert_eq!(status["result"]["state"], "ready");
    assert_eq!(
        status["result"]["workspace_id"],
        mount["result"]["workspace_id"]
    );
    // Watcher must have come up healthy on Mount.
    assert_eq!(
        status["result"]["watcher_status"], "ok",
        "watcher should be running after Mount; got {status:?}"
    );

    // 4. Session.Open + Session.Close
    let opened = round_trip(
        &mut stream,
        "4",
        "Session.Open",
        json!({"client_name":"itest"}),
    )
    .await?;
    let sid = opened["result"]["session_id"]
        .as_str()
        .expect("session_id should be a string")
        .to_string();
    assert!(sid.starts_with("sess_"), "got {sid}");
    let closed = round_trip(
        &mut stream,
        "5",
        "Session.Close",
        json!({ "session_id": sid }),
    )
    .await?;
    assert_eq!(closed["id"], "5");
    assert!(closed["result"].is_object());

    // 5. Negative case: unknown method → INVALID_PARAMS.
    let bad = round_trip(&mut stream, "6", "Index.NotARealVerb", json!({})).await?;
    assert_eq!(bad["error"]["code"], "INVALID_PARAMS");

    // 6. `Index.FindSymbol` returns empty matches for an unknown symbol
    //    (success, not error).
    let empty = round_trip(&mut stream, "7", "Index.FindSymbol", json!({"name":"x"})).await?;
    assert!(
        empty["error"].is_null(),
        "FindSymbol should succeed on empty workspace; got {empty:?}"
    );
    assert_eq!(
        empty["result"]["matches"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(usize::MAX),
        0,
        "expected empty matches on an empty workspace; got {empty:?}"
    );

    // 7. `Index.Outline` on an empty workspace succeeds with zero files
    //    (no more INDEX_NOT_READY — PageRank ships as of alpha.18).
    let outline_resp = round_trip(
        &mut stream,
        "8",
        "Index.Outline",
        json!({ "token_budget": 1024 }),
    )
    .await?;
    assert!(
        outline_resp["error"].is_null(),
        "Outline should succeed on empty workspace; got {outline_resp:?}"
    );
    assert_eq!(outline_resp["result"]["files_considered"], 0);
    assert_eq!(outline_resp["result"]["files_included"], 0);

    Ok(())
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
