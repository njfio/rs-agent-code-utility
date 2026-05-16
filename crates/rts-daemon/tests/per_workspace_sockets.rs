//! End-to-end test: two daemons on **distinct workspaces** can coexist
//! on the same UID's runtime dir simultaneously. Pre-v0.5.4 both
//! daemons would race for `default.sock` and the second would fail
//! with `WORKSPACE_MISMATCH`. v0.5.4+ uses per-workspace
//! `ws-<16hex>.sock` files so they don't collide.

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

/// Compute the per-workspace socket path the way `rts-daemon::socket`
/// does. Mirrors the production hash so the test verifies the actual
/// binding, not a re-implementation.
fn ws_socket_path(runtime_dir: &std::path::Path, canonical_workspace: &std::path::Path) -> PathBuf {
    let bytes = canonical_workspace.as_os_str().as_encoded_bytes();
    let hash = blake3::hash(bytes);
    let short = hash.to_hex();
    let short16 = &short.as_str()[..16];
    runtime_dir.join(format!("ws-{short16}.sock"))
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn two_daemons_one_runtime_dir_distinct_workspaces() -> anyhow::Result<()> {
    // ONE runtime dir / HOME / state dir shared across both daemons.
    // The bug being tested: pre-v0.5.4 the second daemon would
    // collide on `default.sock` regardless of its workspace.
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Two distinct workspaces. Each gets its own daemon below.
    let workspace_a = tempfile::tempdir()?;
    let workspace_b = tempfile::tempdir()?;
    std::fs::write(
        workspace_a.path().join("a.rs"),
        "pub fn workspace_a_marker() {}\n",
    )?;
    std::fs::write(
        workspace_b.path().join("b.rs"),
        "pub fn workspace_b_marker() {}\n",
    )?;

    // Canonical workspace paths — macOS `tempdir` returns `/var/...`
    // but the daemon canonicalises to `/private/var/...`. Match.
    let canon_a = workspace_a.path().canonicalize()?;
    let canon_b = workspace_b.path().canonicalize()?;

    // On macOS the daemon writes to `$HOME/Library/Caches/rts/`;
    // on Linux to `$XDG_RUNTIME_DIR/rts/`. Compute the actual dir.
    let daemon_runtime_dir = if cfg!(target_os = "macos") {
        home_dir.path().join("Library").join("Caches").join("rts")
    } else {
        runtime_dir.path().join("rts")
    };

    let socket_a = ws_socket_path(&daemon_runtime_dir, &canon_a);
    let socket_b = ws_socket_path(&daemon_runtime_dir, &canon_b);
    assert_ne!(
        socket_a, socket_b,
        "distinct workspaces must hash to distinct sockets",
    );

    // Spawn daemon A.
    let mut cmd_a = Command::new(daemon_bin());
    cmd_a
        .args(["--workspace"])
        .arg(workspace_a.path())
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child_a = cmd_a.spawn()?;
    let _kill_a = KillOnDrop(&mut child_a);
    wait_for_socket(&socket_a, Duration::from_secs(5)).await?;

    // Spawn daemon B *while A is still running* — the previously
    // failing scenario.
    let mut cmd_b = Command::new(daemon_bin());
    cmd_b
        .args(["--workspace"])
        .arg(workspace_b.path())
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child_b = cmd_b.spawn()?;
    let _kill_b = KillOnDrop(&mut child_b);
    wait_for_socket(&socket_b, Duration::from_secs(5)).await?;

    // Both sockets exist concurrently. Query each daemon and verify
    // it returns its own workspace's symbol, not the other's.
    let mut stream_a = UnixStream::connect(&socket_a).await?;
    let mount_a = round_trip(
        &mut stream_a,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace_a.path() }),
    )
    .await?;
    assert!(mount_a["error"].is_null(), "mount A: {mount_a:?}");
    let resp_a =
        poll_for_match(&mut stream_a, "workspace_a_marker", Duration::from_secs(5)).await?;
    let matches_a = resp_a["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        matches_a
            .iter()
            .any(|m| m["qualified_name"] == "workspace_a_marker"),
        "daemon A should index workspace A: {resp_a:?}"
    );

    let mut stream_b = UnixStream::connect(&socket_b).await?;
    let mount_b = round_trip(
        &mut stream_b,
        "2",
        "Workspace.Mount",
        json!({ "root": workspace_b.path() }),
    )
    .await?;
    assert!(mount_b["error"].is_null(), "mount B: {mount_b:?}");
    let resp_b =
        poll_for_match(&mut stream_b, "workspace_b_marker", Duration::from_secs(5)).await?;
    let matches_b = resp_b["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        matches_b
            .iter()
            .any(|m| m["qualified_name"] == "workspace_b_marker"),
        "daemon B should index workspace B: {resp_b:?}"
    );

    // Critical assertion: A doesn't see B's symbols and vice-versa.
    // Pre-v0.5.4 a single daemon would have one of them mounted and
    // the other would 404 (or — worse — the second daemon would
    // fail to bind entirely).
    let cross_a = round_trip(
        &mut stream_a,
        "3",
        "Index.FindSymbol",
        json!({ "name": "workspace_b_marker" }),
    )
    .await?;
    assert!(
        cross_a["result"]["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "daemon A must NOT see workspace B's symbols: {cross_a:?}"
    );

    let cross_b = round_trip(
        &mut stream_b,
        "4",
        "Index.FindSymbol",
        json!({ "name": "workspace_a_marker" }),
    )
    .await?;
    assert!(
        cross_b["result"]["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "daemon B must NOT see workspace A's symbols: {cross_b:?}"
    );

    Ok(())
}
