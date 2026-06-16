//! Regression for issue #150: concurrent mounts must not double-open redb.
//!
//! `mount_inner`'s idempotency check drops the `workspace` lock before
//! `Store::open`'s `.await`, so without serialization two concurrent
//! mounts (the startup prewarm + an explicit `Workspace.Mount` RPC, or
//! two explicit RPCs) could both pass the check and both call
//! `Store::open` on the same redb file. redb refuses the second open with
//! "Database already open" and the daemon wedges — returning
//! `STORAGE_FULL` on every later request.
//!
//! The fix serializes the check-open-register critical section
//! (`state.mount_serialize`). This test forces the race deterministically
//! via the `RTS_TEST_MOUNT_OPEN_DELAY_MS` seam (which widens the window
//! between the idempotency check and `Store::open`) and fires several
//! concurrent `Workspace.Mount` RPCs. With the guard, exactly one opens
//! the store and the rest take the idempotent path; without it, the
//! losers come back `STORAGE_FULL`.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-daemon"))
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for_socket(path: &std::path::Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "socket {} did not appear within {timeout:?}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// One `Workspace.Mount` on a fresh connection. Returns the parsed
/// response (which may carry an `error`).
async fn mount_once(socket: PathBuf, root: PathBuf, id: String) -> anyhow::Result<Value> {
    let mut stream = UnixStream::connect(&socket).await?;
    let req = json!({ "id": id, "method": "Workspace.Mount", "params": { "root": root } });
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    let mut buf = Vec::new();
    let (rd, _wr) = stream.split();
    let mut reader = BufReader::new(rd);
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_until(b'\n', &mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for Mount response"))??;
    anyhow::ensure!(n > 0, "EOF before Mount response");
    Ok(serde_json::from_slice(&buf)?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mounts_never_double_open() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn hub_compute(x: u32) -> u32 { x + 1 }\n",
    )?;

    // No `--workspace` → no prewarm; the daemon binds `default.sock` and
    // waits for explicit Mounts. We drive the race purely through
    // concurrent Mount RPCs + the delay seam.
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
        // Widen the check→open window so the concurrent mounts below
        // deterministically overlap there (no-op in production).
        .env("RTS_TEST_MOUNT_OPEN_DELAY_MS", "300")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn()?;
    let _kill = KillOnDrop(child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await;

    // Fire several concurrent Mounts for the same workspace. Pre-fix,
    // they all pass the idempotency check (workspace empty), sleep in the
    // widened window together, then all call Store::open → the losers get
    // STORAGE_FULL. Post-fix, the serialize guard lets exactly one open;
    // the rest take the idempotent path.
    let root: PathBuf = workspace.path().to_path_buf();
    let mut handles = Vec::new();
    for i in 0..6 {
        handles.push(tokio::spawn(mount_once(
            socket_path.clone(),
            root.clone(),
            format!("mount-{i}"),
        )));
    }
    for h in handles {
        let resp = h.await??;
        assert!(
            resp["error"].is_null(),
            "concurrent Mount must not error (issue #150); got {resp:?}"
        );
    }

    // Daemon must still be healthy (a wedged daemon returns STORAGE_FULL
    // on every request). A follow-up query resolves the seeded symbol.
    let mut stream = UnixStream::connect(&socket_path).await?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let req =
            json!({ "id": "q", "method": "Index.FindSymbol", "params": { "name": "hub_compute" } });
        let mut bytes = serde_json::to_vec(&req)?;
        bytes.push(b'\n');
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        let mut buf = Vec::new();
        let (rd, _wr) = stream.split();
        let mut reader = BufReader::new(rd);
        let n = tokio::time::timeout(Duration::from_secs(10), reader.read_until(b'\n', &mut buf))
            .await??;
        anyhow::ensure!(n > 0, "EOF before FindSymbol response");
        let resp: Value = serde_json::from_slice(&buf)?;
        assert!(
            resp["error"].is_null(),
            "daemon wedged after the mount race; got {resp:?}"
        );
        let found = resp["result"]["matches"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        if found {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "symbol never indexed; daemon may be unhealthy"
        );
        tokio::time::sleep(Duration::from_millis(75)).await;
    }

    Ok(())
}
