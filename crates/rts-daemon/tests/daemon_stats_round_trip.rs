//! End-to-end test for v0.5.7 `Daemon.Stats` per-session call counters.
//!
//! Asserts:
//! 1. `Daemon.Ping` advertises `daemon_stats` capability.
//! 2. First `Daemon.Stats` call returns a snapshot where every counter
//!    is 0 *except* the ones for the calls we just made (ping + the
//!    stats RPC itself).
//! 3. Each subsequent RPC bumps its matching counter — exercises
//!    `Index.FindSymbol`, `Index.Grep`, `Workspace.Status` and verifies
//!    the counts before/after.
//! 4. Errored calls (unknown method) increment `unknown_method`.
//! 5. The snapshot includes `uptime_ms`, `version`, `total_calls`,
//!    and a `calls` map keyed by wire-method-name strings.

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
    let n = tokio::time::timeout(Duration::from_secs(5), reader.read_until(b'\n', &mut buf))
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
async fn daemon_stats_counts_each_rpc() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Seed one file so Index.FindSymbol has something to return.
    std::fs::write(workspace.path().join("hub.rs"), "pub fn hello() {}\n")?;

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

    // 1. Ping advertises the capability.
    let pong = round_trip(&mut stream, "1", "Daemon.Ping", json!({})).await?;
    let caps = pong["result"]["capabilities"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let cap_strs: Vec<&str> = caps.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        cap_strs.contains(&"daemon_stats"),
        "expected daemon_stats capability; got {cap_strs:?}"
    );

    // 2. First Daemon.Stats — should show one Daemon.Ping (just
    //    above) and one Daemon.Stats (this call, counted at
    //    dispatch). Everything else zero. We snapshot here before
    //    doing anything else so the assertion is precise.
    let stats1 = round_trip(&mut stream, "2", "Daemon.Stats", json!({})).await?;
    assert!(
        stats1["error"].is_null(),
        "Daemon.Stats errored: {stats1:?}"
    );
    let r1 = &stats1["result"];
    assert!(r1["uptime_ms"].as_u64().is_some(), "uptime_ms missing");
    assert!(r1["version"].as_str().is_some(), "version missing");
    let calls1 = &r1["calls"];
    assert_eq!(
        calls1["Daemon.Ping"].as_u64(),
        Some(1),
        "first stats should show 1 ping; got {calls1:?}"
    );
    assert_eq!(
        calls1["Daemon.Stats"].as_u64(),
        Some(1),
        "first stats should show 1 Daemon.Stats (this RPC); got {calls1:?}"
    );
    assert_eq!(
        calls1["Index.FindSymbol"].as_u64(),
        Some(0),
        "Index.FindSymbol shouldn't have been called yet"
    );

    // 3. Mount the workspace so the next-step Index.* calls succeed.
    let mount = round_trip(
        &mut stream,
        "3",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");
    // Wait for FindSymbol to see something — confirms the writer
    // has committed at least one file's defs.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut id: u32 = 100;
    loop {
        id += 1;
        let r = round_trip(
            &mut stream,
            &id.to_string(),
            "Index.FindSymbol",
            json!({ "name": "hello" }),
        )
        .await?;
        if let Some(arr) = r["result"]["matches"].as_array() {
            if !arr.is_empty() {
                break;
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("`hello` never indexed within 5s");
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }

    // 4. Exercise three more RPCs whose counters we'll check.
    let _ = round_trip(&mut stream, "10", "Workspace.Status", json!({})).await?;
    let _ = round_trip(&mut stream, "11", "Index.Grep", json!({ "text": "pub fn" })).await?;
    let _ = round_trip(&mut stream, "12", "Index.Grep", json!({ "text": "hello" })).await?;

    // 5. Snapshot again — counters should reflect the new calls.
    let stats2 = round_trip(&mut stream, "13", "Daemon.Stats", json!({})).await?;
    let calls2 = &stats2["result"]["calls"];
    assert!(
        calls2["Daemon.Stats"].as_u64().unwrap_or(0) >= 2,
        "Daemon.Stats should have at least 2 counts; got {calls2:?}"
    );
    assert_eq!(
        calls2["Workspace.Mount"].as_u64(),
        Some(1),
        "Workspace.Mount should have 1 count"
    );
    assert_eq!(
        calls2["Workspace.Status"].as_u64(),
        Some(1),
        "Workspace.Status should have 1 count"
    );
    assert_eq!(
        calls2["Index.Grep"].as_u64(),
        Some(2),
        "Index.Grep should have 2 counts; got {calls2:?}"
    );
    assert!(
        calls2["Index.FindSymbol"].as_u64().unwrap_or(0) >= 1,
        "Index.FindSymbol should have at least 1 count (the polling loop above)"
    );

    // 6. Unknown method bumps `unknown_method`. The response is an
    //    error envelope (INVALID_PARAMS), and we still expect the
    //    counter to have advanced because dispatch bumps BEFORE
    //    routing.
    let _bad = round_trip(&mut stream, "20", "Index.NonExistentMethod", json!({})).await?;
    let stats3 = round_trip(&mut stream, "21", "Daemon.Stats", json!({})).await?;
    let calls3 = &stats3["result"]["calls"];
    assert!(
        calls3["unknown_method"].as_u64().unwrap_or(0) >= 1,
        "unknown_method counter should have advanced; got {calls3:?}"
    );

    // 7. total_calls should match the sum of all counters.
    let total = stats3["result"]["total_calls"].as_u64().unwrap_or(0);
    let sum: u64 = calls3
        .as_object()
        .unwrap()
        .values()
        .filter_map(|v| v.as_u64())
        .sum();
    assert_eq!(
        total, sum,
        "total_calls should equal sum of per-method counts"
    );

    Ok(())
}
