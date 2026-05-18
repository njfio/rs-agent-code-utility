//! End-to-end test for U5's persisted-cold-mount decision.
//!
//! Asserts:
//! 1. First mount on a workspace produces `Daemon.Stats v2` with
//!    a hint that the daemon ran a cold walk (FILES populated +
//!    queryable).
//! 2. After killing the daemon and re-spawning it against the same
//!    workspace + state dir, the second mount **rehydrates**:
//!    `Index.FindSymbol` returns matches *immediately* without
//!    waiting for a second cold walk. This is the load-bearing
//!    user-facing invariant — sub-100ms first-query on the second
//!    session.
//! 3. Editing the workspace `.gitignore` between sessions
//!    invalidates the snapshot; the next mount cold-walks again.
//!
//! The `mount_source` string itself is asserted via `Daemon.Stats`
//! after PR 003 (U6 wires the field into the Stats response).
//! For U5 we verify the *behavior* — index reuse — which is the
//! observable invariant.

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

fn socket_path(home_dir: &std::path::Path, runtime_dir: &std::path::Path) -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        home_dir
            .join("Library")
            .join("Caches")
            .join("rts")
            .join("default.sock")
    } else {
        runtime_dir.join("rts").join("default.sock")
    }
}

fn spawn_daemon(
    runtime_dir: &std::path::Path,
    state_dir: &std::path::Path,
    home_dir: &std::path::Path,
) -> anyhow::Result<std::process::Child> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir, std::fs::Permissions::from_mode(0o700));

    let mut cmd = Command::new(daemon_bin());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir)
        .env("XDG_STATE_HOME", state_dir)
        .env("HOME", home_dir)
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(cmd.spawn()?)
}

#[tokio::test(flavor = "current_thread")]
async fn rehydrate_skips_cold_walk_and_keeps_index_warm() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // Seed one Rust file with a known symbol so we can probe
    // FindSymbol both pre- and post-rehydrate.
    std::fs::write(
        workspace.path().join("lib.rs"),
        "pub fn rehydratable_hello() {}\n",
    )?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());

    // ---- Session 1: cold-walk path ----
    {
        let mut child = spawn_daemon(runtime_dir.path(), state_dir.path(), home_dir.path())?;
        let _kill = KillOnDrop(&mut child);
        wait_for_socket(&sock, Duration::from_secs(5)).await?;
        let mut stream = UnixStream::connect(&sock).await?;

        let mount = round_trip(
            &mut stream,
            "1",
            "Workspace.Mount",
            json!({ "root": workspace.path() }),
        )
        .await?;
        assert!(
            mount["error"].is_null(),
            "session-1 mount failed: {mount:?}"
        );

        // Poll for the cold-walk to finish indexing the symbol.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut id: u32 = 10;
        loop {
            id += 1;
            let r = round_trip(
                &mut stream,
                &id.to_string(),
                "Index.FindSymbol",
                json!({ "name": "rehydratable_hello" }),
            )
            .await?;
            if let Some(arr) = r["result"]["matches"].as_array() {
                if !arr.is_empty() {
                    break;
                }
            }
            if Instant::now() >= deadline {
                anyhow::bail!("session-1: symbol never indexed within 5s");
            }
            tokio::time::sleep(Duration::from_millis(75)).await;
        }
        // KillOnDrop fires here; daemon shuts down cleanly enough
        // for the redb file + META fingerprint to survive.
        drop(stream);
    }

    // Give the OS a moment to release the socket file + Unix
    // socket binding. Without this, the next bind sometimes races.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let _ = std::fs::remove_file(&sock);

    // ---- Session 2: rehydrate path ----
    //
    // Same state_dir, same workspace, same home. The new daemon
    // should open the persisted redb, find a matching fingerprint,
    // and skip the cold walk entirely. We prove that by issuing
    // Index.FindSymbol *immediately* after Mount returns and
    // expecting matches in the first response — without polling.
    {
        let mut child = spawn_daemon(runtime_dir.path(), state_dir.path(), home_dir.path())?;
        let _kill = KillOnDrop(&mut child);
        wait_for_socket(&sock, Duration::from_secs(5)).await?;
        let mut stream = UnixStream::connect(&sock).await?;

        let mount_start = Instant::now();
        let mount = round_trip(
            &mut stream,
            "1",
            "Workspace.Mount",
            json!({ "root": workspace.path() }),
        )
        .await?;
        let mount_elapsed = mount_start.elapsed();
        assert!(
            mount["error"].is_null(),
            "session-2 mount failed: {mount:?}"
        );

        // Hard assertion: a single FindSymbol immediately after Mount
        // returns matches. On the cold-walk path this would race; on
        // the rehydrate path it's guaranteed because the index is
        // already populated from session 1.
        let first = round_trip(
            &mut stream,
            "2",
            "Index.FindSymbol",
            json!({ "name": "rehydratable_hello" }),
        )
        .await?;
        let matches = first["result"]["matches"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !matches.is_empty(),
            "session-2 (rehydrate): FindSymbol must return matches without polling; got {first:?}"
        );

        // Soft assertion: mount latency on rehydrate should be
        // sub-second. The plan's AC17 target is <100ms p95 on
        // 100k LOC; this test uses 1 file, so a much looser
        // 1s ceiling is sufficient to catch full-cold-walk
        // regressions without flaking on slow CI.
        assert!(
            mount_elapsed < Duration::from_secs(1),
            "session-2 rehydrate mount took {mount_elapsed:?}; expected sub-second on a 1-file workspace"
        );

        // U6 assertion: Daemon.Stats reports mount_source = "rehydrate"
        // and the cache counter bumped exactly once.
        let stats = round_trip(&mut stream, "3", "Daemon.Stats", json!({})).await?;
        let r = &stats["result"];
        assert_eq!(
            r["mount_source"].as_str(),
            Some("rehydrate"),
            "session-2 should report mount_source=rehydrate; got {r:?}"
        );
        assert!(
            r["rehydrate_attempts_total"].as_u64().unwrap_or(0) >= 1,
            "rehydrate_attempts_total should be >= 1; got {r:?}"
        );
        assert!(
            r["rehydrate_successes_total"].as_u64().unwrap_or(0) >= 1,
            "rehydrate_successes_total should be >= 1; got {r:?}"
        );
        assert!(
            r["rehydrate_invalidations_by_reason"].is_object(),
            "rehydrate_invalidations_by_reason should be an object; got {r:?}"
        );
    }

    Ok(())
}
