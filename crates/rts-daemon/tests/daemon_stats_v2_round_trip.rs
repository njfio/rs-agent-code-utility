//! End-to-end test for v0.6 `Daemon.Stats v2` workspace-metadata fields.
//!
//! Asserts:
//! 1. `Daemon.Ping` advertises the new `daemon_stats_v2` capability.
//! 2. **Pre-mount** `Daemon.Stats` keeps the v1 shape — none of the v2
//!    fields are present. This is the backward-compat invariant from
//!    PR 001 plan AC1.
//! 3. **Post-mount** `Daemon.Stats` carries
//!    `pinned_workspace_path`, `workspace_id`, `index_generation`,
//!    and `cold_walk_completed_at_ms`.
//! 4. `pinned_workspace_path` matches the canonical workspace path
//!    (modulo macOS NFC + symlink-resolution differences).
//! 5. `cold_walk_completed_at_ms` is `null` immediately after Mount,
//!    becomes a Unix-epoch-ms timestamp once the writer's
//!    `ColdWalkComplete` flush commits.

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
async fn daemon_stats_v2_emits_workspace_fields_post_mount() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Seed one Rust file so the writer has something to index and
    // therefore something to flush at cold-walk completion.
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

    // 1. Ping advertises `daemon_stats_v2`.
    let pong = round_trip(&mut stream, "1", "Daemon.Ping", json!({})).await?;
    let caps = pong["result"]["capabilities"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let cap_strs: Vec<&str> = caps.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        cap_strs.contains(&"daemon_stats_v2"),
        "expected daemon_stats_v2 capability; got {cap_strs:?}"
    );

    // 2. Pre-mount Stats keeps the v1 shape — none of the v2 fields
    //    are present. Backward-compat invariant.
    let stats_pre = round_trip(&mut stream, "2", "Daemon.Stats", json!({})).await?;
    let r_pre = &stats_pre["result"];
    assert!(r_pre["uptime_ms"].as_u64().is_some(), "uptime_ms missing");
    assert!(r_pre["version"].as_str().is_some(), "version missing");
    assert!(
        r_pre.get("pinned_workspace_path").is_none(),
        "pre-mount Stats must NOT include pinned_workspace_path; got {r_pre:?}"
    );
    assert!(
        r_pre.get("workspace_id").is_none(),
        "pre-mount Stats must NOT include workspace_id"
    );
    assert!(
        r_pre.get("index_generation").is_none(),
        "pre-mount Stats must NOT include index_generation"
    );
    assert!(
        r_pre.get("cold_walk_completed_at_ms").is_none(),
        "pre-mount Stats must NOT include cold_walk_completed_at_ms"
    );

    // 3. Mount the workspace.
    let mount = round_trip(
        &mut stream,
        "3",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");

    // 4. Post-mount Stats carries all four v2 fields. Poll briefly to
    //    let the writer's ColdWalkComplete flush land before asserting
    //    on cold_walk_completed_at_ms.
    let mut stats_post = serde_json::Value::Null;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut id: u32 = 100;
    loop {
        id += 1;
        stats_post = round_trip(&mut stream, &id.to_string(), "Daemon.Stats", json!({})).await?;
        let r = &stats_post["result"];
        let cold_walk = &r["cold_walk_completed_at_ms"];
        if cold_walk.is_number() {
            break;
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "cold_walk_completed_at_ms never populated within 5s; last r={r:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }

    let r_post = &stats_post["result"];
    let pinned = r_post["pinned_workspace_path"]
        .as_str()
        .expect("pinned_workspace_path should be present and a string");
    assert!(
        !pinned.is_empty(),
        "pinned_workspace_path must not be empty"
    );

    // The pinned path should be the canonicalized workspace temp dir.
    // We compare end-substrings rather than equality because macOS
    // canonicalize() resolves `/var` → `/private/var` and the test
    // tempdir is under /var on macOS.
    let workspace_str = workspace.path().to_string_lossy();
    let workspace_basename = workspace
        .path()
        .file_name()
        .and_then(|n| n.to_str())
        .expect("temp dir has a name");
    assert!(
        pinned.ends_with(workspace_basename),
        "pinned_workspace_path={pinned} should end with {workspace_basename} (workspace={workspace_str})"
    );

    let workspace_id = r_post["workspace_id"]
        .as_str()
        .expect("workspace_id should be present");
    // `WorkspaceFingerprint::id_str()` returns the leading 16 bytes of
    // blake3(dev_id ‖ inode ‖ canonical_path) rendered as 32 hex chars.
    assert_eq!(
        workspace_id.len(),
        32,
        "workspace_id should be 32-char hex (16-byte truncation); got {workspace_id:?}"
    );
    assert!(
        workspace_id.chars().all(|c| c.is_ascii_hexdigit()),
        "workspace_id should be lowercase hex; got {workspace_id:?}"
    );

    let index_generation = r_post["index_generation"].as_u64();
    assert!(
        index_generation.is_some(),
        "index_generation should be a u64; got {:?}",
        r_post["index_generation"]
    );

    let cold_walk_ms = r_post["cold_walk_completed_at_ms"]
        .as_u64()
        .expect("cold_walk_completed_at_ms should be a u64 once the walk finishes");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(
        cold_walk_ms > 0 && cold_walk_ms <= now_ms,
        "cold_walk_completed_at_ms={cold_walk_ms} should be a sane Unix-epoch-ms (now={now_ms})"
    );

    Ok(())
}