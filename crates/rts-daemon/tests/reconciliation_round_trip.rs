//! End-to-end test for the reconciliation worker that runs after a
//! persisted cold-mount (`MountSource::Rehydrate`).
//!
//! Asserts the AC chain from `docs/plans/2026-05-18-004-feat-reconciliation-worker-plan.md`:
//!
//! 1. Mount a workspace, let it index, kill the daemon.
//! 2. Between sessions, modify one file's bytes + mtime and delete
//!    another. The workspace fingerprint stays stable (file content
//!    isn't part of it) so the next mount takes the Rehydrate path.
//! 3. Restart the daemon. `Daemon.Stats` should report
//!    `reconciliation.files_changed >= 1` and `files_removed >= 1`
//!    once the worker drains.
//! 4. `Index.FindSymbol` returns the post-edit symbol (proving
//!    `WatchEvent::Touched` reached the writer + got reparsed).
//! 5. AC16: a third file that was NOT modified still has its
//!    cross-file caller edges visible after reconciliation —
//!    `Index.FindCallers` works without a fresh cold walk.

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

/// Poll until `Index.FindSymbol(name)` returns at least one match. The
/// match indicates the reconciler emitted Touched and the writer
/// reparsed + committed. We don't pin a specific `start_line` because
/// the test only cares that the renamed symbol becomes visible, not
/// which line it landed on.
async fn poll_find_symbol_exists(
    stream: &mut UnixStream,
    name: &str,
    timeout: Duration,
    id_seed: u32,
) -> anyhow::Result<Value> {
    let deadline = Instant::now() + timeout;
    let mut id: u32 = id_seed;
    let mut last: Option<Value> = None;
    loop {
        id += 1;
        let r = round_trip(
            stream,
            &id.to_string(),
            "Index.FindSymbol",
            json!({ "name": name }),
        )
        .await?;
        if let Some(arr) = r["result"]["matches"].as_array() {
            if !arr.is_empty() {
                return Ok(r);
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "FindSymbol({name}) never returned matches within {timeout:?}; last={last:?}"
            );
        }
        last = Some(r);
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn reconciler_reindexes_drift_and_removes_orphans_on_rehydrate() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // Seed three files:
    //   - drifted.rs: gets edited between sessions (new symbol body)
    //   - orphan.rs:  gets deleted between sessions
    //   - stable.rs:  unchanged across sessions; carries a cross-file
    //                 call into a stable callee defined in drifted.rs
    //                 so we can prove UNRESOLVED_REFS survives (AC16).
    std::fs::write(
        workspace.path().join("drifted.rs"),
        "pub fn drift_target_v1() {}\npub fn stable_callee_hub() {}\n",
    )?;
    std::fs::write(
        workspace.path().join("orphan.rs"),
        "pub fn orphan_fn() {}\n",
    )?;
    std::fs::write(
        workspace.path().join("stable.rs"),
        "pub fn stable_caller() {\n    stable_callee_hub();\n}\n",
    )?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());

    // ---- Session 1: cold-walk path; populate the index. ----
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

        // Poll until all three files have at least their hub symbol indexed.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut id: u32 = 10;
        loop {
            id += 1;
            let r = round_trip(
                &mut stream,
                &id.to_string(),
                "Index.FindSymbol",
                json!({ "name": "drift_target_v1" }),
            )
            .await?;
            if let Some(arr) = r["result"]["matches"].as_array() {
                if !arr.is_empty() {
                    break;
                }
            }
            if Instant::now() >= deadline {
                anyhow::bail!("session-1: drift_target_v1 never indexed within 5s");
            }
            tokio::time::sleep(Duration::from_millis(75)).await;
        }

        // Confirm cross-file caller edge landed pre-restart. The
        // writer's batch barrier (`ColdWalkComplete`) flushes
        // everything together so the call from `stable.rs` into
        // `stable_callee_hub` is resolved in REFS, not stranded in
        // UNRESOLVED_REFS.
        let pre = round_trip(
            &mut stream,
            "100",
            "Index.FindCallers",
            json!({ "name": "stable_callee_hub" }),
        )
        .await?;
        let pre_callers = pre["result"]["callers"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !pre_callers.is_empty(),
            "session-1 should resolve stable.rs -> stable_callee_hub: {pre:?}"
        );

        drop(stream);
    }

    // Wait briefly for the daemon to fully tear down so the next
    // bind doesn't race for the socket file.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let _ = std::fs::remove_file(&sock);

    // Mutate the workspace while the daemon is dead:
    //   - drifted.rs gains a NEW symbol (drift_target_v2). Sleep a
    //     beat first so the OS-supplied mtime is guaranteed to be
    //     newer than the original write (the daemon stores
    //     nanosecond-precision mtime, so on Linux even a same-millis
    //     write usually drifts; on coarser-grained APFS, a short
    //     sleep is the cross-platform belt + suspenders).
    //   - orphan.rs is removed entirely
    //   - stable.rs is untouched
    tokio::time::sleep(Duration::from_millis(50)).await;
    std::fs::write(
        workspace.path().join("drifted.rs"),
        // Add leading blank lines so `drift_target_v2` sits at line 3
        // (deterministic for the assertion below).
        "\n\npub fn drift_target_v2() {}\npub fn stable_callee_hub() {}\n",
    )?;
    std::fs::remove_file(workspace.path().join("orphan.rs"))?;

    // ---- Session 2: rehydrate path; reconciler should fire. ----
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
            "session-2 mount failed: {mount:?}"
        );

        // Confirm we actually took the rehydrate path (otherwise the
        // reconciler is moot — a cold walk would handle the drift on
        // its own and this test would still pass for the wrong reason).
        let stats0 = round_trip(&mut stream, "2", "Daemon.Stats", json!({})).await?;
        assert_eq!(
            stats0["result"]["mount_source"].as_str(),
            Some("rehydrate"),
            "session-2 must take rehydrate path; got {stats0:?}"
        );

        // Poll Daemon.Stats.reconciliation until it reflects at least
        // one changed file (drifted.rs) and one removed (orphan.rs).
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut id: u32 = 20;
        loop {
            id += 1;
            let r = round_trip(&mut stream, &id.to_string(), "Daemon.Stats", json!({})).await?;
            let recon = &r["result"]["reconciliation"];
            let changed = recon["files_changed"].as_u64().unwrap_or(0);
            let removed = recon["files_removed"].as_u64().unwrap_or(0);
            let scanned = recon["files_scanned"].as_u64().unwrap_or(0);
            if changed >= 1 && removed >= 1 {
                assert!(
                    scanned >= changed,
                    "files_scanned ({scanned}) should cover files_changed ({changed}); got {recon:?}"
                );
                assert!(
                    recon["last_run_ns"].as_u64().unwrap_or(0) > 0,
                    "last_run_ns should be non-zero once the pass completes: {recon:?}"
                );
                break;
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "reconciliation never reported drift within 10s; last reading: {r:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // The writer drain runs async. Wait for the reparse to land
        // before asserting the post-drift symbol view.
        let r =
            poll_find_symbol_exists(&mut stream, "drift_target_v2", Duration::from_secs(10), 200)
                .await?;
        // Symbol exists in drifted.rs after the reparse — that's what
        // we care about. The exact `start_line` depends on
        // language-specific signature parsing; one match is enough.
        assert!(
            r["result"]["matches"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false),
            "drift_target_v2 should be indexed after reconciliation reparse"
        );

        // Old symbol should be gone (file was overwritten, not
        // appended). Use a short-deadline poll so we don't flake on
        // the still-draining writer.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut id: u32 = 300;
        loop {
            id += 1;
            let r = round_trip(
                &mut stream,
                &id.to_string(),
                "Index.FindSymbol",
                json!({ "name": "drift_target_v1" }),
            )
            .await?;
            let arr = r["result"]["matches"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if arr.is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                anyhow::bail!("drift_target_v1 still present after reconcile + reparse; got {r:?}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // AC16: `stable.rs` was not modified between sessions, and the
        // callee `stable_callee_hub` lives in `drifted.rs` (which WAS
        // touched). Reconciliation must NOT invalidate the cross-file
        // caller edge from `stable.rs` into `stable_callee_hub`.
        // Once the writer commits its post-touch batch, REFS should
        // still contain the edge.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut id: u32 = 400;
        let callers = loop {
            id += 1;
            let r = round_trip(
                &mut stream,
                &id.to_string(),
                "Index.FindCallers",
                json!({ "name": "stable_callee_hub" }),
            )
            .await?;
            let arr = r["result"]["callers"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if !arr.is_empty() {
                break arr;
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "AC16 violation: stable.rs caller edge into stable_callee_hub vanished after reconcile; got {r:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };

        // Confirm it's actually `stable.rs` (not a re-parse of
        // drifted.rs that ate its own caller edge).
        let has_stable = callers.iter().any(|c| {
            c.get("file")
                .and_then(|v| v.as_str())
                .map(|s| s.ends_with("stable.rs"))
                .unwrap_or(false)
        });
        assert!(
            has_stable,
            "AC16: caller edge from stable.rs should survive reconciliation; got {callers:?}"
        );
    }

    Ok(())
}
