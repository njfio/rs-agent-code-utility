//! End-to-end test for the UNRESOLVED_REFS GC pass introduced in
//! PR #128 (capability `daemon_telemetry_unresolved_refs_gc`).
//!
//! Three properties are asserted against the live daemon binary,
//! mirroring the test plan in the PR brief:
//!
//! 1. `gc_drops_refs_for_removed_file` — a workspace where one file
//!    forward-references a symbol that **does not exist anywhere**
//!    parks a row in `UNRESOLVED_REFS`. Deleting the file should
//!    drain that row and advance the telemetry counters.
//! 2. `gc_runs_counter_bumps_on_each_removal` — two independent
//!    removals advance `unresolved_refs_gc_runs_total` by two.
//! 3. `gc_preserves_refs_from_still_present_files` — control test:
//!    removing one file must NOT drop another file's unresolved refs.
//!
//! The test spawns the real daemon binary; it's gated on
//! `--include-ignored` (matching every other integration test in this
//! crate that touches the binary) so it doesn't slow the inner-loop
//! `cargo test`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-daemon"))
}

async fn wait_for_socket(path: &Path, timeout: Duration) -> anyhow::Result<()> {
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

fn socket_path(home_dir: &Path, runtime_dir: &Path) -> PathBuf {
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
    runtime_dir: &Path,
    state_dir: &Path,
    home_dir: &Path,
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

/// Pull the three relevant fields out of a `Daemon.Telemetry`
/// response so tests can assert against them tersely.
fn read_telemetry_fields(resp: &Value) -> (u64, u64, u64) {
    let result = &resp["result"];
    let count = result["unresolved_refs_count"].as_u64().unwrap_or(0);
    let runs = result["unresolved_refs_gc_runs_total"]
        .as_u64()
        .unwrap_or(0);
    let dropped = result["unresolved_refs_gc_dropped_total"]
        .as_u64()
        .unwrap_or(0);
    (count, runs, dropped)
}

/// Poll `Daemon.Telemetry` until `predicate` succeeds against the
/// `(count, runs, dropped)` triple, or `timeout` elapses. Returns the
/// final triple on success; bails with the last observed value
/// otherwise.
async fn poll_telemetry<F>(
    stream: &mut UnixStream,
    id_seed: u32,
    timeout: Duration,
    predicate: F,
) -> anyhow::Result<(u64, u64, u64)>
where
    F: Fn(u64, u64, u64) -> bool,
{
    let deadline = Instant::now() + timeout;
    let mut id = id_seed;
    loop {
        id += 1;
        let r = round_trip(stream, &id.to_string(), "Daemon.Telemetry", json!({})).await?;
        let last = read_telemetry_fields(&r);
        if predicate(last.0, last.1, last.2) {
            return Ok(last);
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "telemetry never satisfied predicate within {timeout:?}; last=(count={}, runs={}, dropped={})",
                last.0,
                last.1,
                last.2
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Poll `Index.FindSymbol(name)` until at least one match comes back,
/// or `timeout` elapses. Used to wait for the writer to drain a touch.
async fn poll_find_symbol_exists(
    stream: &mut UnixStream,
    name: &str,
    timeout: Duration,
    id_seed: u32,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut id = id_seed;
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
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("FindSymbol({name}) never returned matches within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

/// **Test 1.** A workspace with a file whose only ref points at a
/// symbol that **does not exist anywhere** parks a row in
/// `UNRESOLVED_REFS` (`unknown_phantom_target` below — chosen so it
/// can't collide with stdlib / `println!` / Vec etc.). Removing the
/// file on disk must:
///   a) drain the row (count drops by at least one), and
///   b) advance both `unresolved_refs_gc_runs_total` (one removal)
///      and `unresolved_refs_gc_dropped_total` (at least one row).
#[tokio::test(flavor = "current_thread")]
#[ignore = "spawns the daemon binary; opt-in via --include-ignored"]
async fn gc_drops_refs_for_removed_file() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // caller.rs references `unknown_phantom_target`, which is never
    // defined anywhere. Without GC, that row stays in UNRESOLVED_REFS
    // forever; with GC it drops when caller.rs is removed.
    std::fs::write(
        workspace.path().join("caller.rs"),
        "pub fn caller_fn() {\n    unknown_phantom_target();\n}\n",
    )?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
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
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");

    // Wait until indexing observes caller.rs.
    poll_find_symbol_exists(&mut stream, "caller_fn", Duration::from_secs(10), 100).await?;

    // The phantom ref should be parked in UNRESOLVED_REFS. Poll for
    // it: indexing is async, so a same-millisecond check after Mount
    // might catch a half-flushed state.
    let (pre_count, _, pre_dropped) = poll_telemetry(
        &mut stream,
        200,
        Duration::from_secs(10),
        |count, _runs, _dropped| count >= 1,
    )
    .await?;
    assert!(
        pre_count >= 1,
        "unresolved_refs_count should be >= 1 after caller.rs is indexed (phantom ref); got {pre_count}"
    );

    // Delete the file on disk. The watcher should emit Removed,
    // the writer should run GC, and telemetry should reflect both
    // the count drop and the GC counters advancing.
    std::fs::remove_file(workspace.path().join("caller.rs"))?;

    let (post_count, post_runs, post_dropped) = poll_telemetry(
        &mut stream,
        300,
        Duration::from_secs(15),
        |count, _runs, dropped| count < pre_count && dropped > pre_dropped,
    )
    .await?;

    assert!(
        post_count < pre_count,
        "unresolved_refs_count should drop after file removal; pre={pre_count}, post={post_count}"
    );
    assert!(
        post_runs >= 1,
        "unresolved_refs_gc_runs_total should advance after a file removal; got {post_runs}"
    );
    assert!(
        post_dropped >= 1,
        "unresolved_refs_gc_dropped_total should advance by >= 1; got {post_dropped}"
    );

    Ok(())
}

/// **Test 2.** Two independent file removals must each register on
/// `unresolved_refs_gc_runs_total`. Counters are cumulative, so we
/// snapshot before and after and assert the delta.
#[tokio::test(flavor = "current_thread")]
#[ignore = "spawns the daemon binary; opt-in via --include-ignored"]
async fn gc_runs_counter_bumps_on_each_removal() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // Two independent files, each with its own phantom callee. The
    // distinct callees ensure each file's removal touches a different
    // FID_UNRESOLVED reverse-edge set.
    std::fs::write(
        workspace.path().join("first.rs"),
        "pub fn first_fn() {\n    phantom_one();\n}\n",
    )?;
    std::fs::write(
        workspace.path().join("second.rs"),
        "pub fn second_fn() {\n    phantom_two();\n}\n",
    )?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
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
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");

    // Wait for both files to be indexed (both phantom refs parked).
    poll_find_symbol_exists(&mut stream, "first_fn", Duration::from_secs(10), 100).await?;
    poll_find_symbol_exists(&mut stream, "second_fn", Duration::from_secs(10), 200).await?;
    let (_pre_count, pre_runs, _pre_dropped) = poll_telemetry(
        &mut stream,
        300,
        Duration::from_secs(10),
        |count, _runs, _dropped| count >= 2,
    )
    .await?;

    // Remove file 1, wait for runs to advance.
    std::fs::remove_file(workspace.path().join("first.rs"))?;
    let (_c1, runs_1, _d1) = poll_telemetry(
        &mut stream,
        400,
        Duration::from_secs(15),
        |_count, runs, _dropped| runs > pre_runs,
    )
    .await?;
    let after_first = runs_1;

    // Sleep a beat so the watcher's debouncer doesn't fold both
    // removals into one batch. The watcher's debounce window is
    // 150ms (per writer.rs::BATCH_FLUSH_INTERVAL), so 300ms is the
    // safe margin.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Remove file 2.
    std::fs::remove_file(workspace.path().join("second.rs"))?;
    let (_c2, runs_2, _d2) = poll_telemetry(
        &mut stream,
        500,
        Duration::from_secs(15),
        |_count, runs, _dropped| runs > after_first,
    )
    .await?;

    assert!(
        runs_2 >= pre_runs + 2,
        "runs_total should advance by >= 2 after two removals; pre={pre_runs}, post={runs_2}"
    );

    Ok(())
}

/// **Test 3.** Control: removing one file MUST NOT drop unresolved
/// refs that originated in another file. The
/// `FID_UNRESOLVED`-keyed walk in
/// `gc_unresolved_refs_for_removed_files` is the load-bearing
/// invariant here; if it were keyed by callee name alone, it would
/// over-collect.
///
/// Both files reference the SAME phantom callee, so they share a
/// `UNRESOLVED_REFS[name]` multimap key. Removing one file must
/// leave the other's row in place.
#[tokio::test(flavor = "current_thread")]
#[ignore = "spawns the daemon binary; opt-in via --include-ignored"]
async fn gc_preserves_refs_from_still_present_files() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // Both files reference the same phantom callee. The shared name
    // is the point: this catches an implementation that drops every
    // UNRESOLVED_REFS[name] row when ANY file with that callee name
    // is removed.
    std::fs::write(
        workspace.path().join("keeper.rs"),
        "pub fn keeper_fn() {\n    shared_phantom();\n}\n",
    )?;
    std::fs::write(
        workspace.path().join("victim.rs"),
        "pub fn victim_fn() {\n    shared_phantom();\n}\n",
    )?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
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
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");

    poll_find_symbol_exists(&mut stream, "keeper_fn", Duration::from_secs(10), 100).await?;
    poll_find_symbol_exists(&mut stream, "victim_fn", Duration::from_secs(10), 200).await?;

    // Wait until both phantom refs are parked. They share a callee
    // name but live as distinct multimap values (different `fid`
    // inside the RefSite blob); count should reach >= 2.
    let (pre_count, _pre_runs, pre_dropped) = poll_telemetry(
        &mut stream,
        300,
        Duration::from_secs(10),
        |count, _runs, _dropped| count >= 2,
    )
    .await?;
    assert!(
        pre_count >= 2,
        "expected both phantom refs parked; got count={pre_count}"
    );

    // Delete only victim.rs. The GC must drop exactly its row(s),
    // leaving keeper.rs's row intact.
    std::fs::remove_file(workspace.path().join("victim.rs"))?;

    let (post_count, _post_runs, post_dropped) = poll_telemetry(
        &mut stream,
        400,
        Duration::from_secs(15),
        |count, _runs, dropped| dropped > pre_dropped && count < pre_count,
    )
    .await?;

    // The keeper's row must survive: count drop from 2 to 1 (not 0).
    // Strict inequality on the post-count guards against the bug
    // class where every UNRESOLVED_REFS[name] row gets dropped.
    assert!(
        post_count >= 1,
        "keeper.rs's shared_phantom ref should survive victim.rs removal; \
         got post_count={post_count} (pre={pre_count}, dropped_delta={})",
        post_dropped - pre_dropped
    );

    // And to remove any doubt, FindSymbol confirms keeper_fn is still
    // around (its file is still on disk).
    let r = round_trip(
        &mut stream,
        "500",
        "Index.FindSymbol",
        json!({ "name": "keeper_fn" }),
    )
    .await?;
    assert!(
        r["result"]["matches"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "keeper_fn should still be indexed after victim.rs removal: {r:?}"
    );

    Ok(())
}
