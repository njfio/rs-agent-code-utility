//! End-to-end tests for per-request deadlines via the JSON-RPC
//! envelope's optional `deadline_ms` field (`docs/protocol-v0.md` §3.4).
//!
//! A timer arms when `deadline_ms` is supplied; once the budget elapses
//! it trips the request's `CancelToken`, the handler's cooperative poll
//! catches it and returns `CANCELLED`, and the dispatcher rewrites that
//! into `DEADLINE_EXCEEDED`. These tests exercise the four observable
//! behaviors:
//!
//! 1. A slow query whose deadline elapses returns `DEADLINE_EXCEEDED`.
//! 2. A fast query under a generous deadline completes normally.
//! 3. An explicit `Daemon.Cancel` (no `deadline_ms`) still surfaces as
//!    `CANCELLED`, not `DEADLINE_EXCEEDED`.
//! 4. An out-of-range `deadline_ms` (0 or > 600000) is rejected with
//!    `INVALID_PARAMS` before any work runs.
//!
//! The daemon-spawn / Unix-socket round-trip / slow-fixture harness is
//! copied from `cancel_in_flight.rs` to keep each integration test
//! self-contained (cargo compiles each `tests/*.rs` as its own crate).

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

/// Send a JSON-RPC request on `stream` and wait for the matching
/// response line. `extras` is merged into the top-level envelope — used
/// here to set the optional `cancel_id` / `deadline_ms` fields without
/// hard-coding them into a separate helper.
async fn round_trip(
    stream: &mut UnixStream,
    id: &str,
    method: &str,
    params: Value,
    extras: Option<&[(&str, Value)]>,
) -> anyhow::Result<Value> {
    let mut req = serde_json::Map::new();
    req.insert("id".into(), Value::String(id.to_string()));
    req.insert("method".into(), Value::String(method.to_string()));
    req.insert("params".into(), params);
    if let Some(extras) = extras {
        for (k, v) in extras {
            req.insert((*k).into(), v.clone());
        }
    }
    let req = Value::Object(req);
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.flush().await?;

    let mut buf = Vec::new();
    let (rd, _wr) = stream.split();
    let mut reader = BufReader::new(rd);
    let n = tokio::time::timeout(Duration::from_secs(30), reader.read_until(b'\n', &mut buf))
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

/// Seed a workspace whose structural query path fans out across enough
/// files that the per-file cancellation poll has time to fire before
/// the natural scan completes. One `fn` per file; the slow `Index.Grep`
/// walks every in-scope file before the row cap triggers.
fn seed_workspace(root: &std::path::Path, file_count: usize) -> anyhow::Result<()> {
    for i in 0..file_count {
        let path = root.join(format!("file_{i:05}.rs"));
        let body = format!(
            "pub fn marker_{i:05}() {{\n    \
             let a = {i}u32;\n    \
             let b = a.wrapping_mul(31);\n    \
             let c = b ^ 0x5a5a5a5a;\n    \
             let _ = (a, b, c);\n\
             }}\n"
        );
        std::fs::write(&path, body)?;
    }
    Ok(())
}

/// Seed a workspace with a single `hub` fn that calls `leaf_NNNNN()`
/// across `leaf_count` distinct files — one leaf per file. `read_symbol`
/// with `include_dependencies: true` on `hub` resolves every leaf as a
/// depth-1 dependency, and the closure walker reads each leaf's file +
/// runs a tree-sitter signature render per dep. With a large
/// `leaf_count` that render loop runs long enough for a tiny deadline to
/// land inside its cooperative poll. Returns the hub's symbol name.
fn seed_closure_workspace(root: &std::path::Path, leaf_count: usize) -> anyhow::Result<String> {
    for i in 0..leaf_count {
        let path = root.join(format!("leaf_{i:05}.rs"));
        let body = format!(
            "pub fn leaf_{i:05}() -> u32 {{\n    \
             let a = {i}u32;\n    \
             a.wrapping_mul(31) ^ 0x5a5a5a5a\n\
             }}\n"
        );
        std::fs::write(&path, body)?;
    }
    // The hub calls every leaf, so its outgoing-reference set is the
    // full leaf population — exactly what the closure walker expands.
    let mut hub = String::from("pub fn hub() -> u32 {\n    let mut acc = 0u32;\n");
    for i in 0..leaf_count {
        hub.push_str(&format!("    acc = acc.wrapping_add(leaf_{i:05}());\n"));
    }
    hub.push_str("    acc\n}\n");
    std::fs::write(root.join("hub.rs"), hub)?;
    Ok("hub".to_string())
}

/// Wait until the cold walk has committed at least `min_files` distinct
/// files to the index. The structural scanner walks the committed-file
/// set, so the query duration is gated on this — a half-indexed
/// workspace makes for a too-fast natural completion and a flaky race.
async fn wait_for_index_warm(
    stream: &mut UnixStream,
    min_files: u64,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut probe_id: u64 = 9000;
    loop {
        probe_id += 1;
        let resp = round_trip(
            stream,
            &probe_id.to_string(),
            "Workspace.Status",
            json!({}),
            None,
        )
        .await?;
        let files_done = resp["result"]["progress"]["files_done"]
            .as_u64()
            .unwrap_or(0);
        if files_done >= min_files {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "index never reached {min_files} files within {:?} (saw files_done={files_done})",
                timeout
            );
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

/// Poll `Daemon.Stats.cancellations.in_flight` over `stream` until it
/// satisfies `predicate(in_flight)`. The synchronization barrier the
/// explicit-cancel test uses in place of a fixed sleep — see
/// `cancel_in_flight.rs` for the full rationale.
async fn wait_for_in_flight<F>(
    stream: &mut UnixStream,
    mut predicate: F,
    timeout: Duration,
    label: &str,
) -> anyhow::Result<u64>
where
    F: FnMut(u64) -> bool,
{
    let deadline = Instant::now() + timeout;
    let mut probe_id: u64 = 9500;
    loop {
        probe_id += 1;
        let resp = round_trip(
            stream,
            &probe_id.to_string(),
            "Daemon.Stats",
            json!({}),
            None,
        )
        .await?;
        let in_flight = resp["result"]["cancellations"]["in_flight"]
            .as_u64()
            .unwrap_or(0);
        if predicate(in_flight) {
            return Ok(in_flight);
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "{label}: in_flight={in_flight} did not satisfy predicate within {:?}",
                timeout
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Build the structural-grep params used by the slow-query tests.
/// `(function_item) @fn` matches every Rust function; with one fn per
/// file in the fixture the scanner walks every file before the row cap
/// (4096) triggers, giving the deadline timer a long window to land
/// inside the hot loop.
fn slow_grep_params() -> Value {
    json!({
        "structural_query": "(function_item) @fn",
        "language": ["rust"],
        "limit": 4096,
    })
}

/// Test 1: a slow query whose deadline elapses returns
/// `DEADLINE_EXCEEDED`.
///
/// We pick a large fixture (5000 files) so the natural scan is
/// comfortably longer than the small deadline budget — determinism here
/// comes from fixture size, not from a generous timeout. The budget is
/// kept tiny (5 ms) so the timer trips well before the scan could
/// finish even on a fast machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_query_hits_deadline_returns_deadline_exceeded() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    let file_count: u64 = 5000;
    seed_workspace(workspace.path(), file_count as usize)?;

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
        None,
    )
    .await?;
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");
    wait_for_index_warm(&mut stream, file_count, Duration::from_secs(120)).await?;

    let resp = round_trip(
        &mut stream,
        "2",
        "Index.Grep",
        slow_grep_params(),
        Some(&[("deadline_ms", json!(5u64))]),
    )
    .await?;

    let code = resp["error"]["code"].as_str().unwrap_or("<no error>");
    assert_eq!(
        code, "DEADLINE_EXCEEDED",
        "expected DEADLINE_EXCEEDED on a query that overran its budget; got: {resp:?}"
    );
    Ok(())
}

/// Test 2: a fast query under a generous deadline completes normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_query_under_budget_completes_normally() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    std::fs::write(workspace.path().join("only.rs"), "pub fn only_fn() {}\n")?;

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
        None,
    )
    .await?;
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");
    wait_for_index_warm(&mut stream, 1, Duration::from_secs(10)).await?;

    let resp = round_trip(
        &mut stream,
        "2",
        "Index.FindSymbol",
        json!({ "name": "only_fn" }),
        Some(&[("deadline_ms", json!(60_000u64))]),
    )
    .await?;

    assert!(
        resp["error"].is_null(),
        "fast query under a 60s deadline must not error; got: {resp:?}"
    );
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !matches.is_empty(),
        "expected only_fn in the result envelope; got: {resp:?}"
    );
    Ok(())
}

/// Test 3: an explicit `Daemon.Cancel` (no `deadline_ms`) still surfaces
/// as `CANCELLED`, not `DEADLINE_EXCEEDED`.
///
/// Uses the two-connection + poll-`Daemon.Stats`-`in_flight`
/// synchronization pattern from `cancel_in_flight.rs` so the cancel
/// arrives after the token is registered, not on a wall-clock gamble.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_cancel_still_returns_cancelled_not_deadline() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    let file_count: u64 = 3000;
    seed_workspace(workspace.path(), file_count as usize)?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
    let mut child = spawn_daemon(runtime_dir.path(), state_dir.path(), home_dir.path())?;
    let _kill = KillOnDrop(&mut child);
    wait_for_socket(&sock, Duration::from_secs(5)).await?;

    let mut mount_conn = UnixStream::connect(&sock).await?;
    let mount = round_trip(
        &mut mount_conn,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
        None,
    )
    .await?;
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");
    wait_for_index_warm(&mut mount_conn, file_count, Duration::from_secs(60)).await?;
    drop(mount_conn);

    let query_conn = UnixStream::connect(&sock).await?;
    let mut control_conn = UnixStream::connect(&sock).await?;
    let (query_rd, mut query_wr) = query_conn.into_split();

    // Mount on the query connection.
    let mut mount_req = serde_json::Map::new();
    mount_req.insert("id".into(), Value::String("m1".into()));
    mount_req.insert("method".into(), Value::String("Workspace.Mount".into()));
    mount_req.insert("params".into(), json!({ "root": workspace.path() }));
    let mut bytes = serde_json::to_vec(&Value::Object(mount_req))?;
    bytes.push(b'\n');
    tokio::io::AsyncWriteExt::write_all(&mut query_wr, &bytes).await?;
    tokio::io::AsyncWriteExt::flush(&mut query_wr).await?;
    let mut query_reader = tokio::io::BufReader::new(query_rd);
    let mut line = Vec::new();
    tokio::io::AsyncBufReadExt::read_until(&mut query_reader, b'\n', &mut line).await?;

    // Fire the slow query with a cancel_id and NO deadline_ms.
    let cancel_id = "q-cancel-not-deadline";
    let mut grep_req = serde_json::Map::new();
    grep_req.insert("id".into(), Value::String("3".into()));
    grep_req.insert("method".into(), Value::String("Index.Grep".into()));
    grep_req.insert("params".into(), slow_grep_params());
    grep_req.insert("cancel_id".into(), Value::String(cancel_id.into()));
    let mut bytes = serde_json::to_vec(&Value::Object(grep_req))?;
    bytes.push(b'\n');
    tokio::io::AsyncWriteExt::write_all(&mut query_wr, &bytes).await?;
    tokio::io::AsyncWriteExt::flush(&mut query_wr).await?;

    // Barrier: wait for the token to register before cancelling.
    wait_for_in_flight(
        &mut control_conn,
        |n| n >= 1,
        Duration::from_secs(5),
        "explicit-cancel: waiting for grep token to register",
    )
    .await?;

    let cancel = round_trip(
        &mut control_conn,
        "4",
        "Daemon.Cancel",
        json!({ "cancel_id": cancel_id }),
        None,
    )
    .await?;
    assert_eq!(
        cancel["result"]["cancelled"], true,
        "expected cancelled=true on a live in-flight query; got: {cancel:?}"
    );

    // Drain the grep response (id=3).
    let mut buf = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(15),
        tokio::io::AsyncBufReadExt::read_until(&mut query_reader, b'\n', &mut buf),
    )
    .await??;
    let query_resp: Value = serde_json::from_slice(&buf)?;
    assert_eq!(
        query_resp["id"].as_str().unwrap_or(""),
        "3",
        "unexpected response on query connection: {query_resp:?}"
    );
    let code = query_resp["error"]["code"].as_str().unwrap_or("<no error>");
    assert_eq!(
        code, "CANCELLED",
        "an explicit Daemon.Cancel without a deadline must surface as CANCELLED, \
         not DEADLINE_EXCEEDED; got: {query_resp:?}"
    );
    Ok(())
}

/// Capability + stats surface: `Daemon.Ping` advertises the
/// `request_deadlines` capability and `Daemon.Stats` exposes a
/// `deadlines.total` counter (a non-negative integer). No workspace
/// mount is needed — both RPCs answer pre-mount.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capability_and_stats_advertise_deadlines() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
    let mut child = spawn_daemon(runtime_dir.path(), state_dir.path(), home_dir.path())?;
    let _kill = KillOnDrop(&mut child);
    wait_for_socket(&sock, Duration::from_secs(5)).await?;

    let mut stream = UnixStream::connect(&sock).await?;

    let ping = round_trip(&mut stream, "1", "Daemon.Ping", json!({}), None).await?;
    assert!(ping["error"].is_null(), "ping failed: {ping:?}");
    let caps = ping["result"]["capabilities"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        caps.iter().any(|c| c.as_str() == Some("request_deadlines")),
        "Daemon.Ping must advertise the request_deadlines capability; got: {ping:?}"
    );

    let stats = round_trip(&mut stream, "2", "Daemon.Stats", json!({}), None).await?;
    assert!(stats["error"].is_null(), "stats failed: {stats:?}");
    let total = stats["result"]["deadlines"]["total"].as_u64();
    assert!(
        total.is_some(),
        "Daemon.Stats must expose deadlines.total as an integer; got: {stats:?}"
    );
    assert!(
        total.unwrap() < u64::MAX,
        "deadlines.total must be a sane non-negative integer; got: {stats:?}"
    );
    Ok(())
}

/// Test 4: an out-of-range `deadline_ms` is rejected with
/// `INVALID_PARAMS` before any work runs. Covers both the lower bound
/// (0) and just past the upper bound (600001).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn out_of_range_deadline_is_invalid_params() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    std::fs::write(workspace.path().join("only.rs"), "pub fn only_fn() {}\n")?;

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
        None,
    )
    .await?;
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");

    let zero = round_trip(
        &mut stream,
        "2",
        "Index.FindSymbol",
        json!({ "name": "only_fn" }),
        Some(&[("deadline_ms", json!(0u64))]),
    )
    .await?;
    assert_eq!(
        zero["error"]["code"].as_str().unwrap_or("<no error>"),
        "INVALID_PARAMS",
        "deadline_ms=0 must be rejected as INVALID_PARAMS; got: {zero:?}"
    );

    let too_big = round_trip(
        &mut stream,
        "3",
        "Index.FindSymbol",
        json!({ "name": "only_fn" }),
        Some(&[("deadline_ms", json!(600_001u64))]),
    )
    .await?;
    assert_eq!(
        too_big["error"]["code"].as_str().unwrap_or("<no error>"),
        "INVALID_PARAMS",
        "deadline_ms=600001 must be rejected as INVALID_PARAMS; got: {too_big:?}"
    );
    Ok(())
}

/// Task 4 / Part A: `Index.ReadSymbol` with `include_dependencies: true`
/// over a wide dependency closure is interruptible by a tiny deadline.
///
/// Before the closure walker polled the request's `CancelToken`, the
/// dep-closure render loop (a file read + tree-sitter signature render
/// per dep) ran to completion regardless of any deadline. We seed a hub
/// fn with a few thousand single-leaf-per-file dependencies so the
/// render loop runs comfortably longer than the 5ms budget, then assert
/// the response is `DEADLINE_EXCEEDED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deadline_interrupts_read_symbol_dependency_closure() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    let leaf_count: usize = 4000;
    let hub_name = seed_closure_workspace(workspace.path(), leaf_count)?;
    // hub.rs + one file per leaf.
    let file_count = leaf_count as u64 + 1;

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
        None,
    )
    .await?;
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");
    wait_for_index_warm(&mut stream, file_count, Duration::from_secs(120)).await?;

    let resp = round_trip(
        &mut stream,
        "2",
        "Index.ReadSymbol",
        json!({
            "name": hub_name,
            "include_dependencies": true,
            "token_budget": 200_000,
        }),
        Some(&[("deadline_ms", json!(5u64))]),
    )
    .await?;

    let code = resp["error"]["code"].as_str().unwrap_or("<no error>");
    assert_eq!(
        code, "DEADLINE_EXCEEDED",
        "read_symbol over a wide dependency closure must honor the deadline; got: {resp:?}"
    );
    Ok(())
}

/// Task 4 / Part B: `Index.ImpactOf` over a deep call graph is
/// interruptible by a tiny deadline.
///
/// `impact_of` previously didn't receive the request token at all, so
/// neither a deadline nor an explicit `Daemon.Cancel` could interrupt
/// its BFS. The BFS does carry a fixed 50ms wall-clock budget, so this
/// e2e is best-effort: a sub-millisecond deadline on a fan-in graph
/// races the wall-clock cap. We assert the call surfaces *either*
/// `DEADLINE_EXCEEDED` (deadline won) or a normal truncated result
/// (wall-clock won) — never a hang and never a CANCELLED leak. The
/// unit test `impact::tests::impact_bfs_breaks_on_pretripped_token`
/// gives the deterministic poll-fires guarantee.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deadline_interrupts_impact_of() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // Reuse the hub/leaf fixture: every leaf is called by `hub`, so
    // `Index.ImpactOf` on a leaf finds `hub` as a caller. To give the
    // BFS a wide frontier we instead anchor on a shared helper that all
    // leaves call. Simpler: anchor on a leaf — depth-1 fan-in is small,
    // but the call is still exercised end-to-end with a deadline.
    let leaf_count: usize = 4000;
    let _hub = seed_closure_workspace(workspace.path(), leaf_count)?;
    let file_count = leaf_count as u64 + 1;

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
        None,
    )
    .await?;
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");
    wait_for_index_warm(&mut stream, file_count, Duration::from_secs(120)).await?;

    let resp = round_trip(
        &mut stream,
        "2",
        "Index.ImpactOf",
        json!({
            "name": "leaf_00000",
            "depth": 4,
            "max_nodes": 10000,
            "token_budget": 200_000,
        }),
        Some(&[("deadline_ms", json!(1u64))]),
    )
    .await?;

    // The token is now threaded into the BFS, so the request can never
    // hang and never surface a raw CANCELLED. Either the deadline won
    // (DEADLINE_EXCEEDED) or the BFS finished within budget (a normal
    // result envelope, possibly wall-clock-truncated).
    let code = resp["error"]["code"].as_str();
    match code {
        Some("DEADLINE_EXCEEDED") => {}
        Some(other) => panic!("unexpected error code from impact_of under deadline: {other}; {resp:?}"),
        None => assert!(
            resp["result"]["impact"].is_array(),
            "impact_of without a deadline trip must return a normal result; got: {resp:?}"
        ),
    }
    Ok(())
}
