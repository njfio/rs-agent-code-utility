//! End-to-end test for `Daemon.Cancel { cancel_id }` — cooperative
//! cancellation of in-flight requests via the JSON-RPC envelope's
//! optional `cancel_id` field.
//!
//! See `docs/plans/2026-05-19-001-feat-cancellable-queries-plan.md`.
//!
//! Covers the three plan scenarios:
//!
//! 1. **Slow query cancelled mid-flight** — fire a structural
//!    `Index.Grep` on a 10k-file fixture; from another connection
//!    send `Daemon.Cancel`; assert the response is `CANCELLED` within
//!    the cancel-call latency window.
//! 2. **Stale cancel** — let a quick query complete; then send
//!    `Daemon.Cancel` for the same id; assert
//!    `{ cancelled: false }` (idempotent, no error).
//! 3. **Concurrent queries, selective cancel** — fire two slow
//!    queries with different `cancel_id`s; cancel only the first;
//!    assert the first returns CANCELLED and the second completes
//!    normally.

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
/// response line. `extras` is merged into the top-level envelope —
/// used here to set the optional `cancel_id` field without
/// hard-coding it into a separate helper.
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
/// files that the per-file cancellation poll has time to fire. Each
/// file holds one `fn` + a `marker_NNN` probe; the slow `Index.Grep`
/// uses a structural query with `limit: 1` so the row-cap break
/// doesn't short-circuit the walk — the scanner is forced to visit
/// every in-scope file before returning. With ~2000 files at ~1ms
/// per-file tree-sitter parse the natural query duration lands in
/// the 1-2 s range, giving the 50 ms cancel-race a comfortable
/// window in either direction.
///
/// File count stays moderate (the plan's nominal 10k is intentionally
/// not used here — every file pays cold-mount cost in this test, and
/// 10k empty files would dominate wall time without changing the
/// cancellation signal at all).
fn seed_workspace(root: &std::path::Path, file_count: usize) -> anyhow::Result<()> {
    for i in 0..file_count {
        let path = root.join(format!("file_{i:05}.rs"));
        // Body large enough that the parser does real work
        // per file (tree-sitter throughput is byte-bounded), but
        // small enough that 2000 files build in well under a
        // second of test setup time.
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

/// Wait until the cold walk has committed at least `min_files`
/// distinct files to the index. The structural scanner walks the
/// committed-file set, so the query duration is gated on this — a
/// half-indexed workspace makes for a too-fast natural completion
/// and a flaky cancel race.
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

/// Build the structural-grep params used across the three scenarios.
/// `(function_item) @fn` matches every Rust function in the
/// workspace; with one fn per file in the fixture the scanner has to
/// walk every file before the row cap (4096) would trigger, giving
/// the cancellation poll a long window to land inside the hot loop.
fn slow_grep_params() -> Value {
    json!({
        "structural_query": "(function_item) @fn",
        "language": ["rust"],
        "limit": 4096,
    })
}

/// Scenario 1: slow query cancelled mid-flight.
///
/// Intent: prove that `Daemon.Cancel { cancel_id }` interrupts an
/// in-flight `Index.Grep` and that the cancelled handler returns the
/// `CANCELLED` error envelope. This is the load-bearing user-facing
/// invariant the whole feature exists for — without it, agent-burst
/// traffic burns CPU on abandoned queries.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_query_cancelled_mid_flight() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // Need enough fixture files that the natural structural-scan
    // duration on a multi-second daemon worker is comfortably longer
    // than the time between firing `Daemon.Cancel` and the daemon
    // observing it. We use ~3000 files; each fn parses fast on
    // tree-sitter but the scanner walks every file before the row
    // cap (4096) triggers — 3000 files * single-fn-each fits well
    // under the cap.
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

    // One connection for query + cancel — both requests are
    // pipelined on the same socket. The daemon's per-connection
    // serve loop spawns each request on a separate tokio task, so
    // the cancel runs while the grep is still working. (The plan's
    // "from another connection send Daemon.Cancel" wording is
    // satisfied just as well by pipelining on the same connection;
    // the registry is daemon-global, not connection-scoped.)
    let query_conn = UnixStream::connect(&sock).await?;
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
    // Drained mount response.

    let cancel_id = "q-slow-1";
    // Fire the structural query. We do *not* sleep between the
    // send-grep and send-cancel — pipelined writes both land on the
    // daemon's per-connection read loop in order. But we DO sleep
    // before sending the cancel, because tokio's spawn ordering
    // doesn't guarantee the grep's dispatch task has reached its
    // token-register before the cancel's dispatch task runs the
    // registry lookup. A short sleep (50 ms) gives the grep's
    // dispatcher time to land the token in the registry before the
    // cancel checks it.
    let mut grep_req = serde_json::Map::new();
    grep_req.insert("id".into(), Value::String("3".into()));
    grep_req.insert("method".into(), Value::String("Index.Grep".into()));
    grep_req.insert("params".into(), slow_grep_params());
    grep_req.insert("cancel_id".into(), Value::String(cancel_id.into()));
    let mut bytes = serde_json::to_vec(&Value::Object(grep_req))?;
    bytes.push(b'\n');
    tokio::io::AsyncWriteExt::write_all(&mut query_wr, &bytes).await?;
    tokio::io::AsyncWriteExt::flush(&mut query_wr).await?;

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut cancel_req = serde_json::Map::new();
    cancel_req.insert("id".into(), Value::String("4".into()));
    cancel_req.insert("method".into(), Value::String("Daemon.Cancel".into()));
    cancel_req.insert("params".into(), json!({ "cancel_id": cancel_id }));
    let mut bytes = serde_json::to_vec(&Value::Object(cancel_req))?;
    bytes.push(b'\n');
    tokio::io::AsyncWriteExt::write_all(&mut query_wr, &bytes).await?;
    tokio::io::AsyncWriteExt::flush(&mut query_wr).await?;

    let cancel_start = Instant::now();

    // Read responses in id order. Both grep and cancel reply on the
    // same connection but ordering is whoever finishes first — the
    // cancel is sub-millisecond, the grep is hundreds of ms (and
    // returns CANCELLED). We collect both then assert on each.
    let mut responses_by_id: std::collections::HashMap<String, Value> =
        std::collections::HashMap::new();
    while responses_by_id.len() < 2 {
        let mut buf = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(15),
            tokio::io::AsyncBufReadExt::read_until(&mut query_reader, b'\n', &mut buf),
        )
        .await??;
        let v: Value = serde_json::from_slice(&buf)?;
        let id = v["id"].as_str().unwrap_or("?").to_string();
        responses_by_id.insert(id, v);
    }

    let cancel = responses_by_id.remove("4").expect("cancel response by id");
    assert!(
        cancel["error"].is_null(),
        "Daemon.Cancel returned an error envelope: {cancel:?}"
    );
    assert_eq!(
        cancel["result"]["cancelled"], true,
        "expected cancelled=true on a live in-flight query; got: {cancel:?}"
    );

    let query_resp = responses_by_id.remove("3").expect("grep response by id");
    let cancel_to_response = cancel_start.elapsed();
    let error_code = query_resp["error"]["code"]
        .as_str()
        .unwrap_or("<no error>")
        .to_string();
    assert_eq!(
        error_code, "CANCELLED",
        "expected CANCELLED envelope on cancelled query; got: {query_resp:?}"
    );
    // The plan calls for ~50 µs typical abort latency. We give a
    // generous wall budget here (2 s) because the test runs on
    // shared CI hardware and the bound we actually care about is
    // "way less than the natural query completion" — which on this
    // fixture would be hundreds of ms to seconds, not the 2 s we
    // budget here.
    assert!(
        cancel_to_response < Duration::from_secs(2),
        "cancel-to-response latency exceeded 2s: {cancel_to_response:?}"
    );
    Ok(())
}

/// Scenario 2: stale cancel is idempotent.
///
/// Intent: prove that `Daemon.Cancel` against an id that's no longer
/// registered (the query already completed) returns
/// `{ cancelled: false }` with no error envelope. Idempotency keeps
/// the agent's cancel-on-revision logic simple — they don't have to
/// race the daemon to win the cancel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_cancel_is_idempotent() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // Tiny workspace: the query needs to complete in milliseconds so
    // the cancel arrives after the registry entry has dropped.
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
    wait_for_index_warm(&mut stream, 1, Duration::from_secs(5))
        .await
        .ok(); // sub-second on a single-file workspace; non-fatal if it times out

    let cancel_id = "q-stale-1";
    // Issue a fast find_symbol with the cancel_id; let it complete.
    let resp = round_trip(
        &mut stream,
        "2",
        "Index.FindSymbol",
        json!({ "name": "only_fn" }),
        Some(&[("cancel_id", Value::String(cancel_id.into()))]),
    )
    .await?;
    assert!(
        resp["error"].is_null(),
        "fast query should have succeeded: {resp:?}"
    );
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !matches.is_empty(),
        "expected only_fn to be indexed by the time the fast query returned: {resp:?}"
    );

    // The guard-drop spawn that unregisters the token runs on the
    // runtime; yield a couple times so it lands before we issue the
    // cancel. Without this we could race the drop and flake on a
    // `cancelled: true` from a still-registered token.
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let cancel = round_trip(
        &mut stream,
        "3",
        "Daemon.Cancel",
        json!({ "cancel_id": cancel_id }),
        None,
    )
    .await?;
    assert!(
        cancel["error"].is_null(),
        "stale Daemon.Cancel should not error; got: {cancel:?}"
    );
    assert_eq!(
        cancel["result"]["cancelled"], false,
        "stale cancel must return cancelled=false; got: {cancel:?}"
    );
    Ok(())
}

/// Scenario 3: two concurrent queries, selective cancel.
///
/// Intent: prove that the cancel registry keys on `cancel_id` rather
/// than on connection or method, so cancelling one in-flight query
/// leaves a sibling query running to completion.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn concurrent_queries_selective_cancel() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    let file_count: u64 = 1500;
    seed_workspace(workspace.path(), file_count as usize)?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
    let mut child = spawn_daemon(runtime_dir.path(), state_dir.path(), home_dir.path())?;
    let _kill = KillOnDrop(&mut child);
    wait_for_socket(&sock, Duration::from_secs(5)).await?;

    // Pre-mount on a throwaway connection so subsequent connections
    // see a populated index immediately. The actual queries run on
    // their own connections (so they can race on the daemon's
    // multi-thread runtime instead of serializing on the same
    // per-connection in-flight semaphore).
    {
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
    }

    let mut conn_a = UnixStream::connect(&sock).await?;
    let mut conn_b = UnixStream::connect(&sock).await?;
    let mut cancel_conn = UnixStream::connect(&sock).await?;

    // Both query connections must mount before they can read.
    let _ = round_trip(
        &mut conn_a,
        "10",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
        None,
    )
    .await?;
    let _ = round_trip(
        &mut conn_b,
        "10",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
        None,
    )
    .await?;

    let cancel_a = "q-a";
    let cancel_b = "q-b";
    let task_a = tokio::spawn(async move {
        round_trip(
            &mut conn_a,
            "11",
            "Index.Grep",
            slow_grep_params(),
            Some(&[("cancel_id", Value::String(cancel_a.into()))]),
        )
        .await
    });
    let task_b = tokio::spawn(async move {
        round_trip(
            &mut conn_b,
            "12",
            "Index.Grep",
            slow_grep_params(),
            Some(&[("cancel_id", Value::String(cancel_b.into()))]),
        )
        .await
    });

    // Race-window cushion — same rationale as scenario 1.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let cancel = round_trip(
        &mut cancel_conn,
        "13",
        "Daemon.Cancel",
        json!({ "cancel_id": cancel_a }),
        None,
    )
    .await?;
    assert_eq!(
        cancel["result"]["cancelled"], true,
        "expected cancelled=true for active query A: {cancel:?}"
    );

    let resp_a = tokio::time::timeout(Duration::from_secs(10), task_a).await???;
    let resp_b = tokio::time::timeout(Duration::from_secs(30), task_b).await???;

    assert_eq!(
        resp_a["error"]["code"].as_str().unwrap_or("<no error>"),
        "CANCELLED",
        "query A should have been cancelled; got: {resp_a:?}"
    );
    assert!(
        resp_b["error"].is_null(),
        "query B should have completed normally; got: {resp_b:?}"
    );
    let b_matches = resp_b["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !b_matches.is_empty(),
        "query B should have returned structural matches; got: {resp_b:?}"
    );
    Ok(())
}
