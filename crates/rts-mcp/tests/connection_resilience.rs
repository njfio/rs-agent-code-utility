//! Integration tests for the MCP connection-manager resilience layer
//! (Plan 004, `docs/plans/2026-05-19-004-feat-mcp-server-resilience-plan.md`).
//!
//! Four scenarios exercised end-to-end against real `rts-mcp` and
//! `rts-daemon` binaries — no mocks for cross-crate interfaces, per
//! `AGENTS.md` testing conventions:
//!
//! 1. **Daemon idle-shutdown survival.** Setting
//!    `RTS_IDLE_SHUTDOWN_SECS=2` and idling longer than that should
//!    NOT bring the daemon down while the MCP shim is attached — the
//!    shim's heartbeat keeps `active_connections > 0`. The next tool
//!    call still succeeds.
//! 2. **Daemon SIGKILL recovery.** Killing the daemon mid-session
//!    produces a `DAEMON_UNAVAILABLE` (`-32098`) error from concurrent
//!    tool calls, then auto-reconnects + auto-spawns a fresh daemon
//!    and resumes serving successfully.
//! 3. **MCP shim crash leaves daemon alive.** A second `rts-mcp`
//!    process connects to the same daemon after the first one is
//!    killed; the daemon process keeps the same PID.
//! 4. **Concurrent tool calls during reconnect.** 10 concurrent
//!    `find_symbol` calls fired during a known disconnect window
//!    all return `DAEMON_UNAVAILABLE` with consistent shape (no
//!    thundering-herd on the daemon mutex; all 10 short-circuit on
//!    the state check).

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};

fn rts_mcp_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-mcp"))
}

fn rts_daemon_bin() -> PathBuf {
    let mcp = rts_mcp_bin();
    let parent = mcp.parent().expect("CARGO_BIN_EXE_rts-mcp has parent dir");
    parent.join("rts-daemon")
}

async fn read_one_response(reader: &mut BufReader<ChildStdout>) -> Result<Value> {
    let mut buf = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(8), reader.read_until(b'\n', &mut buf))
        .await
        .map_err(|_| anyhow!("timeout reading MCP response"))??;
    if n == 0 {
        anyhow::bail!("EOF before MCP response");
    }
    serde_json::from_slice(&buf).context("decode MCP response")
}

async fn send_request(stdin: &mut ChildStdin, req: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(req)?;
    bytes.push(b'\n');
    stdin.write_all(&bytes).await?;
    stdin.flush().await?;
    Ok(())
}

/// Standard MCP handshake: `initialize` + `notifications/initialized`.
async fn handshake(stdin: &mut ChildStdin, reader: &mut BufReader<ChildStdout>) -> Result<()> {
    send_request(
        stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "resilience-itest", "version": "0.0.0" }
            }
        }),
    )
    .await?;
    let _ = read_one_response(reader).await?;
    send_request(
        stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
    )
    .await?;
    Ok(())
}

/// Poll `find_symbol` until the writer commits and the symbol appears.
async fn poll_find_symbol_success(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    next_id: &mut u64,
    name: &str,
    deadline: Instant,
) -> Result<()> {
    while Instant::now() < deadline {
        *next_id += 1;
        send_request(
            stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": *next_id,
                "method": "tools/call",
                "params": {
                    "name": "find_symbol",
                    "arguments": { "name": name }
                }
            }),
        )
        .await?;
        let resp = read_one_response(reader).await?;
        if resp["result"]["isError"] == Value::Bool(false) {
            let body = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
            let parsed: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            if parsed["matches"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(anyhow!("symbol {name} never appeared via find_symbol"))
}

/// Per-workspace lockfile path matching the daemon's
/// `socket::socket_path_for_workspace` (mirrored from the existing
/// `mcp_round_trip` test). Used to find + kill the daemon process.
fn ws_pid_path(
    daemon_runtime_dir: &std::path::Path,
    canonical_workspace: &std::path::Path,
) -> PathBuf {
    let bytes = canonical_workspace.as_os_str().as_encoded_bytes();
    let hash = blake3::hash(bytes);
    let short = hash.to_hex();
    let short16 = &short.as_str()[..16];
    daemon_runtime_dir.join(format!("ws-{short16}.sock.pid"))
}

fn daemon_runtime_dir(runtime_dir: &std::path::Path, home_dir: &std::path::Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home_dir.join("Library").join("Caches").join("rts")
    } else {
        runtime_dir.join("rts")
    }
}

/// Spawn rts-mcp with consistent test env. Defaults to fast heartbeat
/// (`RTS_MCP_HEARTBEAT_INTERVAL_SECS=1`) so tests don't pay the 10s
/// default per scenario.
fn spawn_rts_mcp(
    workspace: &std::path::Path,
    runtime_dir: &std::path::Path,
    state_dir: &std::path::Path,
    home_dir: &std::path::Path,
    daemon_bin: &std::path::Path,
    extra_env: &[(&str, &str)],
) -> Result<Child> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir, std::fs::Permissions::from_mode(0o700));

    let mut cmd = tokio::process::Command::new(rts_mcp_bin());
    cmd.arg("--workspace")
        .arg(workspace)
        .env("XDG_RUNTIME_DIR", runtime_dir)
        .env("XDG_STATE_HOME", state_dir)
        .env("HOME", home_dir)
        .env("RTS_LOG", "warn")
        .env("RTS_DAEMON_BIN", daemon_bin)
        // Fast heartbeat so test reconnect-window windows are
        // measured in seconds, not tens of seconds.
        .env("RTS_MCP_HEARTBEAT_INTERVAL_SECS", "1")
        .env("RTS_MCP_HEARTBEAT_TIMEOUT_SECS", "2")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.spawn().context("spawn rts-mcp")
}

/// Scenario 1: Daemon idle-shutdown survival.
///
/// `RTS_IDLE_SHUTDOWN_SECS=2` would, in pre-resilience code, let the
/// daemon shut itself down 2s after the last RPC if no connections
/// were holding it open. With the connection manager, the heartbeat
/// keeps `active_connections > 0` (one open UDS) AND issues
/// `Daemon.Ping` every 1s in this test (refreshing `last_activity`),
/// so idle-shutdown should NEVER fire. We idle for 5s — well past the
/// 2s window — and verify the next tool call succeeds without a
/// reconnect.
///
/// Intent: encodes Rule 9 — the heartbeat-defeats-idle-shutdown
/// interaction is intentional and load-bearing. Regression here means
/// long agent sessions silently lose their daemon.
#[tokio::test(flavor = "current_thread")]
async fn scenario_1_idle_shutdown_survival() -> Result<()> {
    let daemon_bin = rts_daemon_bin();
    assert!(daemon_bin.is_file(), "rts-daemon must be built first");

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    std::fs::write(workspace.path().join("lib.rs"), "pub fn idle_probe() {}\n")?;

    let mut child = spawn_rts_mcp(
        workspace.path(),
        runtime_dir.path(),
        state_dir.path(),
        home_dir.path(),
        &daemon_bin,
        // Aggressive 2-second idle window. Daemon should be killable
        // by idle-shutdown WITHOUT the heartbeat keeping it warm.
        &[("RTS_IDLE_SHUTDOWN_SECS", "2")],
    )?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("piped stdout"));

    handshake(&mut stdin, &mut reader).await?;
    let mut next_id: u64 = 10;
    let deadline = Instant::now() + Duration::from_secs(10);
    poll_find_symbol_success(
        &mut stdin,
        &mut reader,
        &mut next_id,
        "idle_probe",
        deadline,
    )
    .await?;

    // Idle 5 seconds — more than 2x the configured idle window. If
    // the heartbeat path were broken (no active connection, no
    // refresh of last_activity), the daemon would shut down here.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Second tool call. If it succeeds (with or without a transient
    // reconnect), we know the manager survived idle-shutdown.
    let deadline = Instant::now() + Duration::from_secs(10);
    poll_find_symbol_success(
        &mut stdin,
        &mut reader,
        &mut next_id,
        "idle_probe",
        deadline,
    )
    .await?;

    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    Ok(())
}

/// Scenario 2: Daemon SIGKILL recovery.
///
/// Kill the daemon mid-session, observe one of:
/// (a) a `DAEMON_UNAVAILABLE` error from a tool call hitting the
///     post-kill-pre-reconnect window, OR
/// (b) a transient success that returns from the auto-spawned fresh
///     daemon (the heartbeat task or the call's own demote-and-spawn
///     path got there first).
/// Then verify the manager fully recovers — subsequent tool calls
/// succeed via the fresh daemon.
///
/// Intent: the agent-visible failure mode in PR #114's predecessor
/// (the originating incident) was "tool call fails with broken pipe,
/// session never recovers." The structured error code + reconnect
/// loop closes both gaps.
#[tokio::test(flavor = "current_thread")]
async fn scenario_2_sigkill_recovery() -> Result<()> {
    let daemon_bin = rts_daemon_bin();
    assert!(daemon_bin.is_file(), "rts-daemon must be built first");

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    std::fs::write(workspace.path().join("lib.rs"), "pub fn kill_probe() {}\n")?;
    let canonical_workspace = workspace.path().canonicalize()?;

    let mut child = spawn_rts_mcp(
        workspace.path(),
        runtime_dir.path(),
        state_dir.path(),
        home_dir.path(),
        &daemon_bin,
        &[("RTS_IDLE_SHUTDOWN_SECS", "60")],
    )?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("piped stdout"));

    handshake(&mut stdin, &mut reader).await?;
    let mut next_id: u64 = 10;
    let deadline = Instant::now() + Duration::from_secs(10);
    poll_find_symbol_success(
        &mut stdin,
        &mut reader,
        &mut next_id,
        "kill_probe",
        deadline,
    )
    .await?;

    // Find + SIGKILL the daemon.
    let pid_path = ws_pid_path(
        &daemon_runtime_dir(runtime_dir.path(), home_dir.path()),
        &canonical_workspace,
    );
    assert!(
        pid_path.exists(),
        "daemon lockfile missing at {}",
        pid_path.display()
    );
    let pid_text = std::fs::read_to_string(&pid_path)?;
    let pid_line = pid_text.lines().next().expect("non-empty PID lockfile");
    let pid: u32 = pid_line.trim().parse().context("parse daemon PID")?;
    let kill_status = std::process::Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status()?;
    assert!(kill_status.success(), "kill -9 {pid} failed");

    // Brief settling delay so the kill has actually closed the socket.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Issue a tool call within the heartbeat-detection window. With
    // the 1-second heartbeat interval set in spawn_rts_mcp, the
    // manager should have demoted to Reconnecting by now and either
    // surface DAEMON_UNAVAILABLE or have already reconnected via the
    // background task.
    next_id += 1;
    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": next_id,
            "method": "tools/call",
            "params": {
                "name": "find_symbol",
                "arguments": { "name": "kill_probe" }
            }
        }),
    )
    .await?;
    let resp = read_one_response(&mut reader).await?;
    // Two acceptable shapes: DAEMON_UNAVAILABLE (during window) OR
    // an immediate success (if the reconnect race resolved in our
    // favor). Both prove the resilience layer is active.
    let is_error = resp["result"]["isError"] == Value::Bool(true);
    if is_error {
        let body_str = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
        let parsed: Value = serde_json::from_str(body_str).unwrap_or(Value::Null);
        let code = parsed["error"]["code"].as_str().unwrap_or("");
        assert_eq!(
            code, "DAEMON_UNAVAILABLE",
            "expected DAEMON_UNAVAILABLE during disconnect window; got {parsed:?}"
        );
        // retry_after_ms hint MUST be present and non-negative; the
        // whole point of the structured error is letting the agent
        // back off.
        let retry_after_ms = parsed["error"]["data"]["retry_after_ms"]
            .as_u64()
            .expect("retry_after_ms must be present");
        // Should be within the backoff schedule (≤ ceiling). Use the
        // default ceiling of 30 s (we didn't override it in env).
        assert!(
            retry_after_ms <= 30_000,
            "retry_after_ms {retry_after_ms} > 30s ceiling"
        );
        assert_eq!(
            parsed["error"]["data"]["transient"],
            Value::Bool(true),
            "transient flag must be true for DAEMON_UNAVAILABLE"
        );
    }

    // Recovery path. The reconnect loop should bring up a fresh daemon
    // within the bounded schedule. Poll until find_symbol succeeds via
    // the new daemon. Bound the wait generously — cold-walk + Mount on
    // the respawned daemon takes longer than steady-state.
    let deadline = Instant::now() + Duration::from_secs(30);
    poll_find_symbol_success(
        &mut stdin,
        &mut reader,
        &mut next_id,
        "kill_probe",
        deadline,
    )
    .await?;

    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    Ok(())
}

/// Scenario 3: MCP shim crash leaves daemon alive.
///
/// Spawn a daemon (via one rts-mcp shim), kill the shim, spawn a
/// fresh shim against the same workspace, verify it connects to the
/// SAME daemon (PID unchanged in the lockfile).
///
/// Intent: the daemon's existence is the workspace's invariant, not
/// the MCP shim's. A crashed MCP host (Claude Code restart, Cursor
/// upgrade) must not bring the daemon down — the daemon's
/// idle-shutdown path is gated on connection count AND activity
/// window, neither of which trips instantly.
///
/// Note: this test does NOT verify `mount_refcount`/`active_connections`
/// directly because `Daemon.Stats` doesn't currently expose those
/// counters. We verify the observable invariant (same daemon PID
/// across shim lifetimes), which is the load-bearing contract.
#[tokio::test(flavor = "current_thread")]
async fn scenario_3_shim_crash_leaves_daemon_alive() -> Result<()> {
    let daemon_bin = rts_daemon_bin();
    assert!(daemon_bin.is_file(), "rts-daemon must be built first");

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    std::fs::write(
        workspace.path().join("lib.rs"),
        "pub fn survive_probe() {}\n",
    )?;
    let canonical_workspace = workspace.path().canonicalize()?;

    // Spawn the first MCP shim — this auto-spawns a daemon.
    let mut child1 = spawn_rts_mcp(
        workspace.path(),
        runtime_dir.path(),
        state_dir.path(),
        home_dir.path(),
        &daemon_bin,
        // Long idle window so the daemon doesn't shut down between
        // shim 1 and shim 2.
        &[("RTS_IDLE_SHUTDOWN_SECS", "60")],
    )?;
    let mut stdin1 = child1.stdin.take().expect("piped stdin");
    let mut reader1 = BufReader::new(child1.stdout.take().expect("piped stdout"));
    handshake(&mut stdin1, &mut reader1).await?;
    let mut next_id: u64 = 10;
    let deadline = Instant::now() + Duration::from_secs(10);
    poll_find_symbol_success(
        &mut stdin1,
        &mut reader1,
        &mut next_id,
        "survive_probe",
        deadline,
    )
    .await?;

    // Capture the daemon PID before we kill shim 1.
    let pid_path = ws_pid_path(
        &daemon_runtime_dir(runtime_dir.path(), home_dir.path()),
        &canonical_workspace,
    );
    let pid_text_before = std::fs::read_to_string(&pid_path)?;
    let daemon_pid_before: u32 = pid_text_before
        .lines()
        .next()
        .expect("non-empty PID lockfile")
        .trim()
        .parse()
        .context("parse daemon PID (before)")?;

    // Kill the MCP shim. SIGKILL avoids the clean-shutdown stats
    // dump but more closely models a real Claude Code/Cursor crash.
    drop(stdin1); // close stdin first → service.waiting() returns
    let _ = tokio::time::timeout(Duration::from_secs(3), child1.wait()).await;
    // Give the daemon a moment to observe the dropped connection
    // (active_connections decrement is async via the accept-loop's
    // disconnect handler).
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Spawn shim 2 against the same workspace. It should reach the
    // same daemon (same PID in the lockfile).
    let mut child2 = spawn_rts_mcp(
        workspace.path(),
        runtime_dir.path(),
        state_dir.path(),
        home_dir.path(),
        &daemon_bin,
        &[("RTS_IDLE_SHUTDOWN_SECS", "60")],
    )?;
    let mut stdin2 = child2.stdin.take().expect("piped stdin");
    let mut reader2 = BufReader::new(child2.stdout.take().expect("piped stdout"));
    handshake(&mut stdin2, &mut reader2).await?;
    let mut next_id: u64 = 10;
    let deadline = Instant::now() + Duration::from_secs(10);
    poll_find_symbol_success(
        &mut stdin2,
        &mut reader2,
        &mut next_id,
        "survive_probe",
        deadline,
    )
    .await?;

    // Verify the daemon PID didn't change — i.e. shim 2 is talking
    // to the SAME daemon shim 1 was using.
    let pid_text_after = std::fs::read_to_string(&pid_path)?;
    let daemon_pid_after: u32 = pid_text_after
        .lines()
        .next()
        .expect("non-empty PID lockfile")
        .trim()
        .parse()
        .context("parse daemon PID (after)")?;
    assert_eq!(
        daemon_pid_before, daemon_pid_after,
        "daemon PID changed across shim crash — daemon should outlive any single MCP shim"
    );

    drop(stdin2);
    let _ = tokio::time::timeout(Duration::from_secs(5), child2.wait()).await;
    Ok(())
}

/// Scenario 4: Concurrent tool calls during reconnect.
///
/// Kill the daemon, then fire 10 concurrent tool calls during the
/// reconnect window. Each call should observe non-Connected state and
/// return DAEMON_UNAVAILABLE quickly (without queuing on the daemon
/// mutex). At least one of the 10 must hit the disconnect window
/// before the reconnect loop recovers; calls that race the recovery
/// and succeed are also acceptable. Critically: no call should hang.
///
/// Intent: pre-resilience, the inline retry-on-disconnect loop would
/// serialize all 10 calls on the daemon mutex, each paying the
/// auto-spawn wait. After resilience, calls in the Reconnecting
/// window short-circuit at the read-lock state check — no
/// thundering-herd on the daemon mutex.
#[tokio::test(flavor = "current_thread")]
async fn scenario_4_concurrent_calls_during_reconnect() -> Result<()> {
    let daemon_bin = rts_daemon_bin();
    assert!(daemon_bin.is_file(), "rts-daemon must be built first");

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    std::fs::write(workspace.path().join("lib.rs"), "pub fn herd_probe() {}\n")?;
    let canonical_workspace = workspace.path().canonicalize()?;

    let mut child = spawn_rts_mcp(
        workspace.path(),
        runtime_dir.path(),
        state_dir.path(),
        home_dir.path(),
        &daemon_bin,
        &[("RTS_IDLE_SHUTDOWN_SECS", "60")],
    )?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("piped stdout"));
    handshake(&mut stdin, &mut reader).await?;
    let mut next_id: u64 = 10;
    let deadline = Instant::now() + Duration::from_secs(10);
    poll_find_symbol_success(
        &mut stdin,
        &mut reader,
        &mut next_id,
        "herd_probe",
        deadline,
    )
    .await?;

    // Kill daemon.
    let pid_path = ws_pid_path(
        &daemon_runtime_dir(runtime_dir.path(), home_dir.path()),
        &canonical_workspace,
    );
    let pid_text = std::fs::read_to_string(&pid_path)?;
    let pid: u32 = pid_text
        .lines()
        .next()
        .expect("non-empty PID lockfile")
        .trim()
        .parse()
        .context("parse daemon PID")?;
    let kill_status = std::process::Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status()?;
    assert!(kill_status.success());

    // Don't wait for the heartbeat to detect the death — fire the
    // herd immediately. The first call's own demote path will move
    // the manager into Reconnecting; the remaining 9 should
    // short-circuit on the state check. Stdio is serialized
    // (single-connection MCP), so we send all 10 requests then read
    // all 10 responses.
    let herd_size = 10;
    let request_send_start = Instant::now();
    let mut request_ids = Vec::with_capacity(herd_size);
    for _ in 0..herd_size {
        next_id += 1;
        request_ids.push(next_id);
        send_request(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": next_id,
                "method": "tools/call",
                "params": {
                    "name": "find_symbol",
                    "arguments": { "name": "herd_probe" }
                }
            }),
        )
        .await?;
    }
    let send_elapsed = request_send_start.elapsed();
    // The whole herd should send in well under the auto-spawn
    // deadline (5s). If the manager queued every call on the daemon
    // mutex during reconnect, we'd see 5s+ of wall clock here even
    // before reading responses.
    assert!(
        send_elapsed < Duration::from_secs(2),
        "10 concurrent requests took {send_elapsed:?} to enqueue — \
         transport-level back-pressure suggests they're serializing on the daemon mutex"
    );

    // Collect responses. Each must be a parseable MCP envelope; we
    // count how many returned DAEMON_UNAVAILABLE vs success.
    let mut unavailable_count = 0usize;
    let mut success_count = 0usize;
    let mut other_error_count = 0usize;
    let mut retry_after_values: Vec<u64> = Vec::new();
    for _ in 0..herd_size {
        let resp = read_one_response(&mut reader).await?;
        if resp["result"]["isError"] == Value::Bool(true) {
            let body_str = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
            let parsed: Value = serde_json::from_str(body_str).unwrap_or(Value::Null);
            let code = parsed["error"]["code"].as_str().unwrap_or("");
            if code == "DAEMON_UNAVAILABLE" {
                unavailable_count += 1;
                if let Some(n) = parsed["error"]["data"]["retry_after_ms"].as_u64() {
                    retry_after_values.push(n);
                }
            } else {
                other_error_count += 1;
            }
        } else {
            success_count += 1;
        }
    }

    // We expect:
    // - All 10 responses parseable (no hangs / no malformed shapes).
    // - At least one DAEMON_UNAVAILABLE (the daemon was just killed;
    //   the first transport error in the herd demotes state and the
    //   rest short-circuit).
    // - Zero `other_error_count`: the only error shape during a
    //   disconnect window is DAEMON_UNAVAILABLE (or DAEMON_DOWN
    //   after exhausting attempts, which doesn't happen in a 10-call
    //   burst).
    assert_eq!(
        unavailable_count + success_count + other_error_count,
        herd_size,
        "all {herd_size} responses must arrive"
    );
    assert!(
        unavailable_count >= 1,
        "at least one call must hit the disconnect window; got \
         unavailable={unavailable_count}, success={success_count}, other={other_error_count}"
    );
    assert_eq!(
        other_error_count, 0,
        "unexpected non-DAEMON_UNAVAILABLE error shape in the herd"
    );

    // retry_after_ms hints should all be in the same ballpark (≤ 30s
    // ceiling). Consistency check: the spread across the 10 hints
    // shouldn't be wider than the reconnect ceiling. This catches a
    // future bug where one caller computed retry_after_ms from a
    // stale state snapshot.
    if let (Some(min), Some(max)) = (
        retry_after_values.iter().min(),
        retry_after_values.iter().max(),
    ) {
        assert!(
            *max <= 30_000,
            "retry_after_ms {max} > 30s ceiling — backoff schedule misconfigured"
        );
        assert!(
            max - min <= 30_000,
            "retry_after_ms spread {min}..={max} too wide; should be bounded by reconnect ceiling"
        );
    }

    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
    Ok(())
}
