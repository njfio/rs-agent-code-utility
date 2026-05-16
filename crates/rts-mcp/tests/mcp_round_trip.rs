//! End-to-end MCP round-trip test.
//!
//! Spawns `rts-mcp` as a subprocess with stdio pipes, gets its stderr → /dev/null,
//! and speaks raw JSON-RPC over stdin/stdout. `rts-mcp` then auto-spawns
//! `rts-daemon` (via `RTS_DAEMON_BIN`). This mirrors how Claude Code launches
//! the MCP server, except we drive it from test code instead of an agent.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout};

fn rts_mcp_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-mcp"))
}

/// Carry-over from the workspace test pattern. `CARGO_BIN_EXE_<name>` only
/// resolves to a binary inside the *current* crate, so we point the daemon
/// path at the sibling output dir.
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

#[tokio::test(flavor = "current_thread")]
async fn mcp_round_trip_against_real_daemon() -> Result<()> {
    let daemon_bin = rts_daemon_bin();
    assert!(
        daemon_bin.is_file(),
        "rts-daemon must be built before this test; missing at {}",
        daemon_bin.display()
    );

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Seed the workspace with one tiny Rust file so the daemon's writer has
    // something to index immediately.
    std::fs::write(
        workspace.path().join("lib.rs"),
        "pub fn build_index() {}\npub struct WidgetIndex;\n",
    )?;

    let mut cmd = tokio::process::Command::new(rts_mcp_bin());
    cmd.arg("--workspace")
        .arg(workspace.path())
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RTS_LOG", "warn")
        .env("RTS_DAEMON_BIN", &daemon_bin)
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = cmd.spawn().context("spawn rts-mcp")?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("piped stdout"));

    // 1. initialize
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "rts-mcp-itest", "version": "0.0.0" }
        }
    });
    send_request(&mut stdin, &init).await?;
    let init_resp = read_one_response(&mut reader).await?;
    assert_eq!(init_resp["id"], 1);
    assert_eq!(
        init_resp["result"]["protocolVersion"], "2024-11-05",
        "got {init_resp:?}"
    );
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "rts-mcp");
    assert!(init_resp["result"]["capabilities"]["tools"].is_object());

    // The `initialized` notification: agents send this; the server expects
    // it before processing further requests (per the MCP handshake).
    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    send_request(&mut stdin, &initialized).await?;

    // 2. tools/list
    send_request(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    )
    .await?;
    let list_resp = read_one_response(&mut reader).await?;
    let tools = list_resp["result"]["tools"]
        .as_array()
        .expect("tools array");
    let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expected in [
        "outline_workspace",
        "find_symbol",
        "read_symbol",
        "read_range",
    ] {
        assert!(
            tool_names.contains(&expected),
            "expected tool `{expected}` in {tool_names:?}"
        );
    }

    // 3. tools/call → find_symbol (poll until the writer commits)
    let mut next_id: u64 = 10;
    let mut found = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        next_id += 1;
        send_request(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": next_id,
                "method": "tools/call",
                "params": {
                    "name": "find_symbol",
                    "arguments": { "name": "build_index" }
                }
            }),
        )
        .await?;
        let resp = read_one_response(&mut reader).await?;
        let body = resp["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let parsed: Value = serde_json::from_str(body).context("parse tool body json")?;
        let matches = parsed["matches"].as_array().cloned().unwrap_or_default();
        if !matches.is_empty() {
            assert_eq!(matches[0]["qualified_name"], "build_index");
            assert_eq!(matches[0]["kind"], "fn");
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        found,
        "writer never produced a build_index match through the MCP tool"
    );

    // 4. tools/call → read_range on the seeded file
    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {
                "name": "read_range",
                "arguments": { "file": "lib.rs", "start_line": 1, "end_line": 1 }
            }
        }),
    )
    .await?;
    let resp = read_one_response(&mut reader).await?;
    let body = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let parsed: Value = serde_json::from_str(body)?;
    assert_eq!(parsed["file"], "lib.rs");
    assert_eq!(parsed["shape"], "body");
    assert!(
        parsed["text"]
            .as_str()
            .unwrap_or_default()
            .contains("pub fn build_index"),
        "line 1 should be the `build_index` declaration; got {parsed:?}"
    );

    // 5. tools/call → outline_workspace returns INDEX_NOT_READY surfaced as
    //    a structured CallToolResult::error (isError=true).
    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "outline_workspace",
                "arguments": {}
            }
        }),
    )
    .await?;
    let resp = read_one_response(&mut reader).await?;
    // outline_workspace now ships end-to-end as of alpha.18 (PageRank +
    // Index.Outline). The seeded `lib.rs` is the only file in the
    // workspace and contains `build_index` + `WidgetIndex`; both should
    // appear in the returned outline.
    assert_eq!(
        resp["result"]["isError"],
        serde_json::Value::Bool(false),
        "outline_workspace should succeed; got {resp:?}"
    );
    let body = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let parsed: Value = serde_json::from_str(body)?;
    assert!(
        parsed["files_considered"].as_u64().unwrap_or(0) >= 1,
        "expected at least 1 file considered; got {parsed:?}"
    );
    let outline_text = parsed["outline_text"].as_str().unwrap_or_default();
    assert!(
        outline_text.contains("build_index"),
        "outline_text should mention seeded symbol; got {outline_text:?}"
    );

    // Close stdin so rts-mcp shuts down cleanly.
    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    Ok(())
}

/// Compute the per-workspace socket-PID-file path the way
/// `rts_daemon::socket::socket_path_for_workspace` + the lifecycle
/// module do. Mirrors the production hash so the test kills the
/// right daemon by reading the lockfile.
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

/// v0.5.5+: when the auto-spawned daemon dies mid-session, the next
/// tool call should transparently reconnect via auto-spawn and
/// succeed. Pre-fix the connection was wedged and every subsequent
/// call returned `Broken pipe`. Surfaced by real Claude Code dogfood
/// — see PR #94 follow-up.
///
/// Test shape:
/// 1. Spawn rts-mcp (which auto-spawns rts-daemon).
/// 2. Do one tool call to verify both are alive.
/// 3. Find the daemon's PID via the per-workspace lockfile, kill it.
/// 4. Do another tool call — must succeed (reconnect kicks in,
///    auto-spawn brings up a fresh daemon, Mount sentinel resets,
///    retry succeeds).
#[tokio::test(flavor = "current_thread")]
async fn mcp_reconnects_after_daemon_death() -> Result<()> {
    let daemon_bin = rts_daemon_bin();
    assert!(daemon_bin.is_file(), "rts-daemon must be built first");

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    std::fs::write(
        workspace.path().join("lib.rs"),
        "pub fn reconnect_smoke() {}\n",
    )?;
    let canonical_workspace = workspace.path().canonicalize()?;

    // Daemon runtime dir on macOS = $HOME/Library/Caches/rts; on
    // Linux = $XDG_RUNTIME_DIR/rts.
    let daemon_runtime_dir = if cfg!(target_os = "macos") {
        home_dir.path().join("Library").join("Caches").join("rts")
    } else {
        runtime_dir.path().join("rts")
    };

    let mut cmd = tokio::process::Command::new(rts_mcp_bin());
    cmd.arg("--workspace")
        .arg(workspace.path())
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RTS_LOG", "warn")
        .env("RTS_DAEMON_BIN", &daemon_bin)
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd.spawn().context("spawn rts-mcp")?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("piped stdout"));

    // MCP handshake.
    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "reconnect-itest", "version": "0.0.0" }
            }
        }),
    )
    .await?;
    let _ = read_one_response(&mut reader).await?;
    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
    )
    .await?;

    // First call: triggers Mount + lazy-spawn the daemon. Poll until
    // the writer commits, so we know the daemon is fully up.
    let pid_path = ws_pid_path(&daemon_runtime_dir, &canonical_workspace);
    let mut next_id: u64 = 10;
    let mut first_call_ok = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        next_id += 1;
        send_request(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": next_id,
                "method": "tools/call",
                "params": {
                    "name": "find_symbol",
                    "arguments": { "name": "reconnect_smoke" }
                }
            }),
        )
        .await?;
        let resp = read_one_response(&mut reader).await?;
        let body_str = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
        let parsed: Value = serde_json::from_str(body_str).unwrap_or(Value::Null);
        if parsed["matches"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false)
        {
            first_call_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        first_call_ok,
        "first tool call never succeeded; daemon may not have started"
    );

    // Read the daemon PID from the per-workspace lockfile + kill it.
    assert!(
        pid_path.exists(),
        "daemon lockfile missing at {}",
        pid_path.display()
    );
    let pid_bytes = std::fs::read(&pid_path)?;
    // The lockfile shape (rts-daemon::lifecycle::write_pid_to_file)
    // is `<pid>\n<start_seconds>\n`. Parse only the first line.
    let pid_text = std::str::from_utf8(&pid_bytes)?;
    let pid_line = pid_text
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty PID lockfile"))?
        .trim();
    let pid: u32 = pid_line.parse().context("parse daemon PID from lockfile")?;
    // SIGKILL via the `kill` binary so the test crate doesn't need
    // `unsafe` (this crate has `#![deny(unsafe_code)]`). Real-world
    // daemon crashes / OOM kills produce the same broken-pipe shape;
    // the choice between SIGKILL and SIGTERM doesn't matter for what
    // we're testing (rts-mcp sees a closed socket either way).
    let kill_status = std::process::Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status()
        .context("invoke kill")?;
    assert!(
        kill_status.success(),
        "kill -9 {pid} failed: {kill_status:?}"
    );

    // Wait briefly for the daemon process to actually exit + the
    // socket file to disappear / become stale.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Second call: this is the test. The DaemonClient inside rts-mcp
    // is still holding a (now dead) socket. The first write or read
    // will fail with `Broken pipe` / `daemon closed connection`. The
    // retry-on-disconnect loop in `RtsServer::call_daemon` must
    // detect that, call `DaemonClient::reconnect()` (which auto-
    // spawns a fresh daemon on the per-workspace socket), reset the
    // Mount sentinel, and retry the call.
    //
    // We poll because the fresh daemon needs to walk + commit before
    // find_symbol returns matches — same shape as the first call's
    // poll loop above.
    next_id += 100;
    let mut second_call_ok = false;
    let deadline2 = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline2 {
        next_id += 1;
        send_request(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": next_id,
                "method": "tools/call",
                "params": {
                    "name": "find_symbol",
                    "arguments": { "name": "reconnect_smoke" }
                }
            }),
        )
        .await?;
        let resp = read_one_response(&mut reader).await?;
        // After a successful reconnect, this should NOT be isError.
        // (A broken-pipe-without-reconnect would surface as
        // isError=true with INTERNAL_ERROR.)
        if resp["result"]["isError"] == serde_json::Value::Bool(false) {
            let body_str = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
            let parsed: Value = serde_json::from_str(body_str).unwrap_or(Value::Null);
            if parsed["matches"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false)
            {
                second_call_ok = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        second_call_ok,
        "post-kill tool call never recovered — reconnect path didn't fire"
    );

    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    Ok(())
}

/// v0.5.8: when the MCP stdio session ends, rts-mcp issues a final
/// `Daemon.Stats` RPC and dumps the snapshot to stderr. This test
/// verifies the dump happens, has the documented shape, and
/// reflects the calls actually made during the session.
///
/// Test shape:
/// 1. Spawn rts-mcp with stderr piped (not /dev/null).
/// 2. Complete handshake + one `find_symbol` call.
/// 3. Close stdin → rts-mcp exits → shutdown dump fires.
/// 4. Read stderr to EOF; assert it contains the documented
///    header lines + the per-method counts that match what we
///    issued during the session.
#[tokio::test(flavor = "current_thread")]
async fn rts_mcp_dumps_session_stats_to_stderr_on_shutdown() -> Result<()> {
    use tokio::io::AsyncReadExt;

    let daemon_bin = rts_daemon_bin();
    assert!(daemon_bin.is_file(), "rts-daemon must be built first");

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Seed one tiny file so find_symbol has something to match.
    std::fs::write(workspace.path().join("hub.rs"), "pub fn hello() {}\n")?;

    let mut cmd = tokio::process::Command::new(rts_mcp_bin());
    cmd.arg("--workspace")
        .arg(workspace.path())
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RTS_LOG", "warn")
        .env("RTS_DAEMON_BIN", &daemon_bin)
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().context("spawn rts-mcp")?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut stderr = child.stderr.take().expect("piped stderr");

    // Handshake + one find_symbol call.
    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": { "name": "stats-test", "version": "0" } }
        }),
    )
    .await?;
    let _ = read_one_response(&mut stdout).await?;
    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}
        }),
    )
    .await?;
    // Poll find_symbol until the writer commits, then make one
    // confirmed call so the find_symbol counter is at >= 1 on
    // shutdown. Using a deadline is safer than a single shot since
    // the cold-walk timing varies on CI noise.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut next_id: u64 = 10;
    let mut find_symbol_succeeded = false;
    while std::time::Instant::now() < deadline {
        next_id += 1;
        send_request(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": next_id,
                "method": "tools/call",
                "params": {
                    "name": "find_symbol",
                    "arguments": { "name": "hello" }
                }
            }),
        )
        .await?;
        let resp = read_one_response(&mut stdout).await?;
        let body = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
        let parsed: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        if !parsed["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(true)
        {
            find_symbol_succeeded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        find_symbol_succeeded,
        "writer never produced a `hello` match through the MCP tool"
    );

    // Close stdin → service.waiting() returns → shutdown dump fires.
    drop(stdin);

    // Reap and collect stderr to EOF. Bound the wait so a stuck
    // child fails fast instead of hanging the test.
    let mut stderr_buf = String::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        stderr.read_to_string(&mut stderr_buf),
    )
    .await
    .context("reading stderr to EOF")??;
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .context("waiting for rts-mcp exit")??;

    // Documented shape: header + per-counter lines for non-zero
    // counters. The dump prints zero-count counters as silent, so
    // we only assert on what we actually used (mount + find_symbol +
    // the final Daemon.Stats RPC itself).
    assert!(
        stderr_buf.contains("rts-mcp session stats:"),
        "stderr should contain the session-stats header; got: {stderr_buf}"
    );
    assert!(
        stderr_buf.contains("daemon-version:"),
        "stderr should contain daemon-version field; got: {stderr_buf}"
    );
    assert!(
        stderr_buf.contains("total-calls:"),
        "stderr should contain total-calls field; got: {stderr_buf}"
    );
    // Each of these counters has been hit at least once during the
    // session and should appear in the per-method breakdown.
    for expected_method in ["Workspace.Mount", "Index.FindSymbol", "Daemon.Stats"] {
        assert!(
            stderr_buf.contains(&format!("{expected_method}: ")),
            "stderr should contain `{expected_method}: N` line; got: {stderr_buf}"
        );
    }

    // Zero-count counters must NOT appear (the dump filters them
    // out to keep tight on quiet sessions). impact_of and grep
    // were never called.
    assert!(
        !stderr_buf.contains("Index.ImpactOf:"),
        "zero-count counters should be filtered out of the dump; got: {stderr_buf}"
    );
    assert!(
        !stderr_buf.contains("Index.Grep:"),
        "zero-count counters should be filtered out of the dump; got: {stderr_buf}"
    );

    Ok(())
}
