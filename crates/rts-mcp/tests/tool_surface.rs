//! Tool-surface profile round trip.
//!
//! Spawns `rts-mcp --tools core` as a subprocess with stdio pipes, exactly as
//! `mcp_round_trip.rs` does, and asserts the three things a profile promises:
//!
//! 1. `tools/list` advertises only the profile's tools, with the one-line descriptions —
//!    which is the whole point, since declarations are paid for on every request.
//! 2. A tool outside the surface is **not callable**, not merely unlisted. This is worth a
//!    test because `ToolRouter::disable_route` documents that it rejects such a call while
//!    this rmcp version dispatches it anyway; the server enforces the surface itself
//!    (`RtsServer::call_tool`) and this test is what keeps that true.
//! 3. A tool inside the surface still works, against a real daemon.
//!
//! A typo in a surface is covered too: it must fail loudly at startup rather than advertise
//! a smaller surface that looks like it worked.

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

/// `CARGO_BIN_EXE_<name>` resolves only inside the current crate, so the daemon path is
/// derived from the sibling output directory.
fn rts_daemon_bin() -> PathBuf {
    let mcp = rts_mcp_bin();
    let parent = mcp.parent().expect("CARGO_BIN_EXE_rts-mcp has parent dir");
    parent.join("rts-daemon")
}

async fn read_one_response(reader: &mut BufReader<ChildStdout>) -> Result<Value> {
    let mut buf = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(30), reader.read_until(b'\n', &mut buf))
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

/// Opens a session against a scratch workspace and returns the pipes plus the handshake
/// responses consumed.
async fn session(
    surface: &str,
) -> Result<(tokio::process::Child, ChildStdin, BufReader<ChildStdout>)> {
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
    // Keep the temp dirs alive for the child's lifetime by leaking the paths into the
    // process — the test process exits right after, and the daemon is killed with the child.
    let keep = [
        runtime_dir.keep(),
        state_dir.keep(),
        home_dir.keep(),
        workspace.keep(),
    ];
    let (runtime, state, home, workspace) = (&keep[0], &keep[1], &keep[2], &keep[3]);

    std::fs::write(
        workspace.join("lib.rs"),
        "pub fn build_index() {}\npub struct WidgetIndex;\n",
    )?;
    let _ = std::fs::set_permissions(runtime, std::os::unix::fs::PermissionsExt::from_mode(0o700));

    let mut cmd = tokio::process::Command::new(rts_mcp_bin());
    cmd.arg("--workspace")
        .arg(workspace)
        .arg("--tools")
        .arg(surface)
        .env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_STATE_HOME", state)
        .env("HOME", home)
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

    send_request(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "surface-test", "version": "0"}}}),
    )
    .await?;
    let _ = read_one_response(&mut reader).await?;
    send_request(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await?;
    Ok((child, stdin, reader))
}

#[tokio::test(flavor = "current_thread")]
async fn a_tool_surface_profile_lists_less_and_refuses_what_it_hides() -> Result<()> {
    let (mut child, mut stdin, mut reader) = session("core").await?;

    // 1. The advertised surface is the profile, described in one line each.
    send_request(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    )
    .await?;
    let listed = read_one_response(&mut reader).await?;
    let tools = listed["result"]["tools"]
        .as_array()
        .context("tools/list returns an array")?;
    let names = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 8, "core is the eight lookup tools: {names:?}");
    assert!(names.contains(&"find_symbol".to_string()), "{names:?}");
    assert!(
        names.contains(&"grep".to_string()),
        "core includes the AST-aware grep: {names:?}"
    );
    assert!(
        !names.contains(&"verify_edit".to_string()),
        "a gate is not in the lookup profile: {names:?}"
    );
    for tool in tools {
        let description = tool["description"].as_str().unwrap_or_default();
        assert!(
            description.len() < 200,
            "profile descriptions are one line, found {} bytes for {}",
            description.len(),
            tool["name"]
        );
        assert!(
            !description.contains("Prefer this over"),
            "the pinned comparative paragraph belongs to the full surface"
        );
    }

    // 2. A tool outside the surface is refused, and says why. `verify_edit` is a gate: it
    // belongs to the editing profile, not the lookup one.
    send_request(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "verify_edit", "arguments": {"files": []}}}),
    )
    .await?;
    let refused = read_one_response(&mut reader).await?;
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("not in this server's tool surface"),
        "a hidden tool must be refused, not dispatched: {refused}"
    );

    // 3. A tool inside the surface still answers, against the real daemon.
    send_request(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "find_symbol", "arguments": {"name": "build_index"}}}),
    )
    .await?;
    let found = read_one_response(&mut reader).await?;
    let text = found["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("build_index"),
        "the profile's own tools keep working: {found}"
    );

    let _ = child.kill().await;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_unknown_tool_name_fails_loudly_at_startup() -> Result<()> {
    let output = tokio::process::Command::new(rts_mcp_bin())
        .arg("--tools")
        .arg("find_symbols,read_symbol")
        .output()
        .await?;
    assert!(!output.status.success(), "a typo must not start a server");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown tool(s) in surface") && stderr.contains("find_symbols"),
        "the error names the offending tool: {stderr}"
    );
    assert!(
        stderr.contains("find_symbol,"),
        "and lists what does exist: {stderr}"
    );
    Ok(())
}
