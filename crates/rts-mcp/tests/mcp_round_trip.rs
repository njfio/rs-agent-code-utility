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
