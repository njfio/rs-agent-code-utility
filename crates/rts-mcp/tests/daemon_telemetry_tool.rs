//! Round-trip test for the new `daemon_telemetry` MCP tool.
//!
//! **Why this exists (Rule 9 — tests verify intent):** PR #115 shipped
//! the `Daemon.Telemetry` JSON-RPC method on the daemon side and PR #120
//! wired its collectors (latency p50/p99, cache hit rate, cold-walk
//! timing, languages indexed, workspace size, error counts), but the
//! rts-mcp server only routed `daemon_stats` to the MCP tool list. This
//! gap blocked external MCP-speaking consumers (Claude Code, Cursor,
//! rts-bench's MCP-based code paths) from reading the new collectors —
//! see PR #123's `TODO(post-G)` markers for one downstream consumer
//! that worked around the gap by marking latency fields `Option<u64>`.
//!
//! This test:
//! 1. spawns rts-mcp + auto-spawned rts-daemon against a tiny fixture
//!    workspace,
//! 2. fires `tools/call name=daemon_telemetry` once,
//! 3. asserts the response carries every collector field that PR #115's
//!    protocol-v0.md update documents.
//!
//! Asserting on the *key set* rather than concrete numbers is
//! deliberate — exact counts/latencies vary with CI noise, but a
//! missing key means the routing dropped a field or the daemon's
//! handler regressed shape.

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
async fn daemon_telemetry_round_trip() -> Result<()> {
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

    // Seed one tiny file so the daemon has something to walk + index
    // (so `languages_indexed` / `workspace_files` aren't trivially zero).
    std::fs::write(
        workspace.path().join("lib.rs"),
        "pub fn telemetry_seed() {}\n",
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
                "clientInfo": { "name": "rts-mcp-itest-telemetry", "version": "0.0.0" }
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

    // `daemon_telemetry` must appear in tools/list — this is the
    // routing-gap regression guard. The pre-fix server exposed only
    // `daemon_stats`, so a future revert that loses the new tool would
    // be caught here before the round-trip even runs.
    send_request(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    )
    .await?;
    let list_resp = read_one_response(&mut reader).await?;
    let tools = list_resp["result"]["tools"]
        .as_array()
        .ok_or_else(|| anyhow!("tools/list returned no array"))?;
    let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(
        tool_names.contains(&"daemon_telemetry"),
        "expected `daemon_telemetry` in tools/list; got {tool_names:?}"
    );

    // Mount the workspace + warm the index with one find_symbol call
    // so the latency / method-count collectors have at least one
    // sample to summarise. Polling matches the pattern used by
    // mcp_round_trip.rs — the cold-walk can take a few hundred ms on
    // CI noise and the test should not flake on that.
    let mut next_id: u64 = 10;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut warm_ok = false;
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
                    "arguments": { "name": "telemetry_seed" }
                }
            }),
        )
        .await?;
        let resp = read_one_response(&mut reader).await?;
        let body = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
        let parsed: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        if parsed["matches"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false)
        {
            warm_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        warm_ok,
        "warm-up find_symbol never succeeded; daemon may not have started"
    );

    // Now the actual subject of the test: call daemon_telemetry over
    // the MCP tools/call envelope.
    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 200,
            "method": "tools/call",
            "params": {
                "name": "daemon_telemetry",
                "arguments": {}
            }
        }),
    )
    .await?;
    let resp = read_one_response(&mut reader).await?;
    assert_eq!(
        resp["result"]["isError"],
        serde_json::Value::Bool(false),
        "daemon_telemetry should succeed; got {resp:?}"
    );
    let body = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let parsed: Value = serde_json::from_str(body).context("parse daemon_telemetry body")?;

    // Per `crates/rts-daemon/src/methods/daemon.rs::telemetry`'s
    // documented wire shape, every one of these keys must be present
    // on every successful response. A missing key means either the
    // daemon handler regressed shape or the MCP routing dropped a
    // field — both are silent failures the asymmetric Option-wrapping
    // in PR #123 had to paper over.
    for key in [
        "uptime_secs",
        "languages_indexed",
        "method_counts",
        "method_latency_p50_ms",
        "method_latency_p99_ms",
        "error_counts",
        "cache_hit_rate",
        "cold_walk_ms_p50",
        "workspace_files",
    ] {
        assert!(
            parsed.get(key).is_some(),
            "daemon_telemetry response missing top-level `{key}`; got {parsed:?}"
        );
    }

    // Stronger shape claims: the maps must be objects, the vector must
    // be an array. A scalar leaking into one of these spots would
    // pass the `.is_some()` check above but break every downstream
    // consumer (rts-bench's regression diff, the `rts telemetry
    // preview` renderer, an external CI gating job).
    assert!(
        parsed["uptime_secs"].is_u64(),
        "uptime_secs must be a non-negative integer; got {:?}",
        parsed["uptime_secs"]
    );
    assert!(
        parsed["languages_indexed"].is_array(),
        "languages_indexed must be an array; got {:?}",
        parsed["languages_indexed"]
    );
    assert!(
        parsed["method_counts"].is_object(),
        "method_counts must be an object; got {:?}",
        parsed["method_counts"]
    );
    assert!(
        parsed["method_latency_p50_ms"].is_object(),
        "method_latency_p50_ms must be an object; got {:?}",
        parsed["method_latency_p50_ms"]
    );
    assert!(
        parsed["method_latency_p99_ms"].is_object(),
        "method_latency_p99_ms must be an object; got {:?}",
        parsed["method_latency_p99_ms"]
    );
    assert!(
        parsed["error_counts"].is_object(),
        "error_counts must be an object; got {:?}",
        parsed["error_counts"]
    );

    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    Ok(())
}
