//! Spike test client. Spawns `rmcp_hello_server` as a subprocess, exchanges
//! MCP JSON-RPC over stdio, validates initialize + tools/list + tools/call,
//! and prints a PASS/FAIL summary.

use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

const SERVER_BIN_ENV: &str = "RMCP_HELLO_SERVER_BIN";

async fn read_one_response(
    reader: &mut BufReader<tokio::process::ChildStdout>,
) -> Result<Value> {
    let mut buf = String::new();
    let read_fut = reader.read_line(&mut buf);
    let n = timeout(Duration::from_secs(5), read_fut).await??;
    if n == 0 {
        bail!("server closed stdout before sending a response");
    }
    let v: Value = serde_json::from_str(buf.trim())
        .with_context(|| format!("non-JSON line on stdout: {buf:?}"))?;
    Ok(v)
}

async fn send(child: &mut Child, msg: &Value) -> Result<()> {
    let stdin = child.stdin.as_mut().context("server stdin missing")?;
    let line = serde_json::to_string(msg)?;
    stdin.write_all(line.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let bin = std::env::var(SERVER_BIN_ENV).context(
        "set RMCP_HELLO_SERVER_BIN=path/to/rmcp_hello_server before running this client",
    )?;
    eprintln!("client: spawning {bin}");

    let mut child = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {bin}"))?;

    let stdout = child.stdout.take().context("no stdout")?;
    let mut reader = BufReader::new(stdout);

    let mut pass = true;

    // 1. initialize
    let started = Instant::now();
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "p0-1-rmcp-hello-client",
                "version": "0.1.0",
            }
        }
    });
    send(&mut child, &init).await?;
    let init_resp = read_one_response(&mut reader).await?;
    let init_elapsed = started.elapsed();
    eprintln!("client: initialize response in {init_elapsed:?}");
    println!("=== initialize response ===");
    println!("{}", serde_json::to_string_pretty(&init_resp)?);

    let protocol_version = init_resp["result"]["protocolVersion"]
        .as_str()
        .unwrap_or("");
    let server_name = init_resp["result"]["serverInfo"]["name"]
        .as_str()
        .unwrap_or("");
    let server_version = init_resp["result"]["serverInfo"]["version"]
        .as_str()
        .unwrap_or("");
    let has_tools_cap = init_resp["result"]["capabilities"]["tools"].is_object();

    if protocol_version != "2024-11-05" {
        eprintln!("FAIL: protocolVersion in initialize response = {protocol_version:?}, expected 2024-11-05");
        pass = false;
    }
    if server_name != "rmcp-hello-spike" {
        eprintln!("FAIL: serverInfo.name = {server_name:?}, expected rmcp-hello-spike");
        pass = false;
    }
    if server_version.is_empty() {
        eprintln!("FAIL: serverInfo.version is empty");
        pass = false;
    }
    if !has_tools_cap {
        eprintln!("FAIL: capabilities.tools missing — server isn't advertising tools");
        pass = false;
    }

    // 2. initialized notification (no id, no response expected)
    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    });
    send(&mut child, &initialized).await?;

    // 3. tools/list
    let list = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    });
    let list_start = Instant::now();
    send(&mut child, &list).await?;
    let list_resp = read_one_response(&mut reader).await?;
    let list_elapsed = list_start.elapsed();
    eprintln!("client: tools/list response in {list_elapsed:?}");
    println!("=== tools/list response ===");
    println!("{}", serde_json::to_string_pretty(&list_resp)?);

    let tools = list_resp["result"]["tools"].as_array();
    let echo_tool = tools
        .and_then(|arr| arr.iter().find(|t| t["name"] == "echo"));
    if echo_tool.is_none() {
        eprintln!("FAIL: tools/list did not include an `echo` tool");
        pass = false;
    } else {
        let tool = echo_tool.unwrap();
        if !tool["inputSchema"].is_object() {
            eprintln!("FAIL: echo tool has no inputSchema object");
            pass = false;
        }
        let schema = &tool["inputSchema"];
        let has_text_prop = schema["properties"]["text"].is_object();
        if !has_text_prop {
            eprintln!("FAIL: echo tool inputSchema missing `text` property");
            pass = false;
        }
        let required = schema["required"].as_array();
        let text_required = required
            .map(|a| a.iter().any(|v| v == "text"))
            .unwrap_or(false);
        if !text_required {
            eprintln!("FAIL: echo tool's `text` is not marked required");
            pass = false;
        }
    }

    // 4. tools/call echo with a sample input
    let payload = "hello from p0-1-rmcp-hello-client";
    let call = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": { "text": payload }
        }
    });
    let call_start = Instant::now();
    send(&mut child, &call).await?;
    let call_resp = read_one_response(&mut reader).await?;
    let call_elapsed = call_start.elapsed();
    eprintln!("client: tools/call response in {call_elapsed:?}");
    println!("=== tools/call response ===");
    println!("{}", serde_json::to_string_pretty(&call_resp)?);

    let content = call_resp["result"]["content"].as_array();
    let echoed = content
        .and_then(|arr| arr.first())
        .and_then(|c| c["text"].as_str())
        .unwrap_or("");
    if echoed != payload {
        eprintln!("FAIL: echoed text = {echoed:?}, expected {payload:?}");
        pass = false;
    }
    let is_error = call_resp["result"]["isError"].as_bool().unwrap_or(false);
    if is_error {
        eprintln!("FAIL: tool result has isError=true unexpectedly");
        pass = false;
    }

    // 5. Try a malformed tools/call to confirm error path
    let bad = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {} // missing required `text`
        }
    });
    send(&mut child, &bad).await?;
    let bad_resp = read_one_response(&mut reader).await?;
    println!("=== tools/call (malformed) response ===");
    println!("{}", serde_json::to_string_pretty(&bad_resp)?);
    let has_error = bad_resp.get("error").is_some()
        || bad_resp["result"]["isError"].as_bool().unwrap_or(false);
    if !has_error {
        eprintln!("FAIL: malformed call did not produce error / isError=true");
        pass = false;
    }

    // 6. Latency summary
    println!("=== latencies ===");
    println!("initialize: {init_elapsed:?}");
    println!("tools/list: {list_elapsed:?}");
    println!("tools/call(echo): {call_elapsed:?}");

    // Shutdown the server cleanly by closing stdin.
    drop(child.stdin.take());
    let kill_started = Instant::now();
    let _ = timeout(Duration::from_secs(2), child.wait()).await;
    if child.try_wait().is_err() || child.try_wait()?.is_none() {
        child.kill().await.ok();
    }
    eprintln!("client: server shutdown in {:?}", kill_started.elapsed());

    if pass {
        println!("\nPASS: all assertions met");
        Ok(())
    } else {
        bail!("FAIL: one or more assertions failed (see stderr above)")
    }
}
