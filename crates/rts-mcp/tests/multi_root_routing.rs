//! End-to-end multi-root routing through the MCP shim.
//!
//! Spawns `rts-mcp --workspace <A> --workspace <B>` (which auto-spawns ONE
//! `rts-daemon`), then drives real `tools/call` requests over stdio and
//! asserts that each call is served by the root its **own arguments** name —
//! without the model ever passing a root:
//!
//! - `read_symbol { file: "<absolute path under B>" }` → served by B,
//!   `_root.resolved_by == "path_match"`, and the body is B's definition.
//! - `read_symbol { name: "answer" }` (no path at all) → served by the
//!   start-up root, `_root.resolved_by == "default"`, and the response says
//!   so.
//! - `grep { file_glob: "<absolute glob under B>" }` → served by B.
//!
//! The two roots define the same symbol differently, so a mis-route shows up
//! as the wrong body rather than as a plausible-looking answer — the exact
//! failure this change exists to remove.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout};

fn rts_mcp_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-mcp"))
}

/// `CARGO_BIN_EXE_<name>` only resolves inside the current crate, so point the
/// daemon path at the sibling output dir.
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

/// One `tools/call`, returning the parsed daemon JSON body (with the shim's
/// `_root` block attached). An error envelope from the daemon comes back as
/// its body (`{"error": …}`), so callers can assert on it.
async fn call_tool(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    id: &mut u64,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    *id += 1;
    send_request(
        stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": *id,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments }
        }),
    )
    .await?;
    let resp = read_one_response(reader).await?;
    if resp["result"]["isError"].as_bool().unwrap_or(false)
        && resp["result"]["content"][0]["text"].is_null()
    {
        anyhow::bail!("{tool} returned an MCP error: {resp:?}");
    }
    let body = resp["result"]["content"][0]["text"]
        .as_str()
        .ok_or_else(|| anyhow!("{tool} returned no text content: {resp:?}"))?;
    serde_json::from_str(body).with_context(|| format!("parse {tool} body"))
}

/// The first call routed to a root pays that root's mount (cold walk + first
/// writer batch), so retry until the index answers — the same shape
/// `mcp_round_trip.rs` uses for a freshly mounted workspace.
async fn call_tool_until_indexed(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    id: &mut u64,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let body = call_tool(stdin, reader, id, tool, arguments.clone()).await?;
        if body.get("error").is_none() {
            return Ok(body);
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("{tool} never became answerable: {body:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn seed_root(path: &Path, marker: &str, answer: u32) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(path.join("src"))?;
    let file = path.join("src/lib.rs");
    std::fs::write(
        &file,
        format!(
            "pub const MARKER: &str = \"{marker}\";\n\n\
             /// Returns this root's answer.\n\
             pub fn answer() -> u32 {{ {answer} }}\n"
        ),
    )?;
    Ok(file)
}

#[tokio::test(flavor = "current_thread")]
async fn mcp_routes_each_tool_call_to_the_root_its_paths_name() -> Result<()> {
    let daemon_bin = rts_daemon_bin();
    assert!(
        daemon_bin.is_file(),
        "rts-daemon must be built before this test; missing at {}",
        daemon_bin.display()
    );

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let root_a = tempfile::tempdir()?;
    let root_b = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    seed_root(root_a.path(), "MARKER_ROOT_A", 1)?;
    let file_b = seed_root(root_b.path(), "MARKER_ROOT_B", 2)?;

    // Canonical (as the shim and the daemon both canonicalise) so the absolute
    // path we send really is under root B.
    let canonical_a = root_a.path().canonicalize()?;
    let canonical_b = root_b.path().canonicalize()?;
    let file_b_abs = file_b.canonicalize()?;
    let glob_b = format!("{}/src/**/*.rs", canonical_b.display());

    let mut cmd = tokio::process::Command::new(rts_mcp_bin());
    cmd.arg("--workspace")
        .arg(&canonical_a)
        .arg("--workspace")
        .arg(&canonical_b)
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

    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "rts-mcp-multiroot-itest", "version": "0.0.0" }
            }
        }),
    )
    .await?;
    let init = read_one_response(&mut reader).await?;
    assert_eq!(init["id"], 1, "initialize failed: {init:?}");
    send_request(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} }),
    )
    .await?;

    let mut id: u64 = 100;

    // 1. An absolute path under root B routes there — and answers with B's
    //    definition of `answer`, not the start-up root's. This first routed
    //    call also pays root B's mount, hence the retry.
    let routed_to_b = call_tool_until_indexed(
        &mut stdin,
        &mut reader,
        &mut id,
        "read_symbol",
        json!({ "name": "answer", "file": file_b_abs.to_string_lossy(), "shape": "body" }),
    )
    .await?;
    assert_eq!(
        routed_to_b["_root"]["path"],
        json!(canonical_b.to_string_lossy()),
        "an absolute path under root B must route to root B: {routed_to_b:?}"
    );
    assert_eq!(routed_to_b["_root"]["resolved_by"], "path_match");
    let body_b = routed_to_b["text"].as_str().unwrap_or_default();
    assert!(
        body_b.contains("{ 2 }"),
        "root B's body must come from root B's index: {body_b:?}"
    );
    let id_b = routed_to_b["_root"]["workspace_id"]
        .as_str()
        .expect("_root.workspace_id")
        .to_string();

    // 2. A glob under root B routes there too.
    let grep_b = call_tool(
        &mut stdin,
        &mut reader,
        &mut id,
        "grep",
        json!({ "text": "MARKER_ROOT_B", "file_glob": glob_b }),
    )
    .await?;
    assert_eq!(
        grep_b["_root"]["path"],
        json!(canonical_b.to_string_lossy()),
        "an absolute glob under root B must route to root B: {grep_b:?}"
    );
    assert_eq!(
        grep_b["matches"].as_array().map(Vec::len),
        Some(1),
        "root B's marker must be found once: {grep_b:?}"
    );

    // 3. A call with no path at all is served by the start-up root, and the
    //    response says so rather than leaving the caller to guess.
    let default_root = call_tool(
        &mut stdin,
        &mut reader,
        &mut id,
        "read_symbol",
        json!({ "name": "answer", "shape": "body" }),
    )
    .await?;
    assert_eq!(
        default_root["_root"]["path"],
        json!(canonical_a.to_string_lossy()),
        "a name-only call must be served by the start-up root: {default_root:?}"
    );
    assert_eq!(default_root["_root"]["resolved_by"], "default");
    assert!(
        default_root["_root"]["note"]
            .as_str()
            .unwrap_or_default()
            .contains("start-up root"),
        "the default must be stated in the response: {default_root:?}"
    );
    let body_a = default_root["text"].as_str().unwrap_or_default();
    assert!(
        body_a.contains("{ 1 }"),
        "the start-up root's body must come from root A's index: {body_a:?}"
    );

    // 4. Both roots are mounted on ONE daemon: the two routes name different
    //    mount ids.
    let id_a = default_root["_root"]["workspace_id"]
        .as_str()
        .expect("_root.workspace_id")
        .to_string();
    assert_ne!(
        id_a, id_b,
        "the two routes must be distinct mounts of the same daemon"
    );

    Ok(())
}
