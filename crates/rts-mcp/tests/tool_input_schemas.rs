//! Tool `inputSchema` contract gate: the one-of rules the server enforces must be advertised.
//!
//! Two tools validate a *one-of* over their arguments in the daemon (`grep`: at least one of
//! `text` | `structural_query` — `NO_SEARCH_SOURCE_PROVIDED`; `find_symbol`: exactly one of
//! `name` | `pattern`). Both argument structs are all-`Option`, so schemars emitted
//! `"required": null` and the advertised schema permitted shapes the server then refused with
//! `INVALID_PARAMS` — observed in production, where a client sent a schema-legal call and
//! retried the identical shape four times because nothing it had been given said the shape was
//! wrong. The constraint now lives in the schema (via `#[schemars(extend(...))]` on the arg
//! struct, the source of truth), and these tests read the schema the server *emits over
//! `tools/list`* — what a client actually sees, not the Rust type — so a future edit that drops
//! the annotation fails here rather than in a host's tool-call loop.
//!
//! `oneOf` for `find_symbol` is deliberate: the daemon rejects *both* `name` and `pattern`
//! (`"provide either \`name\` or \`pattern\`, not both"`), so "exactly one" is the rule, not
//! "at least one". `grep` accepts both sources at once (they intersect), so it is `anyOf`.

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

/// Spawn `rts-mcp`, handshake, and return the `tools/list` array exactly as a client reads it.
async fn fetch_tools_list() -> Result<Vec<Value>> {
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

    // Seed one tiny file so the daemon can start without errors.
    std::fs::write(workspace.path().join("lib.rs"), "pub fn schema_seed() {}\n")?;

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

    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "rts-mcp-itest-input-schemas", "version": "0.0.0" }
            }
        }),
    )
    .await?;
    let _ = read_one_response(&mut reader).await?;

    send_request(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} }),
    )
    .await?;

    send_request(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    )
    .await?;
    let tools = read_one_response(&mut reader).await?["result"]["tools"]
        .as_array()
        .ok_or_else(|| anyhow!("tools/list returned no array"))?
        .clone();

    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;

    Ok(tools)
}

/// The advertised `inputSchema` for `tool_name`.
fn input_schema<'a>(tools: &'a [Value], tool_name: &str) -> &'a Value {
    let tool = tools
        .iter()
        .find(|t| t["name"].as_str() == Some(tool_name))
        .unwrap_or_else(|| panic!("tool `{tool_name}` not present in tools/list"));
    let schema = &tool["inputSchema"];
    assert!(
        schema.is_object(),
        "tool `{tool_name}` has no object inputSchema: {schema}"
    );
    schema
}

/// The `required` lists of each branch under `keyword` (`oneOf` / `anyOf`), in order.
fn branch_required(schema: &Value, keyword: &str) -> Vec<Vec<String>> {
    schema[keyword]
        .as_array()
        .unwrap_or_else(|| panic!("inputSchema has no `{keyword}` array: {schema}"))
        .iter()
        .map(|branch| {
            branch["required"]
                .as_array()
                .unwrap_or_else(|| panic!("`{keyword}` branch has no `required` array: {branch}"))
                .iter()
                .map(|r| {
                    r.as_str()
                        .expect("required entries are strings")
                        .to_string()
                })
                .collect()
        })
        .collect()
}

/// **Why:** the production failure. `find_symbol` post-fix advertises `"required": null` and
/// the daemon refuses a call that omits both `name` and `pattern`; the caller has no way to
/// know before calling. The schema must say exactly-one-of, which is also the daemon's rule
/// (both present is rejected too, so `anyOf` would over-permit).
#[tokio::test(flavor = "current_thread")]
async fn find_symbol_advertises_exactly_one_of_name_or_pattern() -> Result<()> {
    let tools = fetch_tools_list().await?;
    let schema = input_schema(&tools, "find_symbol");
    assert_eq!(
        branch_required(schema, "oneOf"),
        vec![vec!["name".to_string()], vec!["pattern".to_string()]],
        "find_symbol inputSchema must advertise oneOf(name|pattern); got {schema}"
    );
    Ok(())
}

/// **Why:** same failure for `grep`, whose one-of is "at least one source". `anyOf` is the
/// correct keyword — supplying both is legal (the daemon intersects them) and the schema must
/// not forbid it.
#[tokio::test(flavor = "current_thread")]
async fn grep_advertises_at_least_one_search_source() -> Result<()> {
    let tools = fetch_tools_list().await?;
    let schema = input_schema(&tools, "grep");
    assert_eq!(
        branch_required(schema, "anyOf"),
        vec![
            vec!["text".to_string()],
            vec!["structural_query".to_string()]
        ],
        "grep inputSchema must advertise anyOf(text|structural_query); got {schema}"
    );
    Ok(())
}
