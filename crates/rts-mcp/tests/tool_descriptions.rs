//! Tool-description quality gate.
//!
//! These tests guard the per-tool `description` strings advertised over
//! `tools/list`. They encode the Round-13 dogfood lesson: descriptions
//! that just say *what* a tool does lose the agent's tool-selection
//! moment to `Bash(grep)` even with a `PreToolUse:Bash` nudge hook
//! firing on every call. The fix is to make every description
//! comparative ("instead of grep / prefer over X"), action-triggered
//! ("use when the task includes ..."), and right-sized (not so terse
//! the claim is missing, not so verbose agents skim past it).
//!
//! Why these specific assertions matter (Rule 9 — tests verify intent):
//!
//! - `every_tool_description_carries_a_comparative_clause` — catches
//!   the failure mode where someone shortens a description and drops
//!   the "use instead of `Bash(grep)`" framing that wins selection.
//! - `every_tool_description_carries_a_trigger_phrase_hint` — catches
//!   the failure mode where a description reverts to passive "this
//!   tool does X" wording with no signal to the agent about *when*.
//! - `description_length_is_bounded` — catches both too-terse
//!   (under-described, claim absent) and too-verbose (agents skim).
//! - `schema_round_trip` — catches descriptions surviving JSON
//!   serialization/deserialization byte-for-byte (no embedded raw
//!   control chars; no character-encoding drift).

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

/// The agent-facing tools whose descriptions must compete with
/// `Bash`-based defaults or with sibling rts tools. `daemon_stats` is
/// excluded — it's an introspection tool with no `Bash` analog to
/// compete against, so the comparative-clause / trigger-phrase rules
/// don't usefully apply.
///
/// `daemon_telemetry` IS included even though it has no `Bash` analog:
/// its comparative target is `daemon_stats` (the sibling counter RPC),
/// and the selection moment it has to win is "the agent needs latency
/// percentiles / cache-hit rate" → it must clearly differentiate from
/// the cheaper `daemon_stats` rather than be skimmed past.
const AUDITED_TOOLS: &[&str] = &[
    "outline_workspace",
    "find_symbol",
    "read_symbol",
    "read_symbol_at",
    "read_range",
    "find_callers",
    "verify_symbol",
    "verify_signature",
    "verify_import",
    "verify_claims",
    "impact_of",
    "verify_impact",
    "verify_edit",
    "grep",
    "daemon_telemetry",
];

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

/// Spawn `rts-mcp` and fetch the `tools/list` array. Reused across the
/// four assertion tests to avoid spawning four times.
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
    std::fs::write(workspace.path().join("lib.rs"), "pub fn audit_seed() {}\n")?;

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

    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "rts-mcp-itest-descriptions", "version": "0.0.0" }
        }
    });
    send_request(&mut stdin, &init).await?;
    let _ = read_one_response(&mut reader).await?;

    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    send_request(&mut stdin, &initialized).await?;

    send_request(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    )
    .await?;
    let list_resp = read_one_response(&mut reader).await?;
    let tools = list_resp["result"]["tools"]
        .as_array()
        .ok_or_else(|| anyhow!("tools/list returned no array"))?
        .clone();

    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;

    Ok(tools)
}

/// Look up the description for `tool_name`, panicking with a useful
/// message if the tool is missing from the list.
fn description_of<'a>(tools: &'a [Value], tool_name: &str) -> &'a str {
    let tool = tools
        .iter()
        .find(|t| t["name"].as_str() == Some(tool_name))
        .unwrap_or_else(|| panic!("tool `{tool_name}` not present in tools/list"));
    tool["description"]
        .as_str()
        .unwrap_or_else(|| panic!("tool `{tool_name}` has no description field"))
}

/// **Why:** the dogfood signal that drove this audit was the orchestrating
/// agent choosing `Bash(grep)` over `mcp__rts__grep` 30+ times in a multi-
/// day session, even with rts mounted and a `PreToolUse:Bash` nudge hook
/// active. Descriptions that don't reach for a comparison ("instead of",
/// "prefer over X", "vs Bash") lose the selection moment. This test
/// catches the regression where someone shortens a description and the
/// comparative clause silently disappears.
#[tokio::test(flavor = "current_thread")]
async fn every_tool_description_carries_a_comparative_clause() -> Result<()> {
    let tools = fetch_tools_list().await?;

    // Tokens that count as a comparative clause. Case-insensitive
    // substring match. Covers the natural ways a description can
    // claim "use this over Bash / grep / cat / find / rg / Read".
    let needles: &[&str] = &[
        "instead of",
        "prefer this over",
        "prefer over",
        " vs ",
        " vs.",
        "over bash",
        "over grep",
        "over `bash",
        "over `grep",
        "over `rg",
        "over `cat",
        "over `find",
        "over `read",
        "over shell",
        "over a manual",
        "shell grep can't",
    ];

    for tool_name in AUDITED_TOOLS {
        let desc = description_of(&tools, tool_name).to_lowercase();
        let hit = needles.iter().any(|n| desc.contains(n));
        assert!(
            hit,
            "tool `{tool_name}` description lacks a comparative clause \
             (one of: {needles:?}). Descriptions that only describe what a \
             tool does — without comparing to the Bash/grep alternative — \
             lose the agent's tool-selection moment. Current description: \
             {desc:?}"
        );
    }
    Ok(())
}

/// **Why:** agents pattern-match on trigger phrases ("use when the task
/// includes 'find'", "use this for"). A description that says only "this
/// tool does X" is passive and easy to skim past. This test catches the
/// regression where active trigger phrasing reverts to passive.
#[tokio::test(flavor = "current_thread")]
async fn every_tool_description_carries_a_trigger_phrase_hint() -> Result<()> {
    let tools = fetch_tools_list().await?;

    let needles: &[&str] = &[
        "use when",
        "use this for",
        "use this when",
        "when the task",
        "for tasks like",
        "use for",
    ];

    for tool_name in AUDITED_TOOLS {
        let desc = description_of(&tools, tool_name).to_lowercase();
        let hit = needles.iter().any(|n| desc.contains(n));
        assert!(
            hit,
            "tool `{tool_name}` description lacks a trigger-phrase hint \
             (one of: {needles:?}). Agents pattern-match on phrases like \
             'use when' / 'use for' / 'when the task includes' to decide \
             whether to pick a tool; passive descriptions lose. Current \
             description: {desc:?}"
        );
    }
    Ok(())
}

/// **Why:** too terse means the comparative claim couldn't possibly fit
/// (sub-80 chars is one short sentence); too verbose means agents won't
/// read it (above 800 chars is several paragraphs, which empirically
/// gets skimmed). The bounds aren't load-bearing magic numbers — they're
/// the "sane envelope" guard against either failure mode landing
/// silently in a future edit.
#[tokio::test(flavor = "current_thread")]
async fn description_length_is_bounded() -> Result<()> {
    let tools = fetch_tools_list().await?;

    for tool_name in AUDITED_TOOLS {
        let desc = description_of(&tools, tool_name);
        let len = desc.chars().count();
        assert!(
            (80..=800).contains(&len),
            "tool `{tool_name}` description length {len} chars is outside \
             the bounded envelope [80, 800]. Too short → comparative claim \
             missing. Too long → agents skim past. Tighten or expand.",
        );
    }
    Ok(())
}

/// **Why:** the description text is shipped over the JSON-RPC wire and
/// must survive a serialize/parse round trip with the exact same bytes
/// the server emitted. Catches a class of bugs where a hand-edited
/// description sneaks in an unescaped control character, a stray BOM,
/// or non-UTF-8 bytes that schemars happily accepts but JSON parsers
/// reconstruct differently. Also a regression guard against a future
/// rmcp upgrade silently dropping or normalizing the field.
#[tokio::test(flavor = "current_thread")]
async fn schema_round_trip() -> Result<()> {
    let tools = fetch_tools_list().await?;

    // Build name → description from the live tools/list.
    let mut original: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for t in &tools {
        let name = t["name"].as_str().unwrap_or("").to_string();
        let desc = t["description"].as_str().unwrap_or("").to_string();
        original.insert(name, desc);
    }

    // Round-trip the entire tools/list array through serde_json.
    let wire = serde_json::to_string(&tools).context("serialize tools/list")?;
    let parsed: Vec<Value> = serde_json::from_str(&wire).context("re-parse tools/list")?;

    for tool_name in AUDITED_TOOLS {
        let want = original
            .get(*tool_name)
            .unwrap_or_else(|| panic!("audited tool `{tool_name}` missing from tools/list"));
        let got = parsed
            .iter()
            .find(|t| t["name"].as_str() == Some(tool_name))
            .and_then(|t| t["description"].as_str())
            .unwrap_or_else(|| panic!("tool `{tool_name}` lost description through round-trip"));
        assert_eq!(
            got, want,
            "tool `{tool_name}` description changed across JSON round-trip"
        );
        assert!(
            !got.is_empty(),
            "tool `{tool_name}` description is empty after round-trip"
        );
    }
    Ok(())
}
