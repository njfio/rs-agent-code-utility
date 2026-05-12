//! Task 1: "Locate definition of a named function across the repo."
//!
//! Baseline: `rg -n "fn <name>"` + read every candidate file in full
//! (no symbol-awareness, can't tell `fn foo` from `// foo` in a comment).
//!
//! MCP: one `find_symbol(name)` tool call. The daemon already has the
//! symbol→def mapping in `NAME_TO_SID`, so this is one redb lookup
//! returning at most 256 matches with byte ranges.
//!
//! Expected reduction: large. `rg` returns *every line containing the
//! name* (definitions, calls, comments, mentions in strings) and the agent
//! pays for the full content of each candidate file. `find_symbol` returns
//! only the def sites + signatures.

use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use serde_json::json;

use crate::baseline;
use crate::mcp_runner::{McpRun, McpSession};
use crate::tasks::{TaskContext, TaskOutcome};

/// Cap on number of files the baseline path opens. Models a typical agent's
/// patience — it won't read 200 files even if `rg` matches that many. The
/// MCP path's 256-match cap is enforced inside the daemon.
const BASELINE_MAX_FILES: usize = 16;

pub async fn run(ctx: &TaskContext<'_>) -> Result<TaskOutcome> {
    let symbol = ctx.task_inputs["symbol_name"]
        .as_str()
        .ok_or_else(|| anyhow!("`symbol_name` required for locate_def"))?
        .to_string();

    let description = format!(
        "Locate the definition of `{symbol}` across the workspace. Baseline = ripgrep + read \
         every candidate file in full. MCP = one `find_symbol` call returning ranked def \
         sites with byte ranges."
    );

    if !baseline::rg_available().await {
        return Err(anyhow!(
            "ripgrep (`rg`) is not on PATH; install it or set `RTS_BENCH_SKIP_BASELINE=1` to \
             run MCP-only. For now we refuse to skip silently so a missing baseline can't \
             quietly produce a fake reduction number."
        ));
    }

    // `rg`'s pattern captures the actual function-definition syntax across
    // languages. For v0 we keep this loose: matching the bare name catches
    // every reference, which over-counts the baseline — but that's the
    // point. A real agent without rts-mcp pays exactly this over-count.
    let pattern = regex_escape(&symbol);
    let baseline = baseline::locate_and_read(ctx.workspace, &pattern, BASELINE_MAX_FILES)
        .await
        .with_context(|| format!("baseline path for `{symbol}`"))?;

    let mcp_start = Instant::now();
    let mut session =
        McpSession::spawn(ctx.rts_mcp_bin, ctx.rts_daemon_bin, ctx.workspace, &[]).await?;
    let call = session
        .tools_call("find_symbol", json!({ "name": symbol }), 30)
        .await?;
    session.close().await?;

    let mcp = McpRun {
        tokens: call.tokens,
        calls: vec![call],
        elapsed_ms: mcp_start.elapsed().as_millis(),
    };

    Ok(TaskOutcome::Ran {
        baseline,
        mcp,
        inputs: json!({ "symbol_name": symbol, "baseline_max_files": BASELINE_MAX_FILES }),
        description,
    })
}

/// Escape regex metachars so `rg` sees a literal pattern. Just enough for
/// identifiers; symbols with metachars in them (operator overloads, e.g.)
/// would need a richer escape table — defer.
fn regex_escape(s: &str) -> String {
    const ESCAPE: &[char] = &[
        '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$',
    ];
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if ESCAPE.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Synthesize a tiny workspace for the locate_def integration test. Three
/// files; only `lib.rs` actually defines `target_fn`. The other two
/// merely reference it — `rg` over-counts, `find_symbol` doesn't.
#[cfg(test)]
pub fn seed_test_workspace(root: &std::path::Path) -> std::io::Result<()> {
    use std::fs;
    fs::write(
        root.join("lib.rs"),
        "pub fn target_fn() {\n    println!(\"hello\");\n}\n\npub fn other() {\n    target_fn();\n}\n",
    )?;
    fs::write(
        root.join("README.md"),
        "# demo\n\nMentions `target_fn` in prose only.\n",
    )?;
    fs::write(
        root.join("notes.txt"),
        "TODO: revisit target_fn before shipping\n",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_passes_alphanumerics() {
        assert_eq!(regex_escape("target_fn"), "target_fn");
    }

    #[test]
    fn escape_handles_dot_and_paren() {
        assert_eq!(regex_escape("a.b()"), r"a\.b\(\)");
    }
}
