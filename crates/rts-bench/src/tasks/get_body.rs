//! Task 2: "Get the body of a named function (≤200 LOC)."
//!
//! Baseline: `rg -n "fn <name>"` to locate the file, then read the entire
//! containing file in full. The agent has no way to know where the
//! function ends — its only option is to feed the whole file.
//!
//! MCP: one `read_symbol(name)` call returning the def's raw byte slice.
//!
//! Expected reduction: large, especially on big files. A 1000-line
//! module with a 30-line target function: baseline ≈ all 1000 lines /
//! 3 tokens; MCP ≈ 30 lines / 3 tokens. ~97% reduction.

use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use serde_json::json;

use crate::baseline;
use crate::mcp_runner::{McpRun, McpSession};
use crate::tasks::{TaskContext, TaskOutcome};

/// We model an agent that, once it spots `fn <name>` in `rg` output,
/// reads the matching file *once* and stops. The MCP path also makes one
/// call. Hard cap of 4 protects against pathological cases where the
/// symbol name matches in many unrelated files.
const BASELINE_MAX_FILES: usize = 4;

pub async fn run(ctx: &TaskContext<'_>) -> Result<TaskOutcome> {
    let symbol = ctx.task_inputs["symbol_name"]
        .as_str()
        .ok_or_else(|| anyhow!("`symbol_name` required for get_body"))?
        .to_string();

    let description = format!(
        "Get the body of `{symbol}`. Baseline = ripgrep to locate, then read the entire \
         containing file in full (no symbol-end awareness). MCP = one `read_symbol` call \
         returning just the symbol's byte slice."
    );

    if !baseline::rg_available().await {
        return Err(anyhow!(
            "ripgrep (`rg`) is not on PATH; install it to run this task's baseline."
        ));
    }

    // The baseline runner already locates *and* reads — exactly the
    // shape of "find the file, then read it" the task asks for.
    let pattern = regex_escape(&format!("fn {symbol}"));
    let baseline = baseline::locate_and_read(ctx.workspace, &pattern, BASELINE_MAX_FILES)
        .await
        .with_context(|| format!("baseline path for get_body({symbol})"))?;

    let mcp_start = Instant::now();
    let mut session =
        McpSession::spawn(ctx.rts_mcp_bin, ctx.rts_daemon_bin, ctx.workspace, &[]).await?;
    let call = session
        .tools_call(
            "read_symbol",
            json!({ "name": symbol, "shape": "body" }),
            30,
        )
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

/// Same escape table as locate_def. Inlined rather than shared because the
/// table is tiny and the locate_def copy is `pub(super)` for tests; making
/// a third-party helper would just add coupling.
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
