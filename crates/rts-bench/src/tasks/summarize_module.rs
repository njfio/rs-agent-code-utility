//! Task 4: "Summarize a module (top-N exported symbols within a 1k-token budget)."
//!
//! The plan's full version of this task wants ranked top-N symbols with
//! signatures — that needs the P8 `SignatureRenderer` + PageRank to
//! produce a real outline. For the v0 bench slice, we model the
//! "orient-in-an-unfamiliar-file" pattern an agent actually exhibits
//! today:
//!
//! - **Baseline**: read the entire file in full. The agent's only
//!   option without an outline tool.
//! - **MCP**: one `read_range(file, 1, line_budget)` call returning
//!   the first N lines (where imports + most top-level public
//!   declarations live in most codebases).
//!
//! The reduction here is bounded by `line_budget / total_lines` rather
//! than the much higher ratio you get with a real outline. When P8
//! lands, this task gets a second MCP path (`outline_workspace(glob: file)`)
//! and the ratio jumps from "first-N-lines" to "ranked-top-K-signatures".

use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};

use crate::baseline::BaselineRun;
use crate::mcp_runner::{McpRun, McpSession};
use crate::tasks::{TaskContext, TaskOutcome};
use crate::token;

const DEFAULT_LINE_BUDGET: u32 = 50;

pub async fn run(ctx: &TaskContext<'_>) -> Result<TaskOutcome> {
    let file_rel = ctx.task_inputs["file"]
        .as_str()
        .ok_or_else(|| anyhow!("`file` required for summarize_module"))?
        .to_string();
    let line_budget = ctx.task_inputs["line_budget"]
        .as_u64()
        .map(|n| n as u32)
        .unwrap_or(DEFAULT_LINE_BUDGET);

    let description = format!(
        "Summarize the top of `{file_rel}` (first {line_budget} lines). Baseline = read the \
         whole file in full (no outline available). MCP = one `read_range` call returning the \
         module head. v0 approximation; the P8 outline-driven path lands later."
    );

    let abs = ctx.workspace.join(&file_rel);
    if !abs.starts_with(ctx.workspace) || !abs.is_file() {
        return Err(anyhow!(
            "file `{file_rel}` must be a regular file inside the workspace root"
        ));
    }

    let baseline = baseline_read_whole_file(&abs, &file_rel).await?;

    let mcp_start = Instant::now();
    let mut session =
        McpSession::spawn(ctx.rts_mcp_bin, ctx.rts_daemon_bin, ctx.workspace, &[]).await?;
    let call = session
        .tools_call(
            "read_range",
            json!({
                "file": file_rel,
                "start_line": 1,
                "end_line": line_budget
            }),
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
        inputs: json!({
            "file": file_rel,
            "line_budget": line_budget
        }),
        description,
    })
}

/// Read one file in full and surface it as a `BaselineRun`. We don't shell
/// out to `rg` here — the task is "read this whole module" by file path,
/// not by symbol search; padding it with a no-match `rg` call would just
/// pollute the baseline tokens.
async fn baseline_read_whole_file(abs: &Path, rel: &str) -> Result<BaselineRun> {
    let start = Instant::now();
    let bytes = tokio::fs::read(abs)
        .await
        .with_context(|| format!("read {}", abs.display()))?;
    let len = bytes.len();
    let tokens: Value = json!(token::approx_tokens(len));
    let _ = tokens; // documented above; keep variable to silence warnings
    Ok(BaselineRun {
        tokens: token::approx_tokens(len),
        rg_stdout_bytes: 0,
        file_bytes_read: len,
        files_read: vec![std::path::PathBuf::from(rel)],
        elapsed_ms: start.elapsed().as_millis(),
    })
}
