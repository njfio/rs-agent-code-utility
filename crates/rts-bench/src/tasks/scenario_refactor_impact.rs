//! Scenario task: "agent wants the refactor blast radius of a symbol."
//!
//! This is the v0.3 U5 counterpart to alpha.24's
//! `scenario_compiler_fix`. Both bench measure agent-loop wins on
//! tasks an agent does in practice; this one models the *refactor*
//! flow that motivates the persistent ref graph.
//!
//! ### Scenario
//!
//! Agent wants to rename or change the signature of a public function
//! and needs to see (a) all transitive callers — both direct and
//! indirect — and (b) the priority order in which to update them.
//!
//! ### Baseline (no MCP, pre-v0.3)
//!
//! 1. `rg -n "<symbol>"` to find every textual mention.
//! 2. Read every file that matched, in full. The agent doesn't know
//!    which mentions are real call sites vs comments/strings, and
//!    doesn't know which files contain transitive callers (callers
//!    of the direct callers).
//! 3. For each direct caller, repeat the grep + read on *its* name
//!    to surface indirect callers. Two-level recursion.
//!
//! ### MCP (with v0.3 U5)
//!
//! 1. `impact_of(name)` → one call returns the entire transitive
//!    closure with depth + rank ordering and the four truncation
//!    flags. No re-grepping, no re-reading whole files.
//!
//! ### Plan §G2 target
//!
//! ≥ 70 % token reduction vs the baseline path. Single MCP call vs
//! N rounds of grep + read.

use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use serde_json::json;

use crate::baseline;
use crate::mcp_runner::{McpRun, McpSession};
use crate::tasks::{TaskContext, TaskOutcome};

/// Cap on baseline file reads. The baseline path approximates "a
/// real agent reads the top-N hits from each grep" — past N=6 the
/// agent gives up. Matches the alpha.24 task's 4-file cap, adjusted
/// up for the deeper recursion.
const BASELINE_MAX_FILES_PER_LEVEL: usize = 6;

pub async fn run(ctx: &TaskContext<'_>) -> Result<TaskOutcome> {
    // Target symbol: the fn the agent is about to refactor.
    // Reads from `symbol_name` (matching the CLI's `--symbol` arg
    // which other tasks also consume).
    let target = ctx.task_inputs["symbol_name"]
        .as_str()
        .ok_or_else(|| anyhow!("`symbol_name` (--symbol) required for scenario_refactor_impact"))?
        .to_string();
    // Direct callers the bench fixture already knows about — used
    // to compute the second-level baseline grep. Real agents
    // discover these from the first-level grep; the bench hardcodes
    // them so both paths measure the same workload.
    let direct_callers: Vec<String> = ctx.task_inputs["direct_callers"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let description = format!(
        "Refactor-impact scenario for `{target}`. Baseline = `rg <symbol>` + read \
         every match + recurse on each direct caller (~2 grep levels × {} files each). \
         MCP = one `impact_of(name)` call with default depth=2, max_nodes=200, and \
         test-path exclusion.",
        BASELINE_MAX_FILES_PER_LEVEL
    );

    if !baseline::rg_available().await {
        return Err(anyhow!(
            "ripgrep (`rg`) is not on PATH; install it to run this task's baseline."
        ));
    }

    // ---- baseline ----
    // Level 1: grep target symbol, read every matching file in full.
    let target_pattern = regex_escape(&target);
    let baseline_l1 =
        baseline::locate_and_read(ctx.workspace, &target_pattern, BASELINE_MAX_FILES_PER_LEVEL)
            .await?;

    // Level 2: for each direct caller name (one round of recursion),
    // repeat the grep + read.
    let mut baseline_l2_tokens = 0u64;
    let mut baseline_l2_rg: usize = 0;
    let mut baseline_l2_bytes: usize = 0;
    let mut baseline_l2_files: Vec<std::path::PathBuf> = Vec::new();
    let mut baseline_l2_elapsed = 0u128;
    for caller in &direct_callers {
        let pat = regex_escape(caller);
        let r = baseline::locate_and_read(ctx.workspace, &pat, BASELINE_MAX_FILES_PER_LEVEL)
            .await
            .with_context(|| format!("baseline L2: rg {caller}"))?;
        baseline_l2_tokens = baseline_l2_tokens.saturating_add(r.tokens);
        baseline_l2_rg = baseline_l2_rg.saturating_add(r.rg_stdout_bytes);
        baseline_l2_bytes = baseline_l2_bytes.saturating_add(r.file_bytes_read);
        baseline_l2_elapsed = baseline_l2_elapsed.saturating_add(r.elapsed_ms);
        baseline_l2_files.extend(r.files_read);
    }

    let mut all_files = baseline_l1.files_read.clone();
    all_files.extend(baseline_l2_files);

    let baseline_total = crate::baseline::BaselineRun {
        tokens: baseline_l1.tokens.saturating_add(baseline_l2_tokens),
        rg_stdout_bytes: baseline_l1.rg_stdout_bytes.saturating_add(baseline_l2_rg),
        file_bytes_read: baseline_l1
            .file_bytes_read
            .saturating_add(baseline_l2_bytes),
        files_read: all_files,
        elapsed_ms: baseline_l1.elapsed_ms.saturating_add(baseline_l2_elapsed),
    };

    // ---- MCP ----
    let mcp_start = Instant::now();
    let mut session =
        McpSession::spawn(ctx.rts_mcp_bin, ctx.rts_daemon_bin, ctx.workspace, &[]).await?;

    // One call: impact_of with default bounds. The whole transitive
    // closure comes back in a single JSON response.
    let impact_call = session
        .tools_call(
            "impact_of",
            json!({
                "name": target,
                // Defaults are fine for the scenario, but pin them so
                // the bench result is reproducible if defaults change.
                "depth": 2,
                "max_nodes": 200,
                "exclude_test_paths": true,
            }),
            30,
        )
        .await?;

    session.close().await?;

    let mcp = McpRun {
        tokens: impact_call.tokens,
        calls: vec![impact_call],
        elapsed_ms: mcp_start.elapsed().as_millis(),
    };

    Ok(TaskOutcome::Ran {
        baseline: baseline_total,
        mcp,
        inputs: json!({
            "target_symbol": target,
            "direct_callers": direct_callers,
            "baseline_max_files_per_level": BASELINE_MAX_FILES_PER_LEVEL,
        }),
        description,
    })
}

/// Same regex-escape helper as `scenario_compiler_fix`. Inlined to
/// avoid a one-line shared module — the helper is small and the
/// duplication makes each task readable in isolation.
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
