//! The five baseline bench tasks per plan §P9.
//!
//! v0 implements **task 1 (locate_def)** end-to-end so the bench harness can
//! emit a real `bench-<sha>.json` with a non-zero S2 number. The other four
//! tasks are scaffolded with their inputs + descriptions so the report
//! schema is complete, but their bodies return `TaskOutcome::NotImplemented`
//! until later P9 slices.

use std::path::Path;

use anyhow::Result;

use crate::baseline::BaselineRun;
use crate::mcp_runner::McpRun;

pub mod get_body;
pub mod locate_def;
pub mod scenario_compiler_fix;
pub mod summarize_module;

/// Stable identifiers used on the CLI (`rts-bench task <id>`) and in
/// `bench-<sha>.json`.
pub const TASK_IDS: &[&str] = &[
    "locate_def",
    "get_body",
    "find_callers",
    "summarize_module",
    "fix_imports",
    "scenario_compiler_fix",
];

/// Outcome of running one task.
#[derive(Debug)]
pub enum TaskOutcome {
    /// Task ran end-to-end. Carries the two measurements.
    Ran {
        baseline: BaselineRun,
        mcp: McpRun,
        inputs: serde_json::Value,
        description: String,
    },
    /// Task is enumerated in the plan but not yet implemented in this build.
    /// The report omits these entries; surfaced to stdout for visibility.
    NotImplemented { reason: String },
}

/// Per-task launch context: where the workspace is, where the binaries are,
/// what the symbol-of-interest is. Carried in so tasks don't have to
/// rediscover this each time.
pub struct TaskContext<'a> {
    pub workspace: &'a Path,
    pub rts_mcp_bin: &'a Path,
    pub rts_daemon_bin: &'a Path,
    /// Sym/file/path inputs for the task. Schema is task-defined — locate_def
    /// uses `symbol_name`, get_body uses `symbol_name`+`max_lines`, etc.
    pub task_inputs: serde_json::Value,
}

/// Run one task by id. v0 implements `locate_def`, `get_body`, and
/// `summarize_module`. `find_callers` + `fix_imports` need the P8
/// reference-graph that isn't built yet — they return `NotImplemented`
/// with a pointer to the later slice.
pub async fn run_task(id: &str, ctx: &TaskContext<'_>) -> Result<TaskOutcome> {
    match id {
        "locate_def" => locate_def::run(ctx).await,
        "get_body" => get_body::run(ctx).await,
        "summarize_module" => summarize_module::run(ctx).await,
        "scenario_compiler_fix" => scenario_compiler_fix::run(ctx).await,
        "find_callers" => Ok(TaskOutcome::NotImplemented {
            reason: "task `find_callers` needs an inverted ref-graph (closure walker is \
                     anchor→deps; this is the inverse). Defer to v1.1 alongside multi-hop \
                     closure."
                .into(),
        }),
        "fix_imports" => Ok(TaskOutcome::NotImplemented {
            reason: "task `fix_imports` needs the same inverted ref-graph; defer with \
                     find_callers."
                .into(),
        }),
        other => anyhow::bail!("unknown task id: {other}; valid ids: {TASK_IDS:?}"),
    }
}
