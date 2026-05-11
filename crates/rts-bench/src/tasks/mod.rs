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

pub mod locate_def;

/// Stable identifiers used on the CLI (`rts-bench task <id>`) and in
/// `bench-<sha>.json`.
pub const TASK_IDS: &[&str] = &[
    "locate_def",
    "get_body",
    "find_callers",
    "summarize_module",
    "fix_imports",
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

/// Run one task by id. Returns `TaskOutcome::NotImplemented` for tasks 2-5
/// — the v0 contract.
pub async fn run_task(id: &str, ctx: &TaskContext<'_>) -> Result<TaskOutcome> {
    match id {
        "locate_def" => locate_def::run(ctx).await,
        "get_body" | "find_callers" | "summarize_module" | "fix_imports" => {
            Ok(TaskOutcome::NotImplemented {
                reason: format!(
                    "task `{id}` is enumerated in plan §P9 but lands in a later bench slice"
                ),
            })
        }
        other => anyhow::bail!("unknown task id: {other}; valid ids: {TASK_IDS:?}"),
    }
}
