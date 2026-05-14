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
/// `summarize_module`. `find_callers` (the legacy stub) was superseded
/// by `rts-bench query find-callers` once v0.3 U2' shipped the
/// underlying `Index.FindCallers` daemon method; the baseline-bench
/// version of the same workflow will reland as `scenario_find_callers`
/// alongside U5's `scenario_refactor_impact`. `fix_imports` still
/// needs work the v0.3 plan doesn't cover.
pub async fn run_task(id: &str, ctx: &TaskContext<'_>) -> Result<TaskOutcome> {
    match id {
        "locate_def" => locate_def::run(ctx).await,
        "get_body" => get_body::run(ctx).await,
        "summarize_module" => summarize_module::run(ctx).await,
        "scenario_compiler_fix" => scenario_compiler_fix::run(ctx).await,
        "find_callers" => Ok(TaskOutcome::NotImplemented {
            reason: "the underlying `Index.FindCallers` method ships in v0.3 alpha.31+; \
                     for one-shot queries use `rts-bench query find-callers --name <X>`. \
                     The baseline-bench variant of this task will reland as \
                     `scenario_find_callers` alongside `scenario_refactor_impact` (v0.3 U5)."
                .into(),
        }),
        "fix_imports" => Ok(TaskOutcome::NotImplemented {
            reason: "task `fix_imports` is out of scope for v0.3; revisit once a real user \
                     has asked. The closure walker + persisted ref graph are the \
                     primitives it would build on."
                .into(),
        }),
        other => anyhow::bail!("unknown task id: {other}; valid ids: {TASK_IDS:?}"),
    }
}
