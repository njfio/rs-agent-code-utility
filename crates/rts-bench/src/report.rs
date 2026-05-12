//! Bench output report: `bench-<git-sha>.json`.
//!
//! Wire-stable; consumed by the CI gate that asserts the median reduction
//! across all tasks is ≥ 50% per plan §P9.

use std::path::Path;

use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::baseline::BaselineRun;
use crate::mcp_runner::McpRun;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskReport {
    pub task_id: String,
    /// Human-readable summary of what the task asked for.
    pub description: String,
    /// Concrete query inputs (symbol name, file, etc.) — pinned per task
    /// so the report is reproducible.
    pub inputs: serde_json::Value,
    pub baseline: BaselineReport,
    pub mcp: McpReport,
    pub reduction_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineReport {
    pub tokens: u64,
    pub rg_stdout_bytes: usize,
    pub file_bytes_read: usize,
    pub files_read: Vec<String>,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpReport {
    pub tokens: u64,
    pub tool_calls: u32,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    /// Schema version for this report payload.
    pub version: u32,
    /// `rts-bench` package version (so historical diffs can correlate with
    /// algorithm changes).
    pub rts_bench_version: String,
    /// Token oracle: `"bytes_div_3"` (v0) or `"anthropic_count_tokens"`
    /// (with `--with-network` once that lands).
    pub token_counter: String,
    /// Per-task results, in the order they were run.
    pub tasks: IndexMap<String, TaskReport>,
    /// Summary aggregates.
    pub summary: SummaryReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryReport {
    pub total_tasks: u32,
    /// Reduction percentage at the median over `tasks` — the CI gate.
    pub median_reduction_pct: f64,
    pub total_baseline_tokens: u64,
    pub total_mcp_tokens: u64,
}

impl BenchReport {
    pub fn new() -> Self {
        Self {
            version: 1,
            rts_bench_version: env!("CARGO_PKG_VERSION").to_string(),
            token_counter: "bytes_div_3".into(),
            tasks: IndexMap::new(),
            summary: SummaryReport {
                total_tasks: 0,
                median_reduction_pct: 0.0,
                total_baseline_tokens: 0,
                total_mcp_tokens: 0,
            },
        }
    }

    pub fn add_task(
        &mut self,
        task_id: &str,
        description: &str,
        inputs: serde_json::Value,
        baseline: &BaselineRun,
        mcp: &McpRun,
    ) {
        let reduction = pct_reduction(baseline.tokens, mcp.tokens);
        let report = TaskReport {
            task_id: task_id.into(),
            description: description.into(),
            inputs,
            baseline: BaselineReport {
                tokens: baseline.tokens,
                rg_stdout_bytes: baseline.rg_stdout_bytes,
                file_bytes_read: baseline.file_bytes_read,
                files_read: baseline
                    .files_read
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect(),
                elapsed_ms: baseline.elapsed_ms,
            },
            mcp: McpReport {
                tokens: mcp.tokens,
                tool_calls: mcp.calls.len() as u32,
                elapsed_ms: mcp.elapsed_ms,
            },
            reduction_pct: reduction,
        };
        self.tasks.insert(task_id.into(), report);
        self.refresh_summary();
    }

    fn refresh_summary(&mut self) {
        let total = self.tasks.len() as u32;
        let mut reductions: Vec<f64> = self.tasks.values().map(|t| t.reduction_pct).collect();
        reductions.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = if reductions.is_empty() {
            0.0
        } else if reductions.len() % 2 == 1 {
            reductions[reductions.len() / 2]
        } else {
            let mid = reductions.len() / 2;
            (reductions[mid - 1] + reductions[mid]) / 2.0
        };
        let total_baseline = self.tasks.values().map(|t| t.baseline.tokens).sum();
        let total_mcp = self.tasks.values().map(|t| t.mcp.tokens).sum();
        self.summary = SummaryReport {
            total_tasks: total,
            median_reduction_pct: median,
            total_baseline_tokens: total_baseline,
            total_mcp_tokens: total_mcp,
        };
    }

    pub fn write_to(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context("encode bench report")?;
        std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }
}

impl Default for BenchReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Percent reduction from `baseline` to `mcp`. Returns 0.0 when `baseline`
/// is 0 (avoids div-by-zero), positive when MCP used fewer tokens, negative
/// when MCP used more.
pub fn pct_reduction(baseline_tokens: u64, mcp_tokens: u64) -> f64 {
    if baseline_tokens == 0 {
        return 0.0;
    }
    let saved = baseline_tokens as f64 - mcp_tokens as f64;
    100.0 * saved / baseline_tokens as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduction_50_percent() {
        assert!((pct_reduction(1000, 500) - 50.0).abs() < 1e-9);
    }

    #[test]
    fn reduction_handles_zero_baseline() {
        assert_eq!(pct_reduction(0, 100), 0.0);
    }

    #[test]
    fn median_of_three_is_middle() {
        let mut r = BenchReport::new();
        for (id, base, mcp) in [("a", 1000u64, 500u64), ("b", 1000, 800), ("c", 1000, 100)] {
            r.add_task(
                id,
                "test",
                serde_json::json!({}),
                &BaselineRun {
                    tokens: base,
                    rg_stdout_bytes: 0,
                    file_bytes_read: 0,
                    files_read: vec![],
                    elapsed_ms: 0,
                },
                &McpRun {
                    tokens: mcp,
                    calls: vec![],
                    elapsed_ms: 0,
                },
            );
        }
        // Reductions are 50%, 20%, 90%; sorted [20, 50, 90] → median 50%.
        assert_eq!(r.summary.total_tasks, 3);
        assert!((r.summary.median_reduction_pct - 50.0).abs() < 1e-9);
    }
}
