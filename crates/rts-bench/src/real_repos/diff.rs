//! Baseline → current diff with per-metric tolerance bands.
//!
//! The bands are picked to catch *behaviorally meaningful* drift
//! without tripping on CI-runner variance:
//!
//! | metric                     | band         | rationale                                         |
//! |----------------------------|--------------|---------------------------------------------------|
//! | `symbol_count`             | exact        | off-by-one means an extractor changed behavior    |
//! | `files_indexed`            | exact        | a missed file = a filter or walker regression     |
//! | `cold_walk_ms`             | ±25 %        | cache-sensitive on cold runners                   |
//! | `memory_peak_rss_kb`       | ±15 %        | catches leaks; slack for jemalloc thermal noise   |
//! | `unresolved_refs_count`    | +10 %        | one-sided (skipped while not yet wired)           |
//! | `languages_indexed`        | exact set    | skipped while not yet wired through MCP           |
//! | `find_symbol_latency_p99`  | ±50 %        | skipped while not yet wired through MCP           |
//! | `grep_latency_p99`         | ±50 %        | skipped while not yet wired through MCP           |
//!
//! Any metric outside its band is a regression. The compare process
//! exits 1 with the diff written to stdout so the workflow run
//! surfaces it. Metrics that haven't shipped through the MCP wire
//! yet (latencies, language set, unresolved-ref count) skip cleanly
//! when both sides carry `None`; if a future baseline starts
//! recording them, the regression check picks up automatically.

use serde::{Deserialize, Serialize};

use super::{BenchReport, RepoMetrics};

/// Per-metric tolerance percentages. All bands are inclusive — a
/// metric exactly at the band edge passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TolerancePolicy {
    /// Cold-walk wall-clock band (±, percent). Default 25.
    pub cold_walk_pct: f64,
    /// Memory peak band (±, percent). Default 15.
    pub memory_peak_pct: f64,
    /// p99 latency band (±, percent). Applied to both find_symbol and grep. Default 50.
    pub latency_p99_pct: f64,
    /// One-sided unresolved-refs ceiling (+, percent). Default 10.
    pub unresolved_refs_ceiling_pct: f64,
}

impl Default for TolerancePolicy {
    fn default() -> Self {
        Self {
            cold_walk_pct: 25.0,
            memory_peak_pct: 15.0,
            latency_p99_pct: 50.0,
            unresolved_refs_ceiling_pct: 10.0,
        }
    }
}

/// Per-metric comparison row. `kind` is one of:
/// `pass | regression | new-repo | missing-repo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDiff {
    pub repo: String,
    pub metric: String,
    pub kind: String,
    pub baseline: serde_json::Value,
    pub current: serde_json::Value,
    /// Free-text explanation suitable for a workflow annotation.
    pub note: String,
}

/// Top-level compare output. The CI workflow reads `regressions`
/// length and exits accordingly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareReport {
    pub baseline_generated_at_unix_secs: u64,
    pub current_generated_at_unix_secs: u64,
    /// All rows, in stable repo+metric order. Includes passes; the
    /// nightly dashboard wants the full grid, not just the failures.
    pub rows: Vec<MetricDiff>,
    /// Convenience: just the rows where `kind != "pass"`. Length 0
    /// means the run passes.
    pub regressions: Vec<MetricDiff>,
}

/// Compute the full per-metric diff against a baseline.
pub fn compare(
    baseline: &BenchReport,
    current: &BenchReport,
    policy: &TolerancePolicy,
) -> CompareReport {
    let mut rows = Vec::new();
    let baseline_repos: std::collections::HashMap<&str, &RepoMetrics> = baseline
        .repos
        .iter()
        .map(|r| (r.name.as_str(), r))
        .collect();
    let current_repos: std::collections::HashMap<&str, &RepoMetrics> =
        current.repos.iter().map(|r| (r.name.as_str(), r)).collect();

    // Stable iteration order: baseline first (preserved order), then
    // any repo present in current that isn't in baseline.
    let mut names: Vec<&str> = baseline.repos.iter().map(|r| r.name.as_str()).collect();
    for r in &current.repos {
        if !names.contains(&r.name.as_str()) {
            names.push(r.name.as_str());
        }
    }

    for name in names {
        match (baseline_repos.get(name), current_repos.get(name)) {
            (Some(b), Some(c)) => {
                rows.extend(compare_repo(b, c, policy));
            }
            (Some(b), None) => {
                rows.push(MetricDiff {
                    repo: name.to_string(),
                    metric: "presence".to_string(),
                    kind: "missing-repo".to_string(),
                    baseline: serde_json::json!({ "files_indexed": b.files_indexed }),
                    current: serde_json::Value::Null,
                    note: format!("repo `{name}` was in the baseline but not in the current run"),
                });
            }
            (None, Some(c)) => {
                rows.push(MetricDiff {
                    repo: name.to_string(),
                    metric: "presence".to_string(),
                    kind: "new-repo".to_string(),
                    baseline: serde_json::Value::Null,
                    current: serde_json::json!({ "files_indexed": c.files_indexed }),
                    note: format!(
                        "repo `{name}` was not in the baseline; regen baseline to capture it"
                    ),
                });
            }
            (None, None) => unreachable!(),
        }
    }

    let regressions: Vec<MetricDiff> = rows.iter().filter(|r| r.kind != "pass").cloned().collect();
    CompareReport {
        baseline_generated_at_unix_secs: baseline.generated_at_unix_secs,
        current_generated_at_unix_secs: current.generated_at_unix_secs,
        rows,
        regressions,
    }
}

/// Per-repo metric comparison. Emits one `MetricDiff` per checked
/// metric, even on pass — the dashboard wants the full grid.
fn compare_repo(
    baseline: &RepoMetrics,
    current: &RepoMetrics,
    policy: &TolerancePolicy,
) -> Vec<MetricDiff> {
    let mut out = Vec::new();

    // symbol_count: exact match. (Truncation flag is part of the
    // signal — a count of 4096 with truncated=true matches another
    // 4096+truncated=true, but a flip to truncated=false at the same
    // count is still a regression because the underlying total moved.)
    let baseline_sym = serde_json::json!({
        "value": baseline.symbol_count,
        "truncated": baseline.symbol_count_truncated,
    });
    let current_sym = serde_json::json!({
        "value": current.symbol_count,
        "truncated": current.symbol_count_truncated,
    });
    let sym_match = baseline.symbol_count == current.symbol_count
        && baseline.symbol_count_truncated == current.symbol_count_truncated;
    out.push(MetricDiff {
        repo: baseline.name.clone(),
        metric: "symbol_count".to_string(),
        kind: if sym_match { "pass" } else { "regression" }.to_string(),
        baseline: baseline_sym,
        current: current_sym,
        note: if sym_match {
            "exact match".to_string()
        } else {
            format!(
                "symbol_count moved {} → {} (truncated {} → {}); an extractor changed behavior",
                baseline.symbol_count,
                current.symbol_count,
                baseline.symbol_count_truncated,
                current.symbol_count_truncated
            )
        },
    });

    // files_indexed: exact match. A missed file is the same kind of
    // signal as a missed symbol — the workspace walker or filter
    // changed behavior.
    let files_match = baseline.files_indexed == current.files_indexed;
    out.push(MetricDiff {
        repo: baseline.name.clone(),
        metric: "files_indexed".to_string(),
        kind: if files_match { "pass" } else { "regression" }.to_string(),
        baseline: serde_json::json!(baseline.files_indexed),
        current: serde_json::json!(current.files_indexed),
        note: if files_match {
            "exact match".to_string()
        } else {
            format!(
                "files_indexed moved {} → {}; the walker/filter changed behavior",
                baseline.files_indexed, current.files_indexed,
            )
        },
    });

    // languages_indexed: exact set match (sorted before compare).
    // Skipped cleanly when either side is None — the metric isn't
    // wired through MCP yet (see RepoMetrics TODOs).
    if let (Some(b_langs_in), Some(c_langs_in)) =
        (&baseline.languages_indexed, &current.languages_indexed)
    {
        let mut b_langs = b_langs_in.clone();
        b_langs.sort();
        b_langs.dedup();
        let mut c_langs = c_langs_in.clone();
        c_langs.sort();
        c_langs.dedup();
        let langs_match = b_langs == c_langs;
        out.push(MetricDiff {
            repo: baseline.name.clone(),
            metric: "languages_indexed".to_string(),
            kind: if langs_match { "pass" } else { "regression" }.to_string(),
            baseline: serde_json::json!(b_langs),
            current: serde_json::json!(c_langs),
            note: if langs_match {
                "exact set match".to_string()
            } else {
                format!(
                    "languages_indexed set moved {:?} → {:?}; a language detection regressed",
                    b_langs, c_langs
                )
            },
        });
    }

    // cold_walk_ms: ±cold_walk_pct.
    out.push(check_band(
        &baseline.name,
        "cold_walk_ms",
        baseline.cold_walk_ms,
        current.cold_walk_ms,
        policy.cold_walk_pct,
    ));

    // memory_peak_rss_kb: ±memory_peak_pct.
    out.push(check_band(
        &baseline.name,
        "memory_peak_rss_kb",
        baseline.memory_peak_rss_kb,
        current.memory_peak_rss_kb,
        policy.memory_peak_pct,
    ));

    // find_symbol_p99 / grep_p99: ±latency_p99_pct. Both skipped
    // cleanly when None on either side (TODO(post-G) — not yet
    // wired through MCP).
    if let (Some(b), Some(c)) = (
        baseline.find_symbol_latency_p99_ms,
        current.find_symbol_latency_p99_ms,
    ) {
        out.push(check_band(
            &baseline.name,
            "find_symbol_latency_p99_ms",
            b,
            c,
            policy.latency_p99_pct,
        ));
    }
    if let (Some(b), Some(c)) = (baseline.grep_latency_p99_ms, current.grep_latency_p99_ms) {
        out.push(check_band(
            &baseline.name,
            "grep_latency_p99_ms",
            b,
            c,
            policy.latency_p99_pct,
        ));
    }

    // unresolved_refs_count: one-sided (current may not exceed
    // baseline + ceiling%). When the baseline doesn't have it, skip.
    if let (Some(b), Some(c)) = (
        baseline.unresolved_refs_count,
        current.unresolved_refs_count,
    ) {
        out.push(check_ceiling(
            &baseline.name,
            "unresolved_refs_count",
            b,
            c,
            policy.unresolved_refs_ceiling_pct,
        ));
    }

    out
}

/// Symmetric `±pct` band on `current` relative to `baseline`.
///
/// Edge cases:
/// - `baseline == 0`: any non-zero current is a regression. Without
///   this rule, a metric going 0 → 1 would pass at any band (0 × N
///   is still 0). Useful for catching e.g. "find_symbol p99 went
///   from 'never measured' to 'always slow'".
/// - both 0: pass.
fn check_band(repo: &str, metric: &str, baseline: u64, current: u64, pct: f64) -> MetricDiff {
    let kind = if baseline == 0 {
        if current == 0 { "pass" } else { "regression" }
    } else {
        let allowed = (baseline as f64) * (pct / 100.0);
        let delta = (current as f64 - baseline as f64).abs();
        if delta <= allowed + 1e-9 {
            "pass"
        } else {
            "regression"
        }
    };
    MetricDiff {
        repo: repo.to_string(),
        metric: metric.to_string(),
        kind: kind.to_string(),
        baseline: serde_json::json!(baseline),
        current: serde_json::json!(current),
        note: format!(
            "band: ±{pct:.0}% (baseline {baseline}, current {current}, \
             delta {} {})",
            (current as i128 - baseline as i128).abs(),
            if kind == "pass" {
                "within band"
            } else {
                "outside band"
            }
        ),
    }
}

/// One-sided ceiling: `current <= baseline * (1 + pct/100)`.
fn check_ceiling(repo: &str, metric: &str, baseline: u64, current: u64, pct: f64) -> MetricDiff {
    let kind = if baseline == 0 {
        if current == 0 { "pass" } else { "regression" }
    } else {
        let ceiling = (baseline as f64) * (1.0 + pct / 100.0);
        if (current as f64) <= ceiling + 1e-9 {
            "pass"
        } else {
            "regression"
        }
    };
    MetricDiff {
        repo: repo.to_string(),
        metric: metric.to_string(),
        kind: kind.to_string(),
        baseline: serde_json::json!(baseline),
        current: serde_json::json!(current),
        note: format!("ceiling: +{pct:.0}% (baseline {baseline}, current {current})"),
    }
}

/// Render a human-readable summary of a `CompareReport`. Used by the
/// CLI when `--report text` is selected and by `pretty_regression_lines`
/// in workflow annotations.
pub fn render_compare_text(report: &CompareReport) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "compare: {} rows total, {} regressions",
        report.rows.len(),
        report.regressions.len()
    );
    for r in &report.rows {
        let mark = match r.kind.as_str() {
            "pass" => " ok ",
            "regression" => "FAIL",
            "new-repo" => "NEW ",
            "missing-repo" => "MISS",
            _ => "????",
        };
        let _ = writeln!(s, "  [{mark}] {}::{} — {}", r.repo, r.metric, r.note);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metric(name: &str) -> RepoMetrics {
        RepoMetrics {
            name: name.to_string(),
            git_ref: "v1".to_string(),
            files_indexed: 100,
            cold_walk_ms: 1000,
            symbol_count: 500,
            symbol_count_truncated: false,
            memory_peak_rss_kb: 50_000,
            unresolved_refs_count: Some(10),
            languages_indexed: Some(vec!["rust".into()]),
            find_symbol_latency_p50_ms: Some(2),
            find_symbol_latency_p99_ms: Some(10),
            grep_latency_p50_ms: Some(5),
            grep_latency_p99_ms: Some(20),
        }
    }

    fn report_with(repos: Vec<RepoMetrics>) -> BenchReport {
        BenchReport {
            version: 1,
            rts_bench_version: "0.0.0-test".into(),
            generated_at_unix_secs: 0,
            repos,
        }
    }

    #[test]
    fn identical_reports_have_zero_regressions() {
        let b = report_with(vec![sample_metric("tokio")]);
        let c = report_with(vec![sample_metric("tokio")]);
        let d = compare(&b, &c, &TolerancePolicy::default());
        assert!(
            d.regressions.is_empty(),
            "identical reports should not regress: {:#?}",
            d.regressions
        );
    }

    #[test]
    fn symbol_count_off_by_one_is_a_regression() {
        let b = report_with(vec![sample_metric("tokio")]);
        let mut current = sample_metric("tokio");
        current.symbol_count = 501;
        let c = report_with(vec![current]);
        let d = compare(&b, &c, &TolerancePolicy::default());
        let sym_row = d
            .rows
            .iter()
            .find(|r| r.metric == "symbol_count")
            .expect("symbol_count row");
        assert_eq!(sym_row.kind, "regression");
        assert!(
            d.regressions.iter().any(|r| r.metric == "symbol_count"),
            "off-by-one should fail symbol_count: {:#?}",
            d.regressions
        );
    }

    #[test]
    fn cold_walk_within_band_passes() {
        let b = report_with(vec![sample_metric("tokio")]);
        let mut current = sample_metric("tokio");
        current.cold_walk_ms = 1240; // +24% < 25% band
        let c = report_with(vec![current]);
        let d = compare(&b, &c, &TolerancePolicy::default());
        let row = d
            .rows
            .iter()
            .find(|r| r.metric == "cold_walk_ms")
            .expect("cold_walk_ms row");
        assert_eq!(row.kind, "pass", "+24% should be inside ±25%: {row:?}");
    }

    #[test]
    fn cold_walk_outside_band_regresses() {
        let b = report_with(vec![sample_metric("tokio")]);
        let mut current = sample_metric("tokio");
        current.cold_walk_ms = 1300; // +30% > 25% band
        let c = report_with(vec![current]);
        let d = compare(&b, &c, &TolerancePolicy::default());
        assert!(
            d.regressions
                .iter()
                .any(|r| r.metric == "cold_walk_ms" && r.kind == "regression"),
            "+30% should fail ±25% band: {:#?}",
            d.regressions
        );
    }

    #[test]
    fn languages_set_drift_regresses() {
        let b = report_with(vec![sample_metric("tokio")]);
        let mut current = sample_metric("tokio");
        current.languages_indexed = Some(vec!["rust".into(), "markdown".into()]);
        let c = report_with(vec![current]);
        let d = compare(&b, &c, &TolerancePolicy::default());
        let row = d
            .rows
            .iter()
            .find(|r| r.metric == "languages_indexed")
            .expect("languages row");
        assert_eq!(row.kind, "regression");
    }

    #[test]
    fn languages_skipped_when_both_none() {
        let mut b = sample_metric("tokio");
        b.languages_indexed = None;
        let mut c = sample_metric("tokio");
        c.languages_indexed = None;
        let d = compare(
            &report_with(vec![b]),
            &report_with(vec![c]),
            &TolerancePolicy::default(),
        );
        assert!(
            !d.rows.iter().any(|r| r.metric == "languages_indexed"),
            "languages row should be omitted when both None: {:#?}",
            d.rows
        );
    }

    #[test]
    fn unresolved_refs_below_ceiling_passes() {
        let b = report_with(vec![sample_metric("tokio")]);
        let mut current = sample_metric("tokio");
        current.unresolved_refs_count = Some(11); // +10% (allowed)
        let c = report_with(vec![current]);
        let d = compare(&b, &c, &TolerancePolicy::default());
        let row = d
            .rows
            .iter()
            .find(|r| r.metric == "unresolved_refs_count")
            .expect("row");
        assert_eq!(row.kind, "pass", "+10% should be inside ceiling: {row:?}");
    }

    #[test]
    fn unresolved_refs_above_ceiling_regresses() {
        let b = report_with(vec![sample_metric("tokio")]);
        let mut current = sample_metric("tokio");
        current.unresolved_refs_count = Some(15); // +50%
        let c = report_with(vec![current]);
        let d = compare(&b, &c, &TolerancePolicy::default());
        assert!(
            d.regressions
                .iter()
                .any(|r| r.metric == "unresolved_refs_count" && r.kind == "regression"),
        );
    }

    #[test]
    fn missing_repo_in_current_regresses() {
        let b = report_with(vec![sample_metric("tokio"), sample_metric("flask")]);
        let c = report_with(vec![sample_metric("tokio")]);
        let d = compare(&b, &c, &TolerancePolicy::default());
        assert!(
            d.regressions
                .iter()
                .any(|r| r.repo == "flask" && r.kind == "missing-repo"),
            "missing-repo should regress: {:#?}",
            d.regressions
        );
    }

    #[test]
    fn new_repo_in_current_surfaces() {
        let b = report_with(vec![sample_metric("tokio")]);
        let c = report_with(vec![sample_metric("tokio"), sample_metric("flask")]);
        let d = compare(&b, &c, &TolerancePolicy::default());
        let new_row = d
            .rows
            .iter()
            .find(|r| r.repo == "flask")
            .expect("flask row");
        assert_eq!(new_row.kind, "new-repo");
    }

    #[test]
    fn baseline_zero_with_nonzero_current_regresses() {
        // Use cold_walk_ms because it's an always-present scalar
        // (the latency fields are Option<u64> now). The 0→nonzero
        // semantics are identical between cold_walk and latencies —
        // see `check_band` for the rule.
        let mut baseline_repo = sample_metric("tokio");
        baseline_repo.cold_walk_ms = 0;
        let mut current_repo = sample_metric("tokio");
        current_repo.cold_walk_ms = 5;
        let d = compare(
            &report_with(vec![baseline_repo]),
            &report_with(vec![current_repo]),
            &TolerancePolicy::default(),
        );
        assert!(
            d.regressions
                .iter()
                .any(|r| r.metric == "cold_walk_ms" && r.kind == "regression"),
            "0 → nonzero should regress: {:#?}",
            d.regressions
        );
    }

    #[test]
    fn baseline_zero_with_zero_current_passes() {
        let mut baseline_repo = sample_metric("tokio");
        baseline_repo.cold_walk_ms = 0;
        let mut current_repo = sample_metric("tokio");
        current_repo.cold_walk_ms = 0;
        let d = compare(
            &report_with(vec![baseline_repo]),
            &report_with(vec![current_repo]),
            &TolerancePolicy::default(),
        );
        assert!(
            !d.regressions.iter().any(|r| r.metric == "cold_walk_ms"),
            "0 → 0 should pass: {:#?}",
            d.regressions
        );
    }
}
