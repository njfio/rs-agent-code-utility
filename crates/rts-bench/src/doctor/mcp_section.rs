//! `mcp_registration` section — dispatches to per-host detectors and
//! aggregates their results. Cross-host policies (Claude Code multi-scope
//! version drift) are computed here on the union of host findings.
//!
//! Each detector runs sequentially; per-host work is dominated by
//! filesystem reads of small JSON/YAML files, so the savings from
//! threading would not be observable inside doctor's <500 ms budget.

use super::ctx::Ctx;
use super::hosts::{
    aider::Aider, claude_code::ClaudeCode, cline::Cline, continue_::Continue, cursor::Cursor,
    HostDetector, HostFinding,
};
use super::report::{Row, SectionReport};

pub fn run(ctx: &Ctx) -> SectionReport {
    let mut section = SectionReport::new("mcp_registration");

    // Detector order matches docs/install.md's wiring order: Claude
    // Code first (canonical), then Cursor / Cline / Aider / Continue.
    // Doctor's row stream is stable across runs because this list is.
    let detectors: [&dyn HostDetector; 5] = [
        &ClaudeCode,
        &Cursor,
        &Continue,
        &Aider,
        &Cline,
    ];

    let mut findings: Vec<HostFinding> = Vec::with_capacity(detectors.len());
    for d in detectors {
        let f = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| d.detect(ctx)))
            .unwrap_or_else(|_| {
                let mut hf = HostFinding {
                    host_name: d.host_name(),
                    detection_class: d.detection_class(),
                    rows: Vec::new(),
                    rts_registered: None,
                    skipped_reason: Some("detector panicked".to_string()),
                };
                hf.rows.push(Row::warn(
                    format!("{}:detect", d.host_name()),
                    "detector panicked; treating host as not installed",
                ));
                hf
            });
        findings.push(f);
    }

    // Cross-host policy: Claude Code multi-scope drift. If Claude Code
    // produced multiple OK / FAIL rows across distinct scopes that point
    // at different binary paths, surface a WARN row synthesizing the
    // drift. We read this off the row stream rather than carrying a
    // separate list, so the policy stays self-contained.
    if let Some(cc) = findings.iter().find(|f| f.host_name == "claude_code") {
        if let Some(drift_row) = claude_code_drift_row(cc) {
            section.push(drift_row);
        }
    }

    for f in findings {
        // Per-host skipped_reason surfaces as a partial-failure
        // annotation; doctor exit code stays unaffected.
        if let Some(reason) = &f.skipped_reason {
            section.push_partial_failure(format!("{}:skipped", f.host_name), reason);
            // For absent hard hosts the detector emits no rows; add a
            // single `[?]` info row so the user sees that we checked.
            // Soft hosts already emit their own `[?]` row.
            if f.rows.is_empty() {
                section.push(Row::info(
                    format!("{}:skipped", f.host_name),
                    format!("{} ({})", f.host_name, reason),
                ));
            }
        }
        for row in f.rows {
            section.push(row);
        }
    }

    section
}

/// Inspect a Claude Code finding for cross-scope binary drift. Returns
/// `Some(warn_row)` when ≥2 scopes register rts at distinct paths.
fn claude_code_drift_row(cc: &HostFinding) -> Option<Row> {
    use std::collections::BTreeSet;

    // Collect distinct binary paths mentioned in successful (OK or FAIL)
    // scope rows. The detector only carries the *first* registration in
    // `rts_registered`, so we parse the row messages here. Since the
    // detector's message format is stable (`"rts registered (PATH) ..."`),
    // a tiny prefix match is enough.
    let mut paths: BTreeSet<String> = BTreeSet::new();
    for row in &cc.rows {
        if !row.label.starts_with("claude_code:") {
            continue;
        }
        if let Some(start) = row.message.find("rts registered (") {
            let rest = &row.message[start + "rts registered (".len()..];
            if let Some(end) = rest.find(')') {
                paths.insert(rest[..end].to_string());
            }
        } else if let Some(idx) = row.message.find("but binary ") {
            // FAIL form: "rts registered in CONFIG but binary BIN not found"
            let rest = &row.message[idx + "but binary ".len()..];
            if let Some(end) = rest.find(' ') {
                paths.insert(rest[..end].to_string());
            }
        }
    }
    if paths.len() >= 2 {
        let joined = paths
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        Some(Row::warn(
            "claude_code:multi_scope_drift",
            format!(
                "Claude Code registers rts at multiple distinct binaries across scopes: {}",
                joined
            ),
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::report::RowKind;
    use crate::doctor::{DoctorArgs, DoctorOutput};

    fn mk_ctx() -> Ctx {
        Ctx::build(&DoctorArgs {
            output: DoctorOutput::Json,
            no_color: true,
            workspace: None,
        })
        .unwrap()
    }

    #[test]
    fn section_runs_all_five_detectors() {
        // Without a tempdir fixture set, all detectors should still
        // run without panicking and produce a SectionReport.
        let ctx = mk_ctx();
        let s = run(&ctx);
        assert_eq!(s.name, "mcp_registration");
        // Soft hosts (Aider, Cline) emit at least an info row each
        // even on a bare system, so the section is non-empty.
        assert!(!s.rows.is_empty(), "expected at least soft-host rows");
    }

    #[test]
    fn drift_row_emitted_for_multi_scope_finding() {
        // Build a synthetic Claude Code HostFinding with two scope rows
        // pointing at different binaries.
        let mut cc = HostFinding {
            host_name: "claude_code",
            detection_class: crate::doctor::hosts::DetectionClass::Hard,
            rows: Vec::new(),
            rts_registered: None,
            skipped_reason: None,
        };
        cc.rows.push(Row::ok(
            "claude_code:user_scope",
            "rts registered (/opt/a/rts-mcp) via /home/u/.claude.json",
        ));
        cc.rows.push(Row::ok(
            "claude_code:project_scope",
            "rts registered (/opt/b/rts-mcp) via /ws/.mcp.json",
        ));
        let drift = claude_code_drift_row(&cc).expect("drift detected");
        assert_eq!(drift.kind, RowKind::Warn);
        assert_eq!(drift.label, "claude_code:multi_scope_drift");
        assert!(drift.message.contains("/opt/a/rts-mcp"));
        assert!(drift.message.contains("/opt/b/rts-mcp"));
    }

    #[test]
    fn no_drift_when_single_scope() {
        let mut cc = HostFinding {
            host_name: "claude_code",
            detection_class: crate::doctor::hosts::DetectionClass::Hard,
            rows: Vec::new(),
            rts_registered: None,
            skipped_reason: None,
        };
        cc.rows.push(Row::ok(
            "claude_code:user_scope",
            "rts registered (/opt/a/rts-mcp) via ~/.claude.json",
        ));
        assert!(claude_code_drift_row(&cc).is_none());
    }

    #[test]
    fn no_drift_when_same_binary_in_two_scopes() {
        let mut cc = HostFinding {
            host_name: "claude_code",
            detection_class: crate::doctor::hosts::DetectionClass::Hard,
            rows: Vec::new(),
            rts_registered: None,
            skipped_reason: None,
        };
        cc.rows.push(Row::ok(
            "claude_code:user_scope",
            "rts registered (/opt/a/rts-mcp) via ~/.claude.json",
        ));
        cc.rows.push(Row::ok(
            "claude_code:project_scope",
            "rts registered (/opt/a/rts-mcp) via /ws/.mcp.json",
        ));
        assert!(claude_code_drift_row(&cc).is_none());
    }
}
