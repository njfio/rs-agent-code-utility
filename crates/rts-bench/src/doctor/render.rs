//! Output rendering for `rts-bench doctor`. Two modes, both stable for
//! snapshot testing: `render_human` (default — checklist + inline fix
//! snippets, ANSI gated by TTY + `NO_COLOR`) and `render_json` (the
//! `doctor-v0` schema for agent consumption).
//!
//! U3 owns this surface. The implementation is intentionally
//! dependency-light (no `anstream` indirection — we just write the
//! escape codes directly when color is enabled) so the binary's
//! transitive-dep tree stays compact.

use std::io::Write;

use super::report::{DoctorReport, RowKind, SectionReport};

// ANSI escape codes. We emit these verbatim when color_enabled is
// true; otherwise the rows render as plain ASCII with `[OK]` /
// `[WARN]` / `[FAIL]` / `[?]` prefixes.
const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

/// Render the report as a human-readable checklist with inline fix
/// snippets. Section ordering is normative (see `report::SECTION_NAMES`).
///
/// `color` controls ANSI: callers pass `true` when stdout is a TTY,
/// `--no-color` is unset, and `NO_COLOR` is unset.
pub fn render_human<W: Write>(report: &DoctorReport, w: &mut W, color: bool) {
    // Header. Doctor binary version + schema version. No wall-clock
    // timestamps — these would flake snapshot tests.
    let _ = writeln!(
        w,
        "{bold}rts-bench doctor{reset} {dim}(schema={schema}){reset}",
        bold = if color { BOLD } else { "" },
        reset = if color { RESET } else { "" },
        dim = if color { DIM } else { "" },
        schema = report.schema_version,
    );
    let _ = writeln!(w);

    // Self-error: short-circuit before walking sections.
    if let Some(err) = &report.error {
        let _ = writeln!(
            w,
            "{red}[SELF-ERROR]{reset} {err}",
            red = if color { RED } else { "" },
            reset = if color { RESET } else { "" },
        );
        return;
    }

    // Sections in normative order.
    for section in &report.sections {
        render_section_human(section, w, color);
    }

    // Footer: exit class summary.
    let _ = writeln!(w);
    let class_str = match report.exit_class {
        super::report::ExitClass::Ok => "ok",
        super::report::ExitClass::Warn => "warn",
        super::report::ExitClass::Fail => "fail",
        super::report::ExitClass::SelfError => "self_error",
    };
    let class_color = match report.exit_class {
        super::report::ExitClass::Ok => GREEN,
        super::report::ExitClass::Warn => YELLOW,
        super::report::ExitClass::Fail | super::report::ExitClass::SelfError => RED,
    };
    let _ = writeln!(
        w,
        "{dim}exit class:{reset} {c}{class}{reset}",
        dim = if color { DIM } else { "" },
        c = if color { class_color } else { "" },
        reset = if color { RESET } else { "" },
        class = class_str,
    );
}

fn render_section_human<W: Write>(section: &SectionReport, w: &mut W, color: bool) {
    let bold = if color { BOLD } else { "" };
    let reset = if color { RESET } else { "" };
    let dim = if color { DIM } else { "" };
    let cyan = if color { CYAN } else { "" };
    let _ = writeln!(w, "{cyan}{bold}== {name} =={reset}", name = section.name);
    if section.rows.is_empty() && section.partial_failures.is_empty() {
        let _ = writeln!(w, "  {dim}(no checks){reset}");
    }
    for row in &section.rows {
        let (tag, tag_color) = match row.kind {
            RowKind::Ok => ("[OK]  ", GREEN),
            RowKind::Warn => ("[WARN]", YELLOW),
            RowKind::Fail => ("[FAIL]", RED),
            RowKind::Info => ("[?]   ", CYAN),
        };
        let c = if color { tag_color } else { "" };
        let _ = writeln!(
            w,
            "  {c}{tag}{reset} {label} — {msg}",
            label = row.label,
            msg = row.message,
        );
        if let Some(fix) = &row.fix {
            let _ = writeln!(w, "    → {cmd}", cmd = fix.command);
            if let Some(desc) = &fix.description {
                let _ = writeln!(w, "      {dim}{desc}{reset}");
            }
        }
    }
    for pf in &section.partial_failures {
        let _ = writeln!(
            w,
            "  {dim}(partial: {label} — {msg}){reset}",
            label = pf.label,
            msg = pf.message,
        );
    }
    let _ = writeln!(w);
}

/// Render the report as JSON (`doctor-v0`). Pretty-printed for
/// readability; agents that need to consume programmatically should
/// parse the JSON tree, not rely on field ordering.
pub fn render_json<W: Write>(report: &DoctorReport, w: &mut W) {
    // serde_json::to_writer_pretty is infallible on a struct that
    // derives Serialize cleanly; the only real failure mode is
    // stdout closure, which we can't recover from anyway.
    let _ = serde_json::to_writer_pretty(&mut *w, report);
    let _ = writeln!(w);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::report::{FixClass, FixSnippet, Row, SectionReport};

    fn sample_report() -> DoctorReport {
        let mut binary = SectionReport::new("binary");
        binary.push(Row::ok("binary:on_path", "rts-daemon at /usr/local/bin/rts-daemon"));
        let mut daemon = SectionReport::new("daemon");
        daemon.push(
            Row::warn("daemon:not_running", "no daemon socket for this workspace")
                .with_fix(
                    FixSnippet::new(FixClass::StartDaemon, "rts-daemon --workspace $PWD &"),
                ),
        );
        DoctorReport::from_sections(vec![binary, daemon])
    }

    #[test]
    fn human_render_is_stable_without_ansi() {
        let r = sample_report();
        let mut buf = Vec::new();
        render_human(&r, &mut buf, false);
        let s = String::from_utf8(buf).unwrap();
        // Snapshot-stable: no wall-clock timestamps, no ANSI codes.
        assert!(s.contains("rts-bench doctor"));
        assert!(s.contains("== binary =="));
        assert!(s.contains("[OK]"));
        assert!(s.contains("== daemon =="));
        assert!(s.contains("[WARN]"));
        assert!(s.contains("rts-daemon --workspace $PWD &"));
        assert!(s.contains("exit class: warn"));
        // No ESC sequences in no-color mode.
        assert!(!s.contains('\x1b'));
    }

    #[test]
    fn human_render_emits_ansi_when_enabled() {
        let r = sample_report();
        let mut buf = Vec::new();
        render_human(&r, &mut buf, true);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains('\x1b'), "ANSI escape codes should appear in color mode");
    }

    #[test]
    fn json_render_uses_doctor_v0_schema() {
        let r = sample_report();
        let mut buf = Vec::new();
        render_json(&r, &mut buf);
        let s = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["schema_version"], "doctor-v0");
        assert_eq!(parsed["exit_class"], "warn");
        assert!(parsed["capabilities"].is_array());
        assert_eq!(parsed["sections"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn json_render_handles_self_error() {
        let r = DoctorReport::self_error("oh no");
        let mut buf = Vec::new();
        render_json(&r, &mut buf);
        let s = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["exit_class"], "self_error");
        assert_eq!(parsed["error"], "oh no");
    }
}
