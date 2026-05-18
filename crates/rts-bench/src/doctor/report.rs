//! Doctor report types — rows, sections, fix snippets, and the final
//! aggregated `DoctorReport` (human + JSON renderable).
//!
//! Schema version (locked at v1 of the doctor surface):
//!
//! - `schema_version: "doctor-v0"`
//! - `capabilities: [<additive capability strings>]`
//!
//! Future additive fields advertise via new capability strings, never
//! a schema_version bump. See `docs/doctor-schema.md` (U10) for the
//! full wire contract.

use serde::Serialize;

/// Doctor schema version. Locked at v1.
pub const SCHEMA_VERSION: &str = "doctor-v0";

/// Additive capability strings advertised by this doctor binary. Each
/// new capability is an additive feature that consumers can branch on.
/// Schema version bumps are reserved for breaking-shape changes.
pub const CAPABILITIES: &[&str] = &[
    // Initial release. Future additive capabilities (e.g. cross-version
    // drift detection, --fix mode) extend this list.
    "sections_v0",
    "fix_snippets",
    "host_detection_5x", // Claude Code, Cursor, Continue, Aider, Cline
];

/// Per-row severity. Rendering uses these as `[OK]` / `[WARN]` /
/// `[FAIL]` / `[?]` prefixes in human mode; `kind` in JSON mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RowKind {
    /// Healthy state; nothing to do.
    Ok,
    /// Non-fatal anomaly; exit code stays 0 unless a peer row is FAIL.
    Warn,
    /// Fatal anomaly; exit code goes to 1.
    Fail,
    /// Soft-detect result; "we looked but couldn't determine."
    /// Renders as `[?]`. Never affects exit code on its own.
    Info,
}

impl RowKind {
    /// Wire-stable label, used in both human and JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            RowKind::Ok => "ok",
            RowKind::Warn => "warn",
            RowKind::Fail => "fail",
            RowKind::Info => "info",
        }
    }
}

/// One observable signal in a section's report. The `label` is the
/// row's stable identifier (e.g. `claude_code:user_scope`,
/// `daemon:reachable`); the `message` is the freeform human-readable
/// summary; the `fix` is optional and only set on WARN / FAIL rows
/// when doctor has a copy-pasteable recovery action.
#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub kind: RowKind,
    pub label: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<FixSnippet>,
}

impl Row {
    pub fn ok(label: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: RowKind::Ok,
            label: label.into(),
            message: message.into(),
            fix: None,
        }
    }
    pub fn warn(label: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: RowKind::Warn,
            label: label.into(),
            message: message.into(),
            fix: None,
        }
    }
    pub fn fail(label: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: RowKind::Fail,
            label: label.into(),
            message: message.into(),
            fix: None,
        }
    }
    pub fn info(label: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: RowKind::Info,
            label: label.into(),
            message: message.into(),
            fix: None,
        }
    }
    pub fn with_fix(mut self, fix: FixSnippet) -> Self {
        self.fix = Some(fix);
        self
    }
}

/// A copy-pasteable one-line fix attached to a WARN or FAIL row. U9
/// plumbs every section's WARN/FAIL paths through `FixClass` so the
/// taxonomy stays closed; ad-hoc strings are discouraged.
#[derive(Clone, Debug, Serialize)]
pub struct FixSnippet {
    pub class: FixClass,
    /// Shell command the user can paste verbatim. Should be a single
    /// line. Multi-step fixes use `description` to explain context.
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl FixSnippet {
    pub fn new(class: FixClass, command: impl Into<String>) -> Self {
        Self {
            class,
            command: command.into(),
            description: None,
        }
    }
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// Closed taxonomy of fix actions. U9 may extend; do not add ad-hoc
/// variants in section files — open a PR against this enum first so
/// the docs in `docs/doctor-schema.md` stay current.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixClass {
    /// rts binary missing from PATH or version mismatched.
    InstallBinary,
    /// Daemon not running for this workspace; user should start it.
    StartDaemon,
    /// Stale socket file with no live daemon behind it.
    RemoveStaleSocket,
    /// rts not registered with the named agent host's MCP config.
    RegisterMcp,
    /// MCP config references a binary path that doesn't exist or isn't
    /// executable.
    FixMcpBinaryPath,
    /// PreToolUse hook file present but not executable.
    MakeHookExecutable,
    /// Hook file content marker is out of date vs doctor's version.
    UpdateHook,
    /// Daemon pinned to a different workspace than `$PWD`.
    MoveWorkspace,
    /// Index is empty or stale; trigger a re-index.
    ReindexNeeded,
    /// Host config file present but unparseable (JSON/YAML syntax).
    FixConfigSyntax,
}

/// All section names in their normative render order. Sections are
/// emitted in this order in both human and JSON output, so snapshot
/// tests stay stable regardless of section impl ordering inside
/// `mod.rs::run`.
pub const SECTION_NAMES: &[&str] = &[
    "binary",
    "daemon",
    "mcp_registration",
    "hook",
    "workspace_index",
];

/// One section's collected rows plus any partial-failure annotations.
/// Sections that hit a recoverable parse/config error annotate the
/// failure here without aborting the run (and without producing a
/// FAIL row when the failure was on a *peer* tool's surface — e.g.,
/// "Aider config is malformed YAML" is doctor's concern but should
/// not fail doctor's exit code).
#[derive(Clone, Debug, Serialize)]
pub struct SectionReport {
    pub name: &'static str,
    pub rows: Vec<Row>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub partial_failures: Vec<PartialFailure>,
}

impl SectionReport {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            rows: Vec::new(),
            partial_failures: Vec::new(),
        }
    }
    pub fn push(&mut self, row: Row) {
        self.rows.push(row);
    }
    pub fn push_partial_failure(&mut self, label: impl Into<String>, message: impl Into<String>) {
        self.partial_failures.push(PartialFailure {
            label: label.into(),
            message: message.into(),
        });
    }
    pub fn max_kind(&self) -> RowKind {
        self.rows
            .iter()
            .map(|r| r.kind)
            .fold(RowKind::Ok, |acc, k| match (acc, k) {
                (RowKind::Fail, _) | (_, RowKind::Fail) => RowKind::Fail,
                (RowKind::Warn, _) | (_, RowKind::Warn) => RowKind::Warn,
                (RowKind::Info, _) | (_, RowKind::Info) => RowKind::Info,
                _ => RowKind::Ok,
            })
    }
}

/// Annotation for recoverable errors during a section run (e.g. one
/// host's YAML couldn't be parsed). Renders as a footnote-style line
/// under the section header.
#[derive(Clone, Debug, Serialize)]
pub struct PartialFailure {
    pub label: String,
    pub message: String,
}

/// Aggregate exit-class for the whole run, mapping to the documented
/// exit-code contract: ok/warn → 0, fail → 1, self_error → 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitClass {
    Ok,
    Warn,
    Fail,
    /// Doctor panicked or its own I/O failed. Exit 2.
    SelfError,
}

/// Final aggregated report — the top-level JSON envelope and the
/// in-memory structure the human renderer walks.
#[derive(Clone, Debug, Serialize)]
pub struct DoctorReport {
    pub schema_version: &'static str,
    pub capabilities: &'static [&'static str],
    pub sections: Vec<SectionReport>,
    pub exit_class: ExitClass,
    /// Set only on self-error (exit 2). Carries a freeform message
    /// describing what went wrong inside doctor itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl DoctorReport {
    /// Build a report from the dispatched section results. Computes
    /// `exit_class` by max-severity-row across all sections.
    pub fn from_sections(sections: Vec<SectionReport>) -> Self {
        let mut max = RowKind::Ok;
        for s in &sections {
            let k = s.max_kind();
            max = match (max, k) {
                (RowKind::Fail, _) | (_, RowKind::Fail) => RowKind::Fail,
                (RowKind::Warn, _) | (_, RowKind::Warn) => RowKind::Warn,
                _ => RowKind::Ok,
            };
        }
        let exit_class = match max {
            RowKind::Fail => ExitClass::Fail,
            RowKind::Warn => ExitClass::Warn,
            _ => ExitClass::Ok,
        };
        Self {
            schema_version: SCHEMA_VERSION,
            capabilities: CAPABILITIES,
            sections,
            exit_class,
            error: None,
        }
    }

    /// Self-error envelope. Used when doctor itself panicked or
    /// failed to initialize its context. Sections list is empty;
    /// the JSON shape stays parseable.
    pub fn self_error(message: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            capabilities: CAPABILITIES,
            sections: Vec::new(),
            exit_class: ExitClass::SelfError,
            error: Some(message.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report_is_ok() {
        let r = DoctorReport::from_sections(vec![]);
        assert_eq!(r.exit_class, ExitClass::Ok);
        assert_eq!(r.schema_version, "doctor-v0");
    }

    #[test]
    fn warn_row_yields_warn_exit_class() {
        let mut s = SectionReport::new("binary");
        s.push(Row::warn("binary:version", "version drift detected"));
        let r = DoctorReport::from_sections(vec![s]);
        assert_eq!(r.exit_class, ExitClass::Warn);
    }

    #[test]
    fn any_fail_row_yields_fail_exit_class() {
        let mut s1 = SectionReport::new("binary");
        s1.push(Row::ok("binary:on_path", "ok"));
        let mut s2 = SectionReport::new("daemon");
        s2.push(Row::fail("daemon:stale_socket", "stale socket file"));
        let r = DoctorReport::from_sections(vec![s1, s2]);
        assert_eq!(r.exit_class, ExitClass::Fail);
    }

    #[test]
    fn self_error_has_error_envelope() {
        let r = DoctorReport::self_error("panic inside daemon section");
        assert_eq!(r.exit_class, ExitClass::SelfError);
        assert_eq!(r.error.as_deref(), Some("panic inside daemon section"));
    }
}
