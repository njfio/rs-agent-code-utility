//! Per-host MCP-registration detectors. U7 wires the dispatcher and
//! per-host implementations; this file defines the shared trait so
//! sub-agents can implement hosts independently against a stable
//! interface.

use std::path::PathBuf;

use crate::doctor::ctx::Ctx;
use crate::doctor::report::Row;

pub mod aider;
pub mod claude_code;
pub mod cline;
pub mod continue_;
pub mod cursor;

/// Detection class for each host. Hard hosts have canonical config-file
/// paths; soft hosts use best-effort discovery (file existence,
/// CLI-flag scan, VS Code extension state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetectionClass {
    Hard,
    Soft,
}

/// One host's discovery result. The host implementer collects rows
/// (per-scope OK/WARN/FAIL findings) plus an optional registration
/// detail used by the orchestrator's cross-host policies (e.g.
/// "Claude Code's user-scope and project-scope point at different
/// rts binaries").
#[derive(Clone, Debug)]
pub struct HostFinding {
    pub host_name: &'static str,
    pub detection_class: DetectionClass,
    pub rows: Vec<Row>,
    /// Populated when an rts MCP entry was found. None when not
    /// installed or undetected. Multi-scope hosts (Claude Code) may
    /// have multiple entries; in that case `rts_registered` carries
    /// the first one and per-scope rows enumerate the rest.
    pub rts_registered: Option<RegistrationDetail>,
    /// Set when discovery aborted with a recoverable reason
    /// ("permission denied", "not installed"). The orchestrator
    /// surfaces these as partial-failures on the parent section.
    pub skipped_reason: Option<String>,
}

impl HostFinding {
    pub fn skipped(name: &'static str, class: DetectionClass, reason: impl Into<String>) -> Self {
        Self {
            host_name: name,
            detection_class: class,
            rows: Vec::new(),
            rts_registered: None,
            skipped_reason: Some(reason.into()),
        }
    }
}

/// Where rts was found, and at what version/binary path. Used by
/// the orchestrator to detect cross-scope version drift.
#[derive(Clone, Debug)]
pub struct RegistrationDetail {
    /// e.g. `"user_scope"`, `"project_scope"`, `"vs_code_extension"`.
    pub scope: String,
    /// The MCP `command` value, typically an absolute path to a
    /// `rts-mcp` binary (or a `cargo run` invocation).
    pub binary_path: Option<PathBuf>,
    /// Path to the host's config file that declared the registration.
    pub config_path: PathBuf,
}

/// Host detector contract. Each implementation reads its host's
/// canonical config path(s), returns a `HostFinding`. Implementations
/// must NOT panic on malformed input; surface parse errors as
/// `skipped_reason` or as WARN rows.
pub trait HostDetector {
    fn host_name(&self) -> &'static str;
    fn detection_class(&self) -> DetectionClass;
    fn detect(&self, ctx: &Ctx) -> HostFinding;
}
