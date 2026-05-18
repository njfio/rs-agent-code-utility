//! Claude Code MCP-registration detector. Hard-detect.
//!
//! Scopes (per `docs/install.md`):
//! - user scope: `~/.claude.json`
//! - project scope: `<workspace>/.mcp.json`
//! - settings.json hook block: `<workspace>/.claude/settings.json`
//!
//! U7 implements. Multi-scope drift (user + project register
//! different binaries) is the load-bearing foot-gun this detector
//! catches.

use crate::doctor::ctx::Ctx;
use super::{DetectionClass, HostDetector, HostFinding};

pub struct ClaudeCode;

impl HostDetector for ClaudeCode {
    fn host_name(&self) -> &'static str {
        "claude_code"
    }
    fn detection_class(&self) -> DetectionClass {
        DetectionClass::Hard
    }
    fn detect(&self, _ctx: &Ctx) -> HostFinding {
        HostFinding::skipped(
            self.host_name(),
            self.detection_class(),
            "not yet implemented (U7)",
        )
    }
}
