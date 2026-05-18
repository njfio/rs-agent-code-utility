//! Cursor MCP-registration detector. Hard-detect at `~/.cursor/mcp.json`
//! (per `docs/install.md`). U7 implements.

use crate::doctor::ctx::Ctx;
use super::{DetectionClass, HostDetector, HostFinding};

pub struct Cursor;

impl HostDetector for Cursor {
    fn host_name(&self) -> &'static str {
        "cursor"
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
