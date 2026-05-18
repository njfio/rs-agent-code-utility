//! Aider MCP-registration detector. Soft-detect at
//! `~/.config/aider/mcp.json`, `./.aider/mcp.json`, or
//! `~/.aider.conf.yml`. U7 implements.

use crate::doctor::ctx::Ctx;
use super::{DetectionClass, HostDetector, HostFinding};

pub struct Aider;

impl HostDetector for Aider {
    fn host_name(&self) -> &'static str {
        "aider"
    }
    fn detection_class(&self) -> DetectionClass {
        DetectionClass::Soft
    }
    fn detect(&self, _ctx: &Ctx) -> HostFinding {
        HostFinding::skipped(
            self.host_name(),
            self.detection_class(),
            "not yet implemented (U7)",
        )
    }
}
