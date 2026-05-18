//! Cline MCP-registration detector. Soft-detect via VS Code extension
//! settings (path varies by OS). U7 implements.

use crate::doctor::ctx::Ctx;
use super::{DetectionClass, HostDetector, HostFinding};

pub struct Cline;

impl HostDetector for Cline {
    fn host_name(&self) -> &'static str {
        "cline"
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
