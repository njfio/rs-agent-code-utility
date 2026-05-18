//! Continue MCP-registration detector. Hard-detect at
//! `~/.continue/config.yaml` or `<workspace>/.continue/config.yaml`
//! (YAML, per `docs/install.md`). U7 implements.

use crate::doctor::ctx::Ctx;
use super::{DetectionClass, HostDetector, HostFinding};

pub struct Continue;

impl HostDetector for Continue {
    fn host_name(&self) -> &'static str {
        "continue"
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
