//! `mcp_registration` section — dispatches to per-host detectors and
//! aggregates their results. Cross-host policies (e.g. Claude Code
//! multi-scope version drift) computed here on the union of host
//! findings. U7 implements.

use super::ctx::Ctx;
use super::report::{Row, SectionReport};

pub fn run(_ctx: &Ctx) -> SectionReport {
    let mut s = SectionReport::new("mcp_registration");
    s.push(Row::info(
        "mcp_registration:placeholder",
        "mcp_registration section not yet implemented",
    ));
    s
}
