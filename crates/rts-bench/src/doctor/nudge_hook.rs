//! `hook` section — `.claude/hooks/rts-nudge.sh` presence,
//! executability, version-marker match. U8 implements.

use super::ctx::Ctx;
use super::report::{Row, SectionReport};

pub fn run(_ctx: &Ctx) -> SectionReport {
    let mut s = SectionReport::new("hook");
    s.push(Row::info(
        "hook:placeholder",
        "hook section not yet implemented",
    ));
    s
}
