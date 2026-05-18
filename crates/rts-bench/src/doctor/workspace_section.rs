//! `workspace_index` section — per-workspace index health: pinned-path
//! match against `$PWD`, cold-walk completion, index generation, file
//! count. Reads `ctx.daemon_stats` populated by `daemon_section`. U6
//! implements.

use super::ctx::Ctx;
use super::report::{Row, SectionReport};

pub fn run(_ctx: &Ctx) -> SectionReport {
    let mut s = SectionReport::new("workspace_index");
    s.push(Row::info(
        "workspace_index:placeholder",
        "workspace_index section not yet implemented",
    ));
    s
}
