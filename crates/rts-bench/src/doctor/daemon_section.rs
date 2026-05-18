//! `daemon` section — per-workspace socket probe, `Daemon.Stats v2`
//! round-trip with pre-v2 fallback. U5 implements.
//!
//! On success, populates `ctx.daemon_stats` so `workspace_section` can
//! read the pinned-path / index_generation / cold_walk_completed_at_ms
//! fields without a second round-trip.

use super::ctx::Ctx;
use super::report::{Row, SectionReport};

pub fn run(_ctx: &mut Ctx) -> SectionReport {
    let mut s = SectionReport::new("daemon");
    s.push(Row::info(
        "daemon:placeholder",
        "daemon section not yet implemented",
    ));
    s
}
