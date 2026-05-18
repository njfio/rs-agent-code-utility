//! `binary` section — doctor's own version, rts-daemon / rts-mcp
//! presence on PATH, symlink resolution. U4 implements; this file is
//! a placeholder that returns a single info row so U2's wiring
//! compiles end-to-end.

use super::ctx::Ctx;
use super::report::{Row, SectionReport};

pub fn run(ctx: &Ctx) -> SectionReport {
    let mut s = SectionReport::new("binary");
    s.push(Row::info(
        "binary:placeholder",
        format!(
            "binary section not yet implemented (doctor v{ver})",
            ver = ctx.doctor_version
        ),
    ));
    s
}
