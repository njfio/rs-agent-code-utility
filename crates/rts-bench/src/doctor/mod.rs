//! `rts-bench doctor` — read-only first-run health check.
//!
//! Inspects rts install state (binary version, daemon reachability, MCP
//! registration in 5 agent hosts, hook file presence) and per-workspace
//! index state (daemon PID, pinned-workspace path, index generation,
//! cold-walk completion). Prints OK/WARN/FAIL rows with copy-pasteable
//! one-line fix snippets.
//!
//! See `docs/plans/2026-05-18-001-feat-rts-bench-doctor-plan.md` for the
//! full plan; `docs/doctor-schema.md` (added in U10) for the wire shape.

use std::path::PathBuf;

use clap::ValueEnum;

pub mod ctx;
pub mod render;
pub mod report;

pub mod binary_section;
pub mod daemon_section;
pub mod mcp_section;
pub mod nudge_hook;
pub mod workspace_section;

pub mod hosts;

use ctx::Ctx;
use report::{DoctorReport, ExitClass};

/// Output format for `rts-bench doctor`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum DoctorOutput {
    /// Human-readable OK/WARN/FAIL checklist with inline fix snippets.
    /// Default. ANSI color when stdout is a TTY and NO_COLOR is unset.
    Human,
    /// Machine-readable JSON. `schema_version: "doctor-v0"`. Stable
    /// across patch releases; additive evolution via `capabilities`.
    Json,
}

/// Clap-derived input arguments threaded down from `main.rs`.
#[derive(Debug, Clone)]
pub struct DoctorArgs {
    pub output: DoctorOutput,
    pub no_color: bool,
    pub workspace: Option<PathBuf>,
}

/// Doctor's runtime entry. Returns the process exit code per the
/// documented contract:
/// - 0 — no FAIL rows (any WARN allowed)
/// - 1 — at least one FAIL row
/// - 2 — doctor itself panicked or its own I/O failed
///
/// `>= 3` is reserved; CI gates must not depend on specific values
/// above 2.
pub async fn run(args: DoctorArgs) -> i32 {
    // Wrap the whole run in catch_unwind so a panic in any section
    // becomes exit code 2 with a structured `error` envelope in JSON
    // mode, rather than a crash. This is the contract from plan U9 /
    // AC13 — section panics are recoverable, doctor itself stays alive.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ctx = match Ctx::build(&args) {
            Ok(ctx) => ctx,
            Err(e) => {
                eprintln!("rts-bench doctor: failed to initialize context: {e}");
                return DoctorReport::self_error(format!(
                    "context init failed: {e}"
                ));
            }
        };

        // Section dispatch in normative order. Each section returns a
        // SectionReport; cross-section state (e.g. daemon.rs populates
        // the Stats response that workspace_section.rs reads) is
        // threaded via Ctx, which sections are allowed to mutate.
        let mut ctx = ctx;
        // Build the section list explicitly so the daemon section can
        // mutate `ctx.daemon_stats` before workspace_section reads it.
        // The `vec![]` macro can't sequence `&` vs `&mut` borrows of the
        // same Ctx; we accumulate one section at a time.
        let binary = binary_section::run(&ctx);
        let daemon = daemon_section::run(&mut ctx);
        let mcp = mcp_section::run(&ctx);
        let hook = nudge_hook::run(&ctx);
        let workspace = workspace_section::run(&ctx);
        let sections = vec![binary, daemon, mcp, hook, workspace];

        DoctorReport::from_sections(sections)
    }));

    let report = match result {
        Ok(report) => report,
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&'static str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "doctor panicked".to_string());
            DoctorReport::self_error(msg)
        }
    };

    // Render. JSON always succeeds (serde never errors on well-formed
    // input); human render is also infallible.
    match args.output {
        DoctorOutput::Json => render::render_json(&report, &mut std::io::stdout()),
        DoctorOutput::Human => render::render_human(
            &report,
            &mut std::io::stdout(),
            !args.no_color && std::env::var_os("NO_COLOR").is_none(),
        ),
    }

    // Self-error path: stdout already received the JSON envelope (if
    // requested); exit 2 regardless of section row contents.
    match report.exit_class {
        ExitClass::SelfError => 2,
        ExitClass::Fail => 1,
        ExitClass::Ok | ExitClass::Warn => 0,
    }
}
