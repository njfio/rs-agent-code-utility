//! `rts-daemon` — persistent local code-retrieval daemon.
//!
//! Implements the daemon side of [`docs/protocol-v0.md`]. One daemon per
//! workspace; many `rts-mcp` clients per daemon. Wire format: newline-delimited
//! JSON over a Unix-domain socket.
//!
//! See `docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md`
//! for the broader plan.

#![deny(unsafe_code)]

mod closure;
mod error;
mod filter;
mod lifecycle;
mod methods;
mod outline;
mod protocol;
mod refs;
mod socket;
mod state;
mod store;
mod watcher;
mod workspace;
mod writer;

use anyhow::Context;
use std::time::Duration;
use tracing::{error, info};

/// Daemon entrypoint. Single-threaded option discussed in the plan for stdio-only
/// servers; the daemon serves multiple clients over a socket, so we keep
/// multi-thread.
#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    // Cheap CLI flags handled before any setup — operators running
    // `rts-daemon --version` shouldn't pay tracing/preflight cost.
    // No `clap` dep: two flags, two arms.
    // The daemon takes no positional args. We accept exactly one
    // optional flag (--version / --help / -V / -h); anything else is
    // an error. Looking at only `args.nth(1)` is intentional — there's
    // no flag that takes a value, so any second arg is ambiguous.
    if let Some(a) = std::env::args().nth(1) {
        match a.as_str() {
            "--version" | "-V" => {
                // Wire shape: `rts-daemon <SEMVER>`. Stable so the
                // release-build smoke test + operator diagnostics
                // (`which rts-daemon; rts-daemon --version`) can parse
                // it unambiguously.
                println!("rts-daemon {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                eprintln!(
                    "rts-daemon — persistent local code-retrieval daemon for AI coding agents."
                );
                eprintln!();
                eprintln!("Usage: rts-daemon");
                eprintln!();
                eprintln!(
                    "The daemon takes no positional arguments. All configuration is via env:"
                );
                eprintln!("  RTS_LOG                  tracing filter; defaults to `info`.");
                eprintln!("  RTS_IDLE_SHUTDOWN_SECS   idle window before self-exit; default 600.");
                eprintln!(
                    "  XDG_RUNTIME_DIR / HOME   socket location (per platform XDG fallback)."
                );
                eprintln!("  XDG_STATE_HOME           index DB location (defaults under $HOME).");
                return Ok(());
            }
            other => {
                anyhow::bail!("unknown argument: {other}");
            }
        }
    }

    // Stderr-only tracing (stdout is reserved for the MCP server, never the
    // daemon — but it costs nothing to also forbid stdout writes here).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Phase 1: pre-flight (must succeed before binding anything).
    lifecycle::preflight().context("daemon preflight failed")?;

    // Phase 2: socket path and lockfile.
    let socket_path = socket::socket_path_for_default()?;
    let _lock = lifecycle::acquire_lock(&socket_path).with_context(|| {
        format!(
            "could not acquire daemon lock for {}",
            socket_path.display()
        )
    })?;
    info!(socket = %socket_path.display(), "acquired daemon lock");

    // Phase 3: bind the socket. Mode is set by socket::bind_with_safe_perms.
    let listener = socket::bind_with_safe_perms(&socket_path)
        .with_context(|| format!("bind unix socket at {}", socket_path.display()))?;
    info!(socket = %socket_path.display(), "daemon listening");

    // Phase 4: shared state.
    let state = std::sync::Arc::new(state::DaemonState::new());

    // Phase 5: install signal handlers and idle-shutdown timer; run the accept
    // loop until any of them trips.
    let cancel = tokio_util::sync::CancellationToken::new();
    let signal_cancel = cancel.clone();
    tokio::spawn(async move {
        match lifecycle::wait_for_shutdown_signal().await {
            Ok(name) => info!(signal = name, "shutdown signal received"),
            Err(e) => error!(error = %e, "signal handler failed"),
        }
        signal_cancel.cancel();
    });

    let idle = std::env::var("RTS_IDLE_SHUTDOWN_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(600));
    let idle_cancel = cancel.clone();
    let idle_state = state.clone();
    tokio::spawn(async move {
        lifecycle::idle_shutdown_timer(idle_state, idle, idle_cancel).await;
    });

    let result = socket::accept_loop(listener, state, cancel.clone()).await;

    // Phase 6: best-effort cleanup. The lockfile's drop unlinks the PID file;
    // we explicitly unlink the socket path so a quick restart doesn't trip on
    // "address already in use".
    if let Err(e) = std::fs::remove_file(&socket_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            error!(error = %e, socket = %socket_path.display(), "could not unlink socket on shutdown");
        }
    }

    if let Err(e) = result {
        error!(error = %e, "accept loop returned error");
        std::process::exit(1);
    }

    info!("daemon exited cleanly");
    Ok(())
}
