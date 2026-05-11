//! `rts-daemon` — persistent local code-retrieval daemon.
//!
//! Implements the daemon side of [`docs/protocol-v0.md`]. One daemon per
//! workspace; many `rts-mcp` clients per daemon. Wire format: newline-delimited
//! JSON over a Unix-domain socket.
//!
//! See `docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md`
//! for the broader plan.

#![deny(unsafe_code)]

mod error;
mod lifecycle;
mod protocol;
mod methods;
mod socket;
mod state;
mod workspace;

use anyhow::Context;
use std::time::Duration;
use tracing::{error, info};

/// Daemon entrypoint. Single-threaded option discussed in the plan for stdio-only
/// servers; the daemon serves multiple clients over a socket, so we keep
/// multi-thread.
#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
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
    let _lock = lifecycle::acquire_lock(&socket_path)
        .with_context(|| format!("could not acquire daemon lock for {}", socket_path.display()))?;
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

