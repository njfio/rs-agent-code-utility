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
mod impact;
mod language;
mod lifecycle;
mod methods;
mod outline;
mod path;
mod protocol;
mod refs;
mod socket;
mod state;
mod store;
mod symbol_pagerank;
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
    // No `clap` dep: a handful of flags, hand-parsed.
    //
    // Accepted forms:
    //   rts-daemon                              # legacy: no prewarm
    //   rts-daemon --version | -V
    //   rts-daemon --help | -h
    //   rts-daemon --workspace <path>           # prewarm mode (v0.4)
    //   rts-daemon --workspace=<path>           # same, equals form
    //
    // `--workspace <path>` tells the daemon to start the initial walk
    // immediately on startup instead of waiting for the first
    // `Workspace.Mount` RPC. Auto-spawn from `rts-mcp` uses this so
    // the walk overlaps with the MCP handshake — by the time the
    // agent's first `find_symbol` arrives, the index is warm.
    //
    // The flag is OPTIONAL: omitted = legacy behavior (idle daemon
    // waiting for Mount). Tests and operator-launched daemons can
    // still spawn with no args.
    let mut prewarm_workspace: Option<std::path::PathBuf> = None;
    {
        let mut args = std::env::args().skip(1);
        while let Some(a) = args.next() {
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
                    eprintln!("Usage: rts-daemon [--workspace <path>]");
                    eprintln!();
                    eprintln!("Flags:");
                    eprintln!(
                        "  --workspace <path>       Prewarm: start the initial walk for <path>"
                    );
                    eprintln!("                           immediately on startup. The first");
                    eprintln!(
                        "                           `Workspace.Mount` for the same path joins"
                    );
                    eprintln!(
                        "                           the in-progress walk. Used by `rts-mcp`'s"
                    );
                    eprintln!("                           auto-spawn to hide cold-mount latency.");
                    eprintln!();
                    eprintln!("Env:");
                    eprintln!("  RTS_LOG                  tracing filter; defaults to `info`.");
                    eprintln!(
                        "  RTS_IDLE_SHUTDOWN_SECS   idle window before self-exit; default 600."
                    );
                    eprintln!(
                        "  XDG_RUNTIME_DIR / HOME   socket location (per platform XDG fallback)."
                    );
                    eprintln!(
                        "  XDG_STATE_HOME           index DB location (defaults under $HOME)."
                    );
                    return Ok(());
                }
                "--workspace" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--workspace requires a path argument"))?;
                    prewarm_workspace = Some(std::path::PathBuf::from(value));
                }
                eq if eq.starts_with("--workspace=") => {
                    prewarm_workspace = Some(std::path::PathBuf::from(
                        eq.trim_start_matches("--workspace="),
                    ));
                }
                other => {
                    anyhow::bail!("unknown argument: {other}");
                }
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
    //
    // v0.5.4+: when `--workspace <path>` is passed, bind a
    // per-workspace socket (`ws-<16hex>.sock`) so multiple daemons
    // can coexist — one per workspace. Without `--workspace` we
    // bind `default.sock` for the bootstrap case (which still
    // preserves the v0.5.3-and-earlier shape for callers that
    // expect it).
    let socket_path = match prewarm_workspace.as_deref() {
        Some(p) => {
            let canonical = p
                .canonicalize()
                .with_context(|| format!("canonicalize --workspace argument {}", p.display()))?;
            socket::socket_path_for_workspace(&canonical)?
        }
        None => socket::socket_path_for_default()?,
    };
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

    // Phase 4.5: optional background prewarm. If `--workspace <path>`
    // was passed, fire-and-forget a mount task. accept_loop starts
    // immediately below, so:
    //
    //   - The first client (rts-mcp) can connect and send
    //     `Workspace.Mount` right away.
    //   - That RPC sees `state.prewarm_in_flight == true` and waits
    //     on `state.prewarm_done` (Workspace.Mount handler).
    //   - When the background prewarm task finishes, it notifies
    //     waiters; Mount's idempotent path returns with the now-ready
    //     state.
    //
    // The real win lands in the rts-mcp deferred-Mount story: if
    // rts-mcp is spawned by the agent harness at startup but doesn't
    // call Mount until the agent's first tool invocation seconds
    // later, the prewarm completes during that gap and Mount is
    // instant. (Today rts-mcp Mounts immediately on startup so the
    // win is partial — Mount still waits for prewarm, but
    // concurrently with rts-mcp's own startup work + IPC handshake.)
    if let Some(path) = prewarm_workspace.clone() {
        state
            .prewarm_in_flight
            .store(true, std::sync::atomic::Ordering::Release);
        let prewarm_state = state.clone();
        tokio::spawn(async move {
            info!(workspace = %path.display(), "prewarm: background mount starting");
            let t0 = std::time::Instant::now();
            match methods::prewarm_mount(&path, &prewarm_state).await {
                Ok(()) => {
                    info!(
                        workspace = %path.display(),
                        elapsed_ms = t0.elapsed().as_millis() as u64,
                        "prewarm: background mount succeeded",
                    );
                }
                Err(e) => {
                    error!(
                        workspace = %path.display(),
                        error = %e,
                        "prewarm: background mount failed; explicit Workspace.Mount RPC will retry",
                    );
                }
            }
            prewarm_state
                .prewarm_in_flight
                .store(false, std::sync::atomic::Ordering::Release);
            prewarm_state.prewarm_done.notify_waiters();
        });
    }

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
