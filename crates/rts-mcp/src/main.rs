//! `rts-mcp` — Model Context Protocol bridge to `rts-daemon`.
//!
//! Speaks MCP over stdio to the agent (rmcp 1.6, `ProtocolVersion::V_2024_11_05`)
//! and protocol-v0 over a Unix-domain socket to the workspace-pinned
//! daemon. Auto-spawns the daemon on first connect if it isn't running.
//!
//! Stdio discipline: stdout is JSON-RPC frames only; all logs go to stderr
//! with `with_ansi(false)` so Claude Code's stderr parser doesn't choke on
//! color codes (per the P0.1 spike).

use std::path::PathBuf;

use anyhow::{Context, Result};
use rmcp::service::ServiceExt;

mod server;

use rts_mcp::connection::{ConnectionManager, ResilienceConfig};
use rts_mcp::daemon_client::DaemonClient;
use rts_mcp::socket;
use server::RtsServer;

/// CLI flags, parsed manually so we don't pull in `clap` for two flags.
struct Args {
    /// Workspace root to `Workspace.Mount` against. Defaults to `$PWD`.
    workspace: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut workspace: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--workspace" | "-w" => {
                workspace =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        anyhow::anyhow!("--workspace requires a value")
                    })?));
            }
            "--help" | "-h" => {
                eprintln!("rts-mcp — MCP server bridging Claude Code/Cursor/etc. to rts-daemon.");
                eprintln!();
                eprintln!("Usage: rts-mcp [--workspace PATH]");
                eprintln!();
                eprintln!("If --workspace is omitted, the current working directory is used.");
                eprintln!();
                eprintln!("Env:");
                eprintln!(
                    "  RTS_DAEMON_BIN  path to the rts-daemon binary (default: sibling of this exe)"
                );
                eprintln!("  RTS_LOG         tracing filter; defaults to `rts_mcp=info,warn`.");
                std::process::exit(0);
            }
            "--version" | "-V" => {
                // Stable wire shape for the release-bench smoke test
                // and `which rts-mcp; rts-mcp --version` diagnostics:
                // `rts-mcp <SEMVER>`.
                println!("rts-mcp {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => {
                anyhow::bail!("unknown argument: {other}");
            }
        }
    }
    Ok(Args { workspace })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RTS_LOG")
                .or_else(|_| tracing_subscriber::EnvFilter::try_from_default_env())
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("rts_mcp=info,warn")),
        )
        .init();

    let args = parse_args()?;
    let workspace = match args.workspace {
        Some(p) => p,
        None => std::env::current_dir().context("$PWD lookup")?,
    };
    let workspace = std::fs::canonicalize(&workspace)
        .with_context(|| format!("canonicalize {}", workspace.display()))?;

    tracing::info!(
        target: "rts_mcp",
        "rts-mcp starting (pid={}, workspace={})",
        std::process::id(),
        workspace.display()
    );

    let daemon_bin = socket::resolve_daemon_bin()?;
    // v0.4: pass the workspace path to auto-spawn so the daemon
    // prewarms (kicks off the initial walk) before any RPC arrives.
    // Combined with the deferred `Workspace.Mount` below, this hides
    // the cold-mount tax entirely on long-lived agent sessions: the
    // daemon walks in the background while the user types their
    // first question, and the lazy Mount on first tool call hits the
    // idempotent path instantly.
    let stream = socket::connect_with_auto_spawn(&daemon_bin, Some(&workspace))
        .await
        .context("connect to rts-daemon")?;
    // v0.5.5+: pass daemon_bin + workspace to DaemonClient so it can
    // re-auto-spawn if the socket dies mid-session (daemon crash,
    // SIGTERM, upgrade). Without this state the client couldn't
    // re-resolve the binary path or route to the per-workspace socket.
    let daemon = DaemonClient::new(stream, daemon_bin.clone(), workspace.clone());

    // v0.6+: wrap the bare DaemonClient in a ConnectionManager so the
    // shim gets heartbeat + reconnect-with-backoff + structured
    // disconnection state (Plan 004). The heartbeat task is enabled
    // for the long-lived MCP shim; the CLI variant disables it (see
    // `cli::connect`). Env vars `RTS_MCP_HEARTBEAT_*` /
    // `RTS_MCP_RECONNECT_*` override the defaults; see
    // `connection.rs` for the full list.
    let connection = ConnectionManager::new(
        daemon,
        daemon_bin.clone(),
        workspace.clone(),
        ResilienceConfig::from_env(),
        /* start_background_tasks */ true,
    );

    // v0.4: Workspace.Mount is now deferred — see
    // `ConnectionManager::call`. The first agent tool call
    // (find_symbol / outline_workspace / etc.) triggers the Mount.
    // Daemon prewarm overlaps with the seconds the user spends
    // typing their first question, so Mount is effectively free.

    let instructions = format!(
        "rts-mcp serves four read-only retrieval tools for the workspace at {}. \
         Tools are deterministic and offline; no LLM in the server. Use `outline_workspace` \
         first for orientation, then `find_symbol`/`read_symbol` for targeted reads.",
        workspace.display()
    );
    let server = RtsServer::new(connection.clone(), instructions);
    // v0.5.8: hold a clone of the connection so we can issue one
    // last `Daemon.Stats` after `service.waiting()` returns —
    // `serve()` consumes the server, so this is the only window we
    // have to grab a handle. The manager is `Clone` (Arc-counted
    // internals), no Mutex contention at shutdown.
    let connection_for_shutdown = connection.clone();
    let service = server
        .serve(rmcp::transport::stdio())
        .await
        .context("serve stdio")?;
    service.waiting().await.context("service.waiting")?;

    // v0.5.8 session-end stats dump. The whole point of `Daemon.Stats`
    // was to replace anecdotal "I think I used grep more than
    // find_symbol" with a real number; issuing one final query at
    // session end means every session naturally produces a data
    // point on its way out. Failures here are non-fatal: stderr
    // logging is observational, not load-bearing for the daemon
    // lifecycle.
    dump_session_stats(&connection_for_shutdown).await;
    tracing::info!(target: "rts_mcp", "rts-mcp shut down cleanly");
    Ok(())
}

/// Issue a final `Daemon.Stats` RPC and pretty-print the result to
/// stderr (via `eprintln!` so it's visible even when RTS_LOG filters
/// out our tracing target). One eprintln line per non-zero counter
/// — zero-count methods are silent to keep the dump tight on quiet
/// sessions.
///
/// Non-fatal: any failure to query the daemon (it might have
/// crashed before we got here, or the socket may already be gone)
/// is reported via a single `tracing::warn!` and the function
/// returns. Shutdown should never block on observability.
async fn dump_session_stats(connection: &ConnectionManager) {
    let result = connection.call("Daemon.Stats", serde_json::json!({})).await;

    let body = match result {
        Ok(v) => v,
        Err(e) => {
            // Pre-v0.5.7 daemons don't have Daemon.Stats — surfaces
            // here as a daemon-side INVALID_PARAMS. Treat as "no
            // stats available" and log at debug so old-daemon
            // sessions don't get a scary warn on every shutdown.
            tracing::debug!(
                target: "rts_mcp",
                error = %e,
                "Daemon.Stats unavailable (likely pre-v0.5.7 daemon or mid-reconnect); skipping shutdown dump"
            );
            return;
        }
    };

    let uptime_ms = body["uptime_ms"].as_u64().unwrap_or(0);
    let total = body["total_calls"].as_u64().unwrap_or(0);
    let version = body["version"].as_str().unwrap_or("?");
    eprintln!("rts-mcp session stats:");
    eprintln!("  daemon-version: {version}");
    eprintln!("  uptime-ms:      {uptime_ms}");
    eprintln!("  total-calls:    {total}");
    if let Some(calls) = body["calls"].as_object() {
        let mut pairs: Vec<(&String, u64)> = calls
            .iter()
            .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
            .filter(|(_, n)| *n > 0)
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        for (method, n) in pairs {
            eprintln!("  {method}: {n}");
        }
    }
}
