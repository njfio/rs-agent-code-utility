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

mod daemon_client;
mod server;
mod socket;

use daemon_client::DaemonClient;
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
    let daemon = DaemonClient::new(stream);

    // v0.4: Workspace.Mount is now deferred — see `RtsServer::call_daemon`.
    // The first agent tool call (find_symbol / outline_workspace / etc.)
    // triggers the Mount. Daemon prewarm overlaps with the seconds the
    // user spends typing their first question, so Mount is effectively
    // free.
    //
    // Pre-v0.4 behavior was to Mount synchronously here at startup,
    // which paid the 6 s cold-walk tax during rts-mcp boot — before
    // the agent's first tool call could even be served. The deferred
    // approach lets Claude Code / Cursor / etc. show tools as
    // available immediately and amortizes the walk into the user's
    // typing time.

    let instructions = format!(
        "rts-mcp serves four read-only retrieval tools for the workspace at {}. \
         Tools are deterministic and offline; no LLM in the server. Use `outline_workspace` \
         first for orientation, then `find_symbol`/`read_symbol` for targeted reads.",
        workspace.display()
    );
    let server = RtsServer::new(daemon, workspace.clone(), instructions);
    let service = server
        .serve(rmcp::transport::stdio())
        .await
        .context("serve stdio")?;
    service.waiting().await.context("service.waiting")?;
    tracing::info!(target: "rts_mcp", "rts-mcp shut down cleanly");
    Ok(())
}
