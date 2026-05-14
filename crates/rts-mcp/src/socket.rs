//! Socket-path discovery + daemon auto-spawn.
//!
//! Mirrors `rts-daemon`'s `socket::socket_path_for_default` so the MCP server
//! and the daemon agree on where the Unix socket lives:
//!
//!   Linux: `${XDG_RUNTIME_DIR}/rts/default.sock`
//!   macOS: `$HOME/Library/Caches/rts/default.sock`
//!
//! Per-workspace socket paths (the `blake3(dev_id || inode || canonical_path)`
//! flavour from protocol-v0 §5.3) are a v1.1 refinement — v0 is workspace-pinned
//! to one daemon per host, and the "default" socket is the agreed bootstrap
//! location.
//!
//! The auto-spawn flow:
//!   1. If the socket exists and accepts a connection, use it.
//!   2. Otherwise, spawn `rts-daemon` and wait up to 5 s with backoff.
//!   3. The loser of any spawn race polls for the winner's socket instead of
//!      respawning.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::net::UnixStream;
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// Wait-for-socket budget when spawning the daemon. Matches the plan's P7
/// "wait up to 5 s with backoff" guidance.
const SPAWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Initial backoff. Grows by 1.5× up to a cap so a quick-start daemon
/// (~50 ms in practice) doesn't pay the full budget but a slow start still
/// gets enough retries to land.
const INITIAL_POLL: Duration = Duration::from_millis(25);
const MAX_POLL: Duration = Duration::from_millis(250);

/// Resolve the default daemon socket path. Errors if `XDG_RUNTIME_DIR` is
/// unset on Linux (matches the daemon's refusal to fall back to `/tmp`).
pub fn default_socket_path() -> Result<PathBuf> {
    Ok(runtime_root()?.join("default.sock"))
}

fn runtime_root() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let xdg = std::env::var("XDG_RUNTIME_DIR").map_err(|_| {
            anyhow!("XDG_RUNTIME_DIR is unset; refusing to fall back to /tmp (security)")
        })?;
        if xdg.is_empty() {
            return Err(anyhow!("XDG_RUNTIME_DIR is empty"));
        }
        return Ok(PathBuf::from(xdg).join("rts"));
    }
    #[cfg(target_os = "macos")]
    {
        let home =
            dirs::home_dir().ok_or_else(|| anyhow!("could not resolve $HOME for socket dir"))?;
        Ok(home.join("Library").join("Caches").join("rts"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(anyhow!("unsupported OS for v0 socket placement"))
    }
}

/// Try to connect to an existing daemon socket. Returns the stream on
/// success; returns `None` (no error) when the file isn't there yet or
/// refused our connection — caller decides whether to spawn.
pub async fn try_connect(path: &std::path::Path) -> Option<UnixStream> {
    match UnixStream::connect(path).await {
        Ok(s) => Some(s),
        Err(e) => {
            debug!(target: "rts_mcp::socket", "connect({}) failed: {e}", path.display());
            None
        }
    }
}

/// Connect to the daemon, auto-spawning it if necessary.
///
/// `daemon_bin` is the path to the `rts-daemon` binary. The MCP server
/// resolves this from `RTS_DAEMON_BIN` (set by tests + bench harnesses) or
/// looks up the sibling `rts-daemon` in the same directory as the current
/// executable.
pub async fn connect_with_auto_spawn(daemon_bin: &std::path::Path) -> Result<UnixStream> {
    let socket_path = default_socket_path()?;
    if let Some(s) = try_connect(&socket_path).await {
        return Ok(s);
    }

    info!(
        target: "rts_mcp::socket",
        "no daemon at {}, spawning {}",
        socket_path.display(),
        daemon_bin.display()
    );

    // Spawn the daemon. It's a detached child — we don't want it to die when
    // the MCP server exits, and we don't want its stdio to leak into ours
    // (stdin/stdout are JSON-RPC frames to the agent).
    let mut cmd = tokio::process::Command::new(daemon_bin);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        // RTS_INHERIT_DAEMON_STDERR=1 surfaces daemon logs to our
        // stderr (which is the agent harness's stderr). Useful for
        // debugging; default to null so production runs aren't noisy.
        .stderr(
            if std::env::var("RTS_INHERIT_DAEMON_STDERR")
                .map(|v| !v.is_empty() && v != "0")
                .unwrap_or(false)
            {
                std::process::Stdio::inherit()
            } else {
                std::process::Stdio::null()
            },
        );
    // Inherit XDG_RUNTIME_DIR / HOME / XDG_STATE_HOME so the daemon writes to
    // the same socket directory we just probed.
    let child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", daemon_bin.display()))?;
    debug!(target: "rts_mcp::socket", "spawned daemon pid={:?}", child.id());

    // Poll for the socket to come up.
    let deadline = Instant::now() + SPAWN_TIMEOUT;
    let mut poll = INITIAL_POLL;
    loop {
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "rts-daemon at {} did not bind {} within {SPAWN_TIMEOUT:?}",
                daemon_bin.display(),
                socket_path.display()
            ));
        }
        tokio::time::sleep(poll).await;
        if let Some(s) = try_connect(&socket_path).await {
            return Ok(s);
        }
        poll = (poll.mul_f32(1.5)).min(MAX_POLL);
    }
}

/// Resolve the `rts-daemon` binary path. Honours `RTS_DAEMON_BIN` first
/// (tests + benches), otherwise falls back to the binary that lives next to
/// `rts-mcp` (the canonical install layout).
pub fn resolve_daemon_bin() -> Result<PathBuf> {
    if let Ok(env) = std::env::var("RTS_DAEMON_BIN") {
        if !env.is_empty() {
            return Ok(PathBuf::from(env));
        }
    }
    let exe = std::env::current_exe().context("current_exe")?;
    let parent = exe
        .parent()
        .ok_or_else(|| anyhow!("current_exe has no parent dir: {}", exe.display()))?;
    let candidate = parent.join("rts-daemon");
    if candidate.is_file() {
        return Ok(candidate);
    }
    // Last resort: trust $PATH.
    warn!(
        target: "rts_mcp::socket",
        "rts-daemon not found next to {}, falling back to PATH",
        exe.display()
    );
    Ok(PathBuf::from("rts-daemon"))
}
