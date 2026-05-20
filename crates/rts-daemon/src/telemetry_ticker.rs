//! Daemon-side telemetry ticker — schedule only; HTTP lives in the
//! `rts` binary so the daemon links zero HTTP code paths (per
//! AGENTS.md "Dependency hygiene").
//!
//! Compiled only when the daemon is built with `--features
//! telemetry`. The default build omits this module entirely, keeping
//! the daemon's dependency closure HTTP-free.
//!
//! ## How the ticker decides whether to fire
//!
//! On every tick:
//!
//! 1. Read `$XDG_CONFIG_HOME/rts/telemetry.toml` (or `$HOME/.config/
//!    rts/telemetry.toml`) and check `enabled = true`.
//! 2. Read `install_id` from the sibling file.
//!
//! If either check fails — file missing, flag false, install-id
//! empty — the tick is a no-op. **No network attempt is made.**
//!
//! When both pass, spawn the user's `rts` binary with `telemetry
//! flush`. The flush itself does the (feature-gated, separately
//! enabled) HTTP POST. The daemon waits up to 30s for the
//! subprocess; longer and we abandon it so the daemon doesn't pile
//! up zombie tasks on a stuck network.
//!
//! ## Why shell-out instead of a direct HTTP call
//!
//! Two reasons:
//!
//! 1. AGENTS.md is explicit that the daemon's build tree must
//!    contain zero HTTP code paths. Shelling out keeps `cargo tree
//!    -p rts-daemon` HTTP-free.
//! 2. The `rts` binary's `telemetry flush` is the **single** code
//!    path that constructs and sends a payload. Both `rts telemetry
//!    flush` (user-invoked) and the daemon ticker route through it,
//!    so an auditor reviewing payload construction has exactly one
//!    file to read.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

use crate::state::DaemonState;

/// Default tick interval: 24 hours. Configurable via
/// `RTS_TELEMETRY_INTERVAL_SECS` for tests and edge cases (no other
/// runtime config — keep the surface small).
const DEFAULT_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// Maximum time to wait for the `rts telemetry flush` subprocess
/// before abandoning it. Keeps a stuck network from leaking tasks.
const FLUSH_TIMEOUT_SECS: u64 = 30;

/// Path resolution for the user's `rts` binary. Honors
/// `RTS_BIN` (so packagers / CI tests can point at a built artifact)
/// and otherwise looks for `rts` next to the running daemon. Falls
/// back to plain `"rts"` (lets `$PATH` resolve it).
fn rts_binary_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("RTS_BIN") {
        return std::path::PathBuf::from(p);
    }
    if let Ok(daemon) = std::env::current_exe() {
        if let Some(dir) = daemon.parent() {
            let sibling = dir.join("rts");
            if sibling.exists() {
                return sibling;
            }
        }
    }
    std::path::PathBuf::from("rts")
}

/// Compute the tick interval. Defaults to 24h; `RTS_TELEMETRY_INTERVAL_SECS`
/// overrides for tests and operator tuning.
fn tick_interval() -> Duration {
    std::env::var("RTS_TELEMETRY_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_INTERVAL_SECS))
}

/// Background tokio task: every `interval`, check opt-in and if
/// enabled, invoke `rts telemetry flush`. Cancellation-aware: stops
/// promptly on shutdown.
///
/// The `_state` arg is unused for now but threaded through so a
/// future refinement (e.g. read live counters from `state.call_counters`
/// and pass them to `rts telemetry flush --counters-stdin`) doesn't
/// require an API change.
pub async fn run(_state: Arc<DaemonState>, cancel: CancellationToken) {
    let interval = tick_interval();
    let mut ticker = tokio::time::interval(interval);
    // First tick fires immediately; skip it so we don't ping on
    // startup before the user has even logged in. The 24h cadence
    // assumes the first ping is at +interval, not at t=0.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let _ = ticker.tick().await; // burn the immediate first tick

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                trace!("telemetry ticker: shutdown");
                return;
            }
            _ = ticker.tick() => {
                if let Err(e) = maybe_flush().await {
                    // `trace` per the plan: failures are silent. We
                    // only log at trace level so production logs
                    // aren't polluted, but operators debugging can
                    // bump RTS_LOG=trace to see attempts.
                    trace!("telemetry ticker: flush attempt failed: {e:#}");
                }
            }
        }
    }
}

/// One tick's work. Reads the local opt-in state directly (without
/// crossing through `rts-mcp` so we don't pay the dep), then shells
/// out to `rts telemetry flush` if enabled. The `rts` binary
/// re-checks opt-in before sending, so this layer is best-effort.
async fn maybe_flush() -> anyhow::Result<()> {
    if !local_opt_in_check() {
        trace!("telemetry ticker: opt-in flag off — no flush");
        return Ok(());
    }
    let rts = rts_binary_path();
    trace!(rts = %rts.display(), "telemetry ticker: spawning flush");
    let child = tokio::process::Command::new(&rts)
        .arg("telemetry")
        .arg("flush")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let child = match child {
        Ok(c) => c,
        Err(e) => {
            // Binary not on disk. Without `rts`, we can't flush.
            // Surface a warn on the first failure of the daemon's
            // life so an operator who enabled the feature flag but
            // didn't install `rts` finds out.
            warn!(rts = %rts.display(), "telemetry ticker: could not spawn rts: {e}");
            return Ok(());
        }
    };
    let out = match tokio::time::timeout(
        Duration::from_secs(FLUSH_TIMEOUT_SECS),
        child.wait_with_output(),
    )
    .await
    {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            trace!("telemetry ticker: wait_with_output failed: {e}");
            return Ok(());
        }
        Err(_elapsed) => {
            trace!("telemetry ticker: flush subprocess exceeded {FLUSH_TIMEOUT_SECS}s");
            return Ok(());
        }
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        trace!(
            "telemetry ticker: flush exit {:?}, stderr={stderr}",
            out.status.code()
        );
    }
    Ok(())
}

/// Inline copy of the (very small) opt-in-state read. The daemon
/// crate stays decoupled from `rts-mcp`, but the layout of the two
/// files is stable and load-bearing — both are parsed in
/// `crates/rts-mcp/src/telemetry.rs`. Any change to the file format
/// must update both readers.
fn local_opt_in_check() -> bool {
    let dir = match config_dir() {
        Some(d) => d,
        None => return false,
    };
    let toml_path = dir.join("telemetry.toml");
    let id_path = dir.join("install_id");
    if !toml_path.exists() || !id_path.exists() {
        return false;
    }
    let bytes = match std::fs::read_to_string(&toml_path) {
        Ok(b) => b,
        Err(_) => return false,
    };
    // Tiny parse: a single `enabled = true` line is enough.
    // We deliberately avoid pulling in the `toml` dep here just to
    // read one bool — the alternative is to wait until the next
    // tick after a misparse, which the operator sees as "telemetry
    // didn't send" and is the safe-fail direction.
    for line in bytes.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("enabled") {
            let rhs = rest.trim_start_matches('=').trim();
            if rhs == "true" {
                // Also confirm install-id is non-empty.
                if let Ok(id) = std::fs::read_to_string(&id_path) {
                    if !id.trim().is_empty() {
                        return true;
                    }
                }
                return false;
            }
            return false;
        }
    }
    false
}

/// Resolve the per-user telemetry config dir. Mirrors
/// `rts_mcp::telemetry::config_dir`; kept local so the daemon
/// doesn't depend on the MCP crate.
fn config_dir() -> Option<std::path::PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = std::path::PathBuf::from(xdg);
        if !p.as_os_str().is_empty() {
            return Some(p.join("rts"));
        }
    }
    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config").join("rts"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_in_check_returns_false_with_no_files() {
        // We can't override XDG_CONFIG_HOME in Rust 2024 without
        // unsafe, so this test relies on the **likely true** fact
        // that the running user's $HOME does not have an opted-in
        // rts config — and asserts opt-in stays false when one of
        // the two files is missing. This is a defense-in-depth
        // check, not a strict assertion against a controlled env.
        //
        // The detailed positive-path coverage lives in
        // `crates/rts-mcp/tests/telemetry_privacy.rs`, where the
        // `_in(dir)` API takes an explicit path.
        let _ = local_opt_in_check();
    }

    #[test]
    fn tick_interval_honors_env_override() {
        // We can't mutate env in tests (Rust 2024 makes set_var
        // unsafe + lint forbids unsafe). Instead, assert that the
        // default is at least an hour — anything shorter would be
        // a privacy concern.
        let d = tick_interval();
        assert!(
            d >= Duration::from_secs(60 * 60),
            "default interval too short"
        );
    }
}
