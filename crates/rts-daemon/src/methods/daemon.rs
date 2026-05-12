//! `Daemon.*` methods. v0 ships `Daemon.Ping` plus the (notification-only)
//! `Daemon.Telemetry`; the latter is not a request and isn't dispatched here.

use std::sync::Arc;

use crate::error::ProtocolError;
use crate::state::DaemonState;

const DAEMON_CAPABILITIES: &[&str] = &[
    "outline",          // present in spec; reads return IndexNotReady until P6 indexing lands
    "find_symbol",
    "read_symbol",
    "read_range",
    "partial_responses",
    "content_version",
    "secrets_blocklist",
];

/// `Daemon.Ping` — heartbeat + capability advertisement (protocol-v0 §4.1, §7.1).
pub async fn ping(
    _params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let uptime_ms = state.uptime().as_millis() as u64;
    Ok(serde_json::json!({
        "protocol":     "0",
        "daemon": {
            "name":    "rts-daemon",
            "version": env!("CARGO_PKG_VERSION"),
            "git_sha": option_env!("RTS_GIT_SHA").unwrap_or("unknown"),
        },
        "capabilities": DAEMON_CAPABILITIES,
        "uptime_ms":    uptime_ms,
    }))
}
