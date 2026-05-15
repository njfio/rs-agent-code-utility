//! `Daemon.*` methods. v0 ships `Daemon.Ping` plus the (notification-only)
//! `Daemon.Telemetry`; the latter is not a request and isn't dispatched here.

use std::sync::Arc;

use crate::error::ProtocolError;
use crate::state::DaemonState;

/// Canonical advertised capability list. Mirrors protocol-v0.md §4.1
/// + Appendix F. Order matches the canonical list documented in §4.1
/// so capability-string ordering across daemons is stable.
///
/// Each entry corresponds to a method, param, or behavior whose
/// presence clients can branch on without re-issuing methods that may
/// not exist. Reserved-for-future entries live in §4.2 and are NOT in
/// this list; they're advertised only when the implementing alpha
/// lands.
const DAEMON_CAPABILITIES: &[&str] = &[
    // v0 base methods (alpha.1+).
    "outline",
    "find_symbol",
    "read_symbol",
    "read_range",
    // Behaviors + content shape.
    "rank_score",
    "tree_shake",
    "partial_responses",
    "content_version",
    "secrets_blocklist",
    // alpha.18 — file-level PageRank ranking inside Index.Outline.
    "pagerank_filewise",
    // alpha.22 — Index.ReadSymbol.include_dependencies (closure walker).
    "closure_walker",
    // alpha.24 — Index.ReadSymbolAt method + Index.FindSymbol.pattern glob.
    "read_symbol_at",
    "fuzzy_match",
    // alpha.25 — Workspace.Status.watcher_status = "polling_fallback".
    "polling_fallback",
    // v0.3 alpha.32 — Index.FindCallers method.
    "find_callers",
    // v0.3 alpha.32 — Index.ReadSymbol.include_callers param.
    "read_symbol.include_callers",
    // v0.3 alpha.34 — symbol-level PageRank fills rank_score; default
    // sort is descending rank (lexical opt-out via `sort: "lexical"`).
    "pagerank_symbolwise",
    // v0.3 alpha.35 — Index.ImpactOf transitive caller closure.
    "impact_of",
    // v0.4.1 — Index.FindSymbol.limit param (1..=4096, default 256).
    // Used by `rts-bench semantic` to pull the full ranked candidate
    // pool when scoring corpus queries; agents should leave at default.
    "find_symbol_limit_param",
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
