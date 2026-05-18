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
    // v0.5 — Index.FindSymbol response carries real `doc` field
    // populated from indexed `///` / `//!` Rust doc comments. Pre-v0.5
    // daemons always returned `null` for this field. C/JS/Python doc
    // extraction filed as follow-up.
    "find_symbol_doc_field",
    // v0.5.2 — Index.FindSymbol.params.doc_contains: Option<String>
    // filters matches by substring (case-insensitive) against the
    // doc text. Useful for behavior-shaped queries — "find the
    // cache-eviction code" can hit any documented symbol whose
    // comment mentions "evict" regardless of identifier name.
    "find_symbol_doc_filter",
    // v0.5.2 — Index.FindSymbol response includes optional
    // `pre_filter_count: usize` showing the candidate population
    // before any filter (doc_contains) was applied. Lets agents
    // distinguish "filter rejected all matches" from "nothing
    // matched name/pattern". Omitted when no filter was active.
    "find_symbol_pre_filter_count",
    // v0.5.3 — Index.FindSymbol.params.include_signature: bool
    // populates each match's `signature` field via rts-core's
    // per-language SignatureRenderer. Default false — back-compat
    // wire shape preserved. Renders are cached per
    // `(path, byte_range, mtime)` in DaemonState::signature_cache,
    // so repeat queries on the same workspace amortize the parse.
    "find_symbol_signature_field",
    // v0.5.4 — Index.Grep method: literal-substring search across
    // indexed file bytes. Closes the agent-loop hole where the
    // daemon couldn't help find error messages, version strings,
    // log output, or any non-symbol text content. MVP is literal
    // case-insensitive-by-default; regex / file_glob / context
    // lines / enclosing-symbol resolution are filed for follow-up.
    "index_grep",
    // v0.5.7 — Daemon.Stats method: per-session call counts +
    // uptime. Mainly for honest dogfood reflection ("am I actually
    // using this?") — agents can self-report rather than guess.
    "daemon_stats",
    // v0.6 — Daemon.Stats v2: response includes `pinned_workspace_path`,
    // `workspace_id`, `index_generation`, and `cold_walk_completed_at_ms`
    // when a workspace is mounted. Lets `rts-bench doctor` answer
    // "is the daemon pinned to this $PWD?" and "is indexing done?"
    // in a single round-trip. Old clients ignore the new fields.
    "daemon_stats_v2",
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

/// `Daemon.Stats` — per-session call counters + workspace metadata
/// (v0.5.7+, extended to v2 in v0.6+).
///
/// Returns the per-method call-count snapshot from
/// `state.call_counters` plus session-level context (uptime, daemon
/// version, total RPC count). The Stats RPC itself is counted, so
/// querying stats twice in a row shows `Daemon.Stats: 2`.
///
/// **v2 fields (capability `daemon_stats_v2`, v0.6+):** when a
/// workspace is mounted, the response additionally carries
/// `pinned_workspace_path` (UTF-8 canonical path the daemon is
/// pinned to), `workspace_id` (16-char hex blake3 fingerprint),
/// `index_generation` (bumps on every committed write), and
/// `cold_walk_completed_at_ms` (Unix-epoch ms when the writer's
/// `ColdWalkComplete` flush committed, or `null` if not yet). These
/// fields let `rts-bench doctor` answer "is the daemon pinned to
/// this $PWD?" and "is indexing done?" in a single round-trip. Old
/// clients ignore the additional fields; pre-v2 daemons omit them.
///
/// Wire shape (v2):
/// ```jsonc
/// {
///   "uptime_ms":  12345,
///   "version":    "0.6.0",
///   "total_calls": 89,
///   "calls": {
///     "Index.FindSymbol":  3,
///     "Index.Grep":        47,
///     ...
///   },
///   // v2 fields, present only when a workspace is mounted:
///   "pinned_workspace_path":     "/Users/n/RustroverProjects/rust_tree_sitter",
///   "workspace_id":              "8a8a68f7b4c3...",
///   "index_generation":          1247,
///   "cold_walk_completed_at_ms": 1748462100123
/// }
/// ```
///
/// **Counters are not persisted across daemon restarts.** A
/// daemon-internal restart (crash + auto-respawn, SIGTERM + new
/// process, version upgrade) resets every counter to zero. This is
/// intentional: the counters describe *this daemon process's*
/// served traffic; persisting would conflate independent runs.
/// Cross-session aggregation should happen client-side from
/// per-session snapshots.
///
/// Performance: one relaxed-load per counter field, one workspace
/// mutex lock for the v2 fields, plus a JSON serialize. Sub-
/// microsecond on modern hardware; safe to call from a hot agent loop.
pub async fn stats(
    _params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    use std::sync::atomic::Ordering::Relaxed;
    let uptime_ms = state.uptime().as_millis() as u64;

    // v2 fields. Only emitted when a workspace is mounted — old clients
    // and pre-mount Stats calls both see the v1 shape via field absence.
    let (pinned_path, workspace_id, index_gen, cold_walk_at_ms) = match state.workspace.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(mounted) => {
                let pinned = mounted.canonical.path.to_string_lossy().into_owned();
                let ws_id = mounted.fingerprint.id_str().to_string();
                let generation = state.index_generation.load(Relaxed);
                let cold_walk = state.cold_walk_completed_at_ms.load(Relaxed);
                (Some(pinned), Some(ws_id), Some(generation), cold_walk)
            }
            None => (None, None, None, 0),
        },
        Err(_) => (None, None, None, 0),
    };

    // `cold_walk_completed_at_ms: null` when 0 (not yet completed); a
    // real timestamp otherwise. Distinguishes "indexing in progress"
    // from "indexing done" for the agent reading this.
    let cold_walk_value = if cold_walk_at_ms == 0 {
        serde_json::Value::Null
    } else {
        serde_json::Value::Number(cold_walk_at_ms.into())
    };

    let mut body = serde_json::json!({
        "uptime_ms":   uptime_ms,
        "version":     env!("CARGO_PKG_VERSION"),
        "total_calls": state.call_counters.total(),
        "calls":       state.call_counters.snapshot(),
    });

    // v2 fields are added only when a workspace is mounted; pre-mount
    // Stats responses keep the v1 shape exactly.
    if let (Some(path), Some(id), Some(generation)) = (pinned_path, workspace_id, index_gen) {
        let obj = body.as_object_mut().expect("body is an object");
        obj.insert(
            "pinned_workspace_path".into(),
            serde_json::Value::String(path),
        );
        obj.insert("workspace_id".into(), serde_json::Value::String(id));
        obj.insert(
            "index_generation".into(),
            serde_json::Value::Number(generation.into()),
        );
        obj.insert("cold_walk_completed_at_ms".into(), cold_walk_value);
    }

    Ok(body)
}
