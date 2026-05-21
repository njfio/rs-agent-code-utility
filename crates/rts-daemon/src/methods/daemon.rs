//! `Daemon.*` methods. v0 ships `Daemon.Ping` plus the (notification-only)
//! `Daemon.Telemetry`; the latter is not a request and isn't dispatched here.
//!
//! v0.6 adds `Daemon.Cancel { cancel_id }` for cooperative cancellation
//! of in-flight long-running requests; see `crate::cancel`.

use std::sync::Arc;

use serde::Deserialize;

use crate::error::{ErrorCode, ProtocolError};
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
    // v0.6 — Index.Grep v2: three additive capabilities on the
    // existing `Index.Grep` method, plus a bundle. Old callers (no
    // v2 params) get byte-for-byte the same response as v1.
    //
    //   - multiline:      regex `(?s)`/`(?m)` semantics over whole-file buffer
    //   - structural:     raw tree-sitter S-expression queries with named captures
    //   - within_symbol:  byte-range scope filter via find_symbol resolution
    //   - bundle: clients that prefer one check can gate on `index_grep_v2`
    //
    // `language` is intentionally NOT a separate capability — it's
    // a refinement of file selection that pairs with any grep mode,
    // and clients always had to pick file scope somehow. The
    // bundle implies it's available.
    "index_grep_multiline",
    "index_grep_structural",
    "index_grep_within_symbol",
    "index_grep_v2",
    // v0.6 — reconciliation worker runs once on persisted cold-mount
    // (`mount_source: "rehydrate"`) to detect files that drifted on
    // disk while the daemon was dead. Surfaces via `Daemon.Stats`'s
    // `reconciliation: { last_run_ns, files_scanned, files_changed,
    // files_removed, throttled }` object. Old clients can ignore the
    // field; this capability lets them gate on its presence.
    "reconciliation_worker",
    // v0.6 — cooperative cancellation of in-flight requests via
    // `Daemon.Cancel { cancel_id }`. Any request that supplies an
    // optional top-level `cancel_id` becomes addressable; the
    // structural scanner, multiline regex, mount cold-walk, and the
    // other Index.* handlers cooperatively poll the token at hot-loop
    // boundaries. Clients that don't set `cancel_id` see unchanged
    // behavior; this is a pure additive capability. See
    // `docs/protocol-v0.md` and `crate::cancel`.
    "cancellable_queries",
    // v0.6+ — `Daemon.Telemetry` RPC returns the **raw** collector
    // inputs that feed `rts telemetry preview` and the (separately
    // feature-gated) 24h ticker. The bounded-enum filter still runs
    // in `rts-mcp`; this RPC just hands the collectors their data
    // without forcing the CLI to mount the workspace twice. Clients
    // that don't ship the telemetry feature ignore the capability.
    "daemon_telemetry",
    // v0.6+ — `Daemon.Telemetry.unresolved_refs_count` (u64): the
    // size of the UNRESOLVED_REFS multimap at snapshot time. Each
    // row is a reference the resolver couldn't bind to a defined
    // symbol — forward references awaiting a later commit, or true
    // externals (stdlib `Vec`, `println!`, etc). A regression that
    // breaks an extractor surfaces as the count jumping up; the
    // real-repo CI bench gates on this. Lets clients gate on the
    // field's presence without protocol version sniffing.
    "daemon_telemetry_unresolved_refs_count",
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

    // v0.6 cancellation telemetry. Always emitted (pre-mount and
    // post-mount alike) so operators can observe `Daemon.Cancel`
    // traffic against a fresh daemon without needing a workspace to
    // be mounted first. `in_flight` reads the registry size at the
    // instant of the snapshot — it's a point-in-time gauge, not a
    // cumulative counter.
    let cancellations = serde_json::json!({
        "total":     state.cancellations_total.load(Relaxed),
        "in_flight": state.cancel_registry.in_flight().await,
    });

    let mut body = serde_json::json!({
        "uptime_ms":     uptime_ms,
        "version":       env!("CARGO_PKG_VERSION"),
        "total_calls":   state.call_counters.total(),
        "calls":         state.call_counters.snapshot(),
        "cancellations": cancellations,
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

        // v0.6 persisted-cold-mount mount_source (U6). Only emitted
        // when a workspace is mounted, since the value is set by the
        // Workspace.Mount handler. Reads under the mutex (rare write
        // contention; one write per mount).
        if let Ok(slot) = state.mount_source.lock() {
            if let Some(ms) = slot.as_ref() {
                obj.insert(
                    "mount_source".into(),
                    serde_json::Value::String(ms.as_label()),
                );
            }
        }

        // Cumulative cache-effectiveness counters. Present at all
        // points after the first Workspace.Mount; pre-mount stays
        // absent. Reset on daemon restart (counters describe this
        // process's served traffic, same convention as call_counters).
        obj.insert(
            "rehydrate_attempts_total".into(),
            serde_json::Value::Number(state.rehydrate_attempts.load(Relaxed).into()),
        );
        obj.insert(
            "rehydrate_successes_total".into(),
            serde_json::Value::Number(state.rehydrate_successes.load(Relaxed).into()),
        );
        if let Ok(tally) = state.rehydrate_invalidations.lock() {
            let invalidations_obj: serde_json::Map<String, serde_json::Value> = tally
                .iter()
                .map(|(reason, count)| (reason.clone(), serde_json::Value::Number((*count).into())))
                .collect();
            obj.insert(
                "rehydrate_invalidations_by_reason".into(),
                serde_json::Value::Object(invalidations_obj),
            );
        }

        // v0.6 reconciliation worker stats. Only emitted alongside the
        // other workspace-scoped fields (pre-mount Stats omits the
        // entire reconciliation object). Default zeros until the
        // worker completes its first pass; after that the snapshot
        // tracks the most recent run.
        if let Ok(snapshot) = state.reconcile_stats.read() {
            if let Ok(value) = serde_json::to_value(&*snapshot) {
                obj.insert("reconciliation".into(), value);
            }
        }
    }

    Ok(body)
}

/// `Daemon.Telemetry` — return the **raw inputs** that feed the
/// `2026-05-19-003-feat-anonymous-opt-in-telemetry-plan.md` wire
/// schema's collector fields. The bounded-enum filter still runs on
/// the rts-mcp side (`telemetry::build_payload`); this RPC just
/// hands the collectors their data so the CLI doesn't need to
/// re-implement per-method counter / latency / cache snapshots.
///
/// **What this RPC does NOT do:**
///
/// - Apply any bounded-enum filtering. The caller's
///   `telemetry::build_payload` is responsible for dropping any keys
///   outside `METHOD_NAMES` / `ERROR_CODES` / `LANGUAGE_NAMES`.
///   Defense-in-depth: this RPC's output map keys are themselves
///   sourced from closed-enum strings (`CallCounters::snapshot`,
///   `MethodLatencyHistograms::enumerated`, `ErrorCode::as_wire_str`,
///   `writer::lang_tag_to_name`), so no user-controlled string can
///   reach the wire.
/// - Send any network traffic. The telemetry HTTP POST lives in
///   the `rts` binary's `telemetry flush` subcommand, behind its own
///   `--features telemetry` gate. This RPC is HTTP-free.
///
/// Wire shape (response):
/// ```jsonc
/// {
///   "uptime_secs":            12345,
///   "languages_indexed":      ["rust", "python"],
///   "method_counts":          { "Index.FindSymbol": 7, ... },
///   "method_latency_p50_ms":  { "Index.FindSymbol": 2, ... },
///   "method_latency_p99_ms":  { "Index.FindSymbol": 8, ... },
///   "error_counts":           { "INVALID_PARAMS": 3 },
///   "cache_hit_rate":         0.84,
///   "cold_walk_ms_p50":       230,
///   "workspace_files":        47123,
///   "unresolved_refs_count":  117
/// }
/// ```
///
/// `unresolved_refs_count` (u64, capability
/// `daemon_telemetry_unresolved_refs_count`) is the size of the
/// UNRESOLVED_REFS multimap at snapshot time: references the resolver
/// couldn't bind to a defined symbol. Forward references decrement the
/// count when their callee finally lands in a later commit; true
/// externals (stdlib `Vec`, `println!`, etc.) accumulate permanently.
/// Lower is better. Real-repo CI bench (PR #123) gates regressions on
/// this metric.
///
/// Method counts use the same `CallCounters::snapshot` map shape as
/// `Daemon.Stats`; the `unknown_method` synthetic key is filtered
/// out here so it never reaches the receiver-side bounded enum.
pub async fn telemetry(
    _params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let uptime_secs = state.uptime().as_secs();

    // method_counts: drop `unknown_method` so the receiver's bounded
    // filter never has to consider it. Everything else comes from the
    // hardcoded enumerate in `CallCounters::snapshot`.
    let snapshot = state.call_counters.snapshot();
    let mut method_counts = serde_json::Map::new();
    if let Some(obj) = snapshot.as_object() {
        for (k, v) in obj {
            if k == "unknown_method" {
                continue;
            }
            // Drop zero counts so the wire stays compact and matches
            // the "empty histogram" shape (`snapshot_percentile_ms`
            // similarly omits zero-sample methods).
            if v.as_u64() == Some(0) {
                continue;
            }
            method_counts.insert(k.clone(), v.clone());
        }
    }

    let p50 = state.method_latency.snapshot_percentile_ms(0.5);
    let p99 = state.method_latency.snapshot_percentile_ms(0.99);

    let error_counts = state.error_counts_snapshot();

    let cache_hit_rate = state.aggregate_cache_hit_rate();

    let cold_walk_ms_p50 = state.cold_walk_ms_p50();

    // languages_indexed: scan the store's FILES table for `lang`
    // tags, map each to its telemetry-bounded enum string. Unknown
    // tags (corrupt META, schema-newer rows) silently drop —
    // defense in depth against bounded-enum violations.
    //
    // unresolved_refs_count comes from the same store snapshot so we
    // amortize the workspace-mutex lock to one acquisition.
    let mut languages_indexed: std::collections::BTreeSet<&'static str> = Default::default();
    let mut workspace_files: u64 = 0;
    let mut unresolved_refs_count: u64 = 0;
    if let Ok(store_guard) = state.store.lock() {
        if let Some(store) = store_guard.as_ref() {
            if let Ok(tag_counts) = store.language_tag_counts() {
                for (tag, count) in &tag_counts {
                    if let Some(name) = crate::writer::lang_tag_to_name(*tag) {
                        languages_indexed.insert(name);
                    }
                    workspace_files = workspace_files.saturating_add(*count);
                }
            }
            if let Ok(n) = store.unresolved_refs_count() {
                unresolved_refs_count = n;
            }
        }
    }
    let languages_indexed: Vec<&'static str> = languages_indexed.into_iter().collect();

    Ok(serde_json::json!({
        "uptime_secs":           uptime_secs,
        "languages_indexed":     languages_indexed,
        "method_counts":         serde_json::Value::Object(method_counts),
        "method_latency_p50_ms": p50,
        "method_latency_p99_ms": p99,
        "error_counts":          error_counts,
        "cache_hit_rate":        cache_hit_rate,
        "cold_walk_ms_p50":      cold_walk_ms_p50,
        "workspace_files":       workspace_files,
        "unresolved_refs_count": unresolved_refs_count,
    }))
}

#[derive(Debug, Deserialize)]
struct CancelParams {
    cancel_id: String,
}

/// `Daemon.Cancel { cancel_id }` — trip any in-flight request that
/// registered the given `cancel_id`. Idempotent: an unknown id (typo,
/// already-completed request, or never-registered) returns
/// `{ cancelled: false }` with no error.
///
/// Bumps `state.cancellations_total` only on a real hit (a registered
/// token was tripped). Stale cancels don't pollute the counter — they
/// represent client-side accounting drift, not daemon work.
///
/// The actual cancellation propagation is cooperative: the targeted
/// handler must poll `CancelToken::is_cancelled()` at its hot-loop
/// boundaries and return a `CANCELLED` envelope. Worst-case latency
/// to abort is the time between two polls (per-match ~50µs for the
/// structural scanner; per-file for the multiline regex; per-batch
/// for the mount cold walk).
pub async fn cancel(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let p: CancelParams = serde_json::from_value(params).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InvalidParams,
            format!("Daemon.Cancel.params failed validation: {e}"),
        )
    })?;
    if p.cancel_id.is_empty() || p.cancel_id.len() > 256 {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`cancel_id` must be 1..=256 characters",
        ));
    }
    let cancelled = state.cancel_registry.cancel(&p.cancel_id).await;
    if cancelled {
        state
            .cancellations_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(serde_json::json!({ "cancelled": cancelled }))
}
