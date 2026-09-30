//! Shared daemon state.
//!
//! At this phase the state is minimal — a refcount of active workspace mounts
//! and an "active connections" gauge driving the idle-shutdown timer (per
//! `docs/protocol-v0.md` §15.2).

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::cancel::CancelRegistry;
use crate::error::{ErrorCode, ProtocolError};
use crate::latency::MethodLatencyHistograms;
use crate::outline::OutlineCache;
use crate::store::Store;
use crate::symbol_pagerank::SymbolPagerankCache;
use crate::watcher::Watcher;
use crate::workspace::MountedWorkspace;

/// How many recent cold-walk durations to keep for the
/// `cold_walk_ms_p50` telemetry collector. Sixteen is a sweet spot:
/// large enough that a single fluke doesn't dominate the median,
/// small enough that the daemon's working-set memory is unaffected.
const COLD_WALK_WINDOW: usize = 16;

/// Result of the v0.6 persisted-cold-mount decision at `Workspace.Mount`.
/// Surfaces via `Daemon.Stats v2` as the `mount_source` field (U6).
///
/// The label rendering ("cold_walk", "rehydrate",
/// "cold_walk_after_invalidation:<reason>", "cold_walk_after_crash")
/// follows `Fingerprint::diff`'s ordering and the plan's documented
/// telemetry strings.
#[derive(Debug, Clone)]
pub enum MountSource {
    /// First-ever mount on this workspace, OR an empty redb file.
    /// Cold walk runs as in pre-v0.6 daemons.
    ColdWalk,
    /// Stored fingerprint matched the current one; the on-disk redb
    /// is trusted as-is and `InitialWalkHandle::spawn` is skipped.
    /// The watcher catches changes from this point forward.
    Rehydrate,
    /// Stored fingerprint mismatched the current one. Data tables
    /// were wiped (META preserved) before the cold walk.
    ColdWalkAfterInvalidation(crate::fingerprint::InvalidationReason),
    /// `META_RECONCILIATION_IN_PROGRESS` sentinel was set at mount
    /// time, indicating the previous daemon died mid-reconciliation.
    /// Data tables were wiped before the cold walk.
    ColdWalkAfterCrash,
}

impl MountSource {
    /// Stable wire label for inclusion in `Daemon.Stats.mount_source`.
    pub fn as_label(&self) -> String {
        match self {
            MountSource::ColdWalk => "cold_walk".to_string(),
            MountSource::Rehydrate => "rehydrate".to_string(),
            MountSource::ColdWalkAfterInvalidation(reason) => {
                format!("cold_walk_after_invalidation:{}", reason.as_label())
            }
            MountSource::ColdWalkAfterCrash => "cold_walk_after_crash".to_string(),
        }
    }
}

/// Watcher health surfaced in `Workspace.Status.watcher_status` (protocol-v0
/// §7.4). Stored as an `AtomicU8` for lock-free reads from the status handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WatcherStatus {
    /// No watcher running yet (no workspace mounted).
    NoWatcher = 0,
    /// Native (`notify::RecommendedWatcher`) running normally.
    Ok = 1,
    /// Native watcher dropped events; daemon transitioned to "indexing" while
    /// re-walking the affected subtree.
    OverflowedRewalking = 2,
    /// Native watcher unavailable (e.g. inotify exhaustion); fell back to
    /// `PollWatcher`. v0 surfaces the status but the cutover is implemented
    /// in §P6 watcher hardening (later session).
    PollingFallback = 3,
}

impl WatcherStatus {
    /// Stable wire-level name surfaced by `Workspace.Status`.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            WatcherStatus::NoWatcher => "no_watcher",
            WatcherStatus::Ok => "ok",
            WatcherStatus::OverflowedRewalking => "overflowed_rewalking",
            WatcherStatus::PollingFallback => "polling_fallback",
        }
    }

    fn from_u8(n: u8) -> Self {
        match n {
            1 => WatcherStatus::Ok,
            2 => WatcherStatus::OverflowedRewalking,
            3 => WatcherStatus::PollingFallback,
            _ => WatcherStatus::NoWatcher,
        }
    }
}

/// One mounted workspace root and everything owned by it.
///
/// Multi-root: every field here used to live in a single slot on
/// [`DaemonState`]. Keying them per root is what lets two roots answer
/// independently — each owns its own index, watcher, writer task, and
/// persisted-cold-mount decision, so a worktree is never answered from the
/// index of the repo root it was branched from.
#[derive(Debug)]
pub struct MountedRoot {
    /// Canonical path + `(dev, inode)` fingerprint. `fingerprint.id_str()` is
    /// this mount's stable id — the `workspace_id` a caller addresses it by.
    pub workspace: MountedWorkspace,
    /// On-disk index for this root (`${XDG_STATE_HOME}/rts/<id>/db.redb`).
    pub store: Arc<Store>,
    /// Owning handle for this root's file watcher. Never read — held for its
    /// `Drop`: dropping the entry on unmount is what stops the debouncer
    /// thread.
    #[allow(dead_code)]
    pub watcher: Watcher,
    /// Cancellation token that stops this root's writer task.
    pub writer_cancel: tokio_util::sync::CancellationToken,
    /// Persisted-cold-mount decision taken at this root's mount. Reported by
    /// `Daemon.Stats.mount_source` for the default root.
    pub mount_source: MountSource,
    /// Live `Workspace.Mount` refs held on this root, across all connections.
    /// The root is torn down when this reaches zero.
    pub refcount: u32,
}

impl MountedRoot {
    /// Stable id of this mount (`WorkspaceFingerprint::id_str`, hex chars).
    pub fn id(&self) -> String {
        self.workspace.fingerprint.id_str()
    }

    /// Canonical absolute path of this root.
    pub fn root(&self) -> &Path {
        &self.workspace.canonical.path
    }
}

/// The daemon's mounted roots, keyed by `workspace_id`.
///
/// `order` records mount order so the **default root** — the one a call that
/// names no root is served by — is the oldest root still mounted. Unmounting
/// the oldest root promotes the next one rather than leaving the daemon
/// without a default while other roots are still live.
#[derive(Debug, Default)]
pub struct MountTable {
    roots: std::collections::BTreeMap<String, MountedRoot>,
    order: Vec<String>,
}

impl MountTable {
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&MountedRoot> {
        self.roots.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut MountedRoot> {
        self.roots.get_mut(id)
    }

    /// Id of the default root: the oldest root still mounted.
    pub fn default_id(&self) -> Option<&str> {
        self.order
            .iter()
            .find(|id| self.roots.contains_key(*id))
            .map(String::as_str)
    }

    /// The default root itself. See [`Self::default_id`].
    pub fn default_root(&self) -> Option<&MountedRoot> {
        self.default_id().and_then(|id| self.roots.get(id))
    }

    /// Insert a root, returning its `workspace_id`. Re-inserting the same id
    /// (a remount after the entry was released) keeps its original place in
    /// mount order, so the default root stays stable.
    pub fn insert(&mut self, root: MountedRoot) -> String {
        let id = root.id();
        if !self.order.contains(&id) {
            self.order.push(id.clone());
        }
        self.roots.insert(id.clone(), root);
        id
    }

    /// Remove and return a root, dropping it from mount order too.
    pub fn remove(&mut self, id: &str) -> Option<MountedRoot> {
        let removed = self.roots.remove(id);
        if removed.is_some() {
            self.order.retain(|o| o != id);
        }
        removed
    }

    /// Id of the mounted root whose canonical path is exactly `canonical`.
    pub fn id_for_path(&self, canonical: &Path) -> Option<String> {
        self.roots
            .iter()
            .find(|(_, root)| root.root() == canonical)
            .map(|(id, _)| id.clone())
    }

    /// Resolve a caller-supplied root reference — a `workspace_id` or a
    /// workspace path — to a mounted id. `None` resolves to the default root.
    /// An unrecognised reference resolves to `None`; callers turn that into
    /// `WORKSPACE_MISMATCH` rather than substituting another root's answer.
    pub fn resolve(&self, reference: Option<&str>) -> Option<String> {
        match reference {
            None => self.default_id().map(str::to_owned),
            Some(id) if self.roots.contains_key(id) => Some(id.to_owned()),
            Some(path) => {
                let canonical = crate::workspace::canonicalize(Path::new(path)).ok()?;
                self.id_for_path(&canonical.path)
            }
        }
    }

    /// `(workspace_id, canonical path)` for every mounted root, in mount
    /// order. Surfaced as the `mounted_roots` array on
    /// `Workspace.Mount` / `Workspace.Status`.
    pub fn describe(&self) -> Vec<(String, String)> {
        self.order
            .iter()
            .filter_map(|id| {
                self.roots
                    .get(id)
                    .map(|root| (id.clone(), root.root().to_string_lossy().into_owned()))
            })
            .collect()
    }
}

/// Which root a single RPC is served by.
#[derive(Debug, Clone)]
pub struct CallRoot {
    /// `workspace_id` of the serving root (its mount id).
    pub id: String,
    /// Canonical absolute path of the serving root.
    pub path: PathBuf,
    /// The serving root's index.
    pub store: Arc<Store>,
}

/// Optional per-call root selector.
///
/// Carried in the request **envelope** (`workspace_id`) and stamped into
/// `params` by `methods::dispatch`, so handlers can resolve their root without
/// a new argument in every handler signature. It is a routing field, exactly
/// like the envelope's `cancel_id` / `deadline_ms`: no method's param schema
/// declares it and no model ever supplies it — the MCP layer infers the root
/// from the call's own paths and names it here.
#[derive(Debug, Clone, Default)]
pub struct RootHint(pub Option<String>);

impl RootHint {
    /// Read the hint the dispatcher stamped into `params`.
    pub fn from_params(params: &serde_json::Value) -> Self {
        Self(
            params
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        )
    }
}

/// Process-wide daemon state. Cheap to `Arc`-share; everything inside is
/// interior-mutable.
#[derive(Debug)]
pub struct DaemonState {
    /// Number of currently-open client connections. The idle-shutdown timer
    /// only fires when this is 0 *and* `last_activity` is older than the
    /// configured window.
    pub active_connections: AtomicU32,
    /// Last time a connection was accepted or a workspace was mounted. Stored
    /// as a `Mutex<Instant>` rather than an atomic because `Instant` doesn't
    /// have a portable atomic representation; contention is negligible.
    pub last_activity: Mutex<Instant>,
    /// Every workspace root this daemon serves, keyed by `workspace_id`.
    ///
    /// A daemon is **multi-root**: `Workspace.Mount` adds a root (idempotent
    /// per canonical path — a repeat mount joins and holds a second ref), and
    /// `Workspace.Unmount` releases one. Each root owns its own on-disk index
    /// (`${XDG_STATE_HOME}/rts/<workspace_id>/db.redb`), file watcher, writer
    /// task, and persisted-cold-mount decision, so N worktrees of one repo
    /// are served by one process without the index of one answering for
    /// another.
    ///
    /// Which root serves a given `Index.*` call is decided by the caller
    /// (`workspace_id` in the request envelope; see [`RootHint`]) and falls
    /// back to the *default root* — the first root still mounted. Handlers
    /// never guess from the filesystem: a call that names no root gets the
    /// default root's answer, and a call that names an unmounted root is an
    /// error, not a silent substitution.
    pub mounts: Mutex<MountTable>,
    /// Aggregate refcount of `Workspace.Mount` minus `Workspace.Unmount`
    /// across all currently-open connections and all roots. Per-root
    /// refcounts live in [`MountedRoot::refcount`]; this is the sum, kept for
    /// `Daemon.Stats` and for the "nothing is mounted any more" signal.
    pub mount_refcount: AtomicU32,
    /// Process start time, used only for `Daemon.Ping.uptime_ms`.
    pub started_at: Instant,
    /// Daemon-internal generation counter. Bumps on every committed index
    /// write; later phases expose this via `Workspace.Status.index_generation`.
    /// Currently always 0 (no writer yet).
    pub index_generation: AtomicU64,
    /// Unix-epoch milliseconds when the writer's `ColdWalkComplete` flush
    /// committed. `0` means "not yet" — either no workspace mounted, or
    /// the cold walk hasn't drained its first batch yet.
    ///
    /// Surfaced via `Daemon.Stats v2` (capability `daemon_stats_v2`) so
    /// `rts-bench doctor` and the agent-bench harness can distinguish
    /// "index ready" from "indexing in progress" without polling
    /// `Workspace.Status.progress.phase`.
    pub cold_walk_completed_at_ms: AtomicU64,
    /// File-watcher health for `Workspace.Status.watcher_status` (§7.4).
    watcher_status: AtomicU8,
    /// Single-slot memoization cache for `Index.Outline`. Keyed by
    /// `(workspace_id, index_generation, params)` — writer commits bump the
    /// generation and invalidate the entry implicitly on the next lookup. The
    /// `workspace_id` is part of the key because one daemon serves N roots:
    /// without it, an outline computed for one root would be served for
    /// another root sitting at the same generation. See `outline.rs` module
    /// docs for the rationale.
    pub outline_cache: OutlineCache,
    /// Single-slot cache for symbol-level PageRank (v0.3 U4). Keyed by
    /// `(workspace_id, index_generation)` — writer commits bump the generation
    /// and the next `find_symbol` triggers a recompute. Mirrors
    /// `outline_cache`'s shape (including the multi-root `workspace_id` key
    /// component); see `symbol_pagerank.rs` for the algorithm + Deepening §C3
    /// for the perf budget.
    pub symbol_pagerank_cache: SymbolPagerankCache,
    /// LRU cache for rendered signatures, keyed by
    /// `(path, start_byte, end_byte, mtime_ns)`. v0.3 closure walks
    /// hit the tree-sitter signature renderer once per dep; the bench
    /// observed `render_loop_total` averaging 1248 µs (max 10529 µs)
    /// on `crates/rts-core` deps-mode reads, dominating
    /// `read_symbol(deps=true)` after `content_version` got its own
    /// cache. Same shape: invalidates implicitly when mtime changes.
    pub signature_cache: SignatureCache,
    /// LRU cache for `content_version` (blake3-hash-of-file-bytes).
    /// Keyed by `(path, mtime_ns, generation)`. Without this, every
    /// `read_symbol` re-hashes the entire file body — 100k-LOC
    /// workspace bench saw `content_version` averaging 904 µs per
    /// call and peaking at 2325 µs (single biggest cost on the
    /// G5 read_symbol regression hot path). With the cache, repeat
    /// reads on the same file resolve in tens of ns. Invalidates
    /// implicitly when mtime or generation changes.
    pub content_version_cache: ContentVersionCache,
    /// v0.4 prewarm coordination. `prewarm_in_flight` is set to true
    /// while the daemon's `--workspace`-triggered background mount is
    /// running; `prewarm_done` is notified when it completes (success
    /// or failure). `Workspace.Mount` checks these so a Mount RPC that
    /// races with prewarm waits for the prewarm to finish (joining
    /// its work) instead of trying to mount in parallel — concurrent
    /// mounts of the same path would fight over the redb file, the
    /// notify watcher, and the writer task.
    ///
    /// Without prewarm (the daemon was spawned without `--workspace`),
    /// `prewarm_in_flight` stays false and Mount takes the normal
    /// path; nothing waits on `prewarm_done`.
    pub prewarm_in_flight: std::sync::atomic::AtomicBool,
    pub prewarm_done: tokio::sync::Notify,
    /// Serializes the mount critical section (`workspace::mount_inner`).
    /// The idempotency check drops the `workspace` lock before
    /// `Store::open`'s `.await` (the guard is `!Send`), so without this
    /// the startup prewarm and an explicit `Workspace.Mount` RPC can both
    /// pass the check and both open the same redb file — redb then refuses
    /// the second open with "Database already open", wedging the daemon
    /// (issue #150). Held across the whole check-open-set sequence so
    /// exactly one mount opens the store; the loser observes `workspace`
    /// already set and returns the idempotent status.
    pub mount_serialize: tokio::sync::Mutex<()>,
    /// v0.5.7+ per-session call counters. Bumped in `methods::dispatch`
    /// before each handler fires (so even errored calls count — they
    /// still represent agent intent). Surfaced via `Daemon.Stats`.
    ///
    /// Why: every reflection-on-dogfooding round of this project so
    /// far has been *anecdotal* — "I think I used grep more than
    /// find_symbol." With these counters and `Daemon.Stats`, future
    /// reflection rounds can quote actual numbers. Bumping is one
    /// atomic increment per RPC; negligible overhead next to the
    /// rest of the dispatch path.
    pub call_counters: CallCounters,
    /// v0.6 (`index_grep_structural` capability) — LRU cache for
    /// compiled tree-sitter `Query` objects keyed on
    /// `(Language, query_text)`. Agent-supplied structural queries
    /// land here on first compile; subsequent invocations with the
    /// same `(language, query_text)` pair pull from the cache
    /// instead of re-paying the `Query::new` cost (hundreds of µs).
    /// Eviction is recency-ordered; capacity is fixed at compile
    /// time inside the QueryCache (see
    /// `methods/grep_v2/query_cache.rs`).
    pub query_cache: crate::methods::grep_v2::query_cache::QueryCache,
    /// v0.6 persisted-cold-mount cumulative counters. Cache-
    /// effectiveness telemetry: without these we can't tell whether
    /// the rehydrate path is actually doing its job.
    pub rehydrate_attempts: AtomicU64,
    pub rehydrate_successes: AtomicU64,
    /// Per-reason invalidation tally. Keyed by the
    /// `InvalidationReason::as_label()` string so the JSON shape is
    /// stable.
    pub rehydrate_invalidations: Mutex<std::collections::BTreeMap<String, u64>>,
    /// v0.6 persisted-cold-mount reconciliation stats. Shared with the
    /// reconciler worker (spawned from `Workspace.Mount` on the
    /// `Rehydrate` branch) and read by `Daemon.Stats`. `RwLock` rather
    /// than `Mutex` because reads via `Daemon.Stats` outnumber writes
    /// (one write per pass) by a large margin.
    pub reconcile_stats: Arc<RwLock<crate::reconciler::ReconcileStats>>,
    /// In-flight cancellation tokens, keyed by client-supplied
    /// `cancel_id`. See `crate::cancel` for the design rationale.
    /// `Arc` so the dispatcher can hand it to `Daemon.Cancel` and to
    /// the RAII guard without juggling `&self` lifetimes.
    pub cancel_registry: Arc<CancelRegistry>,
    /// Cumulative count of cancellations that actually tripped a
    /// registered token. Surfaced as `Daemon.Stats.cancellations.total`.
    /// Stale-cancel hits (unknown id, idempotent) do not bump this.
    pub cancellations_total: AtomicU64,
    /// Cumulative count of requests aborted by a per-request deadline
    /// (`deadline_ms` elapsed → token tripped → `DEADLINE_EXCEEDED`).
    /// Surfaced via `Daemon.Stats.deadlines.total`. Distinct from
    /// `cancellations_total` (explicit `Daemon.Cancel`).
    pub deadlines_total: AtomicU64,
    /// v0.6+ telemetry collector: per-method latency histograms.
    /// Populated by the dispatcher around every handler call;
    /// surfaced by `Daemon.Telemetry` (which `rts telemetry preview`
    /// and the 24h ticker both read). See `crate::latency`.
    pub method_latency: MethodLatencyHistograms,
    /// v0.6+ telemetry collector: per-error-code counts. Bumped in
    /// the dispatcher's error path with the wire-level error code
    /// string (`ProtocolError::code.as_wire_str()`). Closed-enum keys
    /// from `ErrorCode::as_wire_str` only; the dispatcher cannot leak
    /// attacker-controlled strings into this map. Read at snapshot
    /// time via `error_counts_snapshot()`.
    pub error_counts: Mutex<std::collections::BTreeMap<String, u64>>,
    /// v0.6+ telemetry collector: cache hit/miss counters across the
    /// four query-time caches. Surfaced as a single aggregate
    /// `cache_hit_rate` (the telemetry schema field of the same
    /// name); a per-cache breakdown would risk the receiver inferring
    /// workspace-specific access patterns.
    pub cache_counters: CacheCounters,
    /// v0.6+ telemetry collector: Unix-epoch milliseconds when the
    /// most recent cold walk started (`Workspace.Mount` non-rehydrate
    /// path). Paired with `cold_walk_completed_at_ms` so the writer's
    /// `ColdWalkComplete` handler can push the duration into
    /// `cold_walk_durations_ms` for the `cold_walk_ms_p50` collector.
    /// `0` means "no cold walk has started in this daemon process."
    pub cold_walk_started_at_ms: AtomicU64,
    /// v0.6+ telemetry collector: rolling window of recent cold-walk
    /// durations in milliseconds (last [`COLD_WALK_WINDOW`] entries,
    /// FIFO eviction). The `Daemon.Telemetry` snapshot computes p50
    /// over this window.
    pub cold_walk_durations_ms: Mutex<VecDeque<u64>>,
    /// v0.6+ telemetry counter (PR #128, capability
    /// `daemon_telemetry_unresolved_refs_gc`). Cumulative number of
    /// UNRESOLVED_REFS garbage-collection invocations: one bump per
    /// removed file the writer processed. Paired with
    /// `unresolved_refs_gc_dropped_total` so an external observer can
    /// distinguish "GC is firing but finding nothing" from "GC is not
    /// firing." Reset on daemon restart, same convention as
    /// `cancellations_total`.
    pub unresolved_refs_gc_runs_total: AtomicU64,
    /// v0.6+ telemetry counter (PR #128). Cumulative number of
    /// UNRESOLVED_REFS rows the GC has dropped — orphaned forward-
    /// reference entries whose source file was deleted. Bounds the
    /// growth of `Daemon.Telemetry.unresolved_refs_count`; a healthy
    /// long-running daemon should see this advance whenever files
    /// disappear and `unresolved_refs_count` stay bounded.
    pub unresolved_refs_gc_dropped_total: AtomicU64,
}

/// Cache hit/miss counters shared across the daemon's four query-time
/// caches. Each cache calls `record_hit`/`record_miss` from its
/// existing `get`/`get_or_compute` paths.
///
/// All atomics use `Relaxed` ordering — we're computing a ratio for
/// telemetry, not a coherent transaction.
#[derive(Debug, Default)]
pub struct CacheCounters {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl CacheCounters {
    /// Bump the hits counter. Public so future caches that don't
    /// own their own atomics can feed into the same aggregate. The
    /// four query-time caches (outline, signature, content_version,
    /// symbol_pagerank) instead own per-cache atomics that
    /// `aggregate_cache_hits` sums.
    #[allow(dead_code)]
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the misses counter. See [`Self::record_hit`].
    #[allow(dead_code)]
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Cache hit rate in `[0.0, 1.0]` over this counter pair only.
    /// Most callers want `DaemonState::aggregate_cache_hit_rate`
    /// instead, which folds all four per-cache counters in.
    #[allow(dead_code)]
    pub fn hit_rate(&self) -> f64 {
        let h = self.hits.load(Ordering::Relaxed);
        let m = self.misses.load(Ordering::Relaxed);
        let total = h.saturating_add(m);
        if total == 0 {
            return 0.0;
        }
        h as f64 / total as f64
    }
}

/// Per-method call counts for the daemon's RPC surface. All fields
/// are `AtomicU64` so dispatch can bump them lock-free; the
/// `Daemon.Stats` reader does relaxed loads which is fine — we don't
/// need cross-counter ordering, only eventually-consistent totals.
///
/// The counter set deliberately mirrors the protocol-v0 method names
/// so a future schema change (new method, renamed method) is caught
/// at compile time by the dispatcher rather than silently miscounted.
#[derive(Debug, Default)]
pub struct CallCounters {
    pub daemon_ping: AtomicU64,
    pub daemon_stats: AtomicU64,
    pub daemon_cancel: AtomicU64,
    pub daemon_shutdown: AtomicU64,
    pub workspace_mount: AtomicU64,
    pub workspace_status: AtomicU64,
    pub workspace_unmount: AtomicU64,
    pub session_open: AtomicU64,
    pub session_close: AtomicU64,
    pub index_find_symbol: AtomicU64,
    pub index_find_callers: AtomicU64,
    /// verify-v0 P1.U1: `Index.VerifySymbol` calls.
    pub index_verify_symbol: AtomicU64,
    /// verify-v0 P1.U2: `Index.VerifySignature` calls.
    pub index_verify_signature: AtomicU64,
    /// verify-v0 P1.U3: `Index.VerifyImport` calls.
    pub index_verify_import: AtomicU64,
    /// verify-v0 P1.U4: `Index.VerifyClaims` calls.
    pub index_verify_claims: AtomicU64,
    pub index_impact_of: AtomicU64,
    pub index_verify_impact: AtomicU64,
    pub index_verify_edit: AtomicU64,
    pub index_read_range: AtomicU64,
    pub index_read_symbol: AtomicU64,
    pub index_read_symbol_at: AtomicU64,
    pub index_outline: AtomicU64,
    pub index_grep: AtomicU64,
    /// v0.6 sub-counter: `Index.Grep` calls that exercised the
    /// multiline-regex path (`regex: true, multiline: true`). Bumped
    /// in addition to (not instead of) `index_grep`; appears as a
    /// sibling field in the `Daemon.Stats` snapshot so the existing
    /// closed-enum shape stays stable for v1 consumers.
    pub index_grep_multiline: AtomicU64,
    /// v0.6 sub-counter: `Index.Grep` calls that exercised the
    /// structural-query path (`structural_query` set). Sibling of
    /// `index_grep`; bumped in addition to the parent counter.
    pub index_grep_structural: AtomicU64,
    /// v0.6 sub-counter: `Index.Grep` calls that exercised the
    /// `within_symbol` post-filter (`within_symbol` set). Sibling of
    /// `index_grep`; bumped in addition to the parent counter.
    pub index_grep_within_symbol: AtomicU64,
    /// Method name didn't match any known handler. A growing
    /// `unknown_method` count over time usually means a wire-protocol
    /// version skew (rts-mcp newer than daemon, or vice versa).
    pub unknown_method: AtomicU64,
}

impl CallCounters {
    /// Snapshot as a `serde_json::Value` map for the `Daemon.Stats`
    /// response body. Relaxed loads — no fence needed; we're
    /// reporting an approximate point-in-time view, not a coherent
    /// transaction.
    pub fn snapshot(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering::Relaxed;
        serde_json::json!({
            "Daemon.Ping":         self.daemon_ping.load(Relaxed),
            "Daemon.Stats":        self.daemon_stats.load(Relaxed),
            "Daemon.Cancel":       self.daemon_cancel.load(Relaxed),
            "Daemon.Shutdown":     self.daemon_shutdown.load(Relaxed),
            "Workspace.Mount":     self.workspace_mount.load(Relaxed),
            "Workspace.Status":    self.workspace_status.load(Relaxed),
            "Workspace.Unmount":   self.workspace_unmount.load(Relaxed),
            "Session.Open":        self.session_open.load(Relaxed),
            "Session.Close":       self.session_close.load(Relaxed),
            "Index.FindSymbol":    self.index_find_symbol.load(Relaxed),
            "Index.FindCallers":   self.index_find_callers.load(Relaxed),
            "Index.VerifySymbol":  self.index_verify_symbol.load(Relaxed),
            "Index.VerifySignature": self.index_verify_signature.load(Relaxed),
            "Index.VerifyImport":  self.index_verify_import.load(Relaxed),
            "Index.VerifyClaims":  self.index_verify_claims.load(Relaxed),
            "Index.ImpactOf":      self.index_impact_of.load(Relaxed),
            "Index.VerifyImpact":  self.index_verify_impact.load(Relaxed),
            "Index.VerifyEdit":    self.index_verify_edit.load(Relaxed),
            "Index.ReadRange":     self.index_read_range.load(Relaxed),
            "Index.ReadSymbol":    self.index_read_symbol.load(Relaxed),
            "Index.ReadSymbolAt":  self.index_read_symbol_at.load(Relaxed),
            "Index.Outline":       self.index_outline.load(Relaxed),
            "Index.Grep":          self.index_grep.load(Relaxed),
            // v0.6 grep_v2 sub-counters. Sibling fields (not nested)
            // so existing `--output json` consumers stay parseable.
            // See `docs/plans/2026-05-18-002-feat-index-grep-v2-plan.md` §U7.
            "Index.Grep.multiline":      self.index_grep_multiline.load(Relaxed),
            "Index.Grep.structural":     self.index_grep_structural.load(Relaxed),
            "Index.Grep.within_symbol":  self.index_grep_within_symbol.load(Relaxed),
            "unknown_method":      self.unknown_method.load(Relaxed),
        })
    }

    /// Total of all method counters. Used by `Daemon.Stats` to surface
    /// a session-level traffic indicator.
    pub fn total(&self) -> u64 {
        use std::sync::atomic::Ordering::Relaxed;
        self.daemon_ping.load(Relaxed)
            + self.daemon_stats.load(Relaxed)
            + self.daemon_cancel.load(Relaxed)
            + self.daemon_shutdown.load(Relaxed)
            + self.workspace_mount.load(Relaxed)
            + self.workspace_status.load(Relaxed)
            + self.workspace_unmount.load(Relaxed)
            + self.session_open.load(Relaxed)
            + self.session_close.load(Relaxed)
            + self.index_find_symbol.load(Relaxed)
            + self.index_find_callers.load(Relaxed)
            + self.index_verify_symbol.load(Relaxed)
            + self.index_verify_signature.load(Relaxed)
            + self.index_verify_import.load(Relaxed)
            + self.index_verify_claims.load(Relaxed)
            + self.index_impact_of.load(Relaxed)
            + self.index_verify_impact.load(Relaxed)
            + self.index_verify_edit.load(Relaxed)
            + self.index_read_range.load(Relaxed)
            + self.index_read_symbol.load(Relaxed)
            + self.index_read_symbol_at.load(Relaxed)
            + self.index_outline.load(Relaxed)
            + self.index_grep.load(Relaxed)
            + self.index_grep_multiline.load(Relaxed)
            + self.index_grep_structural.load(Relaxed)
            + self.index_grep_within_symbol.load(Relaxed)
            + self.unknown_method.load(Relaxed)
    }
}

/// Per-(path, start_byte, end_byte, mtime) cache for rendered
/// signatures. Each closure walker call hits the tree-sitter
/// renderer once per dep; profiling on `crates/rts-core` showed
/// `render_loop_total` averaging 1248 µs per closure call (max
/// 10529 µs) — the dominant remaining cost after the content_version
/// cache. Same FIFO eviction + invalidate-via-mtime shape.
#[derive(Default, Debug)]
pub struct SignatureCache {
    inner: Mutex<SignatureCacheInner>,
    /// v0.6+ telemetry collector. Aggregated by
    /// `DaemonState::aggregate_cache_hits` for the telemetry
    /// `cache_hit_rate` field.
    hits: AtomicU64,
    misses: AtomicU64,
}

#[derive(Default, Debug)]
struct SignatureCacheInner {
    order: std::collections::VecDeque<SignatureKey>,
    map: std::collections::HashMap<SignatureKey, Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SignatureKey {
    path: std::path::PathBuf,
    start_byte: u32,
    end_byte: u32,
    mtime_ns: i128,
}

impl SignatureCache {
    /// Cap sized larger than ContentVersionCache because a single
    /// file may host many defs; a typical workspace has thousands
    /// of distinct def sites. 4096 is enough for `crates/rts-core`'s
    /// full symbol set + headroom; eviction is FIFO.
    const MAX_ENTRIES: usize = 4096;

    pub fn new() -> Self {
        Self::default()
    }

    /// Get-or-compute. `None` signature values (renderer returned
    /// `None` because the file's language has no renderer or the
    /// slice didn't parse cleanly) are cached too — repeated calls
    /// on the same dep don't re-try a renderer that already failed.
    pub fn get_or_compute(
        &self,
        path: &std::path::Path,
        start_byte: u32,
        end_byte: u32,
        mtime_ns: i128,
        f: impl FnOnce() -> Option<String>,
    ) -> Option<String> {
        let key = SignatureKey {
            path: path.to_path_buf(),
            start_byte,
            end_byte,
            mtime_ns,
        };
        if let Ok(g) = self.inner.lock() {
            if let Some(v) = g.map.get(&key) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return v.clone();
            }
        }
        // Miss: compute now and insert.
        self.misses.fetch_add(1, Ordering::Relaxed);
        let value = f();
        if let Ok(mut g) = self.inner.lock() {
            while g.order.len() >= Self::MAX_ENTRIES {
                if let Some(oldest) = g.order.pop_front() {
                    g.map.remove(&oldest);
                } else {
                    break;
                }
            }
            g.map.insert(key.clone(), value.clone());
            g.order.push_back(key);
        }
        value
    }

    /// Snapshot `(hits, misses)` for telemetry aggregation.
    pub fn hits_misses(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.map.len()).unwrap_or(0)
    }
}

/// Per-(path, mtime, generation) cache for `content_version`. Sized
/// to the workspace's hot-file working set; v0.3 ships a fixed cap
/// of 256 distinct files (matches the find_symbol MAX_MATCHES cap
/// so the worst-case bench never thrashes), evicted FIFO. Concurrent
/// reads share one mutex; if contention shows up in profiling, swap
/// for a sharded LRU later.
#[derive(Default, Debug)]
pub struct ContentVersionCache {
    inner: Mutex<ContentVersionCacheInner>,
    /// v0.6+ telemetry collector. See `SignatureCache::hits` for
    /// rationale.
    hits: AtomicU64,
    misses: AtomicU64,
}

#[derive(Default, Debug)]
struct ContentVersionCacheInner {
    /// FIFO order — oldest-first — for eviction. Bounded to
    /// `MAX_ENTRIES`.
    order: std::collections::VecDeque<ContentVersionKey>,
    map: std::collections::HashMap<ContentVersionKey, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ContentVersionKey {
    path: std::path::PathBuf,
    mtime_ns: i128,
    generation: u64,
}

impl ContentVersionCache {
    /// Cap. 256 matches the find_symbol MAX_MATCHES so the worst-case
    /// bench (every result triggers a read_symbol) never thrashes.
    const MAX_ENTRIES: usize = 256;

    pub fn new() -> Self {
        Self::default()
    }

    /// Get-or-compute. Computes via `f` only on cache miss. The
    /// closure receives no args — caller has already gathered the
    /// bytes; we only cache the resulting `String`. Returns the
    /// (cached or freshly-computed) version string.
    pub fn get_or_compute(
        &self,
        path: &std::path::Path,
        mtime_ns: i128,
        generation: u64,
        f: impl FnOnce() -> String,
    ) -> String {
        let key = ContentVersionKey {
            path: path.to_path_buf(),
            mtime_ns,
            generation,
        };
        if let Ok(g) = self.inner.lock() {
            if let Some(v) = g.map.get(&key) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return v.clone();
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        // Miss path: compute, then insert. Hold lock just for the
        // insert so the (cpu-bound) compute doesn't block other
        // readers.
        let value = f();
        if let Ok(mut g) = self.inner.lock() {
            // Evict oldest if at cap. Wrap in if-let so a poisoned
            // lock degrades to "no caching" instead of panicking.
            while g.order.len() >= Self::MAX_ENTRIES {
                if let Some(oldest) = g.order.pop_front() {
                    g.map.remove(&oldest);
                } else {
                    break;
                }
            }
            g.map.insert(key.clone(), value.clone());
            g.order.push_back(key);
        }
        value
    }

    /// Snapshot `(hits, misses)` for telemetry aggregation.
    pub fn hits_misses(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.map.len()).unwrap_or(0)
    }
}

impl DaemonState {
    pub fn new() -> Self {
        Self {
            active_connections: AtomicU32::new(0),
            last_activity: Mutex::new(Instant::now()),
            mounts: Mutex::new(MountTable::default()),
            mount_refcount: AtomicU32::new(0),
            started_at: Instant::now(),
            index_generation: AtomicU64::new(0),
            cold_walk_completed_at_ms: AtomicU64::new(0),
            watcher_status: AtomicU8::new(WatcherStatus::NoWatcher as u8),
            outline_cache: OutlineCache::new(),
            symbol_pagerank_cache: SymbolPagerankCache::new(),
            signature_cache: SignatureCache::new(),
            content_version_cache: ContentVersionCache::new(),
            prewarm_in_flight: std::sync::atomic::AtomicBool::new(false),
            prewarm_done: tokio::sync::Notify::new(),
            mount_serialize: tokio::sync::Mutex::new(()),
            call_counters: CallCounters::default(),
            query_cache: crate::methods::grep_v2::query_cache::QueryCache::new(),
            rehydrate_attempts: AtomicU64::new(0),
            rehydrate_successes: AtomicU64::new(0),
            rehydrate_invalidations: Mutex::new(std::collections::BTreeMap::new()),
            reconcile_stats: Arc::new(RwLock::new(crate::reconciler::ReconcileStats::default())),
            cancel_registry: Arc::new(CancelRegistry::new()),
            cancellations_total: AtomicU64::new(0),
            deadlines_total: AtomicU64::new(0),
            method_latency: MethodLatencyHistograms::default(),
            error_counts: Mutex::new(std::collections::BTreeMap::new()),
            cache_counters: CacheCounters::default(),
            cold_walk_started_at_ms: AtomicU64::new(0),
            cold_walk_durations_ms: Mutex::new(VecDeque::with_capacity(COLD_WALK_WINDOW)),
            unresolved_refs_gc_runs_total: AtomicU64::new(0),
            unresolved_refs_gc_dropped_total: AtomicU64::new(0),
        }
    }

    /// Resolve the root that serves a call carrying `hint`.
    ///
    /// - a `workspace_id` naming a mounted root → that root;
    /// - no hint → the default root (oldest still mounted);
    /// - a `workspace_id` naming nothing → `WORKSPACE_MISMATCH`, carrying the
    ///   live `mounted_roots` list. Never a silent fallback: answering about a
    ///   different tree is precisely the failure this routing exists to
    ///   prevent;
    /// - nothing mounted at all → `INDEX_NOT_READY` (unchanged from the
    ///   single-root daemon).
    pub fn root_for_call(&self, hint: &RootHint) -> Result<CallRoot, ProtocolError> {
        let table = self.mounts.lock().map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("mounts poisoned: {e}"))
        })?;
        let id = match table.resolve(hint.0.as_deref()) {
            Some(id) => id,
            None => {
                if let Some(requested) = hint.0.as_deref() {
                    let mounted: Vec<serde_json::Value> = table
                        .describe()
                        .into_iter()
                        .map(|(id, path)| serde_json::json!({ "workspace_id": id, "path": path }))
                        .collect();
                    return Err(ProtocolError::new(
                        ErrorCode::WorkspaceMismatch,
                        format!(
                            "no mounted root with workspace_id `{requested}`; \
                             call Workspace.Mount for it first"
                        ),
                    )
                    .with_data(serde_json::json!({
                        "requested": requested,
                        "mounted_roots": mounted,
                    })));
                }
                return Err(ProtocolError::new(
                    ErrorCode::IndexNotReady,
                    "no workspace mounted",
                ));
            }
        };
        let root = table.get(&id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::InternalError,
                "mount table lost a root between resolve and read",
            )
        })?;
        Ok(CallRoot {
            id,
            path: root.root().to_path_buf(),
            store: root.store.clone(),
        })
    }

    /// `(workspace_id, canonical path, mount_source)` of the default root, for
    /// the process-wide telemetry surfaces (`Daemon.Stats`, `Workspace.Status`).
    /// `None` when nothing is mounted.
    pub fn default_root_info(&self) -> Option<(String, String, MountSource)> {
        let table = self.mounts.lock().ok()?;
        let id = table.default_id()?.to_owned();
        let root = table.get(&id)?;
        Some((
            id,
            root.root().to_string_lossy().into_owned(),
            root.mount_source.clone(),
        ))
    }

    /// The default root's index handle. For process-wide telemetry that
    /// reports a single root's totals (`Daemon.Stats` language tags). `None`
    /// when nothing is mounted.
    pub fn default_root_store(&self) -> Option<Arc<Store>> {
        let table = self.mounts.lock().ok()?;
        table.default_root().map(|root| root.store.clone())
    }

    /// Bump the per-error-code count. Called by the dispatcher when
    /// a handler returns `Err(ProtocolError)`. The caller passes the
    /// closed-enum wire-level string from `ErrorCode::as_wire_str`,
    /// not the human-readable message, so map keys stay bounded.
    pub fn record_error(&self, code: &'static str) {
        if let Ok(mut map) = self.error_counts.lock() {
            *map.entry(code.to_string()).or_insert(0) += 1;
        }
    }

    /// Snapshot per-error-code counts. Empty when no errors have
    /// been recorded yet (the default-state shape expected by
    /// `tests/fixtures/telemetry_v1.golden.json`).
    pub fn error_counts_snapshot(&self) -> std::collections::BTreeMap<String, u64> {
        match self.error_counts.lock() {
            Ok(map) => map.clone(),
            Err(_) => std::collections::BTreeMap::new(),
        }
    }

    /// Record one completed cold-walk's duration in milliseconds.
    /// FIFO-evicts past [`COLD_WALK_WINDOW`].
    pub fn record_cold_walk_duration_ms(&self, ms: u64) {
        if let Ok(mut q) = self.cold_walk_durations_ms.lock() {
            while q.len() >= COLD_WALK_WINDOW {
                q.pop_front();
            }
            q.push_back(ms);
        }
    }

    /// Aggregate cache hit/miss counts across all four query-time
    /// caches (outline, signature, content_version, symbol_pagerank)
    /// plus any standalone `cache_counters` accumulators. Returns
    /// `(total_hits, total_misses)`; the telemetry layer divides to
    /// get `cache_hit_rate`.
    pub fn aggregate_cache_hits(&self) -> (u64, u64) {
        let (oh, om) = self.outline_cache.hits_misses();
        let (sh, sm) = self.signature_cache.hits_misses();
        let (ch, cm) = self.content_version_cache.hits_misses();
        let (ph, pm) = self.symbol_pagerank_cache.hits_misses();
        // Plus standalone counters (room for future caches to feed
        // into the same aggregate without each adding a new field).
        let extra_h = self.cache_counters.hits.load(Ordering::Relaxed);
        let extra_m = self.cache_counters.misses.load(Ordering::Relaxed);
        (
            oh.saturating_add(sh)
                .saturating_add(ch)
                .saturating_add(ph)
                .saturating_add(extra_h),
            om.saturating_add(sm)
                .saturating_add(cm)
                .saturating_add(pm)
                .saturating_add(extra_m),
        )
    }

    /// Aggregate cache hit rate across all four query-time caches.
    /// Returns 0.0 when no cache access has been recorded yet.
    pub fn aggregate_cache_hit_rate(&self) -> f64 {
        let (h, m) = self.aggregate_cache_hits();
        let total = h.saturating_add(m);
        if total == 0 {
            return 0.0;
        }
        h as f64 / total as f64
    }

    /// p50 of the rolling cold-walk-duration window, in milliseconds.
    /// Returns 0 when no walks have completed in this daemon process —
    /// the same shape the telemetry schema's `cold_walk_ms_p50` uses
    /// for a freshly started daemon.
    pub fn cold_walk_ms_p50(&self) -> u64 {
        let q = match self.cold_walk_durations_ms.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        if q.is_empty() {
            return 0;
        }
        let mut sorted: Vec<u64> = q.iter().copied().collect();
        sorted.sort_unstable();
        // Standard middle-element p50 for an odd-sized vec; lower
        // middle for an even-sized vec (no interpolation — keeps us
        // u64-clean and avoids fractional ms in the wire schema).
        sorted[(sorted.len() - 1) / 2]
    }

    /// Current watcher status. Cheap lock-free read.
    pub fn watcher_status(&self) -> WatcherStatus {
        WatcherStatus::from_u8(self.watcher_status.load(Ordering::Relaxed))
    }

    /// Set the watcher status. Called from the watcher's background worker;
    /// the next `Workspace.Status` call reflects the new value.
    pub fn set_watcher_status(&self, status: WatcherStatus) {
        self.watcher_status.store(status as u8, Ordering::Relaxed);
    }

    /// Bump the activity timestamp. Called on connect, on every method
    /// dispatch, and on mount/unmount.
    pub fn touch(&self) {
        if let Ok(mut last) = self.last_activity.lock() {
            *last = Instant::now();
        }
    }

    /// `(active_connections == 0) && (now - last_activity > window)`.
    pub fn is_idle(&self, window: std::time::Duration) -> bool {
        if self.active_connections.load(Ordering::Relaxed) > 0 {
            return false;
        }
        let last = match self.last_activity.lock() {
            Ok(g) => *g,
            Err(_) => return false,
        };
        last.elapsed() >= window
    }

    pub fn uptime(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn idle_detection_respects_active_connections() {
        let state = DaemonState::new();
        // A long window with last_activity = now → not idle.
        assert!(!state.is_idle(Duration::from_secs(60)));
        state.active_connections.store(1, Ordering::Relaxed);
        // Active connection blocks idle even when the window has elapsed.
        std::thread::sleep(Duration::from_millis(10));
        assert!(!state.is_idle(Duration::from_millis(1)));
        state.active_connections.store(0, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(10));
        assert!(state.is_idle(Duration::from_millis(1)));
    }

    #[test]
    fn content_version_cache_returns_first_value_on_repeat() {
        let cache = ContentVersionCache::new();
        let path = std::path::Path::new("/tmp/dummy.rs");
        let mut call_count = 0u32;
        let v1 = cache.get_or_compute(path, 100, 1, || {
            call_count += 1;
            "first".to_string()
        });
        let v2 = cache.get_or_compute(path, 100, 1, || {
            call_count += 1;
            "should-not-call".to_string()
        });
        assert_eq!(v1, "first");
        assert_eq!(v2, "first", "repeat call must hit cache, not recompute");
        assert_eq!(call_count, 1, "compute closure should run exactly once");
    }

    #[test]
    fn content_version_cache_keys_on_mtime_and_generation() {
        let cache = ContentVersionCache::new();
        let path = std::path::Path::new("/tmp/dummy.rs");
        let _ = cache.get_or_compute(path, 100, 1, || "mtime=100,gen=1".to_string());
        // Same path, different mtime → fresh compute.
        let v_mtime = cache.get_or_compute(path, 200, 1, || "mtime=200,gen=1".to_string());
        assert_eq!(v_mtime, "mtime=200,gen=1");
        // Same path + mtime, different generation → fresh compute.
        let v_gen = cache.get_or_compute(path, 100, 2, || "mtime=100,gen=2".to_string());
        assert_eq!(v_gen, "mtime=100,gen=2");
        assert_eq!(cache.len(), 3, "all three distinct keys should be stored");
    }

    #[test]
    fn content_version_cache_evicts_at_cap() {
        let cache = ContentVersionCache::new();
        // Insert MAX_ENTRIES + 5 entries; first 5 should evict FIFO.
        for i in 0..(ContentVersionCache::MAX_ENTRIES + 5) {
            let path = std::path::PathBuf::from(format!("/tmp/file{i}.rs"));
            cache.get_or_compute(&path, 0, 0, || format!("v{i}"));
        }
        assert_eq!(
            cache.len(),
            ContentVersionCache::MAX_ENTRIES,
            "cache should cap at MAX_ENTRIES"
        );
        // First 5 keys should be evicted; check that touching one of
        // them re-computes (call_count would bump in real code).
        let mut recomputed = false;
        let _ = cache.get_or_compute(std::path::Path::new("/tmp/file0.rs"), 0, 0, || {
            recomputed = true;
            "v0-fresh".to_string()
        });
        assert!(recomputed, "FIFO-evicted entry must re-compute");
    }

    #[test]
    fn touch_resets_activity_window() {
        let state = DaemonState::new();
        std::thread::sleep(Duration::from_millis(15));
        assert!(state.is_idle(Duration::from_millis(10)));
        state.touch();
        // After touch, the window starts over.
        assert!(!state.is_idle(Duration::from_millis(10)));
    }
}
