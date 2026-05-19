//! Shared daemon state.
//!
//! At this phase the state is minimal — a refcount of active workspace mounts
//! and an "active connections" gauge driving the idle-shutdown timer (per
//! `docs/protocol-v0.md` §15.2).

use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::outline::OutlineCache;
use crate::store::Store;
use crate::symbol_pagerank::SymbolPagerankCache;
use crate::watcher::Watcher;
use crate::workspace::MountedWorkspace;

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
    /// The single workspace this daemon serves. A daemon is workspace-pinned —
    /// the first `Workspace.Mount` decides; subsequent mounts on different
    /// paths return `WorkspaceVanished`. Stored as `Mutex<Option<...>>` so the
    /// accept loop and method handlers can both reach it.
    pub workspace: Mutex<Option<MountedWorkspace>>,
    /// Owning handle for the active file watcher. `None` until first Mount.
    /// Dropped on Unmount (refcount → 0); dropping stops the debouncer thread.
    pub watcher: Mutex<Option<Watcher>>,
    /// On-disk index. `None` until first Mount; opened at
    /// `${XDG_STATE_HOME}/rts/<workspace_id>/db.redb`. Shared via `Arc` so the
    /// writer task and read handlers can both reach it without cloning the
    /// `DaemonState`'s big bag of state.
    pub store: Mutex<Option<std::sync::Arc<Store>>>,
    /// Cancellation token that stops the writer task on the last Unmount.
    pub writer_cancel: Mutex<Option<tokio_util::sync::CancellationToken>>,
    /// Refcount of `Workspace.Mount` minus `Workspace.Unmount` across all
    /// currently-open connections. When this drops back to 0 with idle time
    /// elapsed, the daemon exits.
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
    /// `(index_generation, params)` — writer commits bump the generation
    /// and invalidate the entry implicitly on the next lookup. See
    /// `outline.rs` module docs for the rationale.
    pub outline_cache: OutlineCache,
    /// Single-slot cache for symbol-level PageRank (v0.3 U4). Keyed by
    /// `index_generation` — writer commits bump the generation and the
    /// next `find_symbol` triggers a recompute. Mirrors `outline_cache`'s
    /// shape; see `symbol_pagerank.rs` for the algorithm + Deepening §C3
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
    /// v0.6 persisted-cold-mount mount source. Set once per
    /// `Workspace.Mount` after the fingerprint decision; surfaced via
    /// `Daemon.Stats v2`'s `mount_source` field. None pre-mount.
    /// `Mutex<Option<...>>` rather than atomic because the enum
    /// carries a heap-allocated `InvalidationReason`; mount happens
    /// once per daemon lifetime in practice, so the mutex cost is
    /// negligible.
    pub mount_source: Mutex<Option<MountSource>>,
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
    pub daemon_shutdown: AtomicU64,
    pub workspace_mount: AtomicU64,
    pub workspace_status: AtomicU64,
    pub workspace_unmount: AtomicU64,
    pub session_open: AtomicU64,
    pub session_close: AtomicU64,
    pub index_find_symbol: AtomicU64,
    pub index_find_callers: AtomicU64,
    pub index_impact_of: AtomicU64,
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
            "Daemon.Shutdown":     self.daemon_shutdown.load(Relaxed),
            "Workspace.Mount":     self.workspace_mount.load(Relaxed),
            "Workspace.Status":    self.workspace_status.load(Relaxed),
            "Workspace.Unmount":   self.workspace_unmount.load(Relaxed),
            "Session.Open":        self.session_open.load(Relaxed),
            "Session.Close":       self.session_close.load(Relaxed),
            "Index.FindSymbol":    self.index_find_symbol.load(Relaxed),
            "Index.FindCallers":   self.index_find_callers.load(Relaxed),
            "Index.ImpactOf":      self.index_impact_of.load(Relaxed),
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
            + self.daemon_shutdown.load(Relaxed)
            + self.workspace_mount.load(Relaxed)
            + self.workspace_status.load(Relaxed)
            + self.workspace_unmount.load(Relaxed)
            + self.session_open.load(Relaxed)
            + self.session_close.load(Relaxed)
            + self.index_find_symbol.load(Relaxed)
            + self.index_find_callers.load(Relaxed)
            + self.index_impact_of.load(Relaxed)
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
                return v.clone();
            }
        }
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
                return v.clone();
            }
        }
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
            workspace: Mutex::new(None),
            watcher: Mutex::new(None),
            store: Mutex::new(None),
            writer_cancel: Mutex::new(None),
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
            call_counters: CallCounters::default(),
            query_cache: crate::methods::grep_v2::query_cache::QueryCache::new(),
            mount_source: Mutex::new(None),
            rehydrate_attempts: AtomicU64::new(0),
            rehydrate_successes: AtomicU64::new(0),
            rehydrate_invalidations: Mutex::new(std::collections::BTreeMap::new()),
            reconcile_stats: Arc::new(RwLock::new(crate::reconciler::ReconcileStats::default())),
        }
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
