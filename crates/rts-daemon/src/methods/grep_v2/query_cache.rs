//! Compiled-`Query` LRU keyed on `(Language, query_text)`.
//!
//! `rts_core::query::Query::new` recompiles the tree-sitter query
//! DSL on every call — fine for one-off use, but the structural
//! `Index.Grep` path runs the *same* user-supplied query against
//! many files per call, and agents often re-issue the same query
//! across turns. Caching the compiled `Query` amortizes the
//! compilation cost across both axes.
//!
//! ## Design
//!
//! * **Key.** `(Language, String)` — the language enum plus the
//!   raw S-expression text the caller sent. Two callers that
//!   submit byte-identical query text share the cache slot.
//! * **Value.** `Arc<rts_core::query::Query>`. Cloning the Arc
//!   is cheap; the underlying `tree_sitter::Query` is `Send + Sync`
//!   in the rts-core wrapper, so multiple threads can dispatch
//!   matches against the same compiled query without
//!   contention.
//! * **Capacity.** 64 entries. See
//!   [`crate::methods::grep_v2::limits::QUERY_CACHE_CAPACITY`] for
//!   the rationale.
//! * **Eviction.** Recency-ordered (LRU). No time-based eviction —
//!   the cache lives for the daemon's lifetime and the workspace
//!   doesn't go stale (tree-sitter grammars are linked at compile
//!   time).
//!
//! ## Telemetry
//!
//! Each `get_or_compile` call bumps either [`QueryCache::hits`] or
//! [`QueryCache::misses`]. The U7 telemetry layer surfaces these
//! in `Daemon.Stats`; this module also emits a `tracing::debug!`
//! line per outcome so hand-verification doesn't require a stats
//! call.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use lru::LruCache;
use rust_tree_sitter::{Language, query::Query};

use super::limits::QUERY_CACHE_CAPACITY;

/// LRU-cached compiled queries. Cheap to share via `Arc` on
/// `DaemonState`; internally synchronised with a `Mutex` (acquisition
/// is uncontended for the common cache-hit path).
#[derive(Debug)]
pub struct QueryCache {
    inner: Mutex<LruCache<(Language, String), Arc<Query>>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl Default for QueryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryCache {
    /// Construct a cache at the configured [`QUERY_CACHE_CAPACITY`].
    pub fn new() -> Self {
        Self::with_capacity(QUERY_CACHE_CAPACITY)
    }

    /// Test helper: construct a cache at a non-default capacity so
    /// eviction tests can exercise the boundary without inserting
    /// 64 dummy queries.
    pub fn with_capacity(cap: usize) -> Self {
        let cap = NonZeroUsize::new(cap.max(1)).expect("capacity >= 1");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Get the cached compiled `Query` for `(language, query_text)`,
    /// compiling it via `Query::new` on miss.
    ///
    /// Returns `Ok(Arc<Query>)` on success — same shape whether the
    /// entry was a hit or a miss. Returns `Err` only when
    /// `Query::new` itself fails (syntax error in the S-expression);
    /// failed-to-compile entries are NOT cached, so the next call
    /// with the same text re-runs the compile and returns the
    /// same diagnostic.
    pub fn get_or_compile(
        &self,
        language: Language,
        query_text: &str,
    ) -> Result<Arc<Query>, rust_tree_sitter::error::Error> {
        // Fast path: lock, look up, clone Arc on hit.
        if let Ok(mut g) = self.inner.lock() {
            if let Some(q) = g.get(&(language, query_text.to_string())) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    target: "rts_daemon::grep_v2::query_cache",
                    language = ?language,
                    query_text_len = query_text.len(),
                    "query_cache hit"
                );
                return Ok(Arc::clone(q));
            }
        }

        // Miss: compile outside the lock so other threads can hit
        // the cache while we work. `Query::new` is CPU-bound but
        // not slow enough to warrant a per-language compile lock —
        // worst-case two threads compile the same query and the
        // last-write-wins insert is harmless.
        let compiled = Query::new(language, query_text)?;
        let arc = Arc::new(compiled);

        if let Ok(mut g) = self.inner.lock() {
            // `put` returns the evicted entry's value if the cache
            // was at capacity; we don't need it.
            let _ = g.put((language, query_text.to_string()), Arc::clone(&arc));
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            target: "rts_daemon::grep_v2::query_cache",
            language = ?language,
            query_text_len = query_text.len(),
            "query_cache miss (compiled)"
        );
        Ok(arc)
    }

    /// Snapshot of hit/miss counters. Relaxed loads — surface a
    /// point-in-time approximation, not a coherent transaction.
    pub fn stats(&self) -> QueryCacheStats {
        QueryCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }

    /// Current entry count. Test-only — uses the LRU's `len()`.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }
}

/// Counters surfaced by [`QueryCache::stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueryCacheStats {
    pub hits: u64,
    pub misses: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miss_then_hit_for_same_key() {
        let cache = QueryCache::new();
        let first = cache
            .get_or_compile(Language::Rust, "(function_item) @fn")
            .expect("first compile");
        let second = cache
            .get_or_compile(Language::Rust, "(function_item) @fn")
            .expect("second compile");
        // Same Arc — hit returned the stored value.
        assert!(
            Arc::ptr_eq(&first, &second),
            "second call must hit the cache (same Arc)"
        );
        let stats = cache.stats();
        assert_eq!(stats.misses, 1, "first call must miss");
        assert_eq!(stats.hits, 1, "second call must hit");
    }

    #[test]
    fn distinct_query_text_yields_distinct_entries() {
        let cache = QueryCache::new();
        let q1 = cache
            .get_or_compile(Language::Rust, "(function_item) @fn")
            .expect("compile q1");
        let q2 = cache
            .get_or_compile(Language::Rust, "(struct_item) @s")
            .expect("compile q2");
        assert!(
            !Arc::ptr_eq(&q1, &q2),
            "distinct query text must produce distinct Arcs"
        );
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.stats().misses, 2);
        assert_eq!(cache.stats().hits, 0);
    }

    #[test]
    fn distinct_language_yields_distinct_entries() {
        let cache = QueryCache::new();
        // Same text, different language — both must compile.
        let q_rust = cache.get_or_compile(Language::Rust, "(function_item) @fn");
        // Python doesn't have `function_item` — compile must fail
        // for Python, but the Rust slot is still cached.
        let q_python = cache.get_or_compile(Language::Python, "(function_item) @fn");
        assert!(q_rust.is_ok(), "rust query should compile");
        assert!(
            q_python.is_err(),
            "python query against a Rust node kind should fail"
        );
        assert_eq!(cache.len(), 1, "only the successful entry is stored");
    }

    #[test]
    fn evicts_oldest_at_capacity() {
        let cache = QueryCache::with_capacity(2);
        let _q1 = cache
            .get_or_compile(Language::Rust, "(function_item) @a")
            .expect("compile a");
        let _q2 = cache
            .get_or_compile(Language::Rust, "(struct_item) @b")
            .expect("compile b");
        // Insert a third; oldest (q1) should evict.
        let _q3 = cache
            .get_or_compile(Language::Rust, "(impl_item) @c")
            .expect("compile c");
        assert_eq!(cache.len(), 2, "cache must respect capacity bound");
        // Re-fetching q1 should now miss (cache evicted it).
        let _q1_again = cache
            .get_or_compile(Language::Rust, "(function_item) @a")
            .expect("re-compile a");
        let stats = cache.stats();
        // Inserts: a, b, c, a-again → 4 misses.
        assert_eq!(stats.misses, 4);
        assert_eq!(stats.hits, 0);
    }

    #[test]
    fn invalid_query_returns_error_not_cached() {
        let cache = QueryCache::new();
        let err = cache.get_or_compile(Language::Rust, "(unbalanced");
        assert!(err.is_err());
        assert_eq!(cache.len(), 0, "failed compiles must not be cached");
        // Retrying the same broken query must NOT be a hit.
        let err2 = cache.get_or_compile(Language::Rust, "(unbalanced");
        assert!(err2.is_err());
        assert_eq!(cache.stats().hits, 0);
    }
}
