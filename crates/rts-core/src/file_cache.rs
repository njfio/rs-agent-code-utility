//! File content caching utility to reduce redundant I/O operations.
//!
//! Provides an LRU-bounded in-memory cache of file contents so that repeated
//! reads during analysis go through O(1) lookups instead of disk I/O.
//!
//! Prior 0.1.x versions of this module used a `HashMap` plus a "first-key from
//! HashMap iteration" eviction policy — effectively random eviction at the
//! mercy of `HashMap`'s rehash seed. The performance-oracle review of the
//! agentic-retrieval pivot plan flagged this as a real latency hazard
//! (random eviction == hot symbols dropped at random under load). This module
//! now backs the cache with the `lru` crate, giving deterministic
//! least-recently-used eviction.

use crate::error::Result;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use tracing::warn;

/// Default cache capacity (file count).
const DEFAULT_CAPACITY: usize = 1000;

/// LRU-bounded in-memory file content cache.
///
/// Cheap to `Clone` — internally an `Arc` over a shared `Mutex<LruCache>` and
/// `RwLock<CacheStats>`. The cache uses a `Mutex` rather than `RwLock` because
/// `LruCache::get` mutates the recency-ordering and therefore requires `&mut`.
#[derive(Debug, Clone)]
pub struct FileCache {
    cache: Arc<Mutex<LruCache<PathBuf, String>>>,
    stats: Arc<RwLock<CacheStats>>,
}

/// Cache statistics for monitoring performance.
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: usize,
    /// Number of cache misses.
    pub misses: usize,
    /// Number of files currently cached.
    pub cached_files: usize,
    /// Total bytes cached.
    pub total_bytes: usize,
}

impl FileCache {
    /// Create a new file cache with the default capacity (`DEFAULT_CAPACITY` entries).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a new file cache with the given capacity.
    ///
    /// `max_size == 0` is silently clamped to 1 — `LruCache` requires a
    /// non-zero capacity, and a zero-capacity cache is degenerate anyway.
    pub fn with_capacity(max_size: usize) -> Self {
        let cap = NonZeroUsize::new(max_size.max(1)).expect("max_size.max(1) is non-zero");
        Self {
            cache: Arc::new(Mutex::new(LruCache::new(cap))),
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    /// Read file content, using cache if available.
    pub fn read_to_string<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        let path = path.as_ref().to_path_buf();

        // Cache lookup. `LruCache::get` is `&mut`, so we need the mutex
        // exclusively even for hits — short critical section.
        {
            let mut cache = self.cache.lock().map_err(|e| {
                crate::error::Error::internal_error(
                    "file_cache",
                    format!("Failed to acquire cache lock: {}", e),
                )
            })?;
            if let Some(content) = cache.get(&path) {
                let content = content.clone();
                drop(cache);
                self.bump_stat(|s| s.hits += 1);
                return Ok(content);
            }
        }

        // Cache miss — read from disk and insert.
        let content = std::fs::read_to_string(&path)?;
        self.insert(path, content.clone());
        self.bump_stat(|s| s.misses += 1);
        Ok(content)
    }

    /// Insert content into the cache, evicting the LRU entry if at capacity.
    fn insert(&self, path: PathBuf, content: String) {
        let content_size = content.len();
        let mut cache = match self.cache.lock() {
            Ok(c) => c,
            Err(e) => {
                // Poisoned-lock case. Visible via the daemon's tracing
                // subscriber; previously this was lost to a bare `eprintln!`
                // on stderr.
                warn!(
                    target: "rust_tree_sitter::file_cache",
                    error = %e,
                    "failed to acquire cache lock; skipping insert",
                );
                return;
            }
        };

        // `LruCache::put` returns the previous value for the same key, OR the
        // LRU-evicted entry when the cache is at capacity. We can't tell which
        // case via the return alone, so we recompute size from the len delta.
        let len_before = cache.len();
        let evicted = cache.put(path, content);
        let len_after = cache.len();
        drop(cache);

        let evicted_bytes = evicted.as_ref().map(|s| s.len()).unwrap_or(0);
        // Net delta: +content_size for the insert, -evicted_bytes for the
        // replaced/evicted entry. `cached_files` only grows on a true insert
        // (no displacement of an existing key).
        self.bump_stat(|s| {
            if len_after > len_before {
                s.cached_files = s.cached_files.saturating_add(1);
            }
            s.total_bytes = s
                .total_bytes
                .saturating_add(content_size)
                .saturating_sub(evicted_bytes);
        });
    }

    /// Update stats while swallowing lock errors. Stats are best-effort.
    fn bump_stat<F: FnOnce(&mut CacheStats)>(&self, f: F) {
        if let Ok(mut stats) = self.stats.write() {
            f(&mut stats);
        }
    }

    /// Clear the cache.
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
        if let Ok(mut stats) = self.stats.write() {
            stats.cached_files = 0;
            stats.total_bytes = 0;
        }
    }

    /// Get a snapshot of cache statistics.
    pub fn stats(&self) -> CacheStats {
        match self.stats.read() {
            Ok(stats) => CacheStats {
                hits: stats.hits,
                misses: stats.misses,
                cached_files: stats.cached_files,
                total_bytes: stats.total_bytes,
            },
            Err(_) => CacheStats::default(),
        }
    }

    /// Get the cache hit ratio (0.0 if no requests yet).
    pub fn hit_ratio(&self) -> f64 {
        let stats = self.stats();
        let total = stats.hits + stats.misses;
        if total == 0 {
            0.0
        } else {
            stats.hits as f64 / total as f64
        }
    }

    /// Check if a file is currently cached.
    ///
    /// Returns `false` on lock failure. Note: this does **not** count as a
    /// hit and does **not** bump recency. Use `read_to_string` for the
    /// canonical hot path.
    pub fn contains<P: AsRef<Path>>(&self, path: P) -> bool {
        match self.cache.lock() {
            Ok(cache) => cache.contains(path.as_ref()),
            Err(_) => false,
        }
    }

    /// Get the number of cached files.
    pub fn len(&self) -> usize {
        match self.cache.lock() {
            Ok(cache) => cache.len(),
            Err(_) => 0,
        }
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        match self.cache.lock() {
            Ok(cache) => cache.is_empty(),
            Err(_) => true,
        }
    }
}

impl Default for FileCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheStats {
    /// Calculate cache efficiency percentage (0.0 if no requests yet).
    pub fn efficiency(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }

    /// Get average file size in bytes (0.0 if cache is empty).
    pub fn average_file_size(&self) -> f64 {
        if self.cached_files == 0 {
            0.0
        } else {
            self.total_bytes as f64 / self.cached_files as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_file_cache_basic_operations() {
        let cache = FileCache::new();
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "Hello, World!").unwrap();

        // First read: miss.
        let content1 = cache.read_to_string(&file_path).unwrap();
        assert_eq!(content1, "Hello, World!");
        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.cached_files, 1);

        // Second read: hit.
        let content2 = cache.read_to_string(&file_path).unwrap();
        assert_eq!(content2, "Hello, World!");
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.cached_files, 1);
        assert_eq!(cache.hit_ratio(), 0.5);
    }

    #[test]
    fn test_lru_eviction_is_deterministic() {
        // Capacity 2: read 1, 2, 3 — the LRU rule says 1 (oldest) is evicted.
        let cache = FileCache::with_capacity(2);
        let temp_dir = TempDir::new().unwrap();
        let f1 = temp_dir.path().join("a.txt");
        let f2 = temp_dir.path().join("b.txt");
        let f3 = temp_dir.path().join("c.txt");
        fs::write(&f1, "a").unwrap();
        fs::write(&f2, "b").unwrap();
        fs::write(&f3, "c").unwrap();

        cache.read_to_string(&f1).unwrap(); // most recent: f1
        cache.read_to_string(&f2).unwrap(); // most recent: f2 ; LRU: f1
        cache.read_to_string(&f3).unwrap(); // evicts f1

        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&f1), "f1 should be evicted (LRU)");
        assert!(cache.contains(&f2), "f2 should remain");
        assert!(cache.contains(&f3), "f3 should remain");
    }

    #[test]
    fn test_lru_eviction_respects_recency() {
        // Touch the oldest entry before adding a new one — that touch should
        // make it the most-recent, so the (now-untouched) other entry is
        // evicted instead.
        let cache = FileCache::with_capacity(2);
        let temp_dir = TempDir::new().unwrap();
        let f1 = temp_dir.path().join("a.txt");
        let f2 = temp_dir.path().join("b.txt");
        let f3 = temp_dir.path().join("c.txt");
        fs::write(&f1, "a").unwrap();
        fs::write(&f2, "b").unwrap();
        fs::write(&f3, "c").unwrap();

        cache.read_to_string(&f1).unwrap(); // most recent: f1
        cache.read_to_string(&f2).unwrap(); // most recent: f2 ; LRU: f1
        // Touch f1 → now f2 is the LRU.
        cache.read_to_string(&f1).unwrap();
        cache.read_to_string(&f3).unwrap(); // evicts f2

        assert!(cache.contains(&f1), "f1 was just touched, should remain");
        assert!(!cache.contains(&f2), "f2 should be evicted (LRU)");
        assert!(cache.contains(&f3), "f3 should remain (just inserted)");
    }

    #[test]
    fn test_cache_clear() {
        let cache = FileCache::new();
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "Test content").unwrap();

        cache.read_to_string(&file_path).unwrap();
        assert_eq!(cache.len(), 1);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
        let stats = cache.stats();
        assert_eq!(stats.cached_files, 0);
        assert_eq!(stats.total_bytes, 0);
    }

    #[test]
    fn test_cache_stats() {
        let cache = FileCache::new();
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let content = "Test content for stats";
        fs::write(&file_path, content).unwrap();

        cache.read_to_string(&file_path).unwrap();
        cache.read_to_string(&file_path).unwrap();

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.cached_files, 1);
        assert_eq!(stats.total_bytes, content.len());
        assert_eq!(stats.efficiency(), 50.0);
        assert_eq!(stats.average_file_size(), content.len() as f64);
    }
}
