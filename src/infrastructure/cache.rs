//! Real caching infrastructure with in-memory and disk-based storage
//!
//! Provides multi-level caching for analysis results, API responses,
//! and computed data with TTL support and automatic cleanup.

use super::paths::app_cache_dir;
use crate::log_debug as debug;
#[cfg(feature = "net")]
use crate::log_error as error;
use anyhow::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Multi-level cache with memory and disk storage
#[derive(Clone)]
pub struct Cache {
    memory_cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    disk_cache_dir: Option<PathBuf>,
    default_ttl: Duration,
    max_memory_entries: usize,
    total_hits: Arc<AtomicU64>,
    total_misses: Arc<AtomicU64>,
}

/// Cache entry with TTL and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub key: String,
    pub data: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    pub access_count: u64,
    pub last_accessed: u64,
    pub size_bytes: usize,
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub memory_entries: usize,
    pub memory_size_bytes: usize,
    pub disk_entries: usize,
    pub disk_size_bytes: usize,
    pub hit_rate: f64,
    pub total_hits: u64,
    pub total_misses: u64,
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub enable_memory: bool,
    pub enable_disk: bool,
    pub memory_max_entries: usize,
    pub disk_cache_dir: Option<PathBuf>,
    pub default_ttl: Duration,
    pub cleanup_interval: Duration,
}

impl Cache {
    /// Create a new cache with the given configuration
    pub fn new(config: CacheConfig) -> Result<Self> {
        let disk_cache_dir = config.disk_cache_dir.clone();

        let cache = Self {
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
            disk_cache_dir: config.disk_cache_dir,
            default_ttl: config.default_ttl,
            max_memory_entries: config.memory_max_entries,
            total_hits: Arc::new(AtomicU64::new(0)),
            total_misses: Arc::new(AtomicU64::new(0)),
        };

        // Create disk cache directory if needed
        if let Some(disk_dir) = &disk_cache_dir {
            if config.enable_disk {
                std::fs::create_dir_all(disk_dir)?;
                debug!("Disk cache directory created: {}", disk_dir.display());
            }
        }

        // Start cleanup task
        #[cfg(feature = "net")]
        if config.enable_memory || config.enable_disk {
            let cache_clone = cache.clone();
            let cleanup_interval = config.cleanup_interval;
            tokio::spawn(async move {
                cache_clone.cleanup_task(cleanup_interval).await;
            });
        }

        Ok(cache)
    }

    /// Store data in cache with default TTL
    pub async fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.set_with_ttl(key, value, self.default_ttl).await
    }

    /// Store data in cache with custom TTL
    pub async fn set_with_ttl<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl: Duration,
    ) -> Result<()> {
        let data = serde_json::to_vec(value)?;
        let now = crate::current_timestamp_millis();
        let expires_at = now.saturating_add(crate::duration_millis_saturated(ttl));

        let entry = CacheEntry {
            key: key.to_string(),
            data: data.clone(),
            created_at: now,
            expires_at,
            access_count: 0,
            last_accessed: now,
            size_bytes: data.len(),
        };

        // Store in memory cache
        self.set_memory_entry(key, entry.clone()).await?;

        // Store in disk cache if enabled
        if self.disk_cache_dir.is_some() {
            self.set_disk_entry(key, &entry).await?;
        }

        // Record a cache miss since the value had to be inserted
        self.total_misses.fetch_add(1, Ordering::Relaxed);

        debug!(
            "Cached entry: {} (size: {} bytes, TTL: {:?})",
            key,
            data.len(),
            ttl
        );
        Ok(())
    }

    /// Get data from cache
    pub async fn get<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>> {
        // Try memory cache first
        if let Some(entry) = self.get_memory_entry(key).await? {
            self.total_hits.fetch_add(1, Ordering::Relaxed);
            let value: T = serde_json::from_slice(&entry.data)?;
            return Ok(Some(value));
        }

        // Try disk cache
        if let Some(entry) = self.get_disk_entry(key).await? {
            self.total_hits.fetch_add(1, Ordering::Relaxed);
            let value: T = serde_json::from_slice(&entry.data)?;

            // Promote to memory cache
            self.set_memory_entry(key, entry).await?;

            return Ok(Some(value));
        }

        self.total_misses.fetch_add(1, Ordering::Relaxed);
        Ok(None)
    }

    /// Check if key exists in cache
    pub async fn exists(&self, key: &str) -> bool {
        self.memory_cache.read().contains_key(key)
            || self.disk_entry_exists(key).await.unwrap_or_else(|e| {
                debug!(
                    "Failed to check disk cache existence for key '{}': {}",
                    key, e
                );
                false
            })
    }

    /// Remove entry from cache
    pub async fn remove(&self, key: &str) -> Result<bool> {
        let memory_removed = self.memory_cache.write().remove(key).is_some();
        let disk_removed = self.remove_disk_entry(key).await.unwrap_or_else(|e| {
            debug!("Failed to remove disk cache entry for key '{}': {}", key, e);
            false
        });

        Ok(memory_removed || disk_removed)
    }

    /// Clear all cache entries
    pub async fn clear(&self) -> Result<()> {
        self.memory_cache.write().clear();

        if let Some(disk_dir) = &self.disk_cache_dir {
            if disk_dir.exists() {
                fs::remove_dir_all(disk_dir)?;
                fs::create_dir_all(disk_dir)?;
            }
        }

        debug!("Cache cleared");
        Ok(())
    }

    /// Get cache statistics
    pub async fn stats(&self) -> Result<CacheStats> {
        let (memory_entries, memory_size_bytes) = {
            let memory_cache = self.memory_cache.read();
            let memory_entries = memory_cache.len();
            let memory_size_bytes: usize =
                memory_cache.values().map(|entry| entry.size_bytes).sum();
            (memory_entries, memory_size_bytes)
        };

        let (disk_entries, disk_size_bytes) = self.get_disk_stats().await?;

        let total_hits = self.total_hits.load(Ordering::Relaxed);
        let total_misses = self.total_misses.load(Ordering::Relaxed);
        let hit_rate = if total_hits + total_misses > 0 {
            total_hits as f64 / (total_hits + total_misses) as f64
        } else {
            0.0
        };

        Ok(CacheStats {
            memory_entries,
            memory_size_bytes,
            disk_entries,
            disk_size_bytes,
            hit_rate,
            total_hits,
            total_misses,
        })
    }

    /// Store entry in memory cache
    async fn set_memory_entry(&self, key: &str, mut entry: CacheEntry) -> Result<()> {
        // Check if we need to evict entries
        if self.memory_cache.read().len() >= self.max_memory_entries {
            self.evict_lru_entries(1).await?;
        }

        entry.last_accessed = crate::current_timestamp_millis();
        self.memory_cache.write().insert(key.to_string(), entry);
        Ok(())
    }

    /// Get entry from memory cache
    async fn get_memory_entry(&self, key: &str) -> Result<Option<CacheEntry>> {
        let now = crate::current_timestamp_millis();
        let mut cache = self.memory_cache.write();
        let mut expired = false;
        let mut result = None;

        if let Some(entry) = cache.get_mut(key) {
            if now > entry.expires_at {
                expired = true;
            } else {
                entry.access_count += 1;
                entry.last_accessed = now;
                result = Some(entry.clone());
            }
        }

        if expired {
            cache.remove(key);
        }

        Ok(result)
    }

    /// Store entry in disk cache
    async fn set_disk_entry(&self, key: &str, entry: &CacheEntry) -> Result<()> {
        if let Some(_disk_dir) = &self.disk_cache_dir {
            let file_path = self.get_disk_file_path(key)?;
            let data = serde_json::to_vec(entry)?;
            fs::write(&file_path, data)?;
            debug!("Stored disk cache entry: {}", file_path.display());
        }
        Ok(())
    }

    /// Get entry from disk cache
    async fn get_disk_entry(&self, key: &str) -> Result<Option<CacheEntry>> {
        if self.disk_cache_dir.is_some() {
            let file_path = self.get_disk_file_path(key)?;

            if file_path.exists() {
                let data = fs::read(&file_path)?;
                let entry: CacheEntry = serde_json::from_slice(&data)?;

                // Check if expired
                let now = crate::current_timestamp_millis();
                if now > entry.expires_at {
                    let _ = fs::remove_file(&file_path);
                    return Ok(None);
                }

                debug!("Retrieved disk cache entry: {}", file_path.display());
                return Ok(Some(entry));
            }
        }

        Ok(None)
    }

    /// Check if disk entry exists
    async fn disk_entry_exists(&self, key: &str) -> Result<bool> {
        if self.disk_cache_dir.is_some() {
            let file_path = self.get_disk_file_path(key)?;
            Ok(file_path.exists())
        } else {
            Ok(false)
        }
    }

    /// Remove entry from disk cache
    async fn remove_disk_entry(&self, key: &str) -> Result<bool> {
        if self.disk_cache_dir.is_some() {
            let file_path = self.get_disk_file_path(key)?;
            if file_path.exists() {
                fs::remove_file(&file_path)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Get disk file path for cache key
    fn get_disk_file_path(&self, key: &str) -> Result<PathBuf> {
        let disk_dir = self.disk_cache_dir.as_ref().ok_or_else(|| {
            crate::error::Error::internal_error_with_context(
                "cache",
                "Disk cache directory not configured".to_string(),
                "Call set_disk_cache_dir() to configure disk caching before use".to_string(),
            )
        })?;
        let safe_key = key.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        Ok(disk_dir.join(format!("{}.cache", safe_key)))
    }

    /// Get disk cache statistics
    async fn get_disk_stats(&self) -> Result<(usize, usize)> {
        if let Some(disk_dir) = &self.disk_cache_dir {
            if disk_dir.exists() {
                let mut entries = 0;
                let mut total_size = 0;

                for entry in fs::read_dir(disk_dir)? {
                    let entry = entry?;
                    if entry.path().extension().is_some_and(|ext| ext == "cache") {
                        entries += 1;
                        if let Ok(metadata) = entry.metadata() {
                            total_size += metadata.len() as usize;
                        }
                    }
                }

                return Ok((entries, total_size));
            }
        }

        Ok((0, 0))
    }

    /// Evict least recently used entries from memory cache
    async fn evict_lru_entries(&self, count: usize) -> Result<()> {
        let mut entries: Vec<_> = self
            .memory_cache
            .read()
            .iter()
            .map(|(key, entry)| (key.clone(), entry.last_accessed))
            .collect();

        entries.sort_by(|a, b| a.1.cmp(&b.1));

        let mut memory_cache = self.memory_cache.write();
        for (key, _) in entries.into_iter().take(count) {
            memory_cache.remove(&key);
            debug!("Evicted LRU cache entry: {}", key);
        }

        Ok(())
    }

    /// Background cleanup task
    #[cfg(feature = "net")]
    async fn cleanup_task(&self, interval: Duration) {
        let mut cleanup_interval = tokio::time::interval(interval);

        loop {
            cleanup_interval.tick().await;

            if let Err(e) = self.cleanup_expired_entries().await {
                error!("Cache cleanup failed: {}", e);
            }
        }
    }

    /// Clean up expired entries
    #[cfg(feature = "net")]
    async fn cleanup_expired_entries(&self) -> Result<()> {
        let now = crate::current_timestamp_millis();
        let mut expired_keys: Vec<_> = self
            .memory_cache
            .read()
            .iter()
            .filter_map(|(key, entry)| (now > entry.expires_at).then_some(key.clone()))
            .collect();

        // Remove expired memory entries
        let mut memory_cache = self.memory_cache.write();
        for key in &expired_keys {
            memory_cache.remove(key);
        }
        drop(memory_cache);

        // Clean up expired disk entries
        if let Some(disk_dir) = &self.disk_cache_dir {
            if disk_dir.exists() {
                for entry in fs::read_dir(disk_dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "cache") {
                        if let Ok(data) = fs::read(&path) {
                            if let Ok(cache_entry) = serde_json::from_slice::<CacheEntry>(&data) {
                                if now > cache_entry.expires_at {
                                    let _ = fs::remove_file(&path);
                                    expired_keys.push(cache_entry.key);
                                }
                            }
                        }
                    }
                }
            }
        }

        if !expired_keys.is_empty() {
            debug!("Cleaned up {} expired cache entries", expired_keys.len());
        }

        Ok(())
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enable_memory: true,
            enable_disk: true,
            memory_max_entries: 10000,
            disk_cache_dir: app_cache_dir("rust_tree_sitter"),
            default_ttl: Duration::from_secs(3600), // 1 hour
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}
