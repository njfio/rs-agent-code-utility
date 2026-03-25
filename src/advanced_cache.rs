//! Advanced multi-level caching system for rust_tree_sitter
//!
//! This module provides a sophisticated caching architecture with three layers:
//! - Memory: Fast in-memory LRU cache
//! - Disk: Persistent cache with TTL
//! - Network: Distributed cache coordination (optional)

use std::marker::PhantomData;

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Cache entry with metadata for advanced caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    /// The cached data
    pub data: T,
    /// When this entry was created
    pub created_at: u64,
    /// When this entry expires
    pub expires_at: u64,
    /// Last access time for LRU eviction
    pub last_accessed: u64,
    /// Access count for statistics
    pub access_count: u64,
    /// Size in bytes for memory management
    pub size_bytes: usize,
    /// Cache key for invalidation
    pub key: String,
    /// Dependencies that could invalidate this entry
    pub dependencies: Vec<String>,
}

impl<T> CacheEntry<T> {
    pub fn new(data: T, ttl: Duration, key: String, dependencies: Vec<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        let size_bytes = std::mem::size_of_val(&data)
            + std::mem::size_of::<Self>()
            + key.len()
            + dependencies.iter().map(|d| d.len()).sum::<usize>();

        Self {
            data,
            created_at: now,
            expires_at: now + ttl.as_secs(),
            last_accessed: now,
            access_count: 0,
            size_bytes,
            key,
            dependencies,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
        now >= self.expires_at
    }

    pub fn touch(&mut self) {
        self.last_accessed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
        self.access_count += 1;
    }

    pub fn remaining_ttl(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        Duration::from_secs(self.expires_at.saturating_sub(now))
    }
}

/// Cache statistics for monitoring and optimization
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub total_requests: u64,
    pub memory_usage_bytes: usize,
    pub disk_usage_bytes: usize,
    pub compression_ratio: f64,
    pub average_access_time_ms: f64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.hits as f64 / self.total_requests as f64
        }
    }

    pub fn record_hit(&mut self, access_time_ms: f64) {
        self.hits += 1;
        self.total_requests += 1;
        self.update_average_access_time(access_time_ms);
    }

    pub fn record_miss(&mut self, access_time_ms: f64) {
        self.misses += 1;
        self.total_requests += 1;
        self.update_average_access_time(access_time_ms);
    }

    fn update_average_access_time(&mut self, new_time: f64) {
        if self.total_requests == 1 {
            self.average_access_time_ms = new_time;
        } else {
            let total_requests = self.total_requests as f64;
            self.average_access_time_ms =
                (self.average_access_time_ms * (total_requests - 1.0) + new_time) / total_requests;
        }
    }
}

/// Configuration for the advanced cache system
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum memory usage in bytes
    pub max_memory_bytes: usize,
    /// Maximum disk usage in bytes
    pub max_disk_bytes: usize,
    /// Default TTL for cache entries
    pub default_ttl: Duration,
    /// Cleanup interval
    pub cleanup_interval: Duration,
    /// Cache directory for disk storage
    pub cache_dir: PathBuf,
    /// Enable network coordination
    pub enable_network: bool,
    /// Network peers for distributed caching
    pub network_peers: Vec<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 100 * 1024 * 1024,        // 100MB
            max_disk_bytes: 1024 * 1024 * 1024,         // 1GB
            default_ttl: Duration::from_secs(3600),     // 1 hour
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            cache_dir: PathBuf::from("./cache"),
            enable_network: false,
            network_peers: Vec::new(),
        }
    }
}

/// Memory cache layer - fast in-memory LRU cache
pub struct MemoryCache<T> {
    entries: Arc<RwLock<HashMap<String, CacheEntry<T>>>>,
    config: CacheConfig,
    stats: Arc<RwLock<CacheStats>>,
}

impl<T> MemoryCache<T>
where
    T: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
{
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    pub fn get(&self, key: &str) -> Result<Option<T>> {
        let start_time = std::time::Instant::now();

        let entries = self
            .entries
            .read()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire read lock"))?;

        if let Some(entry) = entries.get(key) {
            if entry.is_expired() {
                drop(entries);
                let mut stats = self.stats.write().map_err(|_| {
                    Error::internal_error("cache", "Failed to acquire stats write lock")
                })?;
                stats.record_miss(start_time.elapsed().as_millis() as f64);
                return Ok(None);
            }

            let data = entry.data.clone();
            drop(entries);

            // Update access statistics
            let mut entries = self
                .entries
                .write()
                .map_err(|_| Error::internal_error("cache", "Failed to acquire write lock"))?;
            if let Some(entry) = entries.get_mut(key) {
                entry.touch();
            }

            let mut stats = self.stats.write().map_err(|_| {
                Error::internal_error("cache", "Failed to acquire stats write lock")
            })?;
            stats.record_hit(start_time.elapsed().as_millis() as f64);

            Ok(Some(data))
        } else {
            let mut stats = self.stats.write().map_err(|_| {
                Error::internal_error("cache", "Failed to acquire stats write lock")
            })?;
            stats.record_miss(start_time.elapsed().as_millis() as f64);
            Ok(None)
        }
    }

    fn contains_valid_key(&self, key: &str) -> Result<bool> {
        let entries = self
            .entries
            .read()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire read lock"))?;

        Ok(entries.get(key).is_some_and(|entry| !entry.is_expired()))
    }

    pub fn put(
        &self,
        key: String,
        data: T,
        ttl: Option<Duration>,
        dependencies: Vec<String>,
    ) -> Result<()> {
        let ttl = ttl.unwrap_or(self.config.default_ttl);
        let entry = CacheEntry::new(data, ttl, key.clone(), dependencies);

        // Evict entries if we're over memory limit
        self.evict_if_needed(entry.size_bytes)?;

        let mut entries = self
            .entries
            .write()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire write lock"))?;
        entries.insert(key, entry);

        // Update memory usage stats
        let total_size: usize = entries.values().map(|e| e.size_bytes).sum();
        let mut stats = self
            .stats
            .write()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire stats write lock"))?;
        stats.memory_usage_bytes = total_size;

        Ok(())
    }

    fn evict_if_needed(&self, new_entry_size: usize) -> Result<()> {
        let mut entries = self
            .entries
            .write()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire write lock"))?;

        let mut current_size: usize = entries.values().map(|e| e.size_bytes).sum();

        while current_size + new_entry_size > self.config.max_memory_bytes && !entries.is_empty() {
            // Find least recently used entry
            let lru_key = entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_accessed)
                .map(|(key, _)| key.clone());

            if let Some(key) = lru_key {
                if let Some(removed_entry) = entries.remove(&key) {
                    current_size -= removed_entry.size_bytes;

                    let mut stats = self.stats.write().map_err(|_| {
                        Error::internal_error("cache", "Failed to acquire stats write lock")
                    })?;
                    stats.evictions += 1;
                }
            }
        }

        Ok(())
    }

    pub fn invalidate(&self, key: &str) -> Result<bool> {
        let mut entries = self
            .entries
            .write()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire write lock"))?;
        let removed = entries.remove(key).is_some();

        if removed {
            let total_size: usize = entries.values().map(|e| e.size_bytes).sum();
            let mut stats = self.stats.write().map_err(|_| {
                Error::internal_error("cache", "Failed to acquire stats write lock")
            })?;
            stats.memory_usage_bytes = total_size;
        }

        Ok(removed)
    }

    pub fn invalidate_by_dependency(&self, dependency: &str) -> Result<usize> {
        let keys_to_remove = self.keys_for_dependency(dependency)?;
        let removed_count = keys_to_remove.len();

        if removed_count == 0 {
            return Ok(0);
        }

        let mut entries = self
            .entries
            .write()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire write lock"))?;
        for key in keys_to_remove {
            entries.remove(&key);
        }

        let total_size: usize = entries.values().map(|e| e.size_bytes).sum();
        let mut stats = self
            .stats
            .write()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire stats write lock"))?;
        stats.memory_usage_bytes = total_size;

        Ok(removed_count)
    }

    pub fn keys_for_dependency(&self, dependency: &str) -> Result<Vec<String>> {
        let entries = self
            .entries
            .read()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire read lock"))?;

        Ok(entries
            .iter()
            .filter(|(_, entry)| entry.dependencies.iter().any(|dep| dep == dependency))
            .map(|(key, _)| key.clone())
            .collect())
    }

    pub fn cleanup_expired(&self) -> Result<usize> {
        let mut entries = self
            .entries
            .write()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire write lock"))?;

        let initial_len = entries.len();
        entries.retain(|_, entry| !entry.is_expired());
        let removed_count = initial_len - entries.len();

        if removed_count > 0 {
            let total_size: usize = entries.values().map(|e| e.size_bytes).sum();
            let mut stats = self.stats.write().map_err(|_| {
                Error::internal_error("cache", "Failed to acquire stats write lock")
            })?;
            stats.memory_usage_bytes = total_size;
            stats.evictions += removed_count as u64;
        }

        Ok(removed_count)
    }

    pub fn stats(&self) -> Result<CacheStats> {
        let stats = self
            .stats
            .read()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire stats read lock"))?;
        Ok(stats.clone())
    }
}

/// Disk cache layer - persistent storage
pub struct DiskCache<T> {
    cache_dir: PathBuf,
    config: CacheConfig,
    stats: Arc<RwLock<CacheStats>>,
    _phantom: PhantomData<T>,
}

impl<T> DiskCache<T>
where
    T: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
{
    pub fn new(config: CacheConfig) -> Result<Self> {
        fs::create_dir_all(&config.cache_dir).map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to create cache directory: {}",
                e
            )))
        })?;

        Ok(Self {
            cache_dir: config.cache_dir.clone(),
            config,
            stats: Arc::new(RwLock::new(CacheStats::default())),
            _phantom: PhantomData,
        })
    }

    fn get_cache_path(&self, key: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.cache", key))
    }

    fn is_cache_file(path: &Path) -> bool {
        path.extension().and_then(|ext| ext.to_str()) == Some("cache")
    }

    fn load_entry(&self, key: &str) -> Result<Option<CacheEntry<T>>> {
        let cache_path = self.get_cache_path(key);

        if !cache_path.exists() {
            return Ok(None);
        }

        // Check if file is expired by reading metadata
        let metadata = fs::metadata(&cache_path).map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to read cache metadata: {}",
                e
            )))
        })?;

        let modified = metadata.modified().map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to get file modification time: {}",
                e
            )))
        })?;

        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(Duration::from_secs(0));

        if age > self.config.default_ttl {
            // Remove expired file
            let _ = fs::remove_file(&cache_path);
            return Ok(None);
        }

        // Read and deserialize the cache entry from plain JSON.
        let json_data = fs::read_to_string(&cache_path).map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to read cache file: {}",
                e
            )))
        })?;

        let entry: CacheEntry<T> =
            serde_json::from_str(&json_data).map_err(|e| Error::ValidationError {
                message: format!("Failed to deserialize cache entry: {}", e),
                field: None,
                expected_format: Some("valid JSON".to_string()),
                actual_value: None,
            })?;

        if entry.is_expired() {
            let _ = fs::remove_file(&cache_path);
            return Ok(None);
        }

        Ok(Some(entry))
    }

    pub fn get(&self, key: &str) -> Result<Option<T>> {
        Ok(self.load_entry(key)?.map(|entry| entry.data))
    }

    pub fn put(
        &self,
        key: String,
        data: T,
        ttl: Option<Duration>,
        dependencies: Vec<String>,
    ) -> Result<()> {
        let ttl = ttl.unwrap_or(self.config.default_ttl);
        let entry = CacheEntry::new(data, ttl, key.clone(), dependencies);

        // Check disk usage before writing
        self.evict_if_needed(entry.size_bytes)?;

        let cache_path = self.get_cache_path(&key);
        let json_data = serde_json::to_string(&entry).map_err(|e| Error::ValidationError {
            message: format!("Failed to serialize cache entry: {}", e),
            field: None,
            expected_format: Some("serializable data".to_string()),
            actual_value: None,
        })?;

        fs::write(&cache_path, json_data.as_bytes()).map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to write cache file: {}",
                e
            )))
        })?;

        // Update disk usage stats
        self.update_disk_usage_stats()?;

        Ok(())
    }

    fn evict_if_needed(&self, new_entry_size: usize) -> Result<()> {
        let current_usage = self.get_disk_usage()?;

        if current_usage + new_entry_size <= self.config.max_disk_bytes {
            return Ok(());
        }

        // Find oldest files to evict
        let mut cache_files: Vec<_> = fs::read_dir(&self.cache_dir)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| Self::is_cache_file(&entry.path()))
            .filter_map(|entry| {
                let metadata = entry.metadata().ok()?;
                let modified = metadata.modified().ok()?;
                Some((entry.path(), modified, metadata.len()))
            })
            .collect();

        // Sort by modification time (oldest first)
        cache_files.sort_by_key(|(_, modified, _)| *modified);

        let mut total_evicted = 0;
        for (path, _, size) in cache_files {
            if current_usage + new_entry_size - total_evicted <= self.config.max_disk_bytes {
                break;
            }

            if fs::remove_file(&path).is_ok() {
                total_evicted += size as usize;

                let mut stats = self.stats.write().map_err(|_| {
                    Error::internal_error("cache", "Failed to acquire stats write lock")
                })?;
                stats.evictions += 1;
            }
        }

        Ok(())
    }

    fn get_disk_usage(&self) -> Result<usize> {
        let mut total_size = 0;
        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            if Self::is_cache_file(&entry.path()) {
                total_size += entry.metadata()?.len() as usize;
            }
        }
        Ok(total_size)
    }

    fn update_disk_usage_stats(&self) -> Result<()> {
        let usage = self.get_disk_usage()?;
        let mut stats = self
            .stats
            .write()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire stats write lock"))?;
        stats.disk_usage_bytes = usage;
        stats.compression_ratio = 1.0;
        Ok(())
    }

    pub fn invalidate(&self, key: &str) -> Result<bool> {
        let cache_path = self.get_cache_path(key);
        let removed = fs::remove_file(&cache_path).is_ok();

        if removed {
            self.update_disk_usage_stats()?;
        }

        Ok(removed)
    }

    pub fn invalidate_by_dependency(&self, dependency: &str) -> Result<usize> {
        let keys_to_remove = self.keys_for_dependency(dependency)?;

        let mut removed_count = 0;
        for key in keys_to_remove {
            if self.invalidate(&key)? {
                removed_count += 1;
            }
        }

        Ok(removed_count)
    }

    pub fn cleanup_expired(&self) -> Result<usize> {
        let cache_files: Vec<PathBuf> = fs::read_dir(&self.cache_dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| Self::is_cache_file(path))
            .collect();

        let mut removed_count = 0;
        for path in cache_files {
            let existed = path.exists();
            let Some(key) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_owned)
            else {
                continue;
            };

            let _ = self.load_entry(&key)?;
            if existed && !path.exists() {
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            self.update_disk_usage_stats()?;
        }

        Ok(removed_count)
    }

    pub fn keys_for_dependency(&self, dependency: &str) -> Result<Vec<String>> {
        let cache_files: Vec<PathBuf> = fs::read_dir(&self.cache_dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| Self::is_cache_file(path))
            .collect();

        let mut keys = Vec::new();
        for path in cache_files {
            let Some(key) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_owned)
            else {
                continue;
            };

            if let Some(entry) = self.load_entry(&key)? {
                if entry.dependencies.iter().any(|dep| dep == dependency) {
                    keys.push(key);
                }
            }
        }

        Ok(keys)
    }

    pub fn stats(&self) -> Result<CacheStats> {
        let mut stats = self
            .stats
            .read()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire stats read lock"))?
            .clone();

        stats.disk_usage_bytes = self.get_disk_usage()?;
        Ok(stats)
    }
}

/// Multi-level cache combining memory, disk, and network layers
pub struct AdvancedCache<T> {
    memory: MemoryCache<T>,
    disk: Option<DiskCache<T>>,
    _config: CacheConfig,
}

impl<T> AdvancedCache<T>
where
    T: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
{
    pub fn new(config: CacheConfig) -> Result<Self> {
        let disk = if config.max_disk_bytes > 0 {
            Some(DiskCache::new(config.clone())?)
        } else {
            None
        };

        Ok(Self {
            memory: MemoryCache::new(config.clone()),
            disk,
            _config: config,
        })
    }

    fn promote_entry_to_memory(&self, key: &str, entry: &CacheEntry<T>) -> Result<()> {
        let ttl = entry.remaining_ttl();
        if ttl.is_zero() {
            return Ok(());
        }

        self.memory.put(
            key.to_string(),
            entry.data.clone(),
            Some(ttl),
            entry.dependencies.clone(),
        )
    }

    pub async fn get(&self, key: &str) -> Result<Option<T>> {
        // Try memory cache first
        if let Some(data) = self.memory.get(key)? {
            return Ok(Some(data));
        }

        // Try disk cache if available
        if let Some(ref disk_cache) = self.disk {
            if let Some(entry) = disk_cache.load_entry(key)? {
                let data = entry.data.clone();
                let _ = self.promote_entry_to_memory(key, &entry);
                return Ok(Some(data));
            }
        }

        Ok(None)
    }

    pub async fn put(
        &self,
        key: String,
        data: T,
        ttl: Option<Duration>,
        dependencies: Vec<String>,
    ) -> Result<()> {
        // Store in memory
        self.memory
            .put(key.clone(), data.clone(), ttl, dependencies.clone())?;

        // Store in disk if available
        if let Some(ref disk_cache) = self.disk {
            disk_cache.put(key, data, ttl, dependencies)?;
        }

        Ok(())
    }

    pub async fn invalidate(&self, key: &str) -> Result<bool> {
        let mut invalidated = false;

        // Invalidate from memory
        invalidated |= self.memory.invalidate(key)?;

        // Invalidate from disk
        if let Some(ref disk_cache) = self.disk {
            invalidated |= disk_cache.invalidate(key)?;
        }

        Ok(invalidated)
    }

    pub async fn invalidate_by_dependency(&self, dependency: &str) -> Result<usize> {
        let mut keys = self.memory.keys_for_dependency(dependency)?;
        if let Some(ref disk_cache) = self.disk {
            for key in disk_cache.keys_for_dependency(dependency)? {
                if !keys.iter().any(|existing| existing == &key) {
                    keys.push(key);
                }
            }
        }

        for key in &keys {
            let _ = self.memory.invalidate(key)?;
            if let Some(ref disk_cache) = self.disk {
                let _ = disk_cache.invalidate(key)?;
            }
        }

        Ok(keys.len())
    }

    pub async fn cleanup(&self) -> Result<()> {
        // Cleanup memory cache
        let _ = self.memory.cleanup_expired()?;
        if let Some(ref disk_cache) = self.disk {
            let _ = disk_cache.cleanup_expired()?;
        }

        Ok(())
    }

    pub async fn stats(&self) -> Result<CacheStats> {
        let combined_stats = self.memory.stats()?;
        Ok(combined_stats)
    }

    /// Warm up cache with frequently accessed data
    pub async fn warmup(&self, keys: Vec<String>) -> Result<()> {
        let Some(ref disk_cache) = self.disk else {
            return Ok(());
        };

        for key in keys {
            if self.memory.contains_valid_key(&key)? {
                continue;
            }

            if let Some(entry) = disk_cache.load_entry(&key)? {
                let _ = self.promote_entry_to_memory(&key, &entry);
            }
        }

        Ok(())
    }

    /// Get cache key for file-based data with dependency tracking
    pub fn generate_file_key(&self, file_path: &Path, analysis_type: &str) -> String {
        let mut key = format!("file:{}:{}", file_path.display(), analysis_type);

        // Add file modification time to dependencies for invalidation
        if let Ok(metadata) = fs::metadata(file_path) {
            if let Ok(modified) = metadata.modified() {
                let modified_secs = modified
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs();
                key.push_str(&format!(":{}", modified_secs));
            }
        }

        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_memory_cache_basic() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let config = CacheConfig::default();
        let cache: MemoryCache<String> = MemoryCache::new(config);

        // Test put and get
        cache.put(
            "test_key".to_string(),
            "test_value".to_string(),
            None,
            Vec::new(),
        )?;
        let result = cache.get("test_key")?;
        assert_eq!(result, Some("test_value".to_string()));

        // Test miss
        let result = cache.get("nonexistent")?;
        assert_eq!(result, None);

        Ok(())
    }

    #[test]
    fn test_disk_cache_basic() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let config = CacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            ..CacheConfig::default()
        };

        let cache: DiskCache<String> = DiskCache::new(config)?;

        // Test put and get
        cache.put(
            "test_key".to_string(),
            "test_value".to_string(),
            None,
            Vec::new(),
        )?;
        let result = cache.get("test_key")?;
        assert_eq!(result, Some("test_value".to_string()));

        Ok(())
    }

    #[test]
    fn test_cache_invalidation() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let config = CacheConfig::default();
        let cache: MemoryCache<String> = MemoryCache::new(config);

        cache.put(
            "test_key".to_string(),
            "test_value".to_string(),
            None,
            Vec::new(),
        )?;
        assert!(cache.get("test_key")?.is_some());

        cache.invalidate("test_key")?;
        assert!(cache.get("test_key")?.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_warmup_promotes_disk_entries_with_dependencies(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let config = CacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            ..CacheConfig::default()
        };

        let cache: AdvancedCache<String> = AdvancedCache::new(config)?;
        let disk_cache = cache.disk.as_ref().expect("disk cache should be enabled");

        disk_cache.put(
            "warm_key".to_string(),
            "warm_value".to_string(),
            Some(Duration::from_secs(60)),
            vec!["file:src/lib.rs".to_string()],
        )?;

        assert_eq!(cache.memory.get("warm_key")?, None);

        cache.warmup(vec!["warm_key".to_string()]).await?;

        assert_eq!(
            cache.memory.get("warm_key")?,
            Some("warm_value".to_string())
        );
        assert_eq!(cache.invalidate_by_dependency("file:src/lib.rs").await?, 1);
        assert_eq!(cache.memory.get("warm_key")?, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_promotes_disk_entries_with_dependencies(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let config = CacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            ..CacheConfig::default()
        };

        let cache: AdvancedCache<String> = AdvancedCache::new(config)?;
        let disk_cache = cache.disk.as_ref().expect("disk cache should be enabled");

        disk_cache.put(
            "promote_key".to_string(),
            "promoted".to_string(),
            Some(Duration::from_secs(60)),
            vec!["file:src/main.rs".to_string()],
        )?;

        assert_eq!(cache.memory.get("promote_key")?, None);
        assert_eq!(
            cache.get("promote_key").await?,
            Some("promoted".to_string())
        );
        assert_eq!(cache.invalidate_by_dependency("file:src/main.rs").await?, 1);
        assert_eq!(cache.memory.get("promote_key")?, None);
        assert_eq!(cache.get("promote_key").await?, None);

        Ok(())
    }

    #[test]
    fn test_disk_cache_invalidate_by_dependency(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let config = CacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            ..CacheConfig::default()
        };

        let cache: DiskCache<String> = DiskCache::new(config)?;
        cache.put(
            "disk_key".to_string(),
            "disk_value".to_string(),
            Some(Duration::from_secs(60)),
            vec!["file:src/lib.rs".to_string()],
        )?;

        assert_eq!(cache.invalidate_by_dependency("file:src/lib.rs")?, 1);
        assert_eq!(cache.get("disk_key")?, None);

        Ok(())
    }

    #[test]
    fn test_disk_cache_cleanup_expired_entries(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempdir()?;
        let config = CacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            ..CacheConfig::default()
        };

        let cache: DiskCache<String> = DiskCache::new(config)?;
        cache.put(
            "expired_key".to_string(),
            "expired_value".to_string(),
            Some(Duration::from_secs(0)),
            Vec::new(),
        )?;

        assert_eq!(cache.cleanup_expired()?, 1);
        assert_eq!(cache.get("expired_key")?, None);

        Ok(())
    }
}
