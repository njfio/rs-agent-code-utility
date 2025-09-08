//! Advanced multi-level caching system for rust_tree_sitter
//!
//! This module provides a sophisticated caching architecture with three layers:
//! - Memory: Fast in-memory LRU cache
//! - Disk: Persistent compressed cache with TTL
//! - Network: Distributed cache coordination (optional)

use std::marker::PhantomData;

use crate::error::{Error, Result};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
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
            .unwrap()
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
            .unwrap()
            .as_secs();
        now >= self.expires_at
    }

    pub fn touch(&mut self) {
        self.last_accessed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.access_count += 1;
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
    /// Compression level (0-9)
    pub compression_level: u32,
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
            compression_level: 6,
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
        let mut entries = self
            .entries
            .write()
            .map_err(|_| Error::internal_error("cache", "Failed to acquire write lock"))?;

        let keys_to_remove: Vec<String> = entries
            .iter()
            .filter(|(_, entry)| entry.dependencies.contains(&dependency.to_string()))
            .map(|(key, _)| key.clone())
            .collect();

        let mut removed_count = 0;
        for key in keys_to_remove {
            entries.remove(&key);
            removed_count += 1;
        }

        if removed_count > 0 {
            let total_size: usize = entries.values().map(|e| e.size_bytes).sum();
            let mut stats = self.stats.write().map_err(|_| {
                Error::internal_error("cache", "Failed to acquire stats write lock")
            })?;
            stats.memory_usage_bytes = total_size;
        }

        Ok(removed_count)
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

/// Disk cache layer - persistent compressed storage
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
            Error::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create cache directory: {}", e),
            ))
        })?;

        Ok(Self {
            cache_dir: config.cache_dir.clone(),
            config,
            stats: Arc::new(RwLock::new(CacheStats::default())),
            _phantom: PhantomData,
        })
    }

    fn get_cache_path(&self, key: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.cache.gz", key))
    }

    pub fn get(&self, key: &str) -> Result<Option<T>> {
        let cache_path = self.get_cache_path(key);

        if !cache_path.exists() {
            return Ok(None);
        }

        // Check if file is expired by reading metadata
        let metadata = fs::metadata(&cache_path).map_err(|e| {
            Error::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read cache metadata: {}", e),
            ))
        })?;

        let modified = metadata.modified().map_err(|e| {
            Error::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to get file modification time: {}", e),
            ))
        })?;

        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(Duration::from_secs(0));

        if age > self.config.default_ttl {
            // Remove expired file
            let _ = fs::remove_file(&cache_path);
            return Ok(None);
        }

        // Read and decompress
        let compressed_data = fs::read(&cache_path).map_err(|e| {
            Error::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read cache file: {}", e),
            ))
        })?;

        let mut decoder = GzDecoder::new(&compressed_data[..]);
        let mut json_data = String::new();
        decoder.read_to_string(&mut json_data).map_err(|e| {
            Error::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to decompress cache data: {}", e),
            ))
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

        Ok(Some(entry.data))
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

        // Compress and write
        let mut encoder =
            GzEncoder::new(Vec::new(), Compression::new(self.config.compression_level));
        encoder.write_all(json_data.as_bytes()).map_err(|e| {
            Error::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to compress cache data: {}", e),
            ))
        })?;

        let compressed_data = encoder.finish().map_err(|e| {
            Error::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to finish compression: {}", e),
            ))
        })?;

        fs::write(&cache_path, compressed_data).map_err(|e| {
            Error::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to write cache file: {}", e),
            ))
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
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("gz"))
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
            if entry.path().extension().and_then(|ext| ext.to_str()) == Some("gz") {
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
    config: CacheConfig,
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
            config,
        })
    }

    pub async fn get(&self, key: &str) -> Result<Option<T>> {
        // Try memory cache first
        if let Some(data) = self.memory.get(key)? {
            return Ok(Some(data));
        }

        // Try disk cache if available
        if let Some(ref disk_cache) = self.disk {
            if let Some(data) = disk_cache.get(key)? {
                // Promote to memory cache
                let _ = self
                    .memory
                    .put(key.to_string(), data.clone(), None, Vec::new());
                return Ok(Some(data));
            }
        }

        // TODO: Try network cache if enabled

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
            disk_cache.put(key.clone(), data.clone(), ttl, dependencies.clone())?;
        }

        // TODO: Replicate to network peers if enabled

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

        // TODO: Invalidate from network peers

        Ok(invalidated)
    }

    pub async fn invalidate_by_dependency(&self, dependency: &str) -> Result<usize> {
        let mut total_invalidated = 0;

        // Invalidate from memory
        total_invalidated += self.memory.invalidate_by_dependency(dependency)?;

        // TODO: Invalidate from disk and network

        Ok(total_invalidated)
    }

    pub async fn cleanup(&self) -> Result<()> {
        // Cleanup memory cache
        let _ = self.memory.cleanup_expired()?;

        // TODO: Cleanup disk and network caches

        Ok(())
    }

    pub async fn stats(&self) -> Result<CacheStats> {
        let combined_stats = self.memory.stats()?;
        Ok(combined_stats)
    }

    /// Warm up cache with frequently accessed data
    pub async fn warmup(&self, _keys: Vec<String>) -> Result<()> {
        // TODO: Implement cache warming logic
        // This could load frequently accessed files or analysis results
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
    fn test_memory_cache_basic() {
        let config = CacheConfig::default();
        let cache: MemoryCache<String> = MemoryCache::new(config);

        // Test put and get
        cache
            .put(
                "test_key".to_string(),
                "test_value".to_string(),
                None,
                Vec::new(),
            )
            .unwrap();
        let result = cache.get("test_key").unwrap();
        assert_eq!(result, Some("test_value".to_string()));

        // Test miss
        let result = cache.get("nonexistent").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_disk_cache_basic() {
        let temp_dir = tempdir().unwrap();
        let mut config = CacheConfig::default();
        config.cache_dir = temp_dir.path().to_path_buf();

        let cache: DiskCache<String> = DiskCache::new(config).unwrap();

        // Test put and get
        cache
            .put(
                "test_key".to_string(),
                "test_value".to_string(),
                None,
                Vec::new(),
            )
            .unwrap();
        let result = cache.get("test_key").unwrap();
        assert_eq!(result, Some("test_value".to_string()));
    }

    #[test]
    fn test_cache_invalidation() {
        let config = CacheConfig::default();
        let cache: MemoryCache<String> = MemoryCache::new(config);

        cache
            .put(
                "test_key".to_string(),
                "test_value".to_string(),
                None,
                Vec::new(),
            )
            .unwrap();
        assert!(cache.get("test_key").unwrap().is_some());

        cache.invalidate("test_key").unwrap();
        assert!(cache.get("test_key").unwrap().is_none());
    }
}
