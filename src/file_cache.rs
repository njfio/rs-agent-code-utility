//! File content caching utility to reduce redundant I/O operations
//!
//! This module provides a simple in-memory cache for file contents to avoid
//! reading the same file multiple times during analysis operations.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use crate::error::Result;

/// In-memory file content cache
#[derive(Debug, Clone)]
pub struct FileCache {
    /// Cache storage mapping file paths to content
    cache: Arc<RwLock<HashMap<PathBuf, String>>>,
    /// Maximum cache size (number of files)
    max_size: usize,
    /// Cache hit statistics
    stats: Arc<RwLock<CacheStats>>,
}

/// Cache statistics for monitoring performance
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Number of cache hits
    pub hits: usize,
    /// Number of cache misses
    pub misses: usize,
    /// Number of files currently cached
    pub cached_files: usize,
    /// Total bytes cached
    pub total_bytes: usize,
}

impl FileCache {
    /// Create a new file cache with default settings
    pub fn new() -> Self {
        Self::with_capacity(1000) // Default to 1000 files
    }
    
    /// Create a new file cache with specified capacity
    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }
    
    /// Read file content, using cache if available
    pub fn read_to_string<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        let path = path.as_ref().to_path_buf();
        
        // Try to get from cache first
        {
            let cache = self.cache.read()
                .map_err(|e| crate::error::Error::internal_error("file_cache", format!("Failed to acquire read lock: {}", e)))?;
            if let Some(content) = cache.get(&path) {
                // Cache hit
                let mut stats = self.stats.write()
                    .map_err(|e| crate::error::Error::internal_error("file_cache", format!("Failed to acquire write lock for stats: {}", e)))?;
                stats.hits += 1;
                return Ok(content.clone());
            }
        }
        
        // Cache miss - read from disk
        let content = std::fs::read_to_string(&path)?;
        
        // Update cache
        self.insert(path, content.clone());
        
        // Update stats
        {
            let mut stats = self.stats.write()
                .map_err(|e| crate::error::Error::internal_error("file_cache", format!("Failed to acquire write lock for stats: {}", e)))?;
            stats.misses += 1;
        }
        
        Ok(content)
    }
    
    /// Insert content into cache
    fn insert(&self, path: PathBuf, content: String) {
        let mut cache = match self.cache.write() {
            Ok(cache) => cache,
            Err(e) => {
                eprintln!("Warning: Failed to acquire cache write lock: {}", e);
                return;
            }
        };
        
        // Check if we need to evict entries
        if cache.len() >= self.max_size {
            // Simple eviction: remove oldest entry (first in HashMap iteration)
            if let Some(key) = cache.keys().next().cloned() {
                if let Some(removed_content) = cache.remove(&key) {
                    if let Ok(mut stats) = self.stats.write() {
                        stats.cached_files = stats.cached_files.saturating_sub(1);
                        stats.total_bytes = stats.total_bytes.saturating_sub(removed_content.len());
                    }
                }
            }
        }
        
        // Insert new content
        let content_size = content.len();
        cache.insert(path, content);
        
        // Update stats
        {
            if let Ok(mut stats) = self.stats.write() {
                stats.cached_files += 1;
                stats.total_bytes += content_size;
            }
        }
    }
    
    /// Clear the cache
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.cached_files = 0;
            stats.total_bytes = 0;
        }
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        match self.stats.read() {
            Ok(stats) => CacheStats {
                hits: stats.hits,
                misses: stats.misses,
                cached_files: stats.cached_files,
                total_bytes: stats.total_bytes,
            },
            Err(_) => CacheStats::default(), // Return default stats on lock error
        }
    }
    
    /// Get cache hit ratio
    pub fn hit_ratio(&self) -> f64 {
        let stats = self.stats();
        let total = stats.hits + stats.misses;
        if total == 0 {
            0.0
        } else {
            stats.hits as f64 / total as f64
        }
    }
    
    /// Check if a file is cached
    pub fn contains<P: AsRef<Path>>(&self, path: P) -> bool {
        match self.cache.read() {
            Ok(cache) => cache.contains_key(path.as_ref()),
            Err(_) => false, // Return false on lock error
        }
    }

    /// Get the number of cached files
    pub fn len(&self) -> usize {
        match self.cache.read() {
            Ok(cache) => cache.len(),
            Err(_) => 0, // Return 0 on lock error
        }
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        match self.cache.read() {
            Ok(cache) => cache.is_empty(),
            Err(_) => true, // Return true on lock error
        }
    }
}

impl Default for FileCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheStats {
    /// Calculate cache efficiency percentage
    pub fn efficiency(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
    
    /// Get average file size in bytes
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
    use tempfile::TempDir;
    use std::fs;
    
    #[test]
    fn test_file_cache_basic_operations() {
        let cache = FileCache::new();
        
        // Create a temporary file
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "Hello, World!").unwrap();
        
        // First read should be a cache miss
        let content1 = cache.read_to_string(&file_path).unwrap();
        assert_eq!(content1, "Hello, World!");
        
        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.cached_files, 1);
        
        // Second read should be a cache hit
        let content2 = cache.read_to_string(&file_path).unwrap();
        assert_eq!(content2, "Hello, World!");
        
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.cached_files, 1);
        
        // Check hit ratio
        assert_eq!(cache.hit_ratio(), 0.5);
    }
    
    #[test]
    fn test_cache_capacity_and_eviction() {
        let cache = FileCache::with_capacity(2);
        let temp_dir = TempDir::new().unwrap();
        
        // Create three test files
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        let file3 = temp_dir.path().join("file3.txt");
        
        fs::write(&file1, "Content 1").unwrap();
        fs::write(&file2, "Content 2").unwrap();
        fs::write(&file3, "Content 3").unwrap();
        
        // Read first two files
        cache.read_to_string(&file1).unwrap();
        cache.read_to_string(&file2).unwrap();
        assert_eq!(cache.len(), 2);
        
        // Read third file should trigger eviction
        cache.read_to_string(&file3).unwrap();
        assert_eq!(cache.len(), 2); // Still at capacity
        
        // One of the first two files should have been evicted, and file3 should be present
        let file1_present = cache.contains(&file1);
        let file2_present = cache.contains(&file2);
        let file3_present = cache.contains(&file3);

        // Exactly one of the first two files should have been evicted
        assert!(file1_present != file2_present, "Exactly one of file1 or file2 should be evicted");
        assert!(file3_present, "file3 should always be present as it was added last");
    }
    
    #[test]
    fn test_cache_clear() {
        let cache = FileCache::new();
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "Test content").unwrap();
        
        // Add content to cache
        cache.read_to_string(&file_path).unwrap();
        assert_eq!(cache.len(), 1);
        
        // Clear cache
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
        
        // Read file twice
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
