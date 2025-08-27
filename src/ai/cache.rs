//! AI response caching system

use crate::ai::types::{AIRequest, AIResponse};
use crate::ai::error::{AIError, AIResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use std::sync::{Arc, RwLock};

/// Cache statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub size: usize,
    pub hit_rate: f64,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub max_size: usize,
    pub default_ttl: Duration,
    pub cleanup_interval: Duration,
}

/// Cached response entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    response: AIResponse,
    expires_at: SystemTime,
    created_at: SystemTime,
    access_count: u64,
    last_accessed: SystemTime,
}

/// AI response cache
pub trait AICache: Send + Sync {
    /// Get a cached response
    fn get(&self, key: &str) -> AIResult<Option<AIResponse>>;
    
    /// Store a response in cache
    fn put(&self, key: &str, response: AIResponse, ttl: Option<Duration>) -> AIResult<()>;
    
    /// Remove a cached response
    fn remove(&self, key: &str) -> AIResult<bool>;
    
    /// Clear all cached responses
    fn clear(&self) -> AIResult<()>;
    
    /// Get cache statistics
    fn stats(&self) -> CacheStats;
    
    /// Generate cache key for a request
    fn generate_key(&self, request: &AIRequest) -> String;
}

/// In-memory cache implementation
pub struct MemoryCache {
    entries: Arc<RwLock<HashMap<String, CacheEntry>>>,
    config: CacheConfig,
    stats: Arc<RwLock<CacheStats>>,
}

impl MemoryCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }
    
    /// Clean up expired entries
    pub fn cleanup_expired(&self) -> AIResult<()> {
        let now = SystemTime::now();
        let mut entries = self.entries.write()
            .map_err(|_| AIError::cache("Failed to acquire write lock"))?;
        
        let mut stats = self.stats.write()
            .map_err(|_| AIError::cache("Failed to acquire stats write lock"))?;
        
        let initial_size = entries.len();
        entries.retain(|_, entry| entry.expires_at > now);
        let evicted = initial_size - entries.len();
        
        stats.evictions += evicted as u64;
        stats.size = entries.len();
        
        Ok(())
    }
    
    /// Evict least recently used entries if cache is full
    fn evict_lru(&self) -> AIResult<()> {
        let mut entries = self.entries.write()
            .map_err(|_| AIError::cache("Failed to acquire write lock"))?;
        
        if entries.len() < self.config.max_size {
            return Ok(());
        }
        
        // Find the least recently used entry
        let lru_key = entries.iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(key, _)| key.clone());
        
        if let Some(key) = lru_key {
            entries.remove(&key);
            
            let mut stats = self.stats.write()
                .map_err(|_| AIError::cache("Failed to acquire stats write lock"))?;
            stats.evictions += 1;
            stats.size = entries.len();
        }
        
        Ok(())
    }
}

impl AICache for MemoryCache {
    fn get(&self, key: &str) -> AIResult<Option<AIResponse>> {
        let now = SystemTime::now();
        
        // First check if entry exists and is not expired
        {
            let entries = self.entries.read()
                .map_err(|_| AIError::cache("Failed to acquire read lock"))?;
            
            if let Some(entry) = entries.get(key) {
                if entry.expires_at <= now {
                    // Entry is expired, will be cleaned up later
                    let mut stats = self.stats.write()
                        .map_err(|_| AIError::cache("Failed to acquire stats write lock"))?;
                    stats.misses += 1;
                    return Ok(None);
                }
                
                // Entry is valid, update stats and return
                let mut stats = self.stats.write()
                    .map_err(|_| AIError::cache("Failed to acquire stats write lock"))?;
                stats.hits += 1;
                stats.hit_rate = stats.hits as f64 / (stats.hits + stats.misses) as f64;
                
                let response = entry.response.clone();
                drop(entries); // Release read lock before acquiring write lock
                
                // Update access information
                let mut entries = self.entries.write()
                    .map_err(|_| AIError::cache("Failed to acquire write lock"))?;
                if let Some(entry) = entries.get_mut(key) {
                    entry.last_accessed = now;
                    entry.access_count += 1;
                }
                
                return Ok(Some(response));
            }
        }
        
        // Entry not found
        let mut stats = self.stats.write()
            .map_err(|_| AIError::cache("Failed to acquire stats write lock"))?;
        stats.misses += 1;
        stats.hit_rate = stats.hits as f64 / (stats.hits + stats.misses) as f64;
        
        Ok(None)
    }
    
    fn put(&self, key: &str, response: AIResponse, ttl: Option<Duration>) -> AIResult<()> {
        let now = SystemTime::now();
        let ttl = ttl.unwrap_or(self.config.default_ttl);
        let expires_at = now + ttl;
        
        // Evict LRU entries if necessary
        self.evict_lru()?;
        
        let entry = CacheEntry {
            response,
            expires_at,
            created_at: now,
            access_count: 0,
            last_accessed: now,
        };
        
        let mut entries = self.entries.write()
            .map_err(|_| AIError::cache("Failed to acquire write lock"))?;
        entries.insert(key.to_string(), entry);
        
        let mut stats = self.stats.write()
            .map_err(|_| AIError::cache("Failed to acquire stats write lock"))?;
        stats.size = entries.len();
        
        Ok(())
    }
    
    fn remove(&self, key: &str) -> AIResult<bool> {
        let mut entries = self.entries.write()
            .map_err(|_| AIError::cache("Failed to acquire write lock"))?;
        let removed = entries.remove(key).is_some();
        
        let mut stats = self.stats.write()
            .map_err(|_| AIError::cache("Failed to acquire stats write lock"))?;
        stats.size = entries.len();
        
        Ok(removed)
    }
    
    fn clear(&self) -> AIResult<()> {
        let mut entries = self.entries.write()
            .map_err(|_| AIError::cache("Failed to acquire write lock"))?;
        entries.clear();
        
        let mut stats = self.stats.write()
            .map_err(|_| AIError::cache("Failed to acquire stats write lock"))?;
        *stats = CacheStats::default();
        
        Ok(())
    }
    
    fn stats(&self) -> CacheStats {
        self.stats.read()
            .map(|stats| stats.clone())
            .unwrap_or_default()
    }
    
    fn generate_key(&self, request: &AIRequest) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        request.feature.hash(&mut hasher);
        request.content.hash(&mut hasher);

        // Hash context manually since HashMap doesn't implement Hash
        for (key, value) in &request.context {
            key.hash(&mut hasher);
            value.hash(&mut hasher);
        }

        // Hash temperature as bits since f64 doesn't implement Hash
        if let Some(temp) = request.temperature {
            temp.to_bits().hash(&mut hasher);
        }

        request.max_tokens.hash(&mut hasher);

        format!("ai_cache_{:x}", hasher.finish())
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 1000,
            default_ttl: Duration::from_secs(3600), // 1 hour
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}
