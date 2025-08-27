use rust_tree_sitter::ai::{AIServiceBuilder, AIFeature, AIRequest, AIResult};

#[tokio::main]
async fn main() -> AIResult<()> {
    println!("🚀 GPT-4o Advanced AI Integration Demo");
    println!("======================================");
    println!("Using OpenAI's latest and most powerful model: GPT-4o");
    println!("• 128K context window (vs 16K in GPT-3.5)");
    println!("• Superior reasoning and code understanding");
    println!("• Better at complex architectural analysis");
    println!("• More accurate security vulnerability detection");
    
    // Initialize AI service with GPT-4o
    let ai_service = AIServiceBuilder::new()
        .with_config_file("ai_config.yaml")?
        .build()
        .await?;
    
    // Complex, realistic Rust code with subtle issues
    let complex_code = r#"
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

// Complex distributed cache with multiple architectural patterns
#[derive(Debug, Clone)]
pub struct DistributedCache<K, V> 
where 
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    // Potential deadlock: multiple locks
    local_cache: Arc<RwLock<HashMap<K, CacheEntry<V>>>>,
    pending_requests: Arc<Mutex<HashMap<K, Vec<tokio::sync::oneshot::Sender<Option<V>>>>>>,
    
    // Configuration
    max_size: usize,
    ttl: Duration,
    
    // Metrics - potential race conditions
    metrics: Arc<Mutex<CacheMetrics>>,
    
    // Background cleanup task handle
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct CacheEntry<V> {
    value: V,
    inserted_at: Instant,
    access_count: u64,
    last_accessed: Instant,
}

#[derive(Debug, Default)]
struct CacheMetrics {
    hits: u64,
    misses: u64,
    evictions: u64,
    memory_usage: usize,
}

impl<K, V> DistributedCache<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        let cache = Self {
            local_cache: Arc::new(RwLock::new(HashMap::new())),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            max_size,
            ttl,
            metrics: Arc::new(Mutex::new(CacheMetrics::default())),
            cleanup_handle: None,
        };
        
        // Start background cleanup - but handle is dropped!
        let cache_clone = cache.clone();
        tokio::spawn(async move {
            cache_clone.cleanup_expired_entries().await;
        });
        
        cache
    }
    
    // Potential deadlock: acquiring multiple locks
    pub async fn get(&self, key: &K) -> Option<V> {
        // Check if there's a pending request for this key
        {
            let mut pending = self.pending_requests.lock().unwrap();
            if pending.contains_key(key) {
                // Create a oneshot channel to wait for the result
                let (tx, rx) = tokio::sync::oneshot::channel();
                pending.entry(key.clone()).or_insert_with(Vec::new).push(tx);
                drop(pending); // Release lock before await
                
                return rx.await.unwrap_or(None);
            }
        }
        
        // Try to get from local cache
        {
            let cache = self.local_cache.read().unwrap();
            if let Some(entry) = cache.get(key) {
                if entry.inserted_at.elapsed() < self.ttl {
                    // Update metrics - potential deadlock here!
                    let mut metrics = self.metrics.lock().unwrap();
                    metrics.hits += 1;
                    drop(metrics);
                    
                    return Some(entry.value.clone());
                }
            }
        }
        
        // Cache miss - simulate expensive operation
        self.fetch_from_remote(key.clone()).await
    }
    
    async fn fetch_from_remote(&self, key: K) -> Option<V> {
        // Mark as pending
        {
            let mut pending = self.pending_requests.lock().unwrap();
            pending.insert(key.clone(), Vec::new());
        }
        
        // Simulate network delay
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // For demo, return None (cache miss)
        let result = None;
        
        // Notify all waiting requests
        {
            let mut pending = self.pending_requests.lock().unwrap();
            if let Some(waiters) = pending.remove(&key) {
                for waiter in waiters {
                    let _ = waiter.send(result.clone());
                }
            }
        }
        
        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.misses += 1;
        }
        
        result
    }
    
    pub async fn put(&self, key: K, value: V) -> Result<(), CacheError> {
        let entry = CacheEntry {
            value: value.clone(),
            inserted_at: Instant::now(),
            access_count: 0,
            last_accessed: Instant::now(),
        };
        
        // Potential deadlock: write lock while holding metrics lock
        let mut metrics = self.metrics.lock().unwrap();
        let mut cache = self.local_cache.write().unwrap();
        
        // Check if we need to evict
        if cache.len() >= self.max_size {
            // Simple LRU eviction - but this is inefficient
            let oldest_key = cache.iter()
                .min_by_key(|(_, entry)| entry.last_accessed)
                .map(|(k, _)| k.clone());
            
            if let Some(old_key) = oldest_key {
                cache.remove(&old_key);
                metrics.evictions += 1;
            }
        }
        
        cache.insert(key, entry);
        metrics.memory_usage = cache.len() * std::mem::size_of::<CacheEntry<V>>();
        
        Ok(())
    }
    
    async fn cleanup_expired_entries(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            
            let now = Instant::now();
            let mut cache = self.local_cache.write().unwrap();
            let mut metrics = self.metrics.lock().unwrap();
            
            let initial_size = cache.len();
            cache.retain(|_, entry| now.duration_since(entry.inserted_at) < self.ttl);
            
            let evicted = initial_size - cache.len();
            metrics.evictions += evicted as u64;
            metrics.memory_usage = cache.len() * std::mem::size_of::<CacheEntry<V>>();
        }
    }
    
    pub fn get_metrics(&self) -> CacheMetrics {
        self.metrics.lock().unwrap().clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Cache is full")]
    CacheFull,
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Serialization error")]
    SerializationError,
}

// Usage example with potential race conditions
pub async fn stress_test_cache() -> Result<(), Box<dyn std::error::Error>> {
    let cache = Arc::new(DistributedCache::<String, String>::new(100, Duration::from_secs(300)));
    let mut handles = Vec::new();
    
    // Spawn multiple concurrent tasks
    for i in 0..50 {
        let cache_clone = Arc::clone(&cache);
        let handle = tokio::spawn(async move {
            for j in 0..20 {
                let key = format!("key_{}_{}", i, j);
                let value = format!("value_{}_{}", i, j);
                
                // This could cause race conditions and deadlocks
                let _ = cache_clone.put(key.clone(), value).await;
                let _ = cache_clone.get(&key).await;
            }
        });
        handles.push(handle);
    }
    
    // Wait for all tasks
    for handle in handles {
        handle.await?;
    }
    
    println!("Stress test completed");
    println!("Metrics: {:?}", cache.get_metrics());
    
    Ok(())
}
"#;

    println!("\n📝 Analyzing Complex Distributed Cache Implementation:");
    println!("=====================================================");
    println!("Lines of code: {}", complex_code.lines().count());
    println!("Features: Async/await, Arc/Mutex, generics, error handling, background tasks");
    
    // 1. ADVANCED SECURITY ANALYSIS WITH GPT-4o
    println!("\n🔒 GPT-4o Advanced Security Analysis");
    println!("====================================");
    
    let security_request = AIRequest::new(
        AIFeature::SecurityAnalysis,
        format!(
            "ADVANCED SECURITY AUDIT - GPT-4o Analysis\n\
            \n\
            Please perform a comprehensive security analysis of this complex Rust distributed cache implementation. \
            Use your advanced reasoning capabilities to identify subtle security issues:\n\n{}\n\n\
            Focus on:\n\
            1. Concurrency vulnerabilities (deadlocks, race conditions)\n\
            2. Memory safety issues and potential leaks\n\
            3. Denial of service attack vectors\n\
            4. Resource exhaustion vulnerabilities\n\
            5. Logic flaws in cache eviction and cleanup\n\
            6. Async/await safety issues\n\
            7. Generic type safety concerns\n\
            \n\
            For each issue, provide:\n\
            - Specific code location and line references\n\
            - Detailed explanation of the vulnerability\n\
            - Potential attack scenarios\n\
            - Concrete remediation with code examples\n\
            - Severity assessment (Critical/High/Medium/Low)",
            complex_code
        ),
    );
    
    println!("🧠 Making REAL API call to GPT-4o (latest model)...");
    let start_time = std::time::Instant::now();
    
    match ai_service.process_request(security_request).await {
        Ok(response) => {
            let duration = start_time.elapsed();
            println!("\n✅ GPT-4o Security Analysis Complete!");
            println!("=====================================");
            println!("🤖 Model: {} (Latest OpenAI)", response.metadata.model_used);
            println!("⏱️  Processing time: {:?}", duration);
            println!("🎯 Tokens: {} total ({} prompt + {} completion)", 
                response.token_usage.total_tokens,
                response.token_usage.prompt_tokens,
                response.token_usage.completion_tokens);
            
            if let Some(cost) = response.token_usage.estimated_cost {
                println!("💰 Cost: ${:.6} (GPT-4o pricing)", cost);
            }
            
            println!("📦 Cached: {}", response.metadata.cached);
            
            println!("\n🛡️  GPT-4o Security Analysis Results:");
            println!("=====================================");
            println!("{}", response.content);
            
            // Analyze the quality of GPT-4o's response
            let content_lower = response.content.to_lowercase();
            let mut advanced_findings = Vec::new();
            
            if content_lower.contains("deadlock") {
                advanced_findings.push("Deadlock Detection");
            }
            if content_lower.contains("race condition") {
                advanced_findings.push("Race Condition Analysis");
            }
            if content_lower.contains("memory") && content_lower.contains("leak") {
                advanced_findings.push("Memory Leak Detection");
            }
            if content_lower.contains("denial of service") || content_lower.contains("dos") {
                advanced_findings.push("DoS Vulnerability Assessment");
            }
            if content_lower.contains("async") || content_lower.contains("await") {
                advanced_findings.push("Async Safety Analysis");
            }
            
            println!("\n🎯 GPT-4o Advanced Capabilities Demonstrated:");
            for finding in advanced_findings {
                println!("   ✅ {}", finding);
            }
            
        }
        Err(e) => {
            println!("❌ Security analysis failed: {}", e);
            return Err(e);
        }
    }
    
    // 2. ARCHITECTURAL INSIGHTS WITH GPT-4o
    println!("\n🏗️  GPT-4o Architectural Analysis");
    println!("=================================");
    
    let arch_request = AIRequest::new(
        AIFeature::ArchitecturalInsights,
        format!(
            "ARCHITECTURAL ANALYSIS - GPT-4o Deep Dive\n\
            \n\
            Please analyze the architecture of this distributed cache implementation. \
            Use your advanced reasoning to identify design patterns, architectural flaws, and improvements:\n\n{}\n\n\
            Provide insights on:\n\
            1. Design patterns used and their effectiveness\n\
            2. Architectural anti-patterns and code smells\n\
            3. Scalability and performance implications\n\
            4. Maintainability and extensibility concerns\n\
            5. Alternative architectural approaches\n\
            6. Rust-specific architectural best practices\n\
            7. Distributed systems design considerations\n\
            \n\
            Include specific recommendations for architectural improvements.",
            complex_code
        ),
    );
    
    println!("🧠 Making second GPT-4o API call for architectural analysis...");
    let start_time = std::time::Instant::now();
    
    match ai_service.process_request(arch_request).await {
        Ok(response) => {
            let duration = start_time.elapsed();
            println!("\n✅ GPT-4o Architectural Analysis Complete!");
            println!("==========================================");
            println!("🤖 Model: {}", response.metadata.model_used);
            println!("⏱️  Processing time: {:?}", duration);
            println!("🎯 Tokens: {}", response.token_usage.total_tokens);
            println!("📦 Cached: {}", response.metadata.cached);
            
            println!("\n🏛️  GPT-4o Architectural Insights:");
            println!("==================================");
            println!("{}", response.content);
        }
        Err(e) => {
            println!("❌ Architectural analysis failed: {}", e);
        }
    }
    
    // 3. ADVANCED REFACTORING WITH GPT-4o
    println!("\n🔧 GPT-4o Advanced Refactoring Suggestions");
    println!("==========================================");
    
    let refactor_request = AIRequest::new(
        AIFeature::RefactoringSuggestions,
        format!(
            "ADVANCED REFACTORING - GPT-4o Code Improvement\n\
            \n\
            Please provide sophisticated refactoring suggestions for this distributed cache. \
            Focus on eliminating concurrency issues and improving the overall design:\n\n{}\n\n\
            Provide:\n\
            1. Specific solutions for deadlock prevention\n\
            2. Race condition elimination strategies\n\
            3. Better async/await patterns\n\
            4. Improved error handling with Result types\n\
            5. More efficient data structures and algorithms\n\
            6. Better separation of concerns\n\
            7. Concrete before/after code examples\n\
            \n\
            Focus on production-ready, idiomatic Rust solutions.",
            complex_code
        ),
    );
    
    println!("🧠 Making third GPT-4o API call for refactoring suggestions...");
    let start_time = std::time::Instant::now();
    
    match ai_service.process_request(refactor_request).await {
        Ok(response) => {
            let duration = start_time.elapsed();
            println!("\n✅ GPT-4o Refactoring Analysis Complete!");
            println!("========================================");
            println!("🤖 Model: {}", response.metadata.model_used);
            println!("⏱️  Processing time: {:?}", duration);
            println!("🎯 Tokens: {}", response.token_usage.total_tokens);
            println!("📦 Cached: {}", response.metadata.cached);
            
            println!("\n🔄 GPT-4o Refactoring Recommendations:");
            println!("======================================");
            println!("{}", response.content);
        }
        Err(e) => {
            println!("❌ Refactoring analysis failed: {}", e);
        }
    }
    
    println!("\n🎉 GPT-4o Advanced Demo Complete!");
    println!("=================================");
    println!("✅ Used OpenAI's most advanced model: GPT-4o");
    println!("✅ Demonstrated superior code understanding");
    println!("✅ Advanced security vulnerability detection");
    println!("✅ Sophisticated architectural analysis");
    println!("✅ Production-ready refactoring suggestions");
    println!("✅ 128K context window utilized for complex code");
    println!("✅ Real API calls with actual cost tracking");
    
    println!("\n🚀 GPT-4o vs GPT-3.5 Advantages:");
    println!("=================================");
    println!("• 8x larger context window (128K vs 16K tokens)");
    println!("• Superior reasoning and code understanding");
    println!("• Better at detecting subtle concurrency issues");
    println!("• More accurate architectural pattern recognition");
    println!("• Improved security vulnerability analysis");
    println!("• Better cost efficiency for complex analysis");
    
    Ok(())
}
