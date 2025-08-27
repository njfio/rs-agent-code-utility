use rust_tree_sitter::ai::{AIServiceBuilder, AIFeature, AIRequest, AIResult};

#[tokio::main]
async fn main() -> AIResult<()> {
    println!("🤖 AI Integration Showcase");
    println!("===========================");
    
    // Initialize AI service
    let ai_service = AIServiceBuilder::new()
        .with_mock_providers(true)
        .build()
        .await?;
    
    // Complex Rust code example for analysis
    let complex_code = r#"
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;

// Complex async system with multiple patterns
pub struct DistributedCache<K, V> 
where 
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    local_cache: Arc<RwLock<HashMap<K, V>>>,
    remote_nodes: Arc<Mutex<Vec<String>>>,
    replication_factor: usize,
    consistency_level: ConsistencyLevel,
    metrics: Arc<Mutex<CacheMetrics>>,
}

#[derive(Debug, Clone)]
pub enum ConsistencyLevel {
    Eventual,
    Strong,
    Quorum,
}

#[derive(Debug, Default)]
struct CacheMetrics {
    hits: u64,
    misses: u64,
    evictions: u64,
    network_errors: u64,
}

impl<K, V> DistributedCache<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(replication_factor: usize, consistency_level: ConsistencyLevel) -> Self {
        Self {
            local_cache: Arc::new(RwLock::new(HashMap::new())),
            remote_nodes: Arc::new(Mutex::new(Vec::new())),
            replication_factor,
            consistency_level,
            metrics: Arc::new(Mutex::new(CacheMetrics::default())),
        }
    }
    
    pub async fn get(&self, key: &K) -> Option<V> {
        // Try local cache first
        if let Ok(cache) = self.local_cache.read() {
            if let Some(value) = cache.get(key) {
                self.increment_hits().await;
                return Some(value.clone());
            }
        }
        
        // Fallback to distributed lookup
        match self.consistency_level {
            ConsistencyLevel::Eventual => self.eventual_get(key).await,
            ConsistencyLevel::Strong => self.strong_get(key).await,
            ConsistencyLevel::Quorum => self.quorum_get(key).await,
        }
    }
    
    async fn eventual_get(&self, key: &K) -> Option<V> {
        // Implementation would query one random node
        self.increment_misses().await;
        None
    }
    
    async fn strong_get(&self, key: &K) -> Option<V> {
        // Implementation would query all nodes and wait for consensus
        self.increment_misses().await;
        None
    }
    
    async fn quorum_get(&self, key: &K) -> Option<V> {
        // Implementation would query majority of nodes
        self.increment_misses().await;
        None
    }
    
    pub async fn put(&self, key: K, value: V) -> Result<(), CacheError> {
        // Update local cache
        if let Ok(mut cache) = self.local_cache.write() {
            cache.insert(key.clone(), value.clone());
        }
        
        // Replicate to remote nodes based on replication factor
        self.replicate_to_nodes(key, value).await
    }
    
    async fn replicate_to_nodes(&self, key: K, value: V) -> Result<(), CacheError> {
        let nodes = self.remote_nodes.lock().unwrap().clone();
        let mut replication_tasks = Vec::new();
        
        for node in nodes.iter().take(self.replication_factor) {
            let node_url = node.clone();
            let key_clone = key.clone();
            let value_clone = value.clone();
            
            let task = tokio::spawn(async move {
                // Simulate network call
                tokio::time::sleep(Duration::from_millis(10)).await;
                // Would actually send HTTP request to node
                Ok::<(), CacheError>(())
            });
            
            replication_tasks.push(task);
        }
        
        // Wait for all replications to complete
        for task in replication_tasks {
            task.await.map_err(|_| CacheError::NetworkError)??;
        }
        
        Ok(())
    }
    
    async fn increment_hits(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.hits += 1;
        }
    }
    
    async fn increment_misses(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.misses += 1;
        }
    }
    
    pub async fn get_metrics(&self) -> CacheMetrics {
        self.metrics.lock().unwrap().clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Network error occurred")]
    NetworkError,
    #[error("Consistency violation")]
    ConsistencyError,
    #[error("Timeout waiting for response")]
    TimeoutError,
}

// Usage example with potential issues
pub async fn example_usage() -> Result<(), Box<dyn std::error::Error>> {
    let cache = DistributedCache::<String, String>::new(3, ConsistencyLevel::Quorum);
    
    // Potential race condition - multiple threads accessing cache
    let cache_clone = Arc::new(cache);
    let mut handles = Vec::new();
    
    for i in 0..10 {
        let cache_ref = Arc::clone(&cache_clone);
        let handle = tokio::spawn(async move {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            
            // This could cause race conditions
            cache_ref.put(key.clone(), value).await?;
            let retrieved = cache_ref.get(&key).await;
            
            println!("Retrieved: {:?}", retrieved);
            Ok::<(), CacheError>(())
        });
        handles.push(handle);
    }
    
    // Wait for all tasks
    for handle in handles {
        handle.await??;
    }
    
    Ok(())
}
"#;

    println!("📊 Analyzing Complex Distributed Cache Implementation");
    println!("====================================================");
    println!("Lines of code: {}", complex_code.lines().count());
    
    // 1. ARCHITECTURAL ANALYSIS
    println!("\n🏗️  ARCHITECTURAL INSIGHTS");
    println!("==========================");
    
    let arch_request = AIRequest::new(
        AIFeature::ArchitecturalInsights,
        format!(
            "Analyze this complex Rust distributed cache implementation:\n\n{}\n\n\
            Focus on:\n\
            1. Design patterns used (Arc, Mutex, RwLock patterns)\n\
            2. Concurrency architecture\n\
            3. Error handling strategy\n\
            4. Generic type system usage\n\
            5. Async/await patterns\n\
            6. Potential architectural improvements",
            complex_code
        ),
    );
    
    match ai_service.process_request(arch_request).await {
        Ok(response) => {
            println!("🎯 Architectural Analysis:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Architectural analysis failed: {}", e),
    }
    
    // 2. SECURITY DEEP DIVE
    println!("\n🔒 SECURITY ANALYSIS");
    println!("====================");
    
    let security_request = AIRequest::new(
        AIFeature::SecurityAnalysis,
        format!(
            "Perform comprehensive security analysis of this distributed cache:\n\n{}\n\n\
            Identify:\n\
            1. Race condition vulnerabilities\n\
            2. Memory safety issues\n\
            3. Network security concerns\n\
            4. Data integrity risks\n\
            5. Denial of service vectors\n\
            6. Information disclosure risks\n\
            7. Authentication/authorization gaps",
            complex_code
        ),
    );
    
    match ai_service.process_request(security_request).await {
        Ok(response) => {
            println!("🛡️  Security Vulnerabilities:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Security analysis failed: {}", e),
    }
    
    // 3. PERFORMANCE OPTIMIZATION
    println!("\n⚡ PERFORMANCE ANALYSIS");
    println!("=======================");
    
    let perf_request = AIRequest::new(
        AIFeature::QualityAssessment,
        format!(
            "Analyze performance characteristics of this distributed cache:\n\n{}\n\n\
            Evaluate:\n\
            1. Lock contention issues (RwLock vs Mutex usage)\n\
            2. Memory allocation patterns\n\
            3. Network I/O optimization opportunities\n\
            4. Async task spawning efficiency\n\
            5. Cache eviction strategies\n\
            6. Scalability bottlenecks\n\
            7. Specific optimization recommendations",
            complex_code
        ),
    );
    
    match ai_service.process_request(perf_request).await {
        Ok(response) => {
            println!("🚀 Performance Insights:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Performance analysis failed: {}", e),
    }
    
    // 4. REFACTORING SUGGESTIONS
    println!("\n🔧 REFACTORING RECOMMENDATIONS");
    println!("===============================");
    
    let refactor_request = AIRequest::new(
        AIFeature::RefactoringSuggestions,
        format!(
            "Provide detailed refactoring suggestions for this distributed cache:\n\n{}\n\n\
            Focus on:\n\
            1. Eliminating race conditions\n\
            2. Improving error handling (better Result types)\n\
            3. Reducing lock contention\n\
            4. Better separation of concerns\n\
            5. More idiomatic Rust patterns\n\
            6. Testability improvements\n\
            7. API design enhancements",
            complex_code
        ),
    );
    
    match ai_service.process_request(refactor_request).await {
        Ok(response) => {
            println!("🔄 Refactoring Suggestions:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Refactoring analysis failed: {}", e),
    }
    
    // 5. PATTERN DETECTION
    println!("\n🎨 DESIGN PATTERN ANALYSIS");
    println!("===========================");
    
    let pattern_request = AIRequest::new(
        AIFeature::PatternDetection,
        format!(
            "Identify design patterns in this distributed cache implementation:\n\n{}\n\n\
            Analyze:\n\
            1. Existing patterns (Observer, Strategy, etc.)\n\
            2. Missing patterns that could improve the design\n\
            3. Anti-patterns to avoid\n\
            4. Rust-specific patterns (RAII, type state, etc.)\n\
            5. Concurrency patterns\n\
            6. Error handling patterns",
            complex_code
        ),
    );
    
    match ai_service.process_request(pattern_request).await {
        Ok(response) => {
            println!("🎨 Pattern Analysis:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Pattern analysis failed: {}", e),
    }
    
    // 6. TEST GENERATION
    println!("\n🧪 TEST STRATEGY");
    println!("=================");
    
    let test_request = AIRequest::new(
        AIFeature::TestGeneration,
        format!(
            "Generate comprehensive test strategy for this distributed cache:\n\n{}\n\n\
            Include:\n\
            1. Unit tests for individual methods\n\
            2. Integration tests for distributed behavior\n\
            3. Concurrency tests for race conditions\n\
            4. Performance benchmarks\n\
            5. Chaos engineering tests\n\
            6. Property-based testing scenarios\n\
            7. Mock strategies for network calls",
            complex_code
        ),
    );
    
    match ai_service.process_request(test_request).await {
        Ok(response) => {
            println!("🧪 Testing Strategy:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Test generation failed: {}", e),
    }
    
    println!("\n🎉 AI Analysis Complete!");
    println!("=========================");
    println!("✅ Architectural insights provided");
    println!("✅ Security vulnerabilities identified");
    println!("✅ Performance optimizations suggested");
    println!("✅ Refactoring recommendations given");
    println!("✅ Design patterns analyzed");
    println!("✅ Comprehensive test strategy created");
    
    Ok(())
}
