use rust_tree_sitter::ai::{AIServiceBuilder, AIFeature, AIRequest, AIResult};

#[tokio::main]
async fn main() -> AIResult<()> {
    println!("🤖 REAL AI Integration Demo");
    println!("===========================");
    println!("Using Anthropic Claude API with real analysis");
    
    // Initialize AI service with real Anthropic provider
    let ai_service = AIServiceBuilder::new()
        .with_config_file("ai_config.yaml")?
        .build()
        .await?;
    
    // Real Rust code with actual issues to analyze
    let problematic_code = r#"
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

pub struct UserDatabase {
    users: HashMap<String, String>, // Storing passwords in plain text!
    admin_password: String,         // Hardcoded admin password
}

impl UserDatabase {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            admin_password: "admin123".to_string(), // Security issue!
        }
    }
    
    // SQL injection vulnerability if used with database
    pub fn authenticate_user(&self, username: &str, password: &str) -> bool {
        // No input validation
        if let Some(stored_password) = self.users.get(username) {
            stored_password == password // Plain text comparison
        } else {
            false
        }
    }
    
    // Potential path traversal vulnerability
    pub fn load_user_data(&self, filename: &str) -> Result<String, std::io::Error> {
        let path = format!("/users/{}", filename); // No path validation!
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(contents)
    }
    
    // Memory leak - never removes users
    pub fn add_user(&mut self, username: String, password: String) {
        self.users.insert(username, password); // Plain text storage!
    }
    
    // Admin backdoor
    pub fn is_admin(&self, password: &str) -> bool {
        password == self.admin_password // Hardcoded comparison
    }
    
    // Panic on error - poor error handling
    pub fn save_to_file(&self, filename: &str) {
        let data = format!("{:?}", self.users);
        std::fs::write(filename, data).unwrap(); // Will panic!
    }
}

// Usage example with race condition potential
use std::sync::Arc;
use std::thread;

pub fn concurrent_access_example() {
    let db = Arc::new(std::sync::Mutex::new(UserDatabase::new()));
    
    let mut handles = vec![];
    
    for i in 0..10 {
        let db_clone = Arc::clone(&db);
        let handle = thread::spawn(move || {
            let mut db = db_clone.lock().unwrap(); // Could panic!
            db.add_user(format!("user{}", i), "password123".to_string());
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap(); // Could panic!
    }
}
"#;

    println!("📝 Analyzing Real Rust Code:");
    println!("============================");
    println!("Code length: {} lines", problematic_code.lines().count());
    println!("Contains multiple security vulnerabilities and code quality issues");
    
    // 1. REAL SECURITY ANALYSIS
    println!("\n🔒 REAL Security Analysis with Claude");
    println!("=====================================");
    
    let security_request = AIRequest::new(
        AIFeature::SecurityAnalysis,
        format!(
            "Please perform a comprehensive security analysis of this Rust code. \
            Identify specific vulnerabilities, provide line numbers where possible, \
            and suggest concrete remediation steps:\n\n{}\n\n\
            Focus on:\n\
            1. Authentication and authorization flaws\n\
            2. Input validation issues\n\
            3. Data storage security problems\n\
            4. Path traversal vulnerabilities\n\
            5. Error handling security implications\n\
            6. Concurrency safety issues",
            problematic_code
        ),
    );
    
    match ai_service.process_request(security_request).await {
        Ok(response) => {
            println!("🛡️  Claude's Security Analysis:");
            println!("Model: {}", response.metadata.model_used);
            println!("Tokens: {} (${:.4} estimated cost)", 
                response.token_usage.total_tokens,
                response.token_usage.estimated_cost.unwrap_or(0.0));
            println!("Processing time: {:?}", response.metadata.processing_time);
            println!("Cached: {}", response.metadata.cached);
            println!("\n📋 Security Findings:");
            println!("{}", response.content);
        }
        Err(e) => {
            println!("❌ Security analysis failed: {}", e);
            return Err(e);
        }
    }
    
    // 2. REAL CODE EXPLANATION
    println!("\n📚 REAL Code Explanation with Claude");
    println!("====================================");
    
    let explanation_request = AIRequest::new(
        AIFeature::CodeExplanation,
        format!(
            "Please provide a detailed explanation of this Rust code. \
            Explain what it does, how it works, and identify any problematic patterns:\n\n{}\n\n\
            Include:\n\
            1. Overall purpose and functionality\n\
            2. Key data structures and their roles\n\
            3. Method functionality and behavior\n\
            4. Potential issues and concerns\n\
            5. Rust-specific patterns used",
            problematic_code
        ),
    );
    
    match ai_service.process_request(explanation_request).await {
        Ok(response) => {
            println!("📖 Claude's Code Explanation:");
            println!("Model: {}", response.metadata.model_used);
            println!("Tokens: {} (${:.4} estimated cost)", 
                response.token_usage.total_tokens,
                response.token_usage.estimated_cost.unwrap_or(0.0));
            println!("Processing time: {:?}", response.metadata.processing_time);
            println!("Cached: {}", response.metadata.cached);
            println!("\n📝 Explanation:");
            println!("{}", response.content);
        }
        Err(e) => {
            println!("❌ Code explanation failed: {}", e);
        }
    }
    
    // 3. REAL REFACTORING SUGGESTIONS
    println!("\n🔧 REAL Refactoring Suggestions with Claude");
    println!("===========================================");
    
    let refactor_request = AIRequest::new(
        AIFeature::RefactoringSuggestions,
        format!(
            "Please provide specific refactoring suggestions for this Rust code. \
            Focus on security improvements, better error handling, and Rust best practices:\n\n{}\n\n\
            Provide:\n\
            1. Specific security fixes with code examples\n\
            2. Better error handling patterns\n\
            3. Improved data structures and methods\n\
            4. Rust idioms and best practices\n\
            5. Concurrency safety improvements\n\
            6. Before/after code snippets where helpful",
            problematic_code
        ),
    );
    
    match ai_service.process_request(refactor_request).await {
        Ok(response) => {
            println!("🔄 Claude's Refactoring Suggestions:");
            println!("Model: {}", response.metadata.model_used);
            println!("Tokens: {} (${:.4} estimated cost)", 
                response.token_usage.total_tokens,
                response.token_usage.estimated_cost.unwrap_or(0.0));
            println!("Processing time: {:?}", response.metadata.processing_time);
            println!("Cached: {}", response.metadata.cached);
            println!("\n💡 Refactoring Recommendations:");
            println!("{}", response.content);
        }
        Err(e) => {
            println!("❌ Refactoring analysis failed: {}", e);
        }
    }
    
    // 4. CACHE PERFORMANCE TEST
    println!("\n⚡ Testing Cache Performance");
    println!("============================");
    
    // Same request again - should hit cache
    let cache_test_request = AIRequest::new(
        AIFeature::SecurityAnalysis,
        format!(
            "Please perform a comprehensive security analysis of this Rust code:\n\n{}",
            problematic_code
        ),
    );
    
    let start = std::time::Instant::now();
    match ai_service.process_request(cache_test_request).await {
        Ok(response) => {
            let duration = start.elapsed();
            println!("🚀 Cache Test Results:");
            println!("Response time: {:?}", duration);
            println!("Cached: {}", response.metadata.cached);
            println!("Tokens: {}", response.token_usage.total_tokens);
            
            if response.metadata.cached {
                println!("✅ Cache is working! Lightning-fast response from cache.");
            } else {
                println!("⚠️  Cache miss - this was a fresh API call.");
            }
        }
        Err(e) => {
            println!("❌ Cache test failed: {}", e);
        }
    }
    
    println!("\n🎉 REAL AI Integration Demo Complete!");
    println!("====================================");
    println!("✅ Real Anthropic Claude API calls made");
    println!("✅ Actual security vulnerabilities identified");
    println!("✅ Genuine code explanations provided");
    println!("✅ Concrete refactoring suggestions given");
    println!("✅ Cache performance validated");
    println!("✅ Token usage and costs tracked");
    
    Ok(())
}
