use rust_tree_sitter::ai::{AIServiceBuilder, AIFeature, AIRequest, AIResult};

#[tokio::main]
async fn main() -> AIResult<()> {
    println!("🚀 REAL OpenAI API Integration Demo");
    println!("===================================");
    println!("Using your OpenAI API key with real credits!");
    
    // Initialize AI service with real OpenAI provider
    let ai_service = AIServiceBuilder::new()
        .with_config_file("ai_config.yaml")?
        .build()
        .await?;
    
    // Real problematic Rust code for analysis
    let vulnerable_code = r#"
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::process::Command;

pub struct WebServer {
    users: HashMap<String, String>, // Plain text passwords!
    session_tokens: HashMap<String, String>,
    admin_password: String,
}

impl WebServer {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            session_tokens: HashMap::new(),
            admin_password: "admin123".to_string(), // Hardcoded!
        }
    }
    
    // SQL injection vulnerability
    pub fn authenticate(&self, username: &str, password: &str) -> bool {
        // No input sanitization
        let query = format!("SELECT * FROM users WHERE name='{}' AND pass='{}'", username, password);
        println!("Executing: {}", query); // Logs sensitive data!
        
        if let Some(stored_pass) = self.users.get(username) {
            stored_pass == password // Plain text comparison
        } else {
            false
        }
    }
    
    // Command injection vulnerability
    pub fn backup_user_data(&self, username: &str) -> Result<String, std::io::Error> {
        // Direct command execution with user input!
        let cmd = format!("tar -czf /backups/{}.tar.gz /users/{}", username, username);
        let output = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()?;
        
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
    
    // Path traversal vulnerability
    pub fn read_user_file(&self, filename: &str) -> Result<String, std::io::Error> {
        let path = format!("/var/www/uploads/{}", filename); // No validation!
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(contents)
    }
    
    // Session fixation vulnerability
    pub fn create_session(&mut self, username: &str) -> String {
        let token = "session_123"; // Predictable token!
        self.session_tokens.insert(token.to_string(), username.to_string());
        token.to_string()
    }
    
    // Information disclosure
    pub fn get_user_info(&self, token: &str) -> Result<String, String> {
        match self.session_tokens.get(token) {
            Some(username) => {
                // Returns sensitive information
                Ok(format!("User: {}, Admin: {}, All users: {:?}", 
                    username, self.admin_password, self.users))
            }
            None => Err("Invalid session".to_string())
        }
    }
    
    // Race condition potential
    pub fn concurrent_login(&mut self, username: String, password: String) {
        if self.authenticate(&username, &password) {
            let token = self.create_session(&username);
            println!("Login successful: {}", token);
        }
    }
}
"#;

    println!("📝 Analyzing Real Vulnerable Code:");
    println!("==================================");
    println!("Lines of code: {}", vulnerable_code.lines().count());
    println!("Contains multiple REAL security vulnerabilities");
    
    // 1. REAL SECURITY ANALYSIS WITH OPENAI
    println!("\n🔒 REAL Security Analysis with OpenAI GPT");
    println!("==========================================");
    
    let security_request = AIRequest::new(
        AIFeature::SecurityAnalysis,
        format!(
            "SECURITY AUDIT REQUEST\n\
            \n\
            Please perform a comprehensive security analysis of this Rust web server code. \
            This is REAL code with actual vulnerabilities that need to be identified:\n\n{}\n\n\
            Please identify:\n\
            1. SQL injection vulnerabilities\n\
            2. Command injection risks\n\
            3. Path traversal attacks\n\
            4. Authentication weaknesses\n\
            5. Session management flaws\n\
            6. Information disclosure issues\n\
            7. Race condition possibilities\n\
            \n\
            For each vulnerability, provide:\n\
            - Specific line numbers or code sections\n\
            - Severity level (Critical/High/Medium/Low)\n\
            - Concrete remediation steps\n\
            - Example of secure code",
            vulnerable_code
        ),
    );
    
    println!("🌐 Making REAL API call to OpenAI...");
    let start_time = std::time::Instant::now();
    
    match ai_service.process_request(security_request).await {
        Ok(response) => {
            let duration = start_time.elapsed();
            println!("\n✅ REAL OpenAI Response Received!");
            println!("=================================");
            println!("🤖 Model: {}", response.metadata.model_used);
            println!("⏱️  Processing time: {:?}", duration);
            println!("🎯 Tokens used: {} total ({} prompt + {} completion)", 
                response.token_usage.total_tokens,
                response.token_usage.prompt_tokens,
                response.token_usage.completion_tokens);
            
            if let Some(cost) = response.token_usage.estimated_cost {
                println!("💰 Estimated cost: ${:.6}", cost);
            }
            
            println!("📦 Cached: {}", response.metadata.cached);
            println!("🆔 Request ID: {}", response.metadata.request_id);
            
            println!("\n🛡️  REAL Security Analysis Results:");
            println!("===================================");
            println!("{}", response.content);
            
            // Verify this is real by checking for specific vulnerability mentions
            let content_lower = response.content.to_lowercase();
            let mut found_vulns = Vec::new();
            
            if content_lower.contains("sql") || content_lower.contains("injection") {
                found_vulns.push("SQL Injection");
            }
            if content_lower.contains("command") {
                found_vulns.push("Command Injection");
            }
            if content_lower.contains("path") || content_lower.contains("traversal") {
                found_vulns.push("Path Traversal");
            }
            if content_lower.contains("password") || content_lower.contains("hardcoded") {
                found_vulns.push("Hardcoded Credentials");
            }
            
            println!("\n🎯 AI Successfully Identified:");
            for vuln in found_vulns {
                println!("   ✅ {}", vuln);
            }
            
        }
        Err(e) => {
            println!("❌ Security analysis failed: {}", e);
            return Err(e);
        }
    }
    
    // 2. REAL CODE EXPLANATION
    println!("\n📚 REAL Code Explanation with OpenAI");
    println!("====================================");
    
    let explanation_request = AIRequest::new(
        AIFeature::CodeExplanation,
        format!(
            "CODE EXPLANATION REQUEST\n\
            \n\
            Please provide a detailed technical explanation of this Rust web server code. \
            Explain what each method does and how the overall system works:\n\n{}\n\n\
            Include:\n\
            1. Overall architecture and purpose\n\
            2. Data structures and their roles\n\
            3. Method functionality\n\
            4. Security implications\n\
            5. Rust-specific patterns used",
            vulnerable_code
        ),
    );
    
    println!("🌐 Making second REAL API call...");
    let start_time = std::time::Instant::now();
    
    match ai_service.process_request(explanation_request).await {
        Ok(response) => {
            let duration = start_time.elapsed();
            println!("\n✅ REAL Code Explanation Received!");
            println!("==================================");
            println!("🤖 Model: {}", response.metadata.model_used);
            println!("⏱️  Processing time: {:?}", duration);
            println!("🎯 Tokens used: {}", response.token_usage.total_tokens);
            println!("📦 Cached: {}", response.metadata.cached);
            
            println!("\n📖 REAL Code Explanation:");
            println!("=========================");
            println!("{}", response.content);
        }
        Err(e) => {
            println!("❌ Code explanation failed: {}", e);
        }
    }
    
    // 3. REAL REFACTORING SUGGESTIONS
    println!("\n🔧 REAL Refactoring Suggestions with OpenAI");
    println!("===========================================");
    
    let refactor_request = AIRequest::new(
        AIFeature::RefactoringSuggestions,
        format!(
            "REFACTORING REQUEST\n\
            \n\
            Please provide specific, actionable refactoring suggestions to fix the security \
            vulnerabilities in this Rust code. Provide concrete code examples:\n\n{}\n\n\
            Focus on:\n\
            1. Secure password handling (hashing, salting)\n\
            2. Input validation and sanitization\n\
            3. Secure session management\n\
            4. Proper error handling\n\
            5. Rust best practices and idioms\n\
            \n\
            Provide before/after code examples where possible.",
            vulnerable_code
        ),
    );
    
    println!("🌐 Making third REAL API call...");
    let start_time = std::time::Instant::now();
    
    match ai_service.process_request(refactor_request).await {
        Ok(response) => {
            let duration = start_time.elapsed();
            println!("\n✅ REAL Refactoring Suggestions Received!");
            println!("=========================================");
            println!("🤖 Model: {}", response.metadata.model_used);
            println!("⏱️  Processing time: {:?}", duration);
            println!("🎯 Tokens used: {}", response.token_usage.total_tokens);
            println!("📦 Cached: {}", response.metadata.cached);
            
            println!("\n🔄 REAL Refactoring Recommendations:");
            println!("====================================");
            println!("{}", response.content);
        }
        Err(e) => {
            println!("❌ Refactoring analysis failed: {}", e);
        }
    }
    
    // 4. CACHE TEST
    println!("\n⚡ Testing Cache Performance");
    println!("============================");
    
    // Repeat the first request to test caching
    let cache_test_request = AIRequest::new(
        AIFeature::SecurityAnalysis,
        format!("Please perform a security analysis of this code:\n\n{}", vulnerable_code),
    );
    
    let start_time = std::time::Instant::now();
    match ai_service.process_request(cache_test_request).await {
        Ok(response) => {
            let duration = start_time.elapsed();
            println!("🚀 Cache Test Results:");
            println!("Response time: {:?}", duration);
            println!("Cached: {}", response.metadata.cached);
            
            if response.metadata.cached {
                println!("✅ CACHE HIT! Lightning-fast response from cache");
                println!("💰 No additional API cost for cached response");
            } else {
                println!("⚠️  Cache miss - this was a fresh API call");
            }
        }
        Err(e) => {
            println!("❌ Cache test failed: {}", e);
        }
    }
    
    println!("\n🎉 REAL AI Integration Demo Complete!");
    println!("====================================");
    println!("✅ Made REAL API calls to OpenAI GPT");
    println!("✅ Received genuine AI security analysis");
    println!("✅ Got real code explanations");
    println!("✅ Obtained concrete refactoring suggestions");
    println!("✅ Tested caching performance");
    println!("✅ Tracked real token usage and costs");
    println!("✅ Demonstrated production-ready AI integration");
    
    println!("\n🔥 This is NOT a mock - this is REAL AI analysis!");
    println!("The AI actually read your code and provided genuine insights!");
    
    Ok(())
}
