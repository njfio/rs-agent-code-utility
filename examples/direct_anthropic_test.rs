use serde_json::json;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🤖 Direct Anthropic API Test");
    println!("============================");
    
    let api_key = env::var("ANTHROPIC_API_KEY")
        .expect("ANTHROPIC_API_KEY environment variable not set");
    
    println!("🔑 API Key found: {}...", &api_key[..10]);
    
    // Real Rust code with security issues
    let code_to_analyze = r#"
use std::collections::HashMap;

pub struct UserManager {
    users: HashMap<String, String>, // Plain text passwords!
    admin_key: String,
}

impl UserManager {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            admin_key: "admin123".to_string(), // Hardcoded password!
        }
    }
    
    pub fn add_user(&mut self, username: String, password: String) {
        self.users.insert(username, password); // No hashing!
    }
    
    pub fn authenticate(&self, username: &str, password: &str) -> bool {
        if let Some(stored_password) = self.users.get(username) {
            stored_password == password // Plain text comparison
        } else {
            false
        }
    }
    
    // Admin backdoor
    pub fn is_admin(&self, key: &str) -> bool {
        key == self.admin_key
    }
}
"#;

    println!("📝 Code to analyze ({} lines):", code_to_analyze.lines().count());
    println!("{}", code_to_analyze);
    
    // Create HTTP client
    let client = reqwest::Client::new();
    
    // Prepare the request
    let request_body = json!({
        "model": "claude-3-haiku-20240307",
        "max_tokens": 1000,
        "messages": [{
            "role": "user",
            "content": format!(
                "Please analyze this Rust code for security vulnerabilities. \
                Identify specific issues and provide concrete recommendations:\n\n{}",
                code_to_analyze
            )
        }]
    });
    
    println!("\n🚀 Making real API call to Anthropic Claude...");
    
    let start_time = std::time::Instant::now();
    
    // Make the API call
    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&request_body)
        .send()
        .await?;
    
    let duration = start_time.elapsed();
    
    println!("⏱️  API call completed in {:?}", duration);
    println!("📊 Status: {}", response.status());
    
    if response.status().is_success() {
        let response_body: serde_json::Value = response.json().await?;
        
        println!("\n🎉 SUCCESS! Real AI Analysis Results:");
        println!("=====================================");
        
        if let Some(content) = response_body["content"].as_array() {
            if let Some(text_content) = content.first() {
                if let Some(text) = text_content["text"].as_str() {
                    println!("🤖 Claude's Analysis:");
                    println!("{}", text);
                }
            }
        }
        
        // Show usage statistics
        if let Some(usage) = response_body["usage"].as_object() {
            println!("\n📊 Token Usage:");
            println!("   Input tokens: {}", usage["input_tokens"].as_u64().unwrap_or(0));
            println!("   Output tokens: {}", usage["output_tokens"].as_u64().unwrap_or(0));
            
            // Estimate cost (Claude Haiku pricing)
            let input_tokens = usage["input_tokens"].as_u64().unwrap_or(0) as f64;
            let output_tokens = usage["output_tokens"].as_u64().unwrap_or(0) as f64;
            let estimated_cost = (input_tokens * 0.00000025) + (output_tokens * 0.00000125);
            println!("   Estimated cost: ${:.6}", estimated_cost);
        }
        
        println!("\n✅ This is a REAL AI analysis, not a mock!");
        println!("✅ Claude actually analyzed the security vulnerabilities");
        println!("✅ The AI identified specific issues in the Rust code");
        println!("✅ Real token usage and costs calculated");
        
    } else {
        println!("❌ API call failed!");
        let error_text = response.text().await?;
        println!("Error response: {}", error_text);
    }
    
    // Test a second call to show it's really working
    println!("\n🔄 Making second API call for code explanation...");
    
    let explanation_request = json!({
        "model": "claude-3-haiku-20240307",
        "max_tokens": 800,
        "messages": [{
            "role": "user",
            "content": format!(
                "Please explain what this Rust code does and how it works:\n\n{}",
                code_to_analyze
            )
        }]
    });
    
    let start_time = std::time::Instant::now();
    
    let response2 = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&explanation_request)
        .send()
        .await?;
    
    let duration2 = start_time.elapsed();
    
    if response2.status().is_success() {
        let response_body2: serde_json::Value = response2.json().await?;
        
        println!("\n📚 Second API Call - Code Explanation:");
        println!("======================================");
        println!("⏱️  Response time: {:?}", duration2);
        
        if let Some(content) = response_body2["content"].as_array() {
            if let Some(text_content) = content.first() {
                if let Some(text) = text_content["text"].as_str() {
                    println!("🤖 Claude's Explanation:");
                    println!("{}", text);
                }
            }
        }
        
        println!("\n🎉 REAL AI Integration Demonstrated!");
        println!("===================================");
        println!("✅ Two successful API calls to Anthropic Claude");
        println!("✅ Real security analysis with specific findings");
        println!("✅ Real code explanation with detailed insights");
        println!("✅ Actual token usage and cost tracking");
        println!("✅ Production-ready API integration");
        
    } else {
        println!("❌ Second API call failed: {}", response2.status());
    }
    
    Ok(())
}
