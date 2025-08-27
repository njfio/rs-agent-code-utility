use serde_json::json;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Direct OpenAI API Test");
    println!("=========================");
    
    let api_key = env::var("OPENAI_API_KEY")
        .expect("OPENAI_API_KEY environment variable not set");
    
    println!("🔑 API Key found: {}...", &api_key[..20]);
    
    // Real Rust code with security vulnerabilities
    let vulnerable_code = r#"
use std::collections::HashMap;

pub struct UserAuth {
    users: HashMap<String, String>, // Plain text passwords!
    admin_key: String,
}

impl UserAuth {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            admin_key: "admin123".to_string(), // Hardcoded!
        }
    }
    
    // SQL injection vulnerability
    pub fn login(&self, username: &str, password: &str) -> bool {
        let query = format!("SELECT * FROM users WHERE name='{}' AND pass='{}'", username, password);
        println!("Query: {}", query); // Logs sensitive data!
        
        if let Some(stored_pass) = self.users.get(username) {
            stored_pass == password // Plain text comparison
        } else {
            false
        }
    }
    
    // Command injection risk
    pub fn backup_user(&self, username: &str) -> String {
        let cmd = format!("tar -czf {}.tar.gz /users/{}", username, username);
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
            .unwrap_or_else(|_| "Error".to_string())
    }
}
"#;

    println!("📝 Code to analyze ({} lines):", vulnerable_code.lines().count());
    
    // Create HTTP client
    let client = reqwest::Client::new();
    
    // Prepare the OpenAI API request with GPT-4o (latest model)
    let request_body = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": format!(
                "Please analyze this Rust code for security vulnerabilities. \
                Identify specific issues like SQL injection, command injection, \
                hardcoded credentials, and provide concrete recommendations:\n\n{}",
                vulnerable_code
            )
        }],
        "max_tokens": 1000,
        "temperature": 0.3
    });
    
    println!("\n🌐 Making REAL API call to OpenAI GPT-4o (latest model)...");
    
    let start_time = std::time::Instant::now();
    
    // Make the API call
    let response = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;
    
    let duration = start_time.elapsed();
    
    println!("⏱️  API call completed in {:?}", duration);
    println!("📊 Status: {}", response.status());
    
    if response.status().is_success() {
        let response_body: serde_json::Value = response.json().await?;
        
        println!("\n🎉 SUCCESS! Real OpenAI Analysis Results:");
        println!("=========================================");
        
        if let Some(choices) = response_body["choices"].as_array() {
            if let Some(first_choice) = choices.first() {
                if let Some(message) = first_choice["message"].as_object() {
                    if let Some(content) = message["content"].as_str() {
                        println!("🤖 GPT-4o's Security Analysis:");
                        println!("======================================");
                        println!("{}", content);
                    }
                }
            }
        }
        
        // Show usage statistics
        if let Some(usage) = response_body["usage"].as_object() {
            println!("\n📊 Token Usage:");
            println!("   Prompt tokens: {}", usage["prompt_tokens"].as_u64().unwrap_or(0));
            println!("   Completion tokens: {}", usage["completion_tokens"].as_u64().unwrap_or(0));
            println!("   Total tokens: {}", usage["total_tokens"].as_u64().unwrap_or(0));
            
            // Estimate cost (GPT-4o pricing: $0.005/1K prompt, $0.015/1K completion)
            let prompt_tokens = usage["prompt_tokens"].as_u64().unwrap_or(0) as f64;
            let completion_tokens = usage["completion_tokens"].as_u64().unwrap_or(0) as f64;
            let estimated_cost = (prompt_tokens * 0.005 / 1000.0) + (completion_tokens * 0.015 / 1000.0);
            println!("   Estimated cost: ${:.6}", estimated_cost);
        }
        
        println!("\n✅ VERIFICATION: This is REAL AI Analysis!");
        println!("==========================================");
        println!("✅ Made actual API call to OpenAI");
        println!("✅ Used real credits from your account");
        println!("✅ GPT-4o analyzed the security vulnerabilities");
        println!("✅ Received genuine AI-generated insights");
        println!("✅ Real token usage and costs calculated");
        
    } else {
        let status = response.status();
        println!("❌ API call failed!");
        let error_text = response.text().await?;
        println!("Error response: {}", error_text);
        return Err(format!("API call failed with status: {}", status).into());
    }
    
    // Make a second call to demonstrate it's really working
    println!("\n🔄 Making second API call for code explanation...");
    
    let explanation_request = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": format!(
                "Please explain what this Rust code does, how it works, and what its purpose is:\n\n{}",
                vulnerable_code
            )
        }],
        "max_tokens": 800,
        "temperature": 0.3
    });
    
    let start_time = std::time::Instant::now();
    
    let response2 = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&explanation_request)
        .send()
        .await?;
    
    let duration2 = start_time.elapsed();
    
    if response2.status().is_success() {
        let response_body2: serde_json::Value = response2.json().await?;
        
        println!("\n📚 Second API Call - Code Explanation:");
        println!("======================================");
        println!("⏱️  Response time: {:?}", duration2);
        
        if let Some(choices) = response_body2["choices"].as_array() {
            if let Some(first_choice) = choices.first() {
                if let Some(message) = first_choice["message"].as_object() {
                    if let Some(content) = message["content"].as_str() {
                        println!("🤖 GPT-4o's Code Explanation:");
                        println!("=====================================");
                        println!("{}", content);
                    }
                }
            }
        }
        
        // Show second call usage
        if let Some(usage) = response_body2["usage"].as_object() {
            let total_tokens = usage["total_tokens"].as_u64().unwrap_or(0);
            println!("\n📊 Second call tokens: {}", total_tokens);
        }
        
        println!("\n🎉 REAL AI Integration Fully Demonstrated!");
        println!("==========================================");
        println!("✅ Two successful API calls to OpenAI");
        println!("✅ Real security analysis with specific findings");
        println!("✅ Real code explanation with detailed insights");
        println!("✅ Actual token usage and cost tracking");
        println!("✅ Production-ready API integration working");
        println!("✅ Your OpenAI credits were used for genuine AI analysis");
        
        println!("\n🔥 This is NOT a mock - this is REAL AI!");
        println!("The AI actually read and analyzed your Rust code!");
        
    } else {
        println!("❌ Second API call failed: {}", response2.status());
    }
    
    Ok(())
}
