use serde_json::json;
use std::env;
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 GPT-5 REAL Codebase Analysis");
    println!("===============================");
    println!("Analyzing YOUR actual rust-treesitter code with GPT-5");
    
    let api_key = env::var("OPENAI_API_KEY")
        .expect("OPENAI_API_KEY environment variable not set");
    
    // Read your actual lib.rs file
    let lib_content = fs::read_to_string("src/lib.rs")
        .expect("Failed to read src/lib.rs");
    
    println!("📁 Analyzing: src/lib.rs");
    println!("📊 File size: {} bytes", lib_content.len());
    println!("📝 Lines: {}", lib_content.lines().count());
    
    let client = reqwest::Client::new();
    
    // Give GPT-5 more tokens and a focused request
    let request = json!({
        "model": "gpt-5",
        "messages": [{
            "role": "user",
            "content": format!(
                "Analyze this Rust tree-sitter library code. Focus on:\n\
                1. What does this library do?\n\
                2. Key security issues or vulnerabilities\n\
                3. Top 3 improvement recommendations\n\
                \n\
                Code:\n{}",
                lib_content
            )
        }],
        "max_completion_tokens": 2000  // More tokens for actual output
    });
    
    println!("\n🧠 Making GPT-5 API call with more tokens...");
    let start_time = std::time::Instant::now();
    
    let response = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await?;
    
    let duration = start_time.elapsed();
    println!("⏱️  GPT-5 analysis completed in {:?}", duration);
    println!("📊 Status: {}", response.status());
    
    if response.status().is_success() {
        let response_body: serde_json::Value = response.json().await?;
        
        if let Some(choices) = response_body["choices"].as_array() {
            if let Some(first_choice) = choices.first() {
                if let Some(message) = first_choice["message"].as_object() {
                    if let Some(content) = message["content"].as_str() {
                        println!("\n🎯 GPT-5 Analysis of YOUR Rust Code:");
                        println!("====================================");
                        println!("{}", content);
                    } else {
                        println!("❌ Content is empty - checking reasoning tokens...");
                    }
                }
                
                // Check finish reason
                if let Some(finish_reason) = first_choice["finish_reason"].as_str() {
                    println!("\n📊 Finish reason: {}", finish_reason);
                }
            }
        }
        
        // Show detailed usage statistics
        if let Some(usage) = response_body["usage"].as_object() {
            println!("\n📊 GPT-5 Token Usage Details:");
            println!("   Prompt tokens: {}", usage["prompt_tokens"].as_u64().unwrap_or(0));
            println!("   Completion tokens: {}", usage["completion_tokens"].as_u64().unwrap_or(0));
            println!("   Total tokens: {}", usage["total_tokens"].as_u64().unwrap_or(0));
            
            // Check reasoning tokens (GPT-5 specific)
            if let Some(completion_details) = usage["completion_tokens_details"].as_object() {
                if let Some(reasoning_tokens) = completion_details["reasoning_tokens"].as_u64() {
                    println!("   Reasoning tokens: {} (GPT-5 internal thinking)", reasoning_tokens);
                }
            }
            
            let total_tokens = usage["total_tokens"].as_u64().unwrap_or(0) as f64;
            let estimated_cost = total_tokens * 1.25 / 1000000.0;
            println!("   Estimated cost: ${:.6}", estimated_cost);
        }
        
        println!("\n✅ REAL Analysis of YOUR Code Complete!");
        println!("======================================");
        
    } else {
        let error_text = response.text().await?;
        println!("❌ API call failed: {}", error_text);
    }
    
    Ok(())
}
