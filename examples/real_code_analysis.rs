use serde_json::json;
use std::env;
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 REAL Codebase Analysis with GPT-4o");
    println!("======================================");
    println!("Analyzing YOUR actual rust-treesitter code");
    
    let api_key = env::var("OPENAI_API_KEY")
        .expect("OPENAI_API_KEY environment variable not set");
    
    // Read your actual files
    let lib_content = fs::read_to_string("src/lib.rs")
        .expect("Failed to read src/lib.rs");
    
    let analyzer_content = fs::read_to_string("src/analyzer.rs")
        .expect("Failed to read src/analyzer.rs");
    
    println!("📁 Analyzing: src/lib.rs ({} lines)", lib_content.lines().count());
    println!("📁 Analyzing: src/analyzer.rs ({} lines)", analyzer_content.lines().count());
    
    // Take first part of each file to stay within token limits
    let lib_sample = lib_content.chars().take(3000).collect::<String>();
    let analyzer_sample = analyzer_content.chars().take(4000).collect::<String>();
    
    let combined_code = format!(
        "=== FILE: src/lib.rs ===\n{}\n\n=== FILE: src/analyzer.rs ===\n{}",
        lib_sample, analyzer_sample
    );
    
    let client = reqwest::Client::new();
    
    let request = json!({
        "model": "gpt-4o",
        "messages": [{
            "role": "user",
            "content": format!(
                "Please analyze this REAL Rust tree-sitter library code from an actual project:\n\n{}\n\n\
                Provide:\n\
                1. **What this library does** - Main purpose and functionality\n\
                2. **Code quality assessment** - Strengths and weaknesses\n\
                3. **Security analysis** - Potential vulnerabilities\n\
                4. **Performance considerations** - Bottlenecks and optimizations\n\
                5. **Top 3 specific improvements** with concrete examples\n\
                \n\
                Be specific and actionable in your recommendations.",
                combined_code
            )
        }],
        "max_tokens": 2000,
        "temperature": 0.1
    });
    
    println!("\n🧠 Making GPT-4o API call to analyze YOUR code...");
    let start_time = std::time::Instant::now();
    
    let response = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await?;
    
    let duration = start_time.elapsed();
    println!("⏱️  Analysis completed in {:?}", duration);
    println!("📊 Status: {}", response.status());
    
    if response.status().is_success() {
        let response_body: serde_json::Value = response.json().await?;
        
        if let Some(choices) = response_body["choices"].as_array() {
            if let Some(first_choice) = choices.first() {
                if let Some(message) = first_choice["message"].as_object() {
                    if let Some(content) = message["content"].as_str() {
                        println!("\n🎯 GPT-4o Analysis of YOUR REAL Codebase:");
                        println!("==========================================");
                        println!("{}", content);
                    }
                }
            }
        }
        
        if let Some(usage) = response_body["usage"].as_object() {
            println!("\n📊 Analysis Statistics:");
            println!("   Prompt tokens: {}", usage["prompt_tokens"].as_u64().unwrap_or(0));
            println!("   Completion tokens: {}", usage["completion_tokens"].as_u64().unwrap_or(0));
            println!("   Total tokens: {}", usage["total_tokens"].as_u64().unwrap_or(0));
            
            let prompt_tokens = usage["prompt_tokens"].as_u64().unwrap_or(0) as f64;
            let completion_tokens = usage["completion_tokens"].as_u64().unwrap_or(0) as f64;
            let estimated_cost = (prompt_tokens * 0.005 / 1000.0) + (completion_tokens * 0.015 / 1000.0);
            println!("   Estimated cost: ${:.6}", estimated_cost);
        }
        
        println!("\n✅ REAL Codebase Analysis Complete!");
        println!("===================================");
        println!("✅ Analyzed YOUR actual rust-treesitter files");
        println!("✅ Provided actionable insights about YOUR code");
        println!("✅ Identified specific improvements for YOUR project");
        
    } else {
        let error_text = response.text().await?;
        println!("❌ API call failed: {}", error_text);
    }
    
    Ok(())
}
