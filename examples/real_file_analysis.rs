use serde_json::json;
use std::env;
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 GPT-5 Real File Analysis");
    println!("===========================");
    println!("Analyzing ACTUAL files from your rust-treesitter codebase");

    let api_key = env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY environment variable not set");

    // Read the actual lib.rs file
    let lib_content = fs::read_to_string("src/lib.rs").expect("Failed to read src/lib.rs");

    println!("📁 Analyzing: src/lib.rs");
    println!("📊 File size: {} bytes", lib_content.len());
    println!("📝 Lines: {}", lib_content.lines().count());

    // Read another real file - analyzer.rs
    let analyzer_content =
        fs::read_to_string("src/analyzer.rs").expect("Failed to read src/analyzer.rs");

    println!("📁 Also analyzing: src/analyzer.rs");
    println!("📊 File size: {} bytes", analyzer_content.len());
    println!("📝 Lines: {}", analyzer_content.lines().count());

    let combined_content = format!(
        "FILE 1: src/lib.rs\n{}\n\n===================\n\nFILE 2: src/analyzer.rs\n{}",
        lib_content, analyzer_content
    );

    println!("\n🧠 Sending REAL codebase files to GPT-5...");

    let client = reqwest::Client::new();

    let request = json!({
        "model": "gpt-5",
        "messages": [{
            "role": "user",
            "content": format!(
                "REAL CODEBASE ANALYSIS - GPT-5 Expert Review\n\
                \n\
                Please analyze these ACTUAL files from a Rust tree-sitter library codebase:\n\n{}\n\n\
                Provide a comprehensive analysis including:\n\
                \n\
                1. **Code Quality Assessment**\n\
                   - Overall architecture and design patterns\n\
                   - Rust idioms and best practices usage\n\
                   - Error handling patterns\n\
                   - Code organization and modularity\n\
                \n\
                2. **Security Analysis**\n\
                   - Potential vulnerabilities or unsafe patterns\n\
                   - Input validation and sanitization\n\
                   - Memory safety considerations\n\
                   - Dependency security implications\n\
                \n\
                3. **Performance Considerations**\n\
                   - Algorithmic efficiency\n\
                   - Memory usage patterns\n\
                   - Potential bottlenecks\n\
                   - Optimization opportunities\n\
                \n\
                4. **Maintainability & Extensibility**\n\
                   - Code readability and documentation\n\
                   - API design quality\n\
                   - Testing coverage gaps\n\
                   - Future enhancement possibilities\n\
                \n\
                5. **Specific Recommendations**\n\
                   - Concrete improvements with code examples\n\
                   - Priority ranking (High/Medium/Low)\n\
                   - Implementation effort estimates\n\
                \n\
                Focus on actionable insights for this tree-sitter parsing library.",
                combined_content
            )
        }],
        "max_completion_tokens": 3000
    });

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
                        println!("\n🎯 GPT-5 Analysis of Your REAL Codebase:");
                        println!("==========================================");
                        println!("{}", content);
                    }
                }
            }
        }

        // Show usage statistics
        if let Some(usage) = response_body["usage"].as_object() {
            println!("\n📊 GPT-5 Analysis Statistics:");
            println!(
                "   Prompt tokens: {}",
                usage["prompt_tokens"].as_u64().unwrap_or(0)
            );
            println!(
                "   Completion tokens: {}",
                usage["completion_tokens"].as_u64().unwrap_or(0)
            );
            println!(
                "   Total tokens: {}",
                usage["total_tokens"].as_u64().unwrap_or(0)
            );

            let total_tokens = usage["total_tokens"].as_u64().unwrap_or(0) as f64;
            let estimated_cost = total_tokens * 1.25 / 1000000.0;
            println!("   Estimated cost: ${:.6}", estimated_cost);
        }

        println!("\n✅ REAL Codebase Analysis Complete!");
        println!("===================================");
        println!("✅ Analyzed actual files from your rust-treesitter project");
        println!("✅ GPT-5 provided genuine insights about your code");
        println!("✅ Actionable recommendations for improvement");
        println!("✅ Real security and performance analysis");
    } else {
        let status = response.status();
        println!("❌ API call failed!");
        let error_text = response.text().await?;
        println!("Error response: {}", error_text);
        return Err(format!("API call failed with status: {}", status).into());
    }

    Ok(())
}
