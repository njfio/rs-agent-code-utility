use serde_json::json;
use std::env;
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Debug GPT-5 Response");
    println!("========================");

    let api_key = env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY environment variable not set");

    // Simple test with your actual lib.rs
    let lib_content = fs::read_to_string("src/lib.rs").expect("Failed to read src/lib.rs");

    println!(
        "📁 Analyzing: src/lib.rs ({} lines)",
        lib_content.lines().count()
    );

    let client = reqwest::Client::new();

    let request = json!({
        "model": "gpt-5",
        "messages": [{
            "role": "user",
            "content": format!(
                "Please analyze this Rust code and tell me what it does:\n\n{}",
                lib_content.chars().take(2000).collect::<String>() // Limit to first 2000 chars
            )
        }],
        "max_completion_tokens": 500
    });

    println!("\n🧠 Making GPT-5 API call...");

    let response = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await?;

    println!("📊 Status: {}", response.status());

    if response.status().is_success() {
        let response_body: serde_json::Value = response.json().await?;

        // Debug: Print the entire response structure
        println!("\n🔍 DEBUG: Full Response Structure:");
        println!("{}", serde_json::to_string_pretty(&response_body)?);

        // Try to extract content
        if let Some(choices) = response_body["choices"].as_array() {
            println!("\n✅ Found choices array with {} items", choices.len());

            if let Some(first_choice) = choices.first() {
                println!("✅ Found first choice");

                if let Some(message) = first_choice["message"].as_object() {
                    println!("✅ Found message object");

                    if let Some(content) = message["content"].as_str() {
                        println!("✅ Found content string");
                        println!("\n🎯 GPT-5 Analysis:");
                        println!("==================");
                        println!("{}", content);
                    } else {
                        println!("❌ No content string found in message");
                        println!("Message keys: {:?}", message.keys().collect::<Vec<_>>());
                    }
                } else {
                    println!("❌ No message object found in choice");
                    println!(
                        "Choice keys: {:?}",
                        first_choice.as_object().unwrap().keys().collect::<Vec<_>>()
                    );
                }
            } else {
                println!("❌ No first choice found");
            }
        } else {
            println!("❌ No choices array found");
            println!(
                "Response keys: {:?}",
                response_body
                    .as_object()
                    .unwrap()
                    .keys()
                    .collect::<Vec<_>>()
            );
        }
    } else {
        let error_text = response.text().await?;
        println!("❌ API call failed: {}", error_text);
    }

    Ok(())
}
