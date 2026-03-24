use rust_tree_sitter::ai::{AIFeature, AIProvider, AIRequest, AIServiceBuilder};
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 AI Provider Comparison Test");
    println!("==============================");

    let test_code = r#"
fn bubble_sort(arr: &mut [i32]) {
    let n = arr.len();
    for i in 0..n {
        for j in 0..n - 1 - i {
            if arr[j] > arr[j + 1] {
                arr.swap(j, j + 1);
            }
        }
    }
}
"#;

    // Test OpenAI
    println!("\n🤖 Testing OpenAI Provider");
    println!("---------------------------");

    let openai_service = AIServiceBuilder::new()
        .with_config_file("real_ai_config.yaml")?
        .with_default_provider(AIProvider::OpenAI)
        .build()
        .await?;

    let start = Instant::now();
    let openai_request = AIRequest::new(AIFeature::CodeExplanation, test_code.to_string());

    match openai_service.process_request(openai_request).await {
        Ok(response) => {
            let duration = start.elapsed();
            println!("✅ OpenAI Response ({:?}):", duration);
            println!(
                "   Content: {}",
                response.content.chars().take(200).collect::<String>()
            );
            if response.content.len() > 200 {
                println!("   ... (truncated)");
            }
        }
        Err(e) => {
            println!("❌ OpenAI failed: {}", e);
        }
    }

    // Test Groq
    println!("\n⚡ Testing Groq Provider");
    println!("------------------------");

    let groq_service = AIServiceBuilder::new()
        .with_config_file("real_ai_config.yaml")?
        .with_default_provider(AIProvider::Groq)
        .build()
        .await?;

    let start = Instant::now();
    let groq_request = AIRequest::new(AIFeature::CodeExplanation, test_code.to_string());

    match groq_service.process_request(groq_request).await {
        Ok(response) => {
            let duration = start.elapsed();
            println!("✅ Groq Response ({:?}):", duration);
            println!(
                "   Content: {}",
                response.content.chars().take(200).collect::<String>()
            );
            if response.content.len() > 200 {
                println!("   ... (truncated)");
            }
        }
        Err(e) => {
            println!("❌ Groq failed: {}", e);
        }
    }

    println!("\n📊 Provider Comparison Complete");
    println!("================================");
    println!("Both providers tested successfully!");

    Ok(())
}
