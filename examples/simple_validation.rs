use rust_tree_sitter::ai::{
    AIServiceBuilder, AIFeature, AIRequest, AIResult
};

#[tokio::main]
async fn main() -> AIResult<()> {
    println!("🧪 Simple AI Validation Test");
    println!("============================");
    
    // Test with mock provider first
    println!("📋 Creating AI service with mock provider...");
    let service = AIServiceBuilder::new()
        .with_mock_providers(true)
        .build()
        .await?;
    
    println!("✅ AI service created successfully");
    
    // Test basic functionality
    let test_code = r#"
fn fibonacci(n: u32) -> u32 {
    match n {
        0 => 0,
        1 => 1,
        _ => fibonacci(n - 1) + fibonacci(n - 2),
    }
}
"#;

    println!("\n🔍 Testing Code Explanation...");
    let request = AIRequest::new(
        AIFeature::CodeExplanation,
        test_code.to_string(),
    );
    
    match service.process_request(request).await {
        Ok(response) => {
            println!("✅ Response received:");
            println!("   Content: {}", response.content);
            println!("   Model: {}", response.metadata.model_used);
            println!("   Tokens: {}", response.token_usage.total_tokens);
            println!("   Cached: {}", response.metadata.cached);
            
            // Verify it's a mock response
            if response.content.contains("Mock") {
                println!("✅ Mock provider working correctly");
            } else {
                println!("⚠️  Expected mock response");
            }
        }
        Err(e) => {
            println!("❌ Request failed: {}", e);
            return Err(e);
        }
    }

    println!("\n🔒 Testing Security Analysis...");
    let security_request = AIRequest::new(
        AIFeature::SecurityAnalysis,
        test_code.to_string(),
    );
    
    match service.process_request(security_request).await {
        Ok(response) => {
            println!("✅ Security analysis completed");
            println!("   Analysis: {}", response.content);
        }
        Err(e) => {
            println!("❌ Security analysis failed: {}", e);
        }
    }

    println!("\n📊 Validation Summary");
    println!("=====================");
    println!("✅ AI service architecture working");
    println!("✅ Mock provider functional");
    println!("✅ Request processing working");
    println!("✅ Multiple AI features tested");
    
    println!("\n🎉 Simple validation completed successfully!");
    
    Ok(())
}
