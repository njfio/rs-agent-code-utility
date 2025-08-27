//! AI Service Demo
//!
//! This example demonstrates how to use the new AI service layer with
//! configuration-driven provider setup.

use rust_tree_sitter::ai::{
    AIService, AIServiceBuilder, AIConfig as AIServiceConfig, AIProvider, AIFeature, AIRequest,
    ProviderConfig, ModelConfig
};
use rust_tree_sitter::ai::config::{RateLimitConfig, RetryConfig};
use std::collections::HashMap;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging (simplified)
    println!("Starting AI Service Demo...");
    
    println!("🤖 AI Service Demo");
    println!("==================");
    
    // Demo 1: Load configuration from file
    println!("\n📁 Loading configuration from file...");
    match load_config_from_file().await {
        Ok(_) => println!("✅ Configuration loaded successfully"),
        Err(e) => println!("❌ Failed to load config: {}", e),
    }
    
    // Demo 2: Create configuration programmatically
    println!("\n⚙️  Creating configuration programmatically...");
    let service = create_programmatic_config().await?;
    println!("✅ AI service created successfully");
    
    // Demo 3: Test different AI features
    println!("\n🧪 Testing AI features...");
    test_ai_features(&service).await?;
    
    // Demo 4: Show cache statistics
    println!("\n📊 Cache statistics:");
    if let Some(stats) = service.cache_stats() {
        println!("  Hits: {}, Misses: {}, Hit Rate: {:.2}%", 
                 stats.hits, stats.misses, stats.hit_rate * 100.0);
    } else {
        println!("  Cache disabled");
    }
    
    // Demo 5: Validate provider connections
    println!("\n🔗 Validating provider connections...");
    let validation_results = service.validate_connections().await;
    for (provider, result) in validation_results {
        match result {
            Ok(_) => println!("  {:?}: ✅ Connected", provider),
            Err(e) => println!("  {:?}: ❌ Error: {}", provider, e),
        }
    }
    
    println!("\n🎉 Demo completed!");
    Ok(())
}

async fn load_config_from_file() -> Result<AIService, Box<dyn std::error::Error>> {
    // Try to load from JSON file first, then YAML
    let config = if std::path::Path::new("ai_config.json").exists() {
        AIServiceConfig::from_file("ai_config.json")?
    } else if std::path::Path::new("ai_config.yaml").exists() {
        AIServiceConfig::from_file("ai_config.yaml")?
    } else {
        println!("  No config file found, using defaults");
        AIServiceConfig::default()
    };
    
    let service = AIServiceBuilder::new()
        .with_config(config)
        .with_mock_providers(true) // Use mock providers for demo
        .build()
        .await?;
    
    Ok(service)
}

async fn create_programmatic_config() -> Result<AIService, Box<dyn std::error::Error>> {
    // Create a simple configuration programmatically
    let mut config = AIServiceConfig::default();
    config.default_provider = AIProvider::OpenAI;
    
    // Configure OpenAI provider
    let openai_config = ProviderConfig {
        enabled: true,
        api_key: Some("demo-key".to_string()),
        base_url: Some("https://api.openai.com/v1".to_string()),
        organization: None,
        models: vec![
            ModelConfig {
                name: "gpt-4".to_string(),
                context_length: 8192,
                max_tokens: 4096,
                supports_streaming: true,
                cost_per_token: Some(0.00003),
                supported_features: vec![
                    AIFeature::CodeExplanation,
                    AIFeature::SecurityAnalysis,
                    AIFeature::RefactoringSuggestions,
                ],
            }
        ],
        default_model: "gpt-4".to_string(),
        timeout: Duration::from_secs(30),
        rate_limit: RateLimitConfig {
            requests_per_minute: 60,
            tokens_per_minute: 100000,
            burst_size: 10,
        },
        retry: RetryConfig {
            max_retries: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        },
    };
    
    config.providers.insert(AIProvider::OpenAI, openai_config);
    
    let service = AIServiceBuilder::new()
        .with_config(config)
        .with_mock_providers(true) // Use mock providers for demo
        .build()
        .await?;
    
    Ok(service)
}

async fn test_ai_features(service: &AIService) -> Result<(), Box<dyn std::error::Error>> {
    let sample_code = r#"
fn fibonacci(n: u32) -> u32 {
    match n {
        0 => 0,
        1 => 1,
        _ => fibonacci(n - 1) + fibonacci(n - 2),
    }
}
"#;
    
    // Test code explanation
    println!("  🔍 Testing code explanation...");
    let request = AIRequest::new(AIFeature::CodeExplanation, sample_code.to_string())
        .with_context("language".to_string(), "rust".to_string())
        .with_temperature(0.3);
    
    match service.process_request(request).await {
        Ok(response) => {
            println!("    ✅ Response: {}", response.content.chars().take(100).collect::<String>());
            println!("    📊 Tokens: {} prompt + {} completion = {} total", 
                     response.token_usage.prompt_tokens,
                     response.token_usage.completion_tokens,
                     response.token_usage.total_tokens);
        }
        Err(e) => println!("    ❌ Error: {}", e),
    }
    
    // Test security analysis
    println!("  🔒 Testing security analysis...");
    let security_code = r#"
fn process_user_input(input: &str) -> String {
    format!("SELECT * FROM users WHERE name = '{}'", input)
}
"#;
    
    let request = AIRequest::new(AIFeature::SecurityAnalysis, security_code.to_string())
        .with_context("language".to_string(), "rust".to_string())
        .with_temperature(0.1);
    
    match service.process_request(request).await {
        Ok(response) => {
            println!("    ✅ Response: {}", response.content.chars().take(100).collect::<String>());
        }
        Err(e) => println!("    ❌ Error: {}", e),
    }
    
    // Test refactoring suggestions
    println!("  🔧 Testing refactoring suggestions...");
    let messy_code = r#"
fn calculate(x: i32, y: i32, op: &str) -> i32 {
    if op == "add" {
        return x + y;
    } else if op == "sub" {
        return x - y;
    } else if op == "mul" {
        return x * y;
    } else if op == "div" {
        return x / y;
    } else {
        return 0;
    }
}
"#;
    
    let request = AIRequest::new(AIFeature::RefactoringSuggestions, messy_code.to_string())
        .with_context("language".to_string(), "rust".to_string())
        .with_temperature(0.5);
    
    match service.process_request(request).await {
        Ok(response) => {
            println!("    ✅ Response: {}", response.content.chars().take(100).collect::<String>());
        }
        Err(e) => println!("    ❌ Error: {}", e),
    }
    
    Ok(())
}
