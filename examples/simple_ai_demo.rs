//! Simple AI Demo
//!
//! A minimal example demonstrating the AI service functionality
//! without dependencies on CLI modules.

use std::collections::HashMap;
use std::time::Duration;

// Import only the AI types we need
use rust_tree_sitter::ai::{
    AIService, AIServiceBuilder, AIConfig, AIProvider, AIFeature, AIRequest,
    ProviderConfig, ModelConfig
};
use rust_tree_sitter::ai::config::{RateLimitConfig, RetryConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🤖 Simple AI Service Demo");
    println!("========================");
    
    // Create a simple configuration
    let service = create_ai_service().await?;
    println!("✅ AI service created successfully");
    
    // Test different AI features
    test_code_explanation(&service).await?;
    test_security_analysis(&service).await?;
    test_refactoring_suggestions(&service).await?;
    
    // Show cache statistics
    show_cache_stats(&service);
    
    println!("\n🎉 Demo completed successfully!");
    Ok(())
}

async fn create_ai_service() -> Result<AIService, Box<dyn std::error::Error>> {
    // Create configuration programmatically
    let mut config = AIConfig::default();
    config.default_provider = AIProvider::OpenAI;
    
    // Configure OpenAI provider (using mock for demo)
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
                    AIFeature::ArchitecturalInsights,
                    AIFeature::PatternDetection,
                    AIFeature::QualityAssessment,
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
    
    // Build service with mock providers for demo
    let service = AIServiceBuilder::new()
        .with_config(config)
        .with_mock_providers(true) // Use mock providers for demo
        .build()
        .await?;
    
    Ok(service)
}

async fn test_code_explanation(service: &AIService) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Testing Code Explanation");
    println!("----------------------------");
    
    let sample_code = r#"
fn fibonacci(n: u32) -> u32 {
    match n {
        0 => 0,
        1 => 1,
        _ => fibonacci(n - 1) + fibonacci(n - 2),
    }
}
"#;
    
    let request = AIRequest::new(AIFeature::CodeExplanation, sample_code.to_string())
        .with_context("language".to_string(), "rust".to_string())
        .with_context("complexity".to_string(), "beginner".to_string())
        .with_temperature(0.3);
    
    match service.process_request(request).await {
        Ok(response) => {
            println!("✅ Response received:");
            println!("   Content: {}", response.content.chars().take(100).collect::<String>());
            println!("   Model: {}", response.metadata.model_used);
            println!("   Tokens: {} prompt + {} completion = {} total", 
                     response.token_usage.prompt_tokens,
                     response.token_usage.completion_tokens,
                     response.token_usage.total_tokens);
            println!("   Processing time: {:?}", response.metadata.processing_time);
            if let Some(confidence) = response.confidence {
                println!("   Confidence: {:.2}", confidence);
            }
        }
        Err(e) => println!("❌ Error: {}", e),
    }
    
    Ok(())
}

async fn test_security_analysis(service: &AIService) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔒 Testing Security Analysis");
    println!("-----------------------------");
    
    let vulnerable_code = r#"
fn process_user_input(input: &str) -> String {
    // Potential SQL injection vulnerability
    format!("SELECT * FROM users WHERE name = '{}'", input)
}

fn handle_file_upload(filename: &str) -> std::io::Result<String> {
    // Potential path traversal vulnerability
    std::fs::read_to_string(format!("uploads/{}", filename))
}
"#;
    
    let request = AIRequest::new(AIFeature::SecurityAnalysis, vulnerable_code.to_string())
        .with_context("language".to_string(), "rust".to_string())
        .with_context("focus".to_string(), "vulnerabilities".to_string())
        .with_temperature(0.1); // Lower temperature for more focused analysis
    
    match service.process_request(request).await {
        Ok(response) => {
            println!("✅ Security analysis completed:");
            println!("   Analysis: {}", response.content.chars().take(150).collect::<String>());
            println!("   Model: {}", response.metadata.model_used);
            println!("   Tokens used: {}", response.token_usage.total_tokens);
        }
        Err(e) => println!("❌ Error: {}", e),
    }
    
    Ok(())
}

async fn test_refactoring_suggestions(service: &AIService) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔧 Testing Refactoring Suggestions");
    println!("-----------------------------------");
    
    let messy_code = r#"
fn calculate(x: i32, y: i32, op: &str) -> i32 {
    if op == "add" {
        return x + y;
    } else if op == "sub" {
        return x - y;
    } else if op == "mul" {
        return x * y;
    } else if op == "div" {
        if y != 0 {
            return x / y;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}
"#;
    
    let request = AIRequest::new(AIFeature::RefactoringSuggestions, messy_code.to_string())
        .with_context("language".to_string(), "rust".to_string())
        .with_context("focus".to_string(), "readability".to_string())
        .with_temperature(0.5);
    
    match service.process_request(request).await {
        Ok(response) => {
            println!("✅ Refactoring suggestions received:");
            println!("   Suggestions: {}", response.content.chars().take(150).collect::<String>());
            println!("   Model: {}", response.metadata.model_used);
            println!("   Processing time: {:?}", response.metadata.processing_time);
        }
        Err(e) => println!("❌ Error: {}", e),
    }
    
    Ok(())
}

fn show_cache_stats(service: &AIService) {
    println!("\n📊 Cache Statistics");
    println!("-------------------");
    
    if let Some(stats) = service.cache_stats() {
        println!("   Cache hits: {}", stats.hits);
        println!("   Cache misses: {}", stats.misses);
        println!("   Hit rate: {:.2}%", stats.hit_rate * 100.0);
        println!("   Cache size: {} entries", stats.size);
        println!("   Evictions: {}", stats.evictions);
    } else {
        println!("   Cache is disabled");
    }
    
    // Show available providers
    let providers = service.available_providers();
    println!("\n🔌 Available Providers");
    println!("----------------------");
    for provider in providers {
        println!("   {:?}", provider);
    }
    
    // Show supported features
    println!("\n⚡ Supported Features");
    println!("--------------------");
    let features = [
        AIFeature::CodeExplanation,
        AIFeature::SecurityAnalysis,
        AIFeature::RefactoringSuggestions,
        AIFeature::ArchitecturalInsights,
        AIFeature::PatternDetection,
        AIFeature::QualityAssessment,
        AIFeature::DocumentationGeneration,
        AIFeature::TestGeneration,
    ];
    
    for feature in features {
        let supported = service.is_feature_supported(feature);
        let status = if supported { "✅" } else { "❌" };
        println!("   {} {:?}", status, feature);
    }
}
