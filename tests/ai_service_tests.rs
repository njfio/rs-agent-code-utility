//! AI Service Tests
//!
//! Tests for the AI service layer functionality

use rust_tree_sitter::ai::{
    AIServiceBuilder, AIConfig as AIServiceConfig, AIProvider, AIFeature, AIRequest,
    ProviderConfig, ModelConfig
};
use rust_tree_sitter::ai::config::{RateLimitConfig, RetryConfig};
use std::time::Duration;

#[tokio::test]
async fn test_ai_service_creation() {
    // Create a basic configuration with at least one provider
    let mut config = AIServiceConfig::default();
    config.default_provider = AIProvider::OpenAI;

    let openai_config = ProviderConfig {
        enabled: true,
        api_key: Some("test-key".to_string()),
        base_url: Some("https://api.openai.com/v1".to_string()),
        organization: None,
        models: vec![
            ModelConfig {
                name: "gpt-4".to_string(),
                context_length: 8192,
                max_tokens: 4096,
                supports_streaming: true,
                cost_per_token: Some(0.00003),
                supported_features: vec![AIFeature::CodeExplanation],
            }
        ],
        default_model: "gpt-4".to_string(),
        timeout: Duration::from_secs(30),
        rate_limit: RateLimitConfig::default(),
        retry: RetryConfig::default(),
    };

    config.providers.insert(AIProvider::OpenAI, openai_config);

    let service = AIServiceBuilder::new()
        .with_config(config)
        .with_mock_providers(true)
        .build()
        .await;

    assert!(service.is_ok());
}

#[tokio::test]
async fn test_ai_service_with_config() {
    let mut config = AIServiceConfig::default();
    config.default_provider = AIProvider::OpenAI;
    
    // Configure OpenAI provider
    let openai_config = ProviderConfig {
        enabled: true,
        api_key: Some("test-key".to_string()),
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
        .with_mock_providers(true)
        .build()
        .await;
    
    assert!(service.is_ok());
    let service = service.unwrap();
    
    // Test that the service has the expected provider
    let providers = service.available_providers();
    assert!(providers.contains(&AIProvider::OpenAI));
}

#[tokio::test]
async fn test_ai_request_processing() {
    // Create a basic configuration with at least one provider
    let mut config = AIServiceConfig::default();
    config.default_provider = AIProvider::OpenAI;

    let openai_config = ProviderConfig {
        enabled: true,
        api_key: Some("test-key".to_string()),
        base_url: Some("https://api.openai.com/v1".to_string()),
        organization: None,
        models: vec![
            ModelConfig {
                name: "gpt-4".to_string(),
                context_length: 8192,
                max_tokens: 4096,
                supports_streaming: true,
                cost_per_token: Some(0.00003),
                supported_features: vec![AIFeature::CodeExplanation],
            }
        ],
        default_model: "gpt-4".to_string(),
        timeout: Duration::from_secs(30),
        rate_limit: RateLimitConfig::default(),
        retry: RetryConfig::default(),
    };

    config.providers.insert(AIProvider::OpenAI, openai_config);

    let service = AIServiceBuilder::new()
        .with_config(config)
        .with_mock_providers(true)
        .build()
        .await
        .unwrap();
    
    let request = AIRequest::new(
        AIFeature::CodeExplanation,
        "fn hello() { println!(\"Hello, world!\"); }".to_string()
    );
    
    let response = service.process_request(request).await;
    assert!(response.is_ok());
    
    let response = response.unwrap();
    assert_eq!(response.feature, AIFeature::CodeExplanation);
    assert!(!response.content.is_empty());
    assert!(response.token_usage.total_tokens > 0);
}

#[tokio::test]
async fn test_ai_feature_support() {
    // Create a basic configuration with at least one provider
    let mut config = AIServiceConfig::default();
    config.default_provider = AIProvider::OpenAI;

    let openai_config = ProviderConfig {
        enabled: true,
        api_key: Some("test-key".to_string()),
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
        rate_limit: RateLimitConfig::default(),
        retry: RetryConfig::default(),
    };

    config.providers.insert(AIProvider::OpenAI, openai_config);

    let service = AIServiceBuilder::new()
        .with_config(config)
        .with_mock_providers(true)
        .build()
        .await
        .unwrap();
    
    // Test that basic features are supported
    assert!(service.is_feature_supported(AIFeature::CodeExplanation));
    assert!(service.is_feature_supported(AIFeature::SecurityAnalysis));
    assert!(service.is_feature_supported(AIFeature::RefactoringSuggestions));
}

#[tokio::test]
async fn test_ai_cache_functionality() {
    // Create a basic configuration with at least one provider
    let mut config = AIServiceConfig::default();
    config.default_provider = AIProvider::OpenAI;

    let openai_config = ProviderConfig {
        enabled: true,
        api_key: Some("test-key".to_string()),
        base_url: Some("https://api.openai.com/v1".to_string()),
        organization: None,
        models: vec![
            ModelConfig {
                name: "gpt-4".to_string(),
                context_length: 8192,
                max_tokens: 4096,
                supports_streaming: true,
                cost_per_token: Some(0.00003),
                supported_features: vec![AIFeature::CodeExplanation],
            }
        ],
        default_model: "gpt-4".to_string(),
        timeout: Duration::from_secs(30),
        rate_limit: RateLimitConfig::default(),
        retry: RetryConfig::default(),
    };

    config.providers.insert(AIProvider::OpenAI, openai_config);

    let service = AIServiceBuilder::new()
        .with_config(config)
        .with_mock_providers(true)
        .build()
        .await
        .unwrap();
    
    let request1 = AIRequest::new(
        AIFeature::CodeExplanation,
        "fn test() {}".to_string()
    );
    
    let request2 = AIRequest::new(
        AIFeature::CodeExplanation,
        "fn test() {}".to_string()
    );
    
    // First request
    let response1 = service.process_request(request1).await.unwrap();
    
    // Second identical request (should potentially be cached)
    let response2 = service.process_request(request2).await.unwrap();
    
    // Both should succeed
    assert_eq!(response1.feature, response2.feature);
    assert!(!response1.content.is_empty());
    assert!(!response2.content.is_empty());
    
    // Check cache stats
    if let Some(stats) = service.cache_stats() {
        // Cache might have hits or misses depending on implementation
        assert!(stats.hits + stats.misses > 0);
    }
}

#[tokio::test]
async fn test_provider_validation() {
    // Create a basic configuration with at least one provider
    let mut config = AIServiceConfig::default();
    config.default_provider = AIProvider::OpenAI;

    let openai_config = ProviderConfig {
        enabled: true,
        api_key: Some("test-key".to_string()),
        base_url: Some("https://api.openai.com/v1".to_string()),
        organization: None,
        models: vec![
            ModelConfig {
                name: "gpt-4".to_string(),
                context_length: 8192,
                max_tokens: 4096,
                supports_streaming: true,
                cost_per_token: Some(0.00003),
                supported_features: vec![AIFeature::CodeExplanation],
            }
        ],
        default_model: "gpt-4".to_string(),
        timeout: Duration::from_secs(30),
        rate_limit: RateLimitConfig::default(),
        retry: RetryConfig::default(),
    };

    config.providers.insert(AIProvider::OpenAI, openai_config);

    let service = AIServiceBuilder::new()
        .with_config(config)
        .with_mock_providers(true)
        .build()
        .await
        .unwrap();
    
    let validation_results = service.validate_connections().await;
    
    // All mock providers should validate successfully
    for (_, result) in validation_results {
        assert!(result.is_ok());
    }
}
