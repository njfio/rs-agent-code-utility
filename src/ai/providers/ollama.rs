//! Ollama provider implementation

use crate::ai::types::{AIProvider, AIRequest, AIResponse, AICapability, AIFeature};
use crate::ai::config::ProviderConfig;
use crate::ai::error::AIResult;
use crate::ai::providers::{AIProviderImpl, RateLimitInfo};
use async_trait::async_trait;

/// Ollama provider implementation
pub struct OllamaProvider {
    config: ProviderConfig,
}

impl OllamaProvider {
    pub async fn new(config: ProviderConfig) -> AIResult<Self> {
        Ok(Self { config })
    }
}

#[async_trait]
impl AIProviderImpl for OllamaProvider {
    fn provider(&self) -> AIProvider {
        AIProvider::Ollama
    }
    
    fn capabilities(&self) -> Vec<AICapability> {
        vec![
            AICapability {
                feature: AIFeature::CodeExplanation,
                supported: true,
                quality_score: 0.75,
                description: "Code explanations using Ollama models".to_string(),
            },
        ]
    }
    
    async fn validate_connection(&self) -> AIResult<()> {
        Ok(())
    }
    
    async fn process_request(&self, request: AIRequest) -> AIResult<AIResponse> {
        use crate::ai::types::{TokenUsage, ResponseMetadata};
        use std::time::{Duration, SystemTime};
        
        // Placeholder implementation
        tokio::time::sleep(Duration::from_millis(300)).await;
        
        Ok(AIResponse {
            feature: request.feature,
            content: format!("Ollama analysis: {}", request.content.chars().take(100).collect::<String>()),
            structured_data: None,
            confidence: Some(0.75),
            token_usage: TokenUsage::new(45, 90),
            metadata: ResponseMetadata {
                request_id: request.metadata.request_id,
                model_used: self.config.default_model.clone(),
                provider: AIProvider::Ollama,
                processing_time: Duration::from_millis(300),
                cached: false,
                timestamp: SystemTime::now(),
                rate_limit_remaining: Some(500),
            },
        })
    }
    
    fn best_model_for_feature(&self, _feature: AIFeature) -> Option<String> {
        Some("llama2".to_string())
    }
    
    fn rate_limit_info(&self) -> Option<RateLimitInfo> {
        Some(RateLimitInfo {
            requests_per_minute: self.config.rate_limit.requests_per_minute,
            tokens_per_minute: self.config.rate_limit.tokens_per_minute,
            remaining_requests: Some(500),
            remaining_tokens: Some(50000),
            reset_time: None,
        })
    }
}
