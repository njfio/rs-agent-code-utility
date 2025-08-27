//! Azure OpenAI provider implementation

use crate::ai::types::{AIProvider, AIRequest, AIResponse, AICapability, AIFeature};
use crate::ai::config::ProviderConfig;
use crate::ai::error::AIResult;
use crate::ai::providers::{AIProviderImpl, RateLimitInfo};
use async_trait::async_trait;

/// Azure OpenAI provider implementation
pub struct AzureProvider {
    config: ProviderConfig,
}

impl AzureProvider {
    pub async fn new(config: ProviderConfig) -> AIResult<Self> {
        Ok(Self { config })
    }
}

#[async_trait]
impl AIProviderImpl for AzureProvider {
    fn provider(&self) -> AIProvider {
        AIProvider::AzureOpenAI
    }
    
    fn capabilities(&self) -> Vec<AICapability> {
        vec![
            AICapability {
                feature: AIFeature::CodeExplanation,
                supported: true,
                quality_score: 0.93,
                description: "Code explanations using Azure OpenAI".to_string(),
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
        tokio::time::sleep(Duration::from_millis(180)).await;
        
        Ok(AIResponse {
            feature: request.feature,
            content: format!("Azure OpenAI analysis: {}", request.content.chars().take(100).collect::<String>()),
            structured_data: None,
            confidence: Some(0.90),
            token_usage: TokenUsage::new(70, 140),
            metadata: ResponseMetadata {
                request_id: request.metadata.request_id,
                model_used: self.config.default_model.clone(),
                provider: AIProvider::AzureOpenAI,
                processing_time: Duration::from_millis(180),
                cached: false,
                timestamp: SystemTime::now(),
                rate_limit_remaining: Some(60),
            },
        })
    }
    
    fn best_model_for_feature(&self, _feature: AIFeature) -> Option<String> {
        Some("gpt-4".to_string())
    }
    
    fn rate_limit_info(&self) -> Option<RateLimitInfo> {
        Some(RateLimitInfo {
            requests_per_minute: self.config.rate_limit.requests_per_minute,
            tokens_per_minute: self.config.rate_limit.tokens_per_minute,
            remaining_requests: None,
            remaining_tokens: None,
            reset_time: None,
        })
    }
}
