//! Local AI provider implementation

use crate::ai::types::{AIProvider, AIRequest, AIResponse, AICapability, AIFeature};
use crate::ai::config::ProviderConfig;
use crate::ai::error::AIResult;
use crate::ai::providers::{AIProviderImpl, RateLimitInfo};
use async_trait::async_trait;

/// Local AI provider implementation
pub struct LocalProvider {
    config: ProviderConfig,
}

impl LocalProvider {
    pub async fn new(config: ProviderConfig) -> AIResult<Self> {
        Ok(Self { config })
    }
}

#[async_trait]
impl AIProviderImpl for LocalProvider {
    fn provider(&self) -> AIProvider {
        AIProvider::Local
    }
    
    fn capabilities(&self) -> Vec<AICapability> {
        vec![
            AICapability {
                feature: AIFeature::CodeExplanation,
                supported: true,
                quality_score: 0.70,
                description: "Local model code explanations".to_string(),
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
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        Ok(AIResponse {
            feature: request.feature,
            content: format!("Local AI analysis: {}", request.content.chars().take(100).collect::<String>()),
            structured_data: None,
            confidence: Some(0.70),
            token_usage: TokenUsage::new(40, 80),
            metadata: ResponseMetadata {
                request_id: request.metadata.request_id,
                model_used: self.config.default_model.clone(),
                provider: AIProvider::Local,
                processing_time: Duration::from_millis(500),
                cached: false,
                timestamp: SystemTime::now(),
                rate_limit_remaining: Some(1000),
            },
        })
    }
    
    fn best_model_for_feature(&self, _feature: AIFeature) -> Option<String> {
        Some("local-model".to_string())
    }
    
    fn rate_limit_info(&self) -> Option<RateLimitInfo> {
        Some(RateLimitInfo {
            requests_per_minute: self.config.rate_limit.requests_per_minute,
            tokens_per_minute: self.config.rate_limit.tokens_per_minute,
            remaining_requests: Some(1000),
            remaining_tokens: Some(100000),
            reset_time: None,
        })
    }
}
