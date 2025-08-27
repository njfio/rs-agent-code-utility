//! AI provider implementations

use crate::ai::types::{AIProvider, AIRequest, AIResponse, AICapability};
use crate::ai::config::ProviderConfig;
use crate::ai::error::{AIError, AIResult};
use async_trait::async_trait;
use std::time::{Duration, SystemTime};

pub mod openai;
pub mod anthropic;
pub mod google;
pub mod azure;
pub mod local;
pub mod ollama;

/// Provider implementation trait
#[async_trait]
pub trait AIProviderImpl: Send + Sync {
    /// Get the provider type
    fn provider(&self) -> AIProvider;
    
    /// Get provider capabilities
    fn capabilities(&self) -> Vec<AICapability>;
    
    /// Validate connection and authentication
    async fn validate_connection(&self) -> AIResult<()>;
    
    /// Process an AI request
    async fn process_request(&self, request: AIRequest) -> AIResult<AIResponse>;
    
    /// Check if a feature is supported
    fn supports_feature(&self, feature: crate::ai::types::AIFeature) -> bool {
        self.capabilities()
            .iter()
            .any(|cap| cap.feature == feature && cap.supported)
    }
    
    /// Get the best model for a specific feature
    fn best_model_for_feature(&self, feature: crate::ai::types::AIFeature) -> Option<String>;
    
    /// Get rate limit information
    fn rate_limit_info(&self) -> Option<RateLimitInfo>;
}

/// Rate limit information
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub requests_per_minute: usize,
    pub tokens_per_minute: usize,
    pub remaining_requests: Option<usize>,
    pub remaining_tokens: Option<usize>,
    pub reset_time: Option<std::time::SystemTime>,
}

/// Create a provider implementation from configuration
pub async fn create_provider(
    provider: AIProvider,
    config: ProviderConfig,
) -> AIResult<Box<dyn AIProviderImpl>> {
    if !config.enabled {
        return Err(AIError::configuration(
            format!("Provider {:?} is disabled", provider)
        ));
    }
    
    match provider {
        AIProvider::OpenAI => {
            let provider = openai::OpenAIProvider::new(config).await?;
            Ok(Box::new(provider))
        }
        AIProvider::Anthropic => {
            let provider = anthropic::AnthropicProvider::new(config).await?;
            Ok(Box::new(provider))
        }
        AIProvider::Google => {
            let provider = google::GoogleProvider::new(config).await?;
            Ok(Box::new(provider))
        }
        AIProvider::AzureOpenAI => {
            let provider = azure::AzureProvider::new(config).await?;
            Ok(Box::new(provider))
        }
        AIProvider::Local => {
            let provider = local::LocalProvider::new(config).await?;
            Ok(Box::new(provider))
        }
        AIProvider::Ollama => {
            let provider = ollama::OllamaProvider::new(config).await?;
            Ok(Box::new(provider))
        }
    }
}

/// Mock provider for testing
pub struct MockProvider {
    provider: AIProvider,
    config: ProviderConfig,
}

impl MockProvider {
    pub fn new(provider: AIProvider, config: ProviderConfig) -> Self {
        Self { provider, config }
    }
}

#[async_trait]
impl AIProviderImpl for MockProvider {
    fn provider(&self) -> AIProvider {
        self.provider
    }
    
    fn capabilities(&self) -> Vec<AICapability> {
        use crate::ai::types::AIFeature;

        vec![
            AICapability {
                feature: AIFeature::CodeExplanation,
                supported: true,
                quality_score: 0.8,
                description: "Mock code explanation capability".to_string(),
            },
            AICapability {
                feature: AIFeature::SecurityAnalysis,
                supported: true,
                quality_score: 0.7,
                description: "Mock security analysis capability".to_string(),
            },
            AICapability {
                feature: AIFeature::RefactoringSuggestions,
                supported: true,
                quality_score: 0.75,
                description: "Mock refactoring suggestions capability".to_string(),
            },
            AICapability {
                feature: AIFeature::DocumentationGeneration,
                supported: true,
                quality_score: 0.8,
                description: "Mock documentation generation capability".to_string(),
            },
        ]
    }
    
    async fn validate_connection(&self) -> AIResult<()> {
        // Mock validation always succeeds
        Ok(())
    }
    
    async fn process_request(&self, request: AIRequest) -> AIResult<AIResponse> {
        use crate::ai::types::{TokenUsage, ResponseMetadata};
        use std::time::{Duration, SystemTime};
        
        // Simulate processing delay
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let content = match request.feature {
            crate::ai::types::AIFeature::CodeExplanation => {
                format!("Mock explanation for: {}", request.content.chars().take(50).collect::<String>())
            }
            crate::ai::types::AIFeature::SecurityAnalysis => {
                format!("Mock security analysis for: {}", request.content.chars().take(50).collect::<String>())
            }
            crate::ai::types::AIFeature::RefactoringSuggestions => {
                format!("Mock refactoring suggestions for: {}", request.content.chars().take(50).collect::<String>())
            }
            _ => format!("Mock response for {:?}", request.feature),
        };
        
        Ok(AIResponse {
            feature: request.feature,
            content,
            structured_data: None,
            confidence: Some(0.8),
            token_usage: TokenUsage::new(50, 100),
            metadata: ResponseMetadata {
                request_id: request.metadata.request_id,
                model_used: self.config.default_model.clone(),
                provider: self.provider,
                processing_time: Duration::from_millis(100),
                cached: false,
                timestamp: SystemTime::now(),
                rate_limit_remaining: Some(100),
            },
        })
    }
    
    fn best_model_for_feature(&self, _feature: crate::ai::types::AIFeature) -> Option<String> {
        Some(self.config.default_model.clone())
    }
    
    fn rate_limit_info(&self) -> Option<RateLimitInfo> {
        Some(RateLimitInfo {
            requests_per_minute: self.config.rate_limit.requests_per_minute,
            tokens_per_minute: self.config.rate_limit.tokens_per_minute,
            remaining_requests: Some(100),
            remaining_tokens: Some(10000),
            reset_time: Some(SystemTime::now() + Duration::from_secs(60)),
        })
    }
}
