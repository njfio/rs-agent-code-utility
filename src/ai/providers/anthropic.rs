//! Anthropic Claude provider implementation

use crate::ai::types::{AIProvider, AIRequest, AIResponse, AICapability, AIFeature};
use crate::ai::config::ProviderConfig;
use crate::ai::error::{AIError, AIResult};
use crate::ai::providers::{AIProviderImpl, RateLimitInfo};
use async_trait::async_trait;

/// Anthropic provider implementation
pub struct AnthropicProvider {
    config: ProviderConfig,
    #[allow(dead_code)]
    client: Option<reqwest::Client>,
    #[allow(dead_code)]
    base_url: String,
    #[allow(dead_code)]
    api_key: String,
}

impl AnthropicProvider {
    pub async fn new(config: ProviderConfig) -> AIResult<Self> {
        let api_key = config.api_key
            .as_ref()
            .ok_or_else(|| AIError::configuration("Anthropic API key is required"))?
            .clone();
        
        let base_url = config.base_url
            .clone()
            .unwrap_or_else(|| "https://api.anthropic.com/v1".to_string());
        
        #[cfg(feature = "net")]
        let client = Some(
            reqwest::Client::builder()
                .timeout(config.timeout)
                .build()
                .map_err(|e| AIError::configuration(format!("Failed to create HTTP client: {}", e)))?
        );
        
        #[cfg(not(feature = "net"))]
        let client = None;
        
        Ok(Self {
            config,
            client,
            base_url,
            api_key,
        })
    }

    fn create_system_prompt(&self, feature: AIFeature) -> String {
        match feature {
            AIFeature::CodeExplanation => {
                "You are an expert code analyst. Provide clear, concise explanations of code functionality, \
                 architecture, and patterns. Focus on what the code does, how it works, and why it's structured \
                 that way. Include insights about design patterns, best practices, and potential improvements.".to_string()
            }
            AIFeature::SecurityAnalysis => {
                "You are a security expert specializing in code analysis. Identify potential security \
                 vulnerabilities, assess risk levels, and provide specific remediation recommendations. \
                 Focus on common vulnerabilities like injection attacks, authentication issues, \
                 authorization problems, and data exposure risks.".to_string()
            }
            AIFeature::RefactoringSuggestions => {
                "You are a software engineering expert focused on code quality and maintainability. \
                 Analyze the code for refactoring opportunities, identify code smells, suggest design \
                 pattern improvements, and recommend ways to enhance readability, performance, and \
                 maintainability.".to_string()
            }
            AIFeature::ArchitecturalInsights => {
                "You are a software architect. Analyze the code structure and provide insights about \
                 architectural patterns, component relationships, scalability considerations, and \
                 design decisions. Suggest improvements for better modularity and maintainability.".to_string()
            }
            _ => {
                "You are an expert software engineer. Analyze the provided code and provide helpful insights.".to_string()
            }
        }
    }
}

#[async_trait]
impl AIProviderImpl for AnthropicProvider {
    fn provider(&self) -> AIProvider {
        AIProvider::Anthropic
    }
    
    fn capabilities(&self) -> Vec<AICapability> {
        vec![
            AICapability {
                feature: AIFeature::CodeExplanation,
                supported: true,
                quality_score: 0.93,
                description: "High-quality code explanations using Claude models".to_string(),
            },
            AICapability {
                feature: AIFeature::SecurityAnalysis,
                supported: true,
                quality_score: 0.88,
                description: "Security analysis with Claude's reasoning capabilities".to_string(),
            },
            AICapability {
                feature: AIFeature::RefactoringSuggestions,
                supported: true,
                quality_score: 0.91,
                description: "Thoughtful refactoring suggestions".to_string(),
            },
        ]
    }
    
    async fn validate_connection(&self) -> AIResult<()> {
        // TODO: Implement actual Anthropic API validation
        #[cfg(not(feature = "net"))]
        return Err(AIError::configuration("Network features not enabled"));
        
        #[cfg(feature = "net")]
        {
            // Placeholder implementation
            Ok(())
        }
    }
    
    async fn process_request(&self, request: AIRequest) -> AIResult<AIResponse> {
        #[cfg(not(feature = "net"))]
        return Err(AIError::configuration("Network features not enabled"));

        #[cfg(feature = "net")]
        {
            use crate::ai::types::{TokenUsage, ResponseMetadata};
            use std::time::{Duration, SystemTime};
            use serde::{Deserialize, Serialize};

            #[derive(Serialize)]
            struct AnthropicRequest {
                model: String,
                max_tokens: usize,
                messages: Vec<AnthropicMessage>,
                temperature: Option<f64>,
            }

            #[derive(Serialize)]
            struct AnthropicMessage {
                role: String,
                content: String,
            }

            #[derive(Deserialize)]
            struct AnthropicResponse {
                content: Vec<AnthropicContent>,
                usage: AnthropicUsage,
            }

            #[derive(Deserialize)]
            struct AnthropicContent {
                text: String,
            }

            #[derive(Deserialize)]
            struct AnthropicUsage {
                input_tokens: usize,
                output_tokens: usize,
            }

            let system_prompt = self.create_system_prompt(request.feature);

            let anthropic_request = AnthropicRequest {
                model: request.model_preferences
                    .as_ref()
                    .and_then(|models| models.first())
                    .cloned()
                    .unwrap_or_else(|| self.config.default_model.clone()),
                max_tokens: request.max_tokens.unwrap_or(2048),
                messages: vec![
                    AnthropicMessage {
                        role: "user".to_string(),
                        content: format!("{}\n\n{}", system_prompt, request.content),
                    },
                ],
                temperature: request.temperature,
            };

            let client = self.client.as_ref()
                .ok_or_else(|| AIError::configuration("HTTP client not available"))?;

            let start_time = SystemTime::now();
            let response = client
                .post(&format!("{}/messages", self.base_url))
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .header("anthropic-version", "2023-06-01")
                .json(&anthropic_request)
                .send()
                .await
                .map_err(|e| AIError::network(format!("Request failed: {}", e)))?;

            let processing_time = start_time.elapsed()
                .unwrap_or_else(|_| Duration::from_millis(0));

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response.text().await
                    .unwrap_or_else(|_| "Unknown error".to_string());

                return match status.as_u16() {
                    401 => Err(AIError::authentication("Anthropic", "Invalid API key")),
                    429 => Err(AIError::rate_limit("Anthropic", Some(Duration::from_secs(60)))),
                    _ => Err(AIError::provider("Anthropic", format!("HTTP {}: {}", status, error_text))),
                };
            }

            let anthropic_response: AnthropicResponse = response.json().await
                .map_err(|e| AIError::response_parsing(format!("Failed to parse Anthropic response: {}", e)))?;

            let content = anthropic_response.content.into_iter()
                .map(|c| c.text)
                .collect::<Vec<_>>()
                .join("\n");

            Ok(AIResponse {
                feature: request.feature,
                content,
                structured_data: None,
                confidence: Some(0.88),
                token_usage: TokenUsage::new(
                    anthropic_response.usage.input_tokens,
                    anthropic_response.usage.output_tokens,
                ),
                metadata: ResponseMetadata {
                    request_id: request.metadata.request_id,
                    model_used: anthropic_request.model,
                    provider: AIProvider::Anthropic,
                    processing_time,
                    cached: false,
                    timestamp: SystemTime::now(),
                    rate_limit_remaining: None,
                },
            })
        }
    }
    
    fn best_model_for_feature(&self, _feature: AIFeature) -> Option<String> {
        Some("claude-3-sonnet-20240229".to_string())
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
