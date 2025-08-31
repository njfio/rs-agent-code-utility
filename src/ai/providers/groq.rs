//! Groq AI provider implementation
//!
//! Provides fast AI inference using Groq's API.
//! Based on Groq's OpenAI-compatible API endpoint.

use crate::ai::types::{AIProvider, AIRequest, AIResponse, AICapability, TokenUsage, ResponseMetadata};
use crate::ai::config::ProviderConfig;
use crate::ai::error::{AIError, AIResult};
use crate::ai::providers::AIProviderImpl;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Groq provider implementation
pub struct GroqProvider {
    config: ProviderConfig,
    client: Client,
}

/// Groq request structure matching OpenAI format
#[derive(Debug, Serialize)]
struct GroqRequest {
    messages: Vec<GroqMessage>,
    model: String,
    temperature: Option<f64>,
    max_completion_tokens: Option<usize>,
    top_p: Option<f64>,
    stream: bool,
    reasoning_effort: Option<String>,
    response_format: Option<ResponseFormat>,
    stop: Option<Vec<String>>,
}

/// Message structure for Groq
#[derive(Debug, Serialize, Deserialize)]
struct GroqMessage {
    role: String,
    content: String,
}

/// Response format specification
#[derive(Debug, Serialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    format_type: String,
}

/// Groq response structure
#[derive(Debug, Deserialize)]
struct GroqResponse {
    id: String,
    object: String,
    created: u64,
    model: String,
    choices: Vec<GroqChoice>,
    usage: GroqUsage,
}

/// Choice from Groq response
#[derive(Debug, Deserialize)]
struct GroqChoice {
    index: usize,
    message: GroqMessage,
    finish_reason: Option<String>,
}

/// Token usage from Groq
#[derive(Debug, Deserialize)]
struct GroqUsage {
    prompt_tokens: usize,
    completion_tokens: usize,
    total_tokens: usize,
}

impl GroqProvider {
    /// Create new Groq provider
    pub async fn new(config: ProviderConfig) -> AIResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AIError::network(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { config, client })
    }

    /// Get API key from config
    fn get_api_key(&self) -> AIResult<String> {
        self.config.api_key.clone().ok_or_else(|| {
            AIError::configuration("Groq API key not provided in configuration".to_string())
        })
    }

    /// Build Groq request from AI request
    fn build_groq_request(&self, request: &AIRequest) -> GroqRequest {
        let content = self.enhance_content_with_context(&request.content, &request.context);

        let messages = vec![
            GroqMessage {
                role: "user".to_string(),
                content,
            }
        ];

        // Allow callers to request structured JSON via context key
        let want_json = request
            .context
            .get("response_format")
            .map(|v| v == "json_object")
            .unwrap_or(false);

        GroqRequest {
            messages,
            model: request.model_preferences
                .as_ref()
                .and_then(|prefs| prefs.first().cloned())
                .unwrap_or_else(|| {
                    // Prefer the user's referenced model for documentation tasks when unspecified
                    if request.feature == crate::ai::types::AIFeature::DocumentationGeneration {
                        "openai/gpt-oss-120b".to_string()
                    } else {
                        "openai/gpt-4o-mini".to_string()
                    }
                }),
            temperature: request.temperature,
            max_completion_tokens: request.max_tokens,
            top_p: Some(1.0),
            stream: request.stream,
            reasoning_effort: if request.feature == crate::ai::types::AIFeature::DocumentationGeneration {
                Some("medium".to_string())
            } else {
                None
            },
            response_format: if want_json {
                Some(ResponseFormat { format_type: "json_object".to_string() })
            } else if request.feature == crate::ai::types::AIFeature::DocumentationGeneration {
                // Default to text unless explicitly requested JSON
                Some(ResponseFormat { format_type: "text".to_string() })
            } else { None },
            stop: None,
        }
    }

    /// Enhance content with context for better documentation generation
    fn enhance_content_with_context(&self, content: &str, context: &std::collections::HashMap<String, String>) -> String {
        if context.is_empty() {
            return content.to_string();
        }

        let mut enhanced = content.to_string();
        enhanced.push_str("\n\nContext information:\n");

        for (key, value) in context {
            enhanced.push_str(&format!("- {}: {}\n", key, value));
        }

        // Add specific formatting instructions for documentation
        if content.contains("documentation") || content.contains("wiki") {
            enhanced.push_str("\n\nPlease provide clear, well-structured documentation with:\n");
            enhanced.push_str("- Comprehensive module overviews\n");
            enhanced.push_str("- Function documentation with parameters and return types\n");
            enhanced.push_str("- Code examples where helpful\n");
            enhanced.push_str("- Cross-references to related modules\n");
        }

        enhanced
    }

    /// Parse Groq response into AI response
    fn parse_response(&self, groq_response: GroqResponse, request: &AIRequest) -> AIResponse {
        let content = groq_response.choices
            .first()
            .map(|choice| choice.message.content.clone())
            .unwrap_or_else(|| "No response generated".to_string());

        let token_usage = TokenUsage {
            prompt_tokens: groq_response.usage.prompt_tokens,
            completion_tokens: groq_response.usage.completion_tokens,
            total_tokens: groq_response.usage.total_tokens,
            estimated_cost: None, // Groq doesn't specify costs in response
        };

        AIResponse {
            feature: request.feature,
            content,
            structured_data: None,
            confidence: Some(0.85), // Groq generally provides high-quality responses
            token_usage,
            metadata: ResponseMetadata {
                request_id: request.metadata.request_id.clone(),
                model_used: groq_response.model,
                provider: AIProvider::Groq,
                processing_time: Duration::from_secs(1), // Fast inference is Groq's advantage
                cached: false,
                timestamp: SystemTime::now(),
                rate_limit_remaining: None,
            },
        }
    }
}

#[async_trait]
impl AIProviderImpl for GroqProvider {
    fn provider(&self) -> AIProvider {
        AIProvider::Groq
    }

    fn capabilities(&self) -> Vec<AICapability> {
        vec![
            AICapability {
                feature: crate::ai::types::AIFeature::CodeExplanation,
                supported: true,
                quality_score: 0.9,
                description: "Fast code explanation using Groq's optimized inference".to_string(),
            },
            AICapability {
                feature: crate::ai::types::AIFeature::SecurityAnalysis,
                supported: true,
                quality_score: 0.85,
                description: "Security analysis for code vulnerabilities".to_string(),
            },
            AICapability {
                feature: crate::ai::types::AIFeature::RefactoringSuggestions,
                supported: true,
                quality_score: 0.88,
                description: "Code refactoring recommendations".to_string(),
            },
            AICapability {
                feature: crate::ai::types::AIFeature::DocumentationGeneration,
                supported: true,
                quality_score: 0.95,
                description: "**Optimized for wiki generation**: Groq provides exceptionally fast documentation generation perfect for large projects".to_string(),
            },
            AICapability {
                feature: crate::ai::types::AIFeature::QualityAssessment,
                supported: true,
                quality_score: 0.8,
                description: "Code quality evaluation and improvement suggestions".to_string(),
            },
        ]
    }

    async fn validate_connection(&self) -> AIResult<()> {
        let api_key = self.get_api_key()?;
        let test_request = GroqRequest {
            messages: vec![GroqMessage {
                role: "user".to_string(),
                content: "Hello".to_string(),
            }],
            model: "openai/gpt-4o-mini".to_string(),
            temperature: Some(0.1),
            max_completion_tokens: Some(10),
            top_p: Some(1.0),
            stream: false,
            reasoning_effort: None,
            response_format: None,
            stop: None,
        };

        let response = self.client
            .post("https://api.groq.com/openai/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&test_request)
            .send()
            .await
            .map_err(|e| AIError::network(format!("Failed to connect to Groq API: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AIError::network(format!("Groq API error {}: {}", status, error_text)));
        }

        Ok(())
    }

    async fn process_request(&self, request: AIRequest) -> AIResult<AIResponse> {
        let api_key = self.get_api_key()?;
        let groq_request = self.build_groq_request(&request);

        let response = self.client
            .post("https://api.groq.com/openai/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&groq_request)
            .send()
            .await
            .map_err(|e| AIError::network(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AIError::network(format!("API error {}: {}", status, error_text)));
        }

        let groq_response: GroqResponse = response.json().await
            .map_err(|e| AIError::response_parsing(format!("Failed to parse Groq response: {}", e)))?;

        Ok(self.parse_response(groq_response, &request))
    }

    fn best_model_for_feature(&self, feature: crate::ai::types::AIFeature) -> Option<String> {
        match feature {
            crate::ai::types::AIFeature::DocumentationGeneration => {
                // Prefer the large open-source model for rich wiki generation
                Some("openai/gpt-oss-120b".to_string())
            },
            crate::ai::types::AIFeature::CodeExplanation => {
                Some("openai/gpt-4o-mini".to_string())
            },
            crate::ai::types::AIFeature::SecurityAnalysis => {
                Some("openai/gpt-4o-mini".to_string())
            },
            _ => Some(self.config.default_model.clone()),
        }
    }

    fn rate_limit_info(&self) -> Option<crate::ai::providers::RateLimitInfo> {
        // Groq provides higher rate limits than most providers
        Some(crate::ai::providers::RateLimitInfo {
            requests_per_minute: 60, // Higher than typical OpenAI limits
            tokens_per_minute: 40000,
            remaining_requests: None,
            remaining_tokens: None,
            reset_time: None,
        })
    }
}
