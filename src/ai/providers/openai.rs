//! OpenAI provider implementation

use crate::ai::types::{AIProvider, AIRequest, AIResponse, AICapability, AIFeature, TokenUsage, ResponseMetadata};
use crate::ai::config::ProviderConfig;
use crate::ai::error::{AIError, AIResult};
use crate::ai::providers::{AIProviderImpl, RateLimitInfo};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// OpenAI provider implementation
pub struct OpenAIProvider {
    config: ProviderConfig,
    client: Option<reqwest::Client>,
    base_url: String,
    api_key: String,
}

/// OpenAI API request structure
#[derive(Debug, Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    max_tokens: Option<usize>,
    temperature: Option<f64>,
    stream: bool,
}

/// OpenAI message structure
#[derive(Debug, Serialize, Deserialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

/// OpenAI API response structure
#[derive(Debug, Deserialize)]
struct OpenAIResponse {
    id: String,
    object: String,
    created: u64,
    model: String,
    choices: Vec<OpenAIChoice>,
    usage: OpenAIUsage,
}

/// OpenAI choice structure
#[derive(Debug, Deserialize)]
struct OpenAIChoice {
    index: usize,
    message: OpenAIMessage,
    finish_reason: Option<String>,
}

/// OpenAI usage structure
#[derive(Debug, Deserialize)]
struct OpenAIUsage {
    prompt_tokens: usize,
    completion_tokens: usize,
    total_tokens: usize,
}

impl OpenAIProvider {
    pub async fn new(config: ProviderConfig) -> AIResult<Self> {
        let api_key = config.api_key
            .as_ref()
            .ok_or_else(|| AIError::configuration("OpenAI API key is required"))?
            .clone();
        
        let base_url = config.base_url
            .clone()
            .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
        
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
            AIFeature::PatternDetection => {
                "You are an expert in software design patterns. Identify and explain design patterns \
                 present in the code, assess their implementation quality, and suggest pattern-based \
                 improvements or alternatives.".to_string()
            }
            AIFeature::QualityAssessment => {
                "You are a code quality expert. Assess the overall quality of the code including \
                 readability, maintainability, testability, and adherence to best practices. \
                 Provide specific recommendations for improvement.".to_string()
            }
            AIFeature::DocumentationGeneration => {
                "You are a technical documentation expert. Generate clear, comprehensive documentation \
                 for the provided code including function descriptions, parameter explanations, \
                 return values, usage examples, and any important notes or warnings.".to_string()
            }
            AIFeature::TestGeneration => {
                "You are a test automation expert. Generate comprehensive unit tests for the provided \
                 code including edge cases, error conditions, and integration scenarios. Follow \
                 testing best practices and include clear test descriptions.".to_string()
            }
        }
    }
    
    #[cfg(feature = "net")]
    async fn make_request(&self, openai_request: OpenAIRequest) -> AIResult<OpenAIResponse> {
        let client = self.client.as_ref()
            .ok_or_else(|| AIError::configuration("HTTP client not available"))?;
        
        let response = client
            .post(&format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&openai_request)
            .send()
            .await
            .map_err(|e| AIError::network(format!("Request failed: {}", e)))?;
        
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            
            return match status.as_u16() {
                401 => Err(AIError::authentication("OpenAI", "Invalid API key")),
                429 => Err(AIError::rate_limit("OpenAI", Some(Duration::from_secs(60)))),
                _ => Err(AIError::provider("OpenAI", format!("HTTP {}: {}", status, error_text))),
            };
        }
        
        response.json::<OpenAIResponse>().await
            .map_err(|e| AIError::response_parsing(format!("Failed to parse OpenAI response: {}", e)))
    }
    
    #[cfg(not(feature = "net"))]
    async fn make_request(&self, _openai_request: OpenAIRequest) -> AIResult<OpenAIResponse> {
        Err(AIError::configuration("Network features not enabled. Enable 'net' feature to use OpenAI provider."))
    }
}

#[async_trait]
impl AIProviderImpl for OpenAIProvider {
    fn provider(&self) -> AIProvider {
        AIProvider::OpenAI
    }
    
    fn capabilities(&self) -> Vec<AICapability> {
        vec![
            AICapability {
                feature: AIFeature::CodeExplanation,
                supported: true,
                quality_score: 0.95,
                description: "High-quality code explanations using GPT models".to_string(),
            },
            AICapability {
                feature: AIFeature::SecurityAnalysis,
                supported: true,
                quality_score: 0.85,
                description: "Security vulnerability analysis and recommendations".to_string(),
            },
            AICapability {
                feature: AIFeature::RefactoringSuggestions,
                supported: true,
                quality_score: 0.90,
                description: "Code refactoring and improvement suggestions".to_string(),
            },
            AICapability {
                feature: AIFeature::ArchitecturalInsights,
                supported: true,
                quality_score: 0.88,
                description: "Architectural analysis and design recommendations".to_string(),
            },
            AICapability {
                feature: AIFeature::PatternDetection,
                supported: true,
                quality_score: 0.85,
                description: "Design pattern identification and analysis".to_string(),
            },
            AICapability {
                feature: AIFeature::QualityAssessment,
                supported: true,
                quality_score: 0.87,
                description: "Code quality assessment and improvement recommendations".to_string(),
            },
            AICapability {
                feature: AIFeature::DocumentationGeneration,
                supported: true,
                quality_score: 0.92,
                description: "Automated documentation generation".to_string(),
            },
            AICapability {
                feature: AIFeature::TestGeneration,
                supported: true,
                quality_score: 0.80,
                description: "Unit test generation and testing strategies".to_string(),
            },
        ]
    }
    
    async fn validate_connection(&self) -> AIResult<()> {
        // Create a simple test request
        let test_request = OpenAIRequest {
            model: self.config.default_model.clone(),
            messages: vec![OpenAIMessage {
                role: "user".to_string(),
                content: "Hello".to_string(),
            }],
            max_tokens: Some(1),
            temperature: Some(0.0),
            stream: false,
        };
        
        self.make_request(test_request).await?;
        Ok(())
    }
    
    async fn process_request(&self, request: AIRequest) -> AIResult<AIResponse> {
        let system_prompt = self.create_system_prompt(request.feature);
        
        let openai_request = OpenAIRequest {
            model: request.model_preferences
                .as_ref()
                .and_then(|models| models.first())
                .cloned()
                .unwrap_or_else(|| self.config.default_model.clone()),
            messages: vec![
                OpenAIMessage {
                    role: "system".to_string(),
                    content: system_prompt,
                },
                OpenAIMessage {
                    role: "user".to_string(),
                    content: request.content.clone(),
                },
            ],
            max_tokens: request.max_tokens,
            temperature: request.temperature,
            stream: request.stream,
        };
        
        let start_time = SystemTime::now();
        let openai_response = self.make_request(openai_request).await?;
        let processing_time = start_time.elapsed()
            .unwrap_or_else(|_| Duration::from_millis(0));
        
        let choice = openai_response.choices.into_iter().next()
            .ok_or_else(|| AIError::response_parsing("No choices in OpenAI response"))?;
        
        Ok(AIResponse {
            feature: request.feature,
            content: choice.message.content,
            structured_data: None,
            confidence: Some(0.9), // OpenAI doesn't provide confidence scores
            token_usage: TokenUsage::new(
                openai_response.usage.prompt_tokens,
                openai_response.usage.completion_tokens,
            ),
            metadata: ResponseMetadata {
                request_id: request.metadata.request_id,
                model_used: openai_response.model,
                provider: AIProvider::OpenAI,
                processing_time,
                cached: false,
                timestamp: SystemTime::now(),
                rate_limit_remaining: None, // Would need to parse from headers
            },
        })
    }
    
    fn best_model_for_feature(&self, feature: AIFeature) -> Option<String> {
        // Return the best OpenAI model for each feature
        match feature {
            AIFeature::CodeExplanation | AIFeature::RefactoringSuggestions => {
                Some("gpt-4".to_string())
            }
            AIFeature::SecurityAnalysis | AIFeature::QualityAssessment => {
                Some("gpt-4".to_string())
            }
            AIFeature::DocumentationGeneration | AIFeature::TestGeneration => {
                Some("gpt-3.5-turbo".to_string())
            }
            _ => Some(self.config.default_model.clone()),
        }
    }
    
    fn rate_limit_info(&self) -> Option<RateLimitInfo> {
        Some(RateLimitInfo {
            requests_per_minute: self.config.rate_limit.requests_per_minute,
            tokens_per_minute: self.config.rate_limit.tokens_per_minute,
            remaining_requests: None, // Would need to track from API responses
            remaining_tokens: None,
            reset_time: None,
        })
    }
}
