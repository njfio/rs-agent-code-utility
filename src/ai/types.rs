//! Core AI types and data structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Supported AI providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AIProvider {
    OpenAI,
    Anthropic,
    Google,
    AzureOpenAI,
    Local,
    Ollama,
}

/// AI model specifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIModel {
    pub name: String,
    pub provider: AIProvider,
    pub context_length: usize,
    pub max_tokens: usize,
    pub supports_streaming: bool,
    pub cost_per_token: Option<f64>,
}

/// AI feature types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AIFeature {
    CodeExplanation,
    SecurityAnalysis,
    RefactoringSuggestions,
    ArchitecturalInsights,
    PatternDetection,
    QualityAssessment,
    DocumentationGeneration,
    TestGeneration,
}

/// AI capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AICapability {
    pub feature: AIFeature,
    pub supported: bool,
    pub quality_score: f64,
    pub description: String,
}

/// AI request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIRequest {
    pub feature: AIFeature,
    pub content: String,
    pub context: HashMap<String, String>,
    pub model_preferences: Option<Vec<String>>,
    pub max_tokens: Option<usize>,
    pub temperature: Option<f64>,
    pub stream: bool,
    pub metadata: RequestMetadata,
}

/// Request metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    pub request_id: String,
    pub timestamp: SystemTime,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub priority: RequestPriority,
}

/// Request priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// AI response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIResponse {
    pub feature: AIFeature,
    pub content: String,
    pub structured_data: Option<serde_json::Value>,
    pub confidence: Option<f64>,
    pub token_usage: TokenUsage,
    pub metadata: ResponseMetadata,
}

/// Token usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: usize,
    pub completion_tokens: usize,
    pub total_tokens: usize,
    pub estimated_cost: Option<f64>,
}

/// Response metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    pub request_id: String,
    pub model_used: String,
    pub provider: AIProvider,
    pub processing_time: Duration,
    pub cached: bool,
    pub timestamp: SystemTime,
    pub rate_limit_remaining: Option<usize>,
}

impl Default for RequestPriority {
    fn default() -> Self {
        Self::Normal
    }
}

impl TokenUsage {
    pub fn new(prompt_tokens: usize, completion_tokens: usize) -> Self {
        Self {
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
            estimated_cost: None,
        }
    }
    
    pub fn with_cost(mut self, cost: f64) -> Self {
        self.estimated_cost = Some(cost);
        self
    }
}

impl AIRequest {
    pub fn new(feature: AIFeature, content: String) -> Self {
        Self {
            feature,
            content,
            context: HashMap::new(),
            model_preferences: None,
            max_tokens: None,
            temperature: None,
            stream: false,
            metadata: RequestMetadata {
                request_id: uuid::Uuid::new_v4().to_string(),
                timestamp: SystemTime::now(),
                user_id: None,
                session_id: None,
                priority: RequestPriority::Normal,
            },
        }
    }
    
    pub fn with_context(mut self, key: String, value: String) -> Self {
        self.context.insert(key, value);
        self
    }
    
    pub fn with_model_preference(mut self, model: String) -> Self {
        self.model_preferences.get_or_insert_with(Vec::new).push(model);
        self
    }
    
    pub fn with_temperature(mut self, temperature: f64) -> Self {
        self.temperature = Some(temperature);
        self
    }
    
    pub fn with_max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }
    
    pub fn with_streaming(mut self, stream: bool) -> Self {
        self.stream = stream;
        self
    }
}
