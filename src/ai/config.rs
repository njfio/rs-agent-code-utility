//! AI service configuration system
//!
//! Supports loading configuration from JSON/YAML files with environment variable
//! overrides and validation.

use crate::ai::types::{AIProvider, AIFeature};
use crate::ai::error::{AIError, AIResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// Main AI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIConfig {
    /// Default provider to use
    pub default_provider: AIProvider,
    /// Provider configurations
    pub providers: HashMap<AIProvider, ProviderConfig>,
    /// Feature-specific configurations
    pub features: FeatureConfig,
    /// Global settings
    pub global: GlobalConfig,
}

/// Provider-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Whether this provider is enabled
    pub enabled: bool,
    /// API key (can be environment variable reference)
    pub api_key: Option<String>,
    /// API base URL (for custom endpoints)
    pub base_url: Option<String>,
    /// Organization ID (for providers that support it)
    pub organization: Option<String>,
    /// Available models for this provider
    pub models: Vec<ModelConfig>,
    /// Default model to use
    pub default_model: String,
    /// Request timeout
    pub timeout: Duration,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Retry configuration
    pub retry: RetryConfig,
}

/// Model configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Model name/identifier
    pub name: String,
    /// Maximum context length
    pub context_length: usize,
    /// Maximum tokens per request
    pub max_tokens: usize,
    /// Whether streaming is supported
    pub supports_streaming: bool,
    /// Cost per token (optional)
    pub cost_per_token: Option<f64>,
    /// Supported features
    pub supported_features: Vec<AIFeature>,
}

/// Feature-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureConfig {
    /// Code explanation settings
    pub code_explanation: FeatureSettings,
    /// Security analysis settings
    pub security_analysis: FeatureSettings,
    /// Refactoring suggestions settings
    pub refactoring_suggestions: FeatureSettings,
    /// Architectural insights settings
    pub architectural_insights: FeatureSettings,
    /// Pattern detection settings
    pub pattern_detection: FeatureSettings,
    /// Quality assessment settings
    pub quality_assessment: FeatureSettings,
    /// Documentation generation settings
    pub documentation_generation: FeatureSettings,
    /// Test generation settings
    pub test_generation: FeatureSettings,
}

/// Settings for individual features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSettings {
    /// Whether this feature is enabled
    pub enabled: bool,
    /// Preferred provider for this feature
    pub preferred_provider: Option<AIProvider>,
    /// Preferred model for this feature
    pub preferred_model: Option<String>,
    /// Temperature setting (0.0 to 1.0)
    pub temperature: f64,
    /// Maximum tokens for responses
    pub max_tokens: usize,
    /// Whether to use caching
    pub use_cache: bool,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
}

/// Global configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Enable caching globally
    pub enable_cache: bool,
    /// Cache configuration
    pub cache: CacheConfig,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Log level for AI operations
    pub log_level: String,
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Cache type (memory, redis, file)
    pub cache_type: String,
    /// Maximum cache size (in MB for memory cache)
    pub max_size_mb: usize,
    /// Default TTL in seconds
    pub default_ttl: u64,
    /// Cache key prefix
    pub key_prefix: String,
    /// Redis URL (if using Redis cache)
    pub redis_url: Option<String>,
    /// File cache directory (if using file cache)
    pub file_cache_dir: Option<String>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per minute
    pub requests_per_minute: usize,
    /// Tokens per minute
    pub tokens_per_minute: usize,
    /// Burst allowance
    pub burst_size: usize,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retries
    pub max_retries: usize,
    /// Initial retry delay
    pub initial_delay: Duration,
    /// Maximum retry delay
    pub max_delay: Duration,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            default_provider: AIProvider::OpenAI,
            providers: HashMap::new(),
            features: FeatureConfig::default(),
            global: GlobalConfig::default(),
        }
    }
}

impl Default for FeatureConfig {
    fn default() -> Self {
        let default_settings = FeatureSettings::default();
        Self {
            code_explanation: default_settings.clone(),
            security_analysis: default_settings.clone(),
            refactoring_suggestions: default_settings.clone(),
            architectural_insights: default_settings.clone(),
            pattern_detection: default_settings.clone(),
            quality_assessment: default_settings.clone(),
            documentation_generation: default_settings.clone(),
            test_generation: default_settings,
        }
    }
}

impl Default for FeatureSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            preferred_provider: None,
            preferred_model: None,
            temperature: 0.7,
            max_tokens: 2048,
            use_cache: true,
            cache_ttl: 3600, // 1 hour
        }
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            cache: CacheConfig::default(),
            enable_metrics: true,
            log_level: "info".to_string(),
            max_concurrent_requests: 10,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            cache_type: "memory".to_string(),
            max_size_mb: 100,
            default_ttl: 3600,
            key_prefix: "ai_cache".to_string(),
            redis_url: None,
            file_cache_dir: None,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            tokens_per_minute: 100000,
            burst_size: 10,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(1000),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_key: Some("mock-key".to_string()),
            base_url: Some("https://api.mock.com/v1".to_string()),
            organization: None,
            models: vec![
                ModelConfig {
                    name: "mock-model".to_string(),
                    context_length: 4096,
                    max_tokens: 2048,
                    supports_streaming: false,
                    cost_per_token: Some(0.0),
                    supported_features: vec![
                        crate::ai::types::AIFeature::CodeExplanation,
                        crate::ai::types::AIFeature::SecurityAnalysis,
                        crate::ai::types::AIFeature::RefactoringSuggestions,
                    ],
                }
            ],
            default_model: "mock-model".to_string(),
            timeout: Duration::from_secs(30),
            rate_limit: RateLimitConfig::default(),
            retry: RetryConfig::default(),
        }
    }
}

impl AIConfig {
    /// Load configuration from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> AIResult<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| AIError::configuration(format!("Failed to read config file: {}", e)))?;
        
        let extension = path.as_ref()
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("json");
        
        match extension {
            "json" => Self::from_json(&content),
            "yaml" | "yml" => Self::from_yaml(&content),
            _ => Err(AIError::configuration("Unsupported config file format. Use .json or .yaml")),
        }
    }
    
    /// Load configuration from JSON string
    pub fn from_json(json: &str) -> AIResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| AIError::configuration(format!("Invalid JSON config: {}", e)))
    }
    
    /// Load configuration from YAML string
    pub fn from_yaml(yaml: &str) -> AIResult<Self> {
        serde_yaml::from_str(yaml)
            .map_err(|e| AIError::configuration(format!("Invalid YAML config: {}", e)))
    }
    
    /// Apply environment variable overrides
    pub fn with_env_overrides(mut self) -> Self {
        // Override API keys from environment
        for (provider, config) in &mut self.providers {
            let env_key = format!("AI_{:?}_API_KEY", provider).to_uppercase();
            if let Ok(api_key) = std::env::var(&env_key) {
                config.api_key = Some(api_key);
            }
        }
        
        // Override default provider
        if let Ok(provider) = std::env::var("AI_DEFAULT_PROVIDER") {
            if let Ok(provider) = provider.parse::<AIProvider>() {
                self.default_provider = provider;
            }
        }
        
        self
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> AIResult<()> {
        // Check that default provider is configured
        if !self.providers.contains_key(&self.default_provider) {
            return Err(AIError::configuration(
                format!("Default provider {:?} is not configured", self.default_provider)
            ));
        }
        
        // Validate each provider configuration
        for (provider, config) in &self.providers {
            if config.enabled && config.api_key.is_none() && *provider != AIProvider::Local {
                return Err(AIError::configuration(
                    format!("Provider {:?} is enabled but has no API key", provider)
                ));
            }
            
            if config.models.is_empty() {
                return Err(AIError::configuration(
                    format!("Provider {:?} has no models configured", provider)
                ));
            }
            
            // Check that default model exists
            if !config.models.iter().any(|m| m.name == config.default_model) {
                return Err(AIError::configuration(
                    format!("Default model '{}' not found for provider {:?}", 
                           config.default_model, provider)
                ));
            }
        }
        
        Ok(())
    }
}

impl std::str::FromStr for AIProvider {
    type Err = AIError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "openai" => Ok(AIProvider::OpenAI),
            "anthropic" => Ok(AIProvider::Anthropic),
            "google" => Ok(AIProvider::Google),
            "azure" | "azureopenai" => Ok(AIProvider::AzureOpenAI),
            "local" => Ok(AIProvider::Local),
            "ollama" => Ok(AIProvider::Ollama),
            _ => Err(AIError::configuration(format!("Unknown provider: {}", s))),
        }
    }
}
