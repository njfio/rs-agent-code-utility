//! Main AI service implementation

use crate::ai::types::{AIProvider, AIRequest, AIResponse, AIFeature};
use crate::ai::config::{AIConfig, ProviderConfig};
use crate::ai::error::{AIError, AIResult};
use crate::ai::cache::{AICache, MemoryCache, CacheConfig};
use crate::ai::providers::{AIProviderImpl, create_provider};
use std::collections::HashMap;
// use std::sync::Arc; // Not currently used
use std::time::Duration;

/// Main AI service
pub struct AIService {
    config: AIConfig,
    providers: HashMap<AIProvider, Box<dyn AIProviderImpl>>,
    cache: Option<Box<dyn AICache>>,
}

/// AI service builder for easier configuration
pub struct AIServiceBuilder {
    config: AIConfig,
    use_mock_providers: bool,
}

impl AIServiceBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: AIConfig::default(),
            use_mock_providers: false,
        }
    }
    
    /// Set the configuration
    pub fn with_config(mut self, config: AIConfig) -> Self {
        self.config = config;
        self
    }
    
    /// Load configuration from file
    pub fn with_config_file<P: AsRef<std::path::Path>>(mut self, path: P) -> AIResult<Self> {
        self.config = AIConfig::from_file(path)?;
        Ok(self)
    }
    
    /// Use mock providers for testing
    pub fn with_mock_providers(mut self, use_mock: bool) -> Self {
        self.use_mock_providers = use_mock;
        self
    }
    
    /// Add a provider configuration
    pub fn with_provider(mut self, provider: AIProvider, config: ProviderConfig) -> Self {
        self.config.providers.insert(provider, config);
        self
    }
    
    /// Set the default provider
    pub fn with_default_provider(mut self, provider: AIProvider) -> Self {
        self.config.default_provider = provider;
        self
    }
    
    /// Build the AI service
    pub async fn build(self) -> AIResult<AIService> {
        AIService::new(self.config, self.use_mock_providers).await
    }
}

impl Default for AIServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AIService {
    /// Create a new AI service with the given configuration
    pub async fn new(config: AIConfig, use_mock_providers: bool) -> AIResult<Self> {
        // Validate configuration (skip for mock providers)
        if !use_mock_providers {
            config.validate()?;
        }
        
        // Apply environment variable overrides
        let config = config.with_env_overrides();
        
        // Initialize providers
        let mut providers = HashMap::new();

        if use_mock_providers {
            // For mock providers, create a default mock provider if none are configured
            if config.providers.is_empty() {
                let mock_config = ProviderConfig::default();
                let provider = Box::new(crate::ai::providers::MockProvider::new(config.default_provider, mock_config))
                    as Box<dyn AIProviderImpl>;
                providers.insert(config.default_provider, provider);
            } else {
                for (provider_type, provider_config) in &config.providers {
                    if provider_config.enabled {
                        let provider = Box::new(crate::ai::providers::MockProvider::new(*provider_type, provider_config.clone()))
                            as Box<dyn AIProviderImpl>;
                        providers.insert(*provider_type, provider);
                    }
                }
            }
        } else {
            for (provider_type, provider_config) in &config.providers {
                if provider_config.enabled {
                    let provider = create_provider(*provider_type, provider_config.clone()).await?;
                    providers.insert(*provider_type, provider);
                }
            }
        }
        
        // Initialize cache if enabled
        let cache: Option<Box<dyn AICache>> = if config.global.enable_cache {
            let cache_config = CacheConfig {
                max_size: config.global.cache.max_size_mb * 1024, // Convert MB to entries (rough estimate)
                default_ttl: Duration::from_secs(config.global.cache.default_ttl),
                cleanup_interval: Duration::from_secs(300),
            };
            Some(Box::new(MemoryCache::new(cache_config)))
        } else {
            None
        };
        
        Ok(Self {
            config,
            providers,
            cache,
        })
    }
    
    /// Process an AI request
    pub async fn process_request(&self, request: AIRequest) -> AIResult<AIResponse> {
        // Check cache first if enabled
        if let Some(cache) = &self.cache {
            let cache_key = cache.generate_key(&request);
            if let Some(cached_response) = cache.get(&cache_key)? {
                return Ok(cached_response);
            }
        }
        
        // Determine which provider to use
        let provider_type = self.select_provider(&request)?;
        let provider = self.providers.get(&provider_type)
            .ok_or_else(|| AIError::configuration(format!("Provider {:?} not available", provider_type)))?;
        
        // Check if the provider supports the requested feature
        if !provider.supports_feature(request.feature) {
            return Err(AIError::feature_not_supported(
                format!("{:?}", request.feature),
                format!("{:?}", provider_type),
            ));
        }
        
        // Process the request
        let mut response = provider.process_request(request.clone()).await?;
        
        // Cache the response if caching is enabled
        if let Some(cache) = &self.cache {
            let cache_key = cache.generate_key(&request);
            let feature_config = self.get_feature_config(request.feature);
            let ttl = if feature_config.use_cache {
                Some(Duration::from_secs(feature_config.cache_ttl))
            } else {
                None
            };
            
            if let Some(ttl) = ttl {
                let _ = cache.put(&cache_key, response.clone(), Some(ttl));
            }
        }
        
        // Mark as not cached since we just processed it
        response.metadata.cached = false;
        
        Ok(response)
    }
    
    /// Select the best provider for a request
    fn select_provider(&self, request: &AIRequest) -> AIResult<AIProvider> {
        let feature_config = self.get_feature_config(request.feature);
        
        // Check if there's a preferred provider for this feature
        if let Some(preferred) = feature_config.preferred_provider {
            if self.providers.contains_key(&preferred) {
                return Ok(preferred);
            }
        }
        
        // Check model preferences in the request
        if let Some(model_prefs) = &request.model_preferences {
            for model in model_prefs {
                for (provider_type, provider) in &self.providers {
                    if provider.best_model_for_feature(request.feature)
                        .map_or(false, |best_model| best_model == *model) {
                        return Ok(*provider_type);
                    }
                }
            }
        }
        
        // Fall back to default provider
        if self.providers.contains_key(&self.config.default_provider) {
            Ok(self.config.default_provider)
        } else {
            // Use any available provider that supports the feature
            for (provider_type, provider) in &self.providers {
                if provider.supports_feature(request.feature) {
                    return Ok(*provider_type);
                }
            }
            
            Err(AIError::configuration(
                format!("No available provider supports feature {:?}", request.feature)
            ))
        }
    }
    
    /// Get feature configuration
    fn get_feature_config(&self, feature: AIFeature) -> &crate::ai::config::FeatureSettings {
        match feature {
            AIFeature::CodeExplanation => &self.config.features.code_explanation,
            AIFeature::SecurityAnalysis => &self.config.features.security_analysis,
            AIFeature::RefactoringSuggestions => &self.config.features.refactoring_suggestions,
            AIFeature::ArchitecturalInsights => &self.config.features.architectural_insights,
            AIFeature::PatternDetection => &self.config.features.pattern_detection,
            AIFeature::QualityAssessment => &self.config.features.quality_assessment,
            AIFeature::DocumentationGeneration => &self.config.features.documentation_generation,
            AIFeature::TestGeneration => &self.config.features.test_generation,
        }
    }
    
    /// Validate all provider connections
    pub async fn validate_connections(&self) -> HashMap<AIProvider, AIResult<()>> {
        let mut results = HashMap::new();
        
        for (provider_type, provider) in &self.providers {
            let result = provider.validate_connection().await;
            results.insert(*provider_type, result);
        }
        
        results
    }
    
    /// Get available providers
    pub fn available_providers(&self) -> Vec<AIProvider> {
        self.providers.keys().copied().collect()
    }
    
    /// Check if a feature is supported by any provider
    pub fn is_feature_supported(&self, feature: AIFeature) -> bool {
        self.providers.values()
            .any(|provider| provider.supports_feature(feature))
    }
    
    /// Get cache statistics
    pub fn cache_stats(&self) -> Option<crate::ai::cache::CacheStats> {
        self.cache.as_ref().map(|cache| cache.stats())
    }
    
    /// Clear cache
    pub fn clear_cache(&self) -> AIResult<()> {
        if let Some(cache) = &self.cache {
            cache.clear()?;
        }
        Ok(())
    }
    
    /// Get configuration
    pub fn config(&self) -> &AIConfig {
        &self.config
    }
}
