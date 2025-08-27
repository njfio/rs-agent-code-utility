//! AI Service Layer and Provider Integrations
//!
//! This module provides a comprehensive AI service layer that supports multiple
//! LLM providers with configuration-driven setup, caching, rate limiting, and
//! error handling.

pub mod config;
pub mod providers;
pub mod service;
pub mod types;
pub mod error;
pub mod cache;

// Re-export main types for convenience
pub use config::{AIConfig, ProviderConfig, ModelConfig, FeatureConfig};
pub use service::{AIService, AIServiceBuilder};
pub use types::{
    AIProvider, AIModel, AIFeature, AIRequest, AIResponse, 
    TokenUsage, ResponseMetadata, AICapability
};
pub use error::{AIError, AIResult};
pub use cache::{AICache, CacheConfig, CacheStats};
