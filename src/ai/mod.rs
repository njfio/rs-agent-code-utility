//! AI Service Layer and Provider Integrations
//!
//! This module provides a comprehensive AI service layer that supports multiple
//! LLM providers with configuration-driven setup, caching, rate limiting, and
//! error handling.

pub mod cache;
pub mod config;
pub mod error;
pub mod providers;
pub mod service;
pub mod types;

// Re-export main types for convenience
pub use cache::{AICache, CacheConfig, CacheStats};
pub use config::{AIConfig, FeatureConfig, ModelConfig, ProviderConfig};
pub use error::{AIError, AIResult};
pub use service::{AIService, AIServiceBuilder};
pub use types::{
    AICapability, AIFeature, AIModel, AIProvider, AIRequest, AIResponse, ResponseMetadata,
    TokenUsage,
};
