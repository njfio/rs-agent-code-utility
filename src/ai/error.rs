//! AI service error types and handling

use thiserror::Error;
use std::time::Duration;

/// AI service result type
pub type AIResult<T> = Result<T, AIError>;

/// AI service error types
#[derive(Error, Debug)]
pub enum AIError {
    /// Configuration errors
    #[error("Configuration error: {message}")]
    Configuration { message: String },

    /// Provider-specific errors
    #[error("Provider error ({provider}): {message}")]
    Provider { provider: String, message: String },

    /// Authentication errors
    #[error("Authentication failed for provider {provider}: {message}")]
    Authentication { provider: String, message: String },

    /// Rate limiting errors
    #[error("Rate limit exceeded for provider {provider}. Retry after {retry_after:?}")]
    RateLimit { provider: String, retry_after: Option<Duration> },

    /// Network/HTTP errors
    #[error("Network error: {message}")]
    Network { message: String },

    /// Request validation errors
    #[error("Invalid request: {message}")]
    InvalidRequest { message: String },

    /// Response parsing errors
    #[error("Failed to parse response: {message}")]
    ResponseParsing { message: String },

    /// Model not available
    #[error("Model {model} not available for provider {provider}")]
    ModelUnavailable { model: String, provider: String },

    /// Feature not supported
    #[error("Feature {feature} not supported by provider {provider}")]
    FeatureNotSupported { feature: String, provider: String },

    /// Token limit exceeded
    #[error("Token limit exceeded: requested {requested}, limit {limit}")]
    TokenLimitExceeded { requested: usize, limit: usize },

    /// Cache errors
    #[error("Cache error: {message}")]
    Cache { message: String },

    /// Timeout errors
    #[error("Request timeout after {duration:?}")]
    Timeout { duration: Duration },

    /// Internal service errors
    #[error("Internal error: {message}")]
    Internal { message: String },

    /// JSON serialization/deserialization errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// HTTP client errors
    #[cfg(feature = "net")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl AIError {
    /// Create a configuration error
    pub fn configuration<S: Into<String>>(message: S) -> Self {
        Self::Configuration { message: message.into() }
    }

    /// Create a provider error
    pub fn provider<S1: Into<String>, S2: Into<String>>(provider: S1, message: S2) -> Self {
        Self::Provider {
            provider: provider.into(),
            message: message.into()
        }
    }

    /// Create an authentication error
    pub fn authentication<S1: Into<String>, S2: Into<String>>(provider: S1, message: S2) -> Self {
        Self::Authentication {
            provider: provider.into(),
            message: message.into()
        }
    }

    /// Create a rate limit error
    pub fn rate_limit<S: Into<String>>(provider: S, retry_after: Option<Duration>) -> Self {
        Self::RateLimit { 
            provider: provider.into(), 
            retry_after 
        }
    }

    /// Create a network error
    pub fn network<S: Into<String>>(message: S) -> Self {
        Self::Network { message: message.into() }
    }

    /// Create an invalid request error
    pub fn invalid_request<S: Into<String>>(message: S) -> Self {
        Self::InvalidRequest { message: message.into() }
    }

    /// Create a response parsing error
    pub fn response_parsing<S: Into<String>>(message: S) -> Self {
        Self::ResponseParsing { message: message.into() }
    }

    /// Create a model unavailable error
    pub fn model_unavailable<S1: Into<String>, S2: Into<String>>(model: S1, provider: S2) -> Self {
        Self::ModelUnavailable {
            model: model.into(),
            provider: provider.into()
        }
    }

    /// Create a feature not supported error
    pub fn feature_not_supported<S1: Into<String>, S2: Into<String>>(feature: S1, provider: S2) -> Self {
        Self::FeatureNotSupported {
            feature: feature.into(),
            provider: provider.into()
        }
    }

    /// Create a token limit exceeded error
    pub fn token_limit_exceeded(requested: usize, limit: usize) -> Self {
        Self::TokenLimitExceeded { requested, limit }
    }

    /// Create a cache error
    pub fn cache<S: Into<String>>(message: S) -> Self {
        Self::Cache { message: message.into() }
    }

    /// Create a timeout error
    pub fn timeout(duration: Duration) -> Self {
        Self::Timeout { duration }
    }

    /// Create an internal error
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal { message: message.into() }
    }

    /// Check if the error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(self, 
            AIError::Network { .. } |
            AIError::RateLimit { .. } |
            AIError::Timeout { .. } |
            AIError::Internal { .. }
        )
    }

    /// Get retry delay for retryable errors
    pub fn retry_delay(&self) -> Option<Duration> {
        match self {
            AIError::RateLimit { retry_after, .. } => *retry_after,
            AIError::Network { .. } => Some(Duration::from_secs(1)),
            AIError::Timeout { .. } => Some(Duration::from_millis(500)),
            AIError::Internal { .. } => Some(Duration::from_secs(2)),
            _ => None,
        }
    }
}
