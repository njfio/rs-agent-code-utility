//! Infrastructure module for real production-grade functionality
//!
//! This module provides the foundation for converting mock implementations
//! into fully functional, tested, and validated professional code.

pub mod cache;
pub mod config;
#[cfg(feature = "db")]
pub mod database;
#[cfg(feature = "net")]
pub mod http_client;
#[cfg(feature = "net")]
pub mod rate_limiter;

pub use cache::{Cache, CacheConfig, CacheEntry, CacheStats};
pub use config::{
    AnalysisConfig, ApiConfig, AppConfig, ConfigManager, DatabaseConfig, LoggingConfig,
};
#[cfg(feature = "db")]
pub use database::{
    AnalysisCacheEntry, DatabaseManager, DatabaseStats, SecretPattern, VulnerabilityRecord,
};
#[cfg(feature = "net")]
#[cfg(feature = "net")]
pub use http_client::{AuthConfig, HttpClient, HttpResponse, RateLimiter, RequestConfig};
#[cfg(feature = "net")]
pub use rate_limiter::{
    MultiServiceRateLimiter, RateLimitConfig, RateLimitResult, RateLimitStats, ServiceRateLimiter,
};
