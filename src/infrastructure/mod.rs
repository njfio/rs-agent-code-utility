//! Infrastructure module for real production-grade functionality
//! 
//! This module provides the foundation for converting mock implementations
//! into fully functional, tested, and validated professional code.

pub mod config;
pub mod database;
pub mod http_client;
pub mod cache;
pub mod rate_limiter;

pub use config::{AppConfig, ConfigManager, DatabaseConfig, ApiConfig, AnalysisConfig, LoggingConfig};
pub use database::{DatabaseManager, VulnerabilityRecord, AnalysisCacheEntry, SecretPattern, DatabaseStats};
pub use http_client::{HttpClient, HttpResponse, RequestConfig, AuthConfig, RateLimiter};
pub use cache::{Cache, CacheEntry, CacheStats, CacheConfig};
pub use rate_limiter::{MultiServiceRateLimiter, ServiceRateLimiter, RateLimitConfig, RateLimitResult, RateLimitStats};
