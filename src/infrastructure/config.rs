//! Real configuration management system
//! 
//! Provides environment-based configuration, API key management,
//! and secure configuration handling for production use.

use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};


/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Database configuration
    pub database: DatabaseConfig,
    /// External API configurations
    pub apis: ApiConfig,
    /// Analysis configuration
    pub analysis: AnalysisConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Cache configuration
    pub cache: CacheConfig,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL (SQLite file path)
    pub url: String,
    /// Maximum number of connections
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Enable WAL mode for SQLite
    pub enable_wal: bool,
}

/// External API configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// National Vulnerability Database (NVD) configuration
    pub nvd: NvdConfig,
    /// Open Source Vulnerabilities (OSV) configuration
    pub osv: OsvConfig,
    /// GitHub Security Advisory configuration
    pub github: GitHubConfig,
}

/// NVD API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdConfig {
    /// API base URL
    pub base_url: String,
    /// API key (optional but recommended)
    pub api_key: Option<String>,
    /// Rate limit (requests per minute)
    pub rate_limit: u32,
    /// Request timeout in seconds
    pub timeout: u64,
    /// Enable caching
    pub enable_cache: bool,
    /// Cache TTL in hours
    pub cache_ttl: u64,
}

/// OSV API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvConfig {
    /// API base URL
    pub base_url: String,
    /// Rate limit (requests per minute)
    pub rate_limit: u32,
    /// Request timeout in seconds
    pub timeout: u64,
    /// Enable caching
    pub enable_cache: bool,
}

/// GitHub API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// API base URL
    pub base_url: String,
    /// GitHub token for authenticated requests
    pub token: Option<String>,
    /// Rate limit (requests per hour)
    pub rate_limit: u32,
    /// Request timeout in seconds
    pub timeout: u64,
}

/// Analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Maximum file size to analyze (in bytes)
    pub max_file_size: u64,
    /// Maximum number of files to analyze
    pub max_files: usize,
    /// Enable parallel analysis
    pub enable_parallel: bool,
    /// Number of worker threads
    pub worker_threads: usize,
    /// Analysis timeout in seconds
    pub timeout: u64,
    /// Enable ML-based analysis
    pub enable_ml: bool,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Log format (json, pretty)
    pub format: String,
    /// Enable file logging
    pub enable_file: bool,
    /// Log file path
    pub file_path: Option<PathBuf>,
    /// Enable structured logging
    pub structured: bool,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable in-memory caching
    pub enable_memory: bool,
    /// Memory cache size (number of entries)
    pub memory_size: usize,
    /// Enable disk caching
    pub enable_disk: bool,
    /// Disk cache directory
    pub disk_path: Option<PathBuf>,
    /// Default TTL in seconds
    pub default_ttl: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            database: DatabaseConfig::default(),
            apis: ApiConfig::default(),
            analysis: AnalysisConfig::default(),
            logging: LoggingConfig::default(),
            cache: CacheConfig::default(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("rust_tree_sitter");
        
        Self {
            url: format!("sqlite://{}/database.db", data_dir.display()),
            max_connections: 10,
            connection_timeout: 30,
            enable_wal: true,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            nvd: NvdConfig::default(),
            osv: OsvConfig::default(),
            github: GitHubConfig::default(),
        }
    }
}

impl Default for NvdConfig {
    fn default() -> Self {
        Self {
            base_url: "https://services.nvd.nist.gov/rest/json".to_string(),
            api_key: None,
            rate_limit: 50, // 50 requests per minute without API key
            timeout: 30,
            enable_cache: true,
            cache_ttl: 24, // 24 hours
        }
    }
}

impl Default for OsvConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.osv.dev".to_string(),
            rate_limit: 100,
            timeout: 30,
            enable_cache: true,
        }
    }
}

impl Default for GitHubConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.github.com".to_string(),
            token: None,
            rate_limit: 5000, // 5000 requests per hour with token
            timeout: 30,
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_files: 10000,
            enable_parallel: true,
            worker_threads: num_cpus::get(),
            timeout: 300, // 5 minutes
            enable_ml: false,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
            enable_file: false,
            file_path: None,
            structured: false,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enable_memory: true,
            memory_size: 10000,
            enable_disk: true,
            disk_path: None,
            default_ttl: 3600, // 1 hour
        }
    }
}

/// Configuration manager for loading and managing application configuration
pub struct ConfigManager {
    config: AppConfig,
}

impl ConfigManager {
    /// Load configuration from multiple sources
    pub fn load() -> Result<Self, ConfigError> {
        let mut config_builder = Config::builder()
            // Start with default configuration
            .add_source(Config::try_from(&AppConfig::default())?);

        // Add configuration file if it exists
        let config_file = Self::get_config_file_path();
        if config_file.exists() {
            info!("Loading configuration from: {}", config_file.display());
            config_builder = config_builder.add_source(File::from(config_file));
        } else {
            info!("No configuration file found, using defaults");
        }

        // Add environment variables (with prefix RUST_TREE_SITTER_)
        config_builder = config_builder.add_source(
            Environment::with_prefix("RUST_TREE_SITTER")
                .separator("__")
                .try_parsing(true)
        );

        let config: AppConfig = config_builder.build()?.try_deserialize()?;
        
        // Validate configuration
        Self::validate_config(&config)?;
        
        Ok(Self { config })
    }

    /// Get the configuration
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    /// Get configuration file path
    fn get_config_file_path() -> PathBuf {
        // Check for config file in multiple locations
        let possible_paths = vec![
            PathBuf::from("rust_tree_sitter.toml"),
            PathBuf::from("config/rust_tree_sitter.toml"),
            dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("rust_tree_sitter")
                .join("config.toml"),
        ];

        for path in possible_paths {
            if path.exists() {
                return path;
            }
        }

        // Default path
        PathBuf::from("rust_tree_sitter.toml")
    }

    /// Validate configuration values
    fn validate_config(config: &AppConfig) -> Result<(), ConfigError> {
        // Validate database configuration
        if config.database.max_connections == 0 {
            return Err(ConfigError::Message("Database max_connections must be > 0".to_string()));
        }

        // Validate analysis configuration
        if config.analysis.max_file_size == 0 {
            return Err(ConfigError::Message("Analysis max_file_size must be > 0".to_string()));
        }

        if config.analysis.worker_threads == 0 {
            return Err(ConfigError::Message("Analysis worker_threads must be > 0".to_string()));
        }

        // Validate API rate limits
        if config.apis.nvd.rate_limit == 0 {
            warn!("NVD rate limit is 0, this may cause API errors");
        }

        Ok(())
    }

    /// Create a sample configuration file
    pub fn create_sample_config() -> Result<(), Box<dyn std::error::Error>> {
        let config = AppConfig::default();
        let toml_content = serde_json::to_string_pretty(&config)?;
        
        let config_path = Self::get_config_file_path();
        std::fs::write(&config_path, toml_content)?;
        
        info!("Sample configuration created at: {}", config_path.display());
        Ok(())
    }
}
