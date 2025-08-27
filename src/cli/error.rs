//! CLI error handling module
//! 
//! Provides structured error types for CLI operations with user-friendly messages.

use std::fmt;

/// CLI-specific error types
#[derive(Debug)]
pub enum CliError {
    /// Analysis operation failed
    Analysis(String),
    /// Query operation failed
    Query(String),
    /// Security scan failed
    Security(String),
    /// Refactoring analysis failed
    Refactoring(String),
    /// Dependency analysis failed
    Dependencies(String),
    /// File I/O error
    Io(std::io::Error),
    /// JSON serialization/deserialization error
    Json(serde_json::Error),
    /// Invalid configuration
    Config(String),
    /// Invalid command arguments
    InvalidArgs(String),
    /// Path does not exist or is not accessible
    InvalidPath(std::path::PathBuf),
    /// Unsupported format
    UnsupportedFormat(String),
    /// Language not supported
    UnsupportedLanguage(String),
    /// Invalid language
    InvalidLanguage(String),
    /// IO error (alternative)
    IoError(std::io::Error),
    /// Serialization error (alternative)
    SerializationError(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Analysis(msg) => write!(f, "Analysis error: {}", msg),
            CliError::Query(msg) => write!(f, "Query error: {}", msg),
            CliError::Security(msg) => write!(f, "Security scan error: {}", msg),
            CliError::Refactoring(msg) => write!(f, "Refactoring analysis error: {}", msg),
            CliError::Dependencies(msg) => write!(f, "Dependency analysis error: {}", msg),
            CliError::Io(err) => write!(f, "File I/O error: {}", err),
            CliError::Json(err) => write!(f, "JSON error: {}", err),
            CliError::Config(msg) => write!(f, "Configuration error: {}", msg),
            CliError::InvalidArgs(msg) => write!(f, "Invalid arguments: {}", msg),
            CliError::InvalidPath(path) => write!(f, "Invalid path: {}", path.display()),
            CliError::UnsupportedFormat(format) => write!(f, "Unsupported format: {}", format),
            CliError::UnsupportedLanguage(lang) => write!(f, "Unsupported language: {}", lang),
            CliError::InvalidLanguage(lang) => write!(f, "Invalid language: {}", lang),
            CliError::IoError(err) => write!(f, "IO error: {}", err),
            CliError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Io(err) => Some(err),
            CliError::Json(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        CliError::Io(err)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(err: serde_json::Error) -> Self {
        CliError::Json(err)
    }
}

impl From<Box<dyn std::error::Error>> for CliError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        CliError::Analysis(err.to_string())
    }
}

impl From<crate::error::Error> for CliError {
    fn from(err: crate::error::Error) -> Self {
        CliError::Analysis(err.to_string())
    }
}

impl From<String> for CliError {
    fn from(err: String) -> Self {
        CliError::Analysis(err)
    }
}

/// Result type for CLI operations
pub type CliResult<T> = Result<T, CliError>;

/// Helper function to validate path exists and is accessible
pub fn validate_path(path: &std::path::Path) -> CliResult<()> {
    if !path.exists() {
        return Err(CliError::InvalidPath(path.to_path_buf()));
    }
    
    // Check if we can read the path
    if path.is_dir() {
        std::fs::read_dir(path)
            .map_err(CliError::Io)?
            .next(); // Just check if we can start reading
    } else {
        std::fs::File::open(path)
            .map_err(CliError::Io)?;
    }
    
    Ok(())
}

/// Helper function to validate output format
pub fn validate_format(format: &str, valid_formats: &[&str]) -> CliResult<()> {
    if !valid_formats.contains(&format) {
        return Err(CliError::UnsupportedFormat(format.to_string()));
    }
    Ok(())
}

/// Helper function to validate language
pub fn validate_language(language: &str) -> CliResult<()> {
    use crate::supported_languages;
    
    let supported = supported_languages();
    if !supported.iter().any(|lang| lang.name.to_lowercase() == language.to_lowercase()) {
        return Err(CliError::UnsupportedLanguage(language.to_string()));
    }
    Ok(())
}
