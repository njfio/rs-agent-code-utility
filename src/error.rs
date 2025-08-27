//! Error types for the rust_tree_sitter library

use thiserror::Error;
use std::path::PathBuf;

/// Result type alias for this library
pub type Result<T> = std::result::Result<T, Error>;

/// Language-specific error details
#[derive(Debug, Clone)]
pub struct LanguageErrorDetails {
    pub language_name: String,
    pub operation: String,
    pub underlying_error: Option<String>,
}

/// Parse error details with location information
#[derive(Debug, Clone)]
pub struct ParseErrorDetails {
    pub file_path: Option<PathBuf>,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub error_kind: String,
    pub source_snippet: Option<String>,
}

/// Query error details with pattern information
#[derive(Debug, Clone)]
pub struct QueryErrorDetails {
    pub pattern: String,
    pub language: String,
    pub error_type: QueryErrorType,
    pub position: Option<usize>,
}

/// Types of query errors
#[derive(Debug, Clone, PartialEq)]
pub enum QueryErrorType {
    SyntaxError,
    CompilationError,
    ExecutionError,
    InvalidCapture,
    UnsupportedFeature,
}

/// Tree manipulation error details
#[derive(Debug, Clone)]
pub struct TreeErrorDetails {
    pub operation: String,
    pub node_kind: Option<String>,
    pub position: Option<(usize, usize)>,
    pub context: Option<String>,
}

/// Input validation error details
#[derive(Debug, Clone)]
pub struct InvalidInputDetails {
    pub input_type: String,
    pub expected: String,
    pub actual: String,
    pub suggestion: Option<String>,
}

/// Main error type for the library
#[derive(Error, Debug)]
pub enum Error {
    /// Error setting the language on a parser
    #[error("Language error in {operation} for {language_name}: {underlying_error}",
            operation = details.operation,
            language_name = details.language_name,
            underlying_error = details.underlying_error.as_ref().unwrap_or(&"Unknown error".to_string()))]
    LanguageError {
        details: LanguageErrorDetails,
    },

    /// Error during parsing with location information
    #[error("Parse error{location}: {error_kind}",
            location = details.file_path.as_ref().map(|p| format!(" in {}", p.display())).unwrap_or_default(),
            error_kind = details.error_kind)]
    ParseError {
        details: ParseErrorDetails,
    },

    /// Error with query compilation or execution
    #[error("Query error in {language}: {error_type:?} in pattern '{pattern}'",
            language = details.language,
            error_type = details.error_type,
            pattern = details.pattern)]
    QueryError {
        details: QueryErrorDetails,
    },

    /// Error with tree navigation or manipulation
    #[error("Tree error during {operation}: {context}",
            operation = details.operation,
            context = details.context.as_ref().unwrap_or(&"No additional context".to_string()))]
    TreeError {
        details: TreeErrorDetails,
    },

    /// IO error when reading files
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// UTF-8 encoding error
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    /// Invalid input provided to the library
    #[error("Invalid {input_type}: expected {expected}, got {actual}",
            input_type = details.input_type,
            expected = details.expected,
            actual = details.actual)]
    InvalidInput {
        details: InvalidInputDetails,
    },

    /// Feature not supported
    #[error("Feature not supported: {feature} (reason: {reason})")]
    NotSupported {
        feature: String,
        reason: String,
        alternative: Option<String>,
    },

    /// Internal library error
    #[error("Internal error in {component}: {message}")]
    Internal {
        component: String,
        message: String,
        context: Option<String>,
    },

    /// CLI operation error
    #[error("CLI error: {message}")]
    CliError {
        message: String,
        operation: Option<String>,
        suggestion: Option<String>,
    },

    /// Configuration error
    #[error("Configuration error: {message}")]
    ConfigError {
        message: String,
        config_path: Option<PathBuf>,
        field: Option<String>,
    },

    /// Network error for AI services
    #[error("Network error: {message}")]
    NetworkError {
        message: String,
        url: Option<String>,
        status_code: Option<u16>,
    },

    /// Authentication error for AI services
    #[error("Authentication error: {message}")]
    AuthenticationError {
        message: String,
        provider: Option<String>,
    },

    /// Rate limiting error
    #[error("Rate limit exceeded: {message}")]
    RateLimitError {
        message: String,
        retry_after: Option<u64>,
    },

    /// Timeout error
    #[error("Operation timed out: {operation} after {duration_ms}ms")]
    TimeoutError {
        operation: String,
        duration_ms: u64,
    },

    /// Resource exhaustion error
    #[error("Resource exhausted: {resource} - {message}")]
    ResourceExhausted {
        resource: String,
        message: String,
        current_usage: Option<String>,
        limit: Option<String>,
    },

    /// Validation error with detailed context
    #[error("Validation failed: {message}")]
    ValidationError {
        message: String,
        field: Option<String>,
        expected_format: Option<String>,
        actual_value: Option<String>,
    },

    /// Dependency error
    #[error("Dependency error: {dependency} - {message}")]
    DependencyError {
        dependency: String,
        message: String,
        version_required: Option<String>,
        version_found: Option<String>,
    },

    /// Security error
    #[error("Security error: {message}")]
    SecurityError {
        message: String,
        vulnerability_type: Option<String>,
        severity: Option<String>,
        file_path: Option<PathBuf>,
        line_number: Option<usize>,
    },

    /// Analysis error
    #[error("Analysis error in {component}: {message}")]
    AnalysisError {
        component: String,
        message: String,
        file_path: Option<PathBuf>,
        context: Option<String>,
    },

    /// Anyhow error (for external libraries)
    #[error("External error: {0}")]
    Anyhow(#[from] anyhow::Error),
}

impl Error {
    /// Create a new language error with structured details
    pub fn language_error(language_name: impl Into<String>, operation: impl Into<String>) -> Self {
        Self::LanguageError {
            details: LanguageErrorDetails {
                language_name: language_name.into(),
                operation: operation.into(),
                underlying_error: None,
            },
        }
    }

    /// Create a language error with underlying error details
    pub fn language_error_with_cause(
        language_name: impl Into<String>,
        operation: impl Into<String>,
        cause: impl Into<String>
    ) -> Self {
        Self::LanguageError {
            details: LanguageErrorDetails {
                language_name: language_name.into(),
                operation: operation.into(),
                underlying_error: Some(cause.into()),
            },
        }
    }

    /// Create a new parse error with location information
    pub fn parse_error(error_kind: impl Into<String>) -> Self {
        Self::ParseError {
            details: ParseErrorDetails {
                file_path: None,
                line: None,
                column: None,
                error_kind: error_kind.into(),
                source_snippet: None,
            },
        }
    }

    /// Create a parse error with file and location information
    pub fn parse_error_with_location(
        file_path: Option<PathBuf>,
        line: Option<usize>,
        column: Option<usize>,
        error_kind: impl Into<String>,
        source_snippet: Option<String>,
    ) -> Self {
        Self::ParseError {
            details: ParseErrorDetails {
                file_path,
                line,
                column,
                error_kind: error_kind.into(),
                source_snippet,
            },
        }
    }

    /// Create a new query error
    pub fn query_error(
        pattern: impl Into<String>,
        language: impl Into<String>,
        error_type: QueryErrorType,
    ) -> Self {
        Self::QueryError {
            details: QueryErrorDetails {
                pattern: pattern.into(),
                language: language.into(),
                error_type,
                position: None,
            },
        }
    }

    /// Create a query error with position information
    pub fn query_error_with_position(
        pattern: impl Into<String>,
        language: impl Into<String>,
        error_type: QueryErrorType,
        position: usize,
    ) -> Self {
        Self::QueryError {
            details: QueryErrorDetails {
                pattern: pattern.into(),
                language: language.into(),
                error_type,
                position: Some(position),
            },
        }
    }

    /// Create a new tree error
    pub fn tree_error(operation: impl Into<String>) -> Self {
        Self::TreeError {
            details: TreeErrorDetails {
                operation: operation.into(),
                node_kind: None,
                position: None,
                context: None,
            },
        }
    }

    /// Create a tree error with context
    pub fn tree_error_with_context(
        operation: impl Into<String>,
        node_kind: Option<String>,
        position: Option<(usize, usize)>,
        context: Option<String>,
    ) -> Self {
        Self::TreeError {
            details: TreeErrorDetails {
                operation: operation.into(),
                node_kind,
                position,
                context,
            },
        }
    }

    /// Create a new invalid input error
    pub fn invalid_input_error(
        input_type: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::InvalidInput {
            details: InvalidInputDetails {
                input_type: input_type.into(),
                expected: expected.into(),
                actual: actual.into(),
                suggestion: None,
            },
        }
    }

    /// Create an invalid input error with suggestion
    pub fn invalid_input_with_suggestion(
        input_type: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self::InvalidInput {
            details: InvalidInputDetails {
                input_type: input_type.into(),
                expected: expected.into(),
                actual: actual.into(),
                suggestion: Some(suggestion.into()),
            },
        }
    }

    /// Create a new not supported error
    pub fn not_supported_error(
        feature: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::NotSupported {
            feature: feature.into(),
            reason: reason.into(),
            alternative: None,
        }
    }

    /// Create a not supported error with alternative
    pub fn not_supported_with_alternative(
        feature: impl Into<String>,
        reason: impl Into<String>,
        alternative: impl Into<String>,
    ) -> Self {
        Self::NotSupported {
            feature: feature.into(),
            reason: reason.into(),
            alternative: Some(alternative.into()),
        }
    }

    /// Create a new internal error
    pub fn internal_error(
        component: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::Internal {
            component: component.into(),
            message: message.into(),
            context: None,
        }
    }

    /// Create an internal error with context
    pub fn internal_error_with_context(
        component: impl Into<String>,
        message: impl Into<String>,
        context: impl Into<String>,
    ) -> Self {
        Self::Internal {
            component: component.into(),
            message: message.into(),
            context: Some(context.into()),
        }
    }

    /// Create a CLI error
    pub fn cli_error(message: impl Into<String>) -> Self {
        Self::CliError {
            message: message.into(),
            operation: None,
            suggestion: None,
        }
    }

    /// Create a CLI error with operation context and suggestion
    pub fn cli_error_with_suggestion(
        message: impl Into<String>,
        operation: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self::CliError {
            message: message.into(),
            operation: Some(operation.into()),
            suggestion: Some(suggestion.into()),
        }
    }

    // Backward compatibility methods (deprecated)
    #[deprecated(note = "Use language_error instead")]
    pub fn language<S: Into<String>>(msg: S) -> Self {
        Self::language_error("unknown", msg)
    }

    #[deprecated(note = "Use parse_error instead")]
    pub fn parse<S: Into<String>>(msg: S) -> Self {
        Self::parse_error(msg)
    }

    #[deprecated(note = "Use query_error instead")]
    pub fn query<S: Into<String>>(msg: S) -> Self {
        Self::query_error(msg, "unknown", QueryErrorType::SyntaxError)
    }

    #[deprecated(note = "Use tree_error instead")]
    pub fn tree<S: Into<String>>(msg: S) -> Self {
        Self::tree_error(msg)
    }

    #[deprecated(note = "Use invalid_input_error instead")]
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        Self::invalid_input_error("input", "valid input", msg)
    }

    #[deprecated(note = "Use not_supported_error instead")]
    pub fn not_supported<S: Into<String>>(msg: S) -> Self {
        Self::not_supported_error(msg, "not implemented")
    }

    #[deprecated(note = "Use internal_error instead")]
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        Self::internal_error("unknown", msg)
    }

    /// Create a configuration error
    pub fn config_error(message: impl Into<String>) -> Self {
        Self::ConfigError {
            message: message.into(),
            config_path: None,
            field: None,
        }
    }

    /// Create a configuration error with file path and field context
    pub fn config_error_with_context(
        message: impl Into<String>,
        config_path: Option<PathBuf>,
        field: Option<String>,
    ) -> Self {
        Self::ConfigError {
            message: message.into(),
            config_path,
            field,
        }
    }

    /// Create a network error
    pub fn network_error(message: impl Into<String>) -> Self {
        Self::NetworkError {
            message: message.into(),
            url: None,
            status_code: None,
        }
    }

    /// Create a network error with URL and status code
    pub fn network_error_with_details(
        message: impl Into<String>,
        url: Option<String>,
        status_code: Option<u16>,
    ) -> Self {
        Self::NetworkError {
            message: message.into(),
            url,
            status_code,
        }
    }

    /// Create an authentication error
    pub fn auth_error(message: impl Into<String>) -> Self {
        Self::AuthenticationError {
            message: message.into(),
            provider: None,
        }
    }

    /// Create an authentication error with provider context
    pub fn auth_error_with_provider(
        message: impl Into<String>,
        provider: impl Into<String>,
    ) -> Self {
        Self::AuthenticationError {
            message: message.into(),
            provider: Some(provider.into()),
        }
    }

    /// Create a rate limit error
    pub fn rate_limit_error(message: impl Into<String>) -> Self {
        Self::RateLimitError {
            message: message.into(),
            retry_after: None,
        }
    }

    /// Create a rate limit error with retry information
    pub fn rate_limit_error_with_retry(
        message: impl Into<String>,
        retry_after_seconds: u64,
    ) -> Self {
        Self::RateLimitError {
            message: message.into(),
            retry_after: Some(retry_after_seconds),
        }
    }

    /// Create a timeout error
    pub fn timeout_error(operation: impl Into<String>, duration_ms: u64) -> Self {
        Self::TimeoutError {
            operation: operation.into(),
            duration_ms,
        }
    }

    /// Create a resource exhaustion error
    pub fn resource_exhausted(resource: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ResourceExhausted {
            resource: resource.into(),
            message: message.into(),
            current_usage: None,
            limit: None,
        }
    }

    /// Create a resource exhaustion error with usage details
    pub fn resource_exhausted_with_details(
        resource: impl Into<String>,
        message: impl Into<String>,
        current_usage: Option<String>,
        limit: Option<String>,
    ) -> Self {
        Self::ResourceExhausted {
            resource: resource.into(),
            message: message.into(),
            current_usage,
            limit,
        }
    }

    /// Create a validation error
    pub fn validation_error(message: impl Into<String>) -> Self {
        Self::ValidationError {
            message: message.into(),
            field: None,
            expected_format: None,
            actual_value: None,
        }
    }

    /// Create a validation error with field context
    pub fn validation_error_with_context(
        message: impl Into<String>,
        field: Option<String>,
        expected_format: Option<String>,
        actual_value: Option<String>,
    ) -> Self {
        Self::ValidationError {
            message: message.into(),
            field,
            expected_format,
            actual_value,
        }
    }

    /// Create a dependency error
    pub fn dependency_error(dependency: impl Into<String>, message: impl Into<String>) -> Self {
        Self::DependencyError {
            dependency: dependency.into(),
            message: message.into(),
            version_required: None,
            version_found: None,
        }
    }

    /// Create a dependency error with version information
    pub fn dependency_error_with_versions(
        dependency: impl Into<String>,
        message: impl Into<String>,
        version_required: Option<String>,
        version_found: Option<String>,
    ) -> Self {
        Self::DependencyError {
            dependency: dependency.into(),
            message: message.into(),
            version_required,
            version_found,
        }
    }

    /// Create a security error
    pub fn security_error(message: impl Into<String>) -> Self {
        Self::SecurityError {
            message: message.into(),
            vulnerability_type: None,
            severity: None,
            file_path: None,
            line_number: None,
        }
    }

    /// Create a security error with vulnerability details
    pub fn security_error_with_details(
        message: impl Into<String>,
        vulnerability_type: Option<String>,
        severity: Option<String>,
        file_path: Option<PathBuf>,
        line_number: Option<usize>,
    ) -> Self {
        Self::SecurityError {
            message: message.into(),
            vulnerability_type,
            severity,
            file_path,
            line_number,
        }
    }

    /// Create an analysis error
    pub fn analysis_error(component: impl Into<String>, message: impl Into<String>) -> Self {
        Self::AnalysisError {
            component: component.into(),
            message: message.into(),
            file_path: None,
            context: None,
        }
    }

    /// Create an analysis error with file and context information
    pub fn analysis_error_with_context(
        component: impl Into<String>,
        message: impl Into<String>,
        file_path: Option<PathBuf>,
        context: Option<String>,
    ) -> Self {
        Self::AnalysisError {
            component: component.into(),
            message: message.into(),
            file_path,
            context,
        }
    }
}

/// Convert tree-sitter language error to our error type
impl From<tree_sitter::LanguageError> for Error {
    fn from(err: tree_sitter::LanguageError) -> Self {
        Self::language_error_with_cause(
            "tree-sitter",
            "language initialization",
            format!("{:?}", err)
        )
    }
}

/// Convert tree-sitter query error to our error type
impl From<tree_sitter::QueryError> for Error {
    fn from(err: tree_sitter::QueryError) -> Self {
        // tree_sitter::QueryError is a struct, not an enum
        // We'll use the debug representation to determine the error type
        let error_str = format!("{:?}", err);
        let error_type = if error_str.contains("syntax") {
            QueryErrorType::SyntaxError
        } else if error_str.contains("node") || error_str.contains("type") {
            QueryErrorType::CompilationError
        } else if error_str.contains("field") || error_str.contains("capture") {
            QueryErrorType::InvalidCapture
        } else {
            QueryErrorType::UnsupportedFeature
        };

        Self::query_error(
            "unknown pattern",
            "tree-sitter",
            error_type
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structured_error_creation() {
        let err = Error::language_error("rust", "parser initialization");
        assert!(matches!(err, Error::LanguageError { .. }));
        assert!(err.to_string().contains("rust"));
        assert!(err.to_string().contains("parser initialization"));

        let err = Error::parse_error("unexpected token");
        assert!(matches!(err, Error::ParseError { .. }));
        assert!(err.to_string().contains("unexpected token"));

        let err = Error::query_error("(function)", "rust", QueryErrorType::SyntaxError);
        assert!(matches!(err, Error::QueryError { .. }));
        assert!(err.to_string().contains("(function)"));
        assert!(err.to_string().contains("rust"));
    }

    #[test]
    fn test_error_with_context() {
        let err = Error::parse_error_with_location(
            Some(PathBuf::from("test.rs")),
            Some(10),
            Some(5),
            "missing semicolon".to_string(),
            Some("let x = 5".to_string()),
        );
        assert!(matches!(err, Error::ParseError { .. }));
        assert!(err.to_string().contains("test.rs"));

        let err = Error::tree_error_with_context(
            "node navigation",
            Some("function_item".to_string()),
            Some((10, 5)),
            Some("attempting to find function name".to_string()),
        );
        assert!(matches!(err, Error::TreeError { .. }));
        assert!(err.to_string().contains("node navigation"));
    }

    #[test]
    fn test_invalid_input_with_suggestion() {
        let err = Error::invalid_input_with_suggestion(
            "language",
            "rust, python, javascript",
            "unknown_lang",
            "try 'rust' instead",
        );
        assert!(matches!(err, Error::InvalidInput { .. }));
        assert!(err.to_string().contains("language"));
        assert!(err.to_string().contains("unknown_lang"));
    }

    #[test]
    fn test_not_supported_with_alternative() {
        let err = Error::not_supported_with_alternative(
            "incremental parsing",
            "not yet implemented",
            "use full parsing instead",
        );
        assert!(matches!(err, Error::NotSupported { .. }));
        assert!(err.to_string().contains("incremental parsing"));
    }

    #[test]
    fn test_internal_error_with_context() {
        let err = Error::internal_error_with_context(
            "parser",
            "mutex lock failed",
            "during concurrent access",
        );
        assert!(matches!(err, Error::Internal { .. }));
        assert!(err.to_string().contains("parser"));
        assert!(err.to_string().contains("mutex lock failed"));
    }

    #[test]
    fn test_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::IoError(_)));
    }

    #[test]
    fn test_backward_compatibility() {
        // Test that deprecated methods still work
        #[allow(deprecated)]
        {
            let err = Error::language("test language error");
            assert!(matches!(err, Error::LanguageError { .. }));

            let err = Error::parse("test parse error");
            assert!(matches!(err, Error::ParseError { .. }));

            let err = Error::query("test query error");
            assert!(matches!(err, Error::QueryError { .. }));
        }
    }
}
