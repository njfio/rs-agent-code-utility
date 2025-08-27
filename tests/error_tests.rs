use rust_tree_sitter::Error;
use rust_tree_sitter::error::QueryErrorType;
use std::path::PathBuf;

/// Test language error creation
#[test]
fn test_language_error() {
    let error = Error::language_error("Rust", "parsing");
    
    match &error {
        Error::LanguageError { details } => {
            assert_eq!(details.language_name, "Rust");
            assert_eq!(details.operation, "parsing");
            assert!(details.underlying_error.is_none());
        }
        _ => panic!("Expected LanguageError"),
    }

    // Test error display
    let error_string = format!("{}", error);
    assert!(error_string.contains("Rust"));
    assert!(error_string.contains("parsing"));
}

/// Test language error with cause
#[test]
fn test_language_error_with_cause() {
    let error = Error::language_error_with_cause("Python", "initialization", "library not found");
    
    match &error {
        Error::LanguageError { details } => {
            assert_eq!(details.language_name, "Python");
            assert_eq!(details.operation, "initialization");
            assert_eq!(details.underlying_error, Some("library not found".to_string()));
        }
        _ => panic!("Expected LanguageError"),
    }

    let error_string = format!("{}", error);
    assert!(error_string.contains("Python"));
    assert!(error_string.contains("initialization"));
    assert!(error_string.contains("library not found"));
}

/// Test parse error creation
#[test]
fn test_parse_error() {
    let error = Error::parse_error("syntax error");
    
    match error {
        Error::ParseError { details } => {
            assert_eq!(details.error_kind, "syntax error");
            assert!(details.file_path.is_none());
            assert!(details.line.is_none());
            assert!(details.column.is_none());
            assert!(details.source_snippet.is_none());
        }
        _ => panic!("Expected ParseError"),
    }
}

/// Test parse error with location
#[test]
fn test_parse_error_with_location() {
    let file_path = PathBuf::from("test.rs");
    let error = Error::parse_error_with_location(
        Some(file_path.clone()),
        Some(10),
        Some(5),
        "unexpected token",
        Some("let x = ;".to_string()),
    );
    
    match error {
        Error::ParseError { details } => {
            assert_eq!(details.file_path, Some(file_path));
            assert_eq!(details.line, Some(10));
            assert_eq!(details.column, Some(5));
            assert_eq!(details.error_kind, "unexpected token");
            assert_eq!(details.source_snippet, Some("let x = ;".to_string()));
        }
        _ => panic!("Expected ParseError"),
    }
}

/// Test query error creation
#[test]
fn test_query_error() {
    let error = Error::query_error("(function_item)", "Rust", QueryErrorType::SyntaxError);
    
    match error {
        Error::QueryError { details } => {
            assert_eq!(details.pattern, "(function_item)");
            assert_eq!(details.language, "Rust");
            assert_eq!(details.error_type, QueryErrorType::SyntaxError);
            assert!(details.position.is_none());
            // QueryErrorDetails doesn't have a suggestion field
        }
        _ => panic!("Expected QueryError"),
    }
}

/// Test query error with position
#[test]
fn test_query_error_with_position() {
    let error = Error::query_error_with_position(
        "(invalid_pattern",
        "JavaScript",
        QueryErrorType::SyntaxError,
        15, // position as usize, not tuple
    );
    
    match error {
        Error::QueryError { details } => {
            assert_eq!(details.pattern, "(invalid_pattern");
            assert_eq!(details.language, "JavaScript");
            assert_eq!(details.error_type, QueryErrorType::SyntaxError);
            assert_eq!(details.position, Some(15));
            // QueryErrorDetails doesn't have a suggestion field
        }
        _ => panic!("Expected QueryError"),
    }
}

/// Test tree error creation
#[test]
fn test_tree_error() {
    let error = Error::tree_error("navigation");
    
    match error {
        Error::TreeError { details } => {
            assert_eq!(details.operation, "navigation");
            assert!(details.context.is_none());
        }
        _ => panic!("Expected TreeError"),
    }
}

/// Test tree error with context
#[test]
fn test_tree_error_with_context() {
    let error = Error::tree_error_with_context(
        "node access",
        Some("function_item".to_string()),
        Some((5, 10)),
        Some("Node not found at position".to_string()),
    );
    
    match error {
        Error::TreeError { details } => {
            assert_eq!(details.operation, "node access");
            assert_eq!(details.context, Some("Node not found at position".to_string()));
        }
        _ => panic!("Expected TreeError"),
    }
}

/// Test invalid input error
#[test]
fn test_invalid_input_error() {
    let error = Error::invalid_input_error("file path", "existing file", "/nonexistent/path");
    
    match error {
        Error::InvalidInput { details } => {
            assert_eq!(details.input_type, "file path");
            assert_eq!(details.expected, "existing file");
            assert_eq!(details.actual, "/nonexistent/path");
            assert!(details.suggestion.is_none());
        }
        _ => panic!("Expected InvalidInput"),
    }
}

/// Test invalid input error with suggestion
#[test]
fn test_invalid_input_with_suggestion() {
    let error = Error::invalid_input_with_suggestion(
        "language",
        "supported language",
        "unknown_lang",
        "Try 'rust', 'python', or 'javascript'",
    );
    
    match error {
        Error::InvalidInput { details } => {
            assert_eq!(details.input_type, "language");
            assert_eq!(details.expected, "supported language");
            assert_eq!(details.actual, "unknown_lang");
            assert_eq!(details.suggestion, Some("Try 'rust', 'python', or 'javascript'".to_string()));
        }
        _ => panic!("Expected InvalidInput"),
    }
}

/// Test not supported error
#[test]
fn test_not_supported_error() {
    let error = Error::not_supported_error("advanced feature", "not implemented yet");
    
    match error {
        Error::NotSupported { feature, reason, alternative } => {
            assert_eq!(feature, "advanced feature");
            assert_eq!(reason, "not implemented yet");
            assert!(alternative.is_none());
        }
        _ => panic!("Expected NotSupported"),
    }
}

/// Test not supported error with alternative
#[test]
fn test_not_supported_with_alternative() {
    let error = Error::not_supported_with_alternative(
        "feature X",
        "deprecated",
        "use feature Y instead",
    );
    
    match error {
        Error::NotSupported { feature, reason, alternative } => {
            assert_eq!(feature, "feature X");
            assert_eq!(reason, "deprecated");
            assert_eq!(alternative, Some("use feature Y instead".to_string()));
        }
        _ => panic!("Expected NotSupported"),
    }
}

/// Test internal error
#[test]
fn test_internal_error() {
    let error = Error::internal_error("parser", "unexpected state");
    
    match error {
        Error::Internal { component, message, context } => {
            assert_eq!(component, "parser");
            assert_eq!(message, "unexpected state");
            assert!(context.is_none());
        }
        _ => panic!("Expected Internal"),
    }
}

/// Test internal error with context
#[test]
fn test_internal_error_with_context() {
    let error = Error::internal_error_with_context(
        "analyzer",
        "failed to process",
        "while analyzing file.rs",
    );
    
    match error {
        Error::Internal { component, message, context } => {
            assert_eq!(component, "analyzer");
            assert_eq!(message, "failed to process");
            assert_eq!(context, Some("while analyzing file.rs".to_string()));
        }
        _ => panic!("Expected Internal"),
    }
}

/// Test error conversion from std::io::Error
#[test]
fn test_io_error_conversion() {
    let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let error: Error = io_error.into();
    
    match error {
        Error::IoError(_) => {
            // Success - converted correctly
        }
        _ => panic!("Expected IoError"),
    }
}

/// Test error conversion from UTF-8 error
#[test]
fn test_utf8_error_conversion() {
    let invalid_utf8 = &[0xFF, 0xFE, 0xFD]; // Invalid UTF-8 bytes
    let utf8_error = std::str::from_utf8(invalid_utf8).unwrap_err();
    let error: Error = utf8_error.into();
    
    match error {
        Error::Utf8Error(_) => {
            // Success - converted correctly
        }
        _ => panic!("Expected Utf8Error"),
    }
}
