# Rust Tree-Sitter Style Guide and Best Practices

## Overview

This document outlines the coding standards, style guidelines, and best practices for the rust-tree-sitter project. Following these guidelines ensures consistency, maintainability, and high code quality.

## Code Style

### Naming Conventions

**Functions and Variables**
```rust
// ✅ Good: snake_case for functions and variables
fn analyze_complexity(source_code: &str) -> Result<ComplexityMetrics>
let file_path = PathBuf::from("src/main.rs");
```

**Types and Structs**
```rust
// ✅ Good: PascalCase for types
struct CodebaseAnalyzer {
    config: AnalysisConfig,
}

enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}
```

**Constants**
```rust
// ✅ Good: SCREAMING_SNAKE_CASE for constants
const MAX_FILE_SIZE: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
```

**Modules**
```rust
// ✅ Good: snake_case for modules
mod complexity_analysis;
mod security_scanner;
```

### Documentation Standards

**Module Documentation**
```rust
//! Code complexity analysis module
//!
//! This module provides functionality for analyzing code complexity using
//! various metrics including cyclomatic complexity, cognitive complexity,
//! and Halstead metrics.

/// Analyzes code complexity for a given syntax tree
/// 
/// # Arguments
/// 
/// * `tree` - The syntax tree to analyze
/// * `language` - The programming language of the code
/// 
/// # Returns
/// 
/// Returns `ComplexityMetrics` containing various complexity measurements
/// 
/// # Errors
/// 
/// Returns an error if the syntax tree is invalid or analysis fails
/// 
/// # Examples
/// 
/// ```rust
/// use rust_tree_sitter::{Parser, ComplexityAnalyzer, Language};
/// 
/// let parser = Parser::new(Language::Rust)?;
/// let tree = parser.parse("fn main() {}", None)?;
/// let analyzer = ComplexityAnalyzer::new("rust");
/// let metrics = analyzer.analyze_complexity(&tree)?;
/// ```
pub fn analyze_complexity(tree: &SyntaxTree, language: &str) -> Result<ComplexityMetrics>
```

**Error Documentation**
```rust
/// Errors that can occur during code analysis
#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    /// Parse error occurred while processing source code
    #[error("Parse error: {message} at line {line}")]
    ParseError { message: String, line: usize },
    
    /// I/O error occurred while reading files
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}
```

### Error Handling Patterns

**Consistent Error Types**
```rust
// ✅ Good: Use project-specific Result type
type Result<T> = std::result::Result<T, Error>;

// ✅ Good: Proper error context
fn read_config_file(path: &Path) -> Result<Config> {
    let content = fs::read_to_string(path)
        .map_err(|e| Error::ConfigError(format!("Failed to read {}: {}", path.display(), e)))?;
    
    serde_json::from_str(&content)
        .map_err(|e| Error::ConfigError(format!("Invalid JSON in {}: {}", path.display(), e)))
}
```

**Error Propagation**
```rust
// ✅ Good: Use ? operator for error propagation
fn analyze_file(path: &Path) -> Result<FileAnalysis> {
    let content = fs::read_to_string(path)?;
    let tree = parse_content(&content)?;
    let analysis = perform_analysis(&tree)?;
    Ok(analysis)
}
```

### Performance Best Practices

**Collection Pre-allocation**
```rust
// ✅ Good: Pre-allocate when size is known
let mut results = Vec::with_capacity(files.len());
let mut symbol_map = HashMap::with_capacity(expected_symbols);

// ✅ Good: Use iterators instead of collecting
files.iter()
    .filter(|f| f.is_rust_file())
    .map(|f| analyze_file(f))
    .collect::<Result<Vec<_>>>()?
```

**String Handling**
```rust
// ✅ Good: Use &str when possible
fn process_identifier(name: &str) -> bool {
    name.starts_with("test_")
}

// ✅ Good: Use Cow for conditional ownership
use std::borrow::Cow;

fn normalize_path(path: &str) -> Cow<str> {
    if path.contains('\\') {
        Cow::Owned(path.replace('\\', "/"))
    } else {
        Cow::Borrowed(path)
    }
}
```

**Memory Management**
```rust
// ✅ Good: Use appropriate smart pointers
use std::sync::Arc;
use std::rc::Rc;

// For shared immutable data across threads
let shared_config = Arc::new(config);

// For shared immutable data within single thread
let shared_data = Rc::new(expensive_computation());
```

### Concurrency Patterns

**Thread Safety**
```rust
// ✅ Good: Use appropriate synchronization primitives
use std::sync::{Arc, Mutex, RwLock};
use rayon::prelude::*;

// For shared mutable state
let cache = Arc::new(Mutex::new(HashMap::new()));

// For read-heavy workloads
let symbol_table = Arc::new(RwLock::new(SymbolTable::new()));

// For parallel processing
files.par_iter()
    .map(|file| analyze_file(file))
    .collect::<Vec<_>>()
```

### Testing Standards

**Unit Test Structure**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_complexity_analysis_simple_function() -> Result<()> {
        // Arrange
        let source = "fn simple() { println!(\"hello\"); }";
        let parser = Parser::new(Language::Rust)?;
        let tree = parser.parse(source, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        
        // Act
        let metrics = analyzer.analyze_complexity(&tree)?;
        
        // Assert
        assert_eq!(metrics.cyclomatic_complexity, 1);
        assert!(metrics.cognitive_complexity <= 1);
        
        Ok(())
    }
    
    #[test]
    fn test_error_handling() {
        // Test error conditions
        let result = analyze_invalid_syntax("invalid rust code");
        assert!(result.is_err());
        
        match result.unwrap_err() {
            Error::ParseError(msg) => assert!(msg.contains("syntax error")),
            _ => panic!("Expected ParseError"),
        }
    }
}
```

**Integration Test Patterns**
```rust
// tests/integration_test.rs
use rust_tree_sitter::*;
use tempfile::TempDir;

#[test]
fn test_full_analysis_workflow() -> Result<()> {
    // Create temporary test project
    let temp_dir = TempDir::new()?;
    create_test_project(&temp_dir)?;
    
    // Run full analysis
    let mut analyzer = CodebaseAnalyzer::new()?;
    let result = analyzer.analyze_directory(temp_dir.path())?;
    
    // Verify results
    assert!(result.total_files > 0);
    assert!(result.parsed_files == result.total_files);
    
    Ok(())
}
```

### API Design Principles

**Builder Pattern**
```rust
// ✅ Good: Use builder pattern for complex configuration
pub struct AnalysisConfigBuilder {
    config: AnalysisConfig,
}

impl AnalysisConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: AnalysisConfig::default(),
        }
    }
    
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.config.max_depth = Some(depth);
        self
    }
    
    pub fn enable_security(mut self, enabled: bool) -> Self {
        self.config.enable_security = enabled;
        self
    }
    
    pub fn build(self) -> AnalysisConfig {
        self.config
    }
}
```

**Fluent Interfaces**
```rust
// ✅ Good: Chainable methods
let query = QueryBuilder::new()
    .pattern("(function_item)")
    .language(Language::Rust)
    .case_sensitive(true)
    .build()?;
```

### Security Best Practices

**Input Validation**
```rust
// ✅ Good: Validate inputs
fn analyze_file_with_size_limit(path: &Path, max_size: usize) -> Result<Analysis> {
    let metadata = fs::metadata(path)?;
    
    if metadata.len() > max_size as u64 {
        return Err(Error::FileTooLarge {
            path: path.to_path_buf(),
            size: metadata.len(),
            limit: max_size as u64,
        });
    }
    
    // Proceed with analysis
    analyze_file(path)
}
```

**Safe Defaults**
```rust
// ✅ Good: Secure defaults
impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_secrets_detection: true,
            enable_vulnerability_scanning: true,
            min_confidence: 0.8, // High confidence threshold
            max_findings_per_category: 100, // Prevent DoS
        }
    }
}
```

## Code Organization

### Module Structure
```
src/
├── lib.rs              # Public API exports
├── error.rs            # Error types
├── analyzer/           # Core analysis functionality
│   ├── mod.rs
│   ├── codebase.rs
│   └── file.rs
├── security/           # Security analysis
│   ├── mod.rs
│   ├── scanner.rs
│   └── vulnerabilities.rs
└── utils/              # Utility functions
    ├── mod.rs
    └── helpers.rs
```

### Dependency Management
```rust
// ✅ Good: Group related imports
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

// ✅ Good: Separate external crates
use serde::{Deserialize, Serialize};
use tree_sitter::{Language, Parser};

// ✅ Good: Project imports last
use crate::error::{Error, Result};
use crate::languages::Language;
```

## Performance Guidelines

### Algorithmic Complexity
- Document time and space complexity for non-trivial algorithms
- Prefer O(n log n) over O(n²) algorithms where possible
- Use appropriate data structures (HashMap for lookups, Vec for sequences)

### Memory Usage
- Pre-allocate collections when size is known
- Use string slices (&str) instead of owned strings when possible
- Consider using `Box<str>` for immutable strings
- Implement `Drop` for custom cleanup when needed

### I/O Operations
- Use buffered I/O for large files
- Consider memory-mapped files for very large inputs
- Implement streaming for processing large datasets

## Conclusion

Following these guidelines ensures that the rust-tree-sitter codebase remains:
- **Consistent**: Uniform style across all modules
- **Maintainable**: Clear structure and documentation
- **Performant**: Efficient algorithms and memory usage
- **Safe**: Robust error handling and input validation
- **Testable**: Comprehensive test coverage

All contributors should familiarize themselves with these guidelines and apply them consistently in their code contributions.
