//! # Rust Tree-sitter Library
//!
//! A comprehensive Rust library for processing source code using tree-sitter.
//! This library provides high-level abstractions for parsing, navigating, and
//! querying syntax trees across multiple programming languages, with advanced
//! features for code analysis, security scanning, and AI-powered insights.
//!
//! ## Features
//!
//! ### Core Parsing
//! - **Multi-language support**: Parse Rust and additional feature-gated languages
//! - **Incremental parsing**: Efficient re-parsing of modified code sections
//! - **Query system**: Powerful pattern matching with Tree-sitter queries
//! - **Error recovery**: Robust parsing with detailed error reporting and recovery
//! - **Thread-safe**: Safe concurrent access to parsers and trees
//! - **Memory-efficient**: Optimized memory usage for large codebases
//!
//! ### Code Analysis
//! - **Symbol extraction**: Functions, classes, variables, imports, and exports
//! - **Dependency analysis**: Import/export relationships and dependency graphs
//! - **Structural analysis**: Code complexity, nesting levels, and architectural patterns
//! - **Performance analysis**: Identify potential bottlenecks and optimization opportunities
//! - **Code metrics**: Lines of code, cyclomatic complexity, maintainability index
//!
//! ### Security & Quality
//! - **Security scanning**: Detect potential vulnerabilities and code smells
//! - **OWASP compliance**: Check against common security patterns and best practices
//! - **Code quality metrics**: Maintainability, complexity, and adherence to best practices
//! - **Vulnerability database**: Integration with security advisory databases
//! - **Secrets detection**: Find hardcoded credentials and sensitive information
//!
//! ### AI Integration
//! - **GPT-5/GPT-4o support**: Latest OpenAI models for advanced code analysis
//! - **Real codebase analysis**: Analyze actual project files with actionable insights
//! - **Security vulnerability detection**: AI-powered security analysis and recommendations
//! - **Code quality assessment**: Automated code review with improvement suggestions
//! - **Architectural insights**: Design pattern analysis and architectural improvements
//! - **Cost tracking**: Monitor API usage and costs for AI services
//!
//! ### Infrastructure & Configuration
//! - **Configuration management**: Flexible YAML-based configuration system
//! - **Caching**: Efficient result caching for repeated operations
//! - **Parallel processing**: Multi-threaded analysis using `rayon` for large codebases
//! - **CLI interface**: Command-line tools for batch processing and automation
//! - **Extensible**: Plugin architecture for custom analyzers and processors
//!
//! ## Quick Start
//!
//! ### Basic Parsing
//!
//! ```rust,no_run
//! use rust_tree_sitter::{CodebaseAnalyzer, AnalysisResult, AnalysisConfig};
//!
//! # fn main() -> Result<(), rust_tree_sitter::Error> {
//! let mut analyzer = CodebaseAnalyzer::new()?;
//!
//! // Analyze entire directory
//! let result = analyzer.analyze_directory("src/")?;
//!
//! for file_info in &result.files {
//!     println!("File: {}", file_info.path.display());
//!     println!("  Functions: {}", file_info.symbols.len());
//!     println!("  Security issues: {}", file_info.security_vulnerabilities.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Code Analysis
//!
//! ```rust
//! use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig, AnalysisResult};
//!
//! # fn main() -> Result<(), rust_tree_sitter::Error> {
//! // Create analyzer with custom configuration
//! let config = AnalysisConfig {
//!     max_depth: Some(10),
//!     ..Default::default()
//! };
//! let mut analyzer = CodebaseAnalyzer::with_config(config)?;
//!
//! // Analyze a Rust file
//! let result = analyzer.analyze_file("src/bin/main.rs")?;

//! // Access analysis results
//! println!("Functions found: {}", result.files[0].symbols.len());
//! # Ok(())
//! # }
//! ```
//!
//! ### AI-Powered Analysis
//!
//! ```rust,no_run
//! # #[cfg(feature = "net")]
//! use rust_tree_sitter::ai::{AIServiceBuilder, AIFeature, AIRequest};
//!
//! # #[cfg(feature = "net")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize AI service with OpenAI
//! let ai_service = AIServiceBuilder::new()
//!     .with_config_file("ai_config.yaml")?
//!     .build()
//!     .await?;
//!
//! // Analyze code with AI for security vulnerabilities
//! let request = AIRequest::new(
//!     AIFeature::SecurityAnalysis,
//!     "Please analyze this Rust code for security vulnerabilities: \
//!      fn unsafe_function() { let password = \"admin123\"; }".to_string()
//! );
//!
//! let response = ai_service.process_request(request).await?;
//! println!("AI Security Analysis: {}", response.content);
//! println!("Cost: ${:.6}", response.token_usage.estimated_cost.unwrap_or(0.0));
//! # Ok(())
//! # }
//! ```
//!
//! ### Security Scanning
//!
//! ```rust
//! use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig};
//!
//! # fn main() -> Result<(), rust_tree_sitter::Error> {
//! // Create analyzer with security enabled
//! let config = AnalysisConfig {
//!     enable_security: true,
//!     ..Default::default()
//! };
//! let mut analyzer = CodebaseAnalyzer::with_config(config)?;
//!
//! // Analyze file for vulnerabilities
//! let result = analyzer.analyze_file("src/bin/main.rs")?;
//!
//! // Report security findings
//! for vuln in &result.files[0].security_vulnerabilities {
//!     println!("🚨 Security Issue: {} (Severity: {})",
//!              vuln.description, vuln.severity);
//!     println!("   Location: {}:{}", vuln.location.file.display(), vuln.location.start_line);
//! }
//! # Ok(())
//! # }
//! ```
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub(crate) fn system_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
}

pub(crate) fn generated_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQUE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

    let counter = UNIQUE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    format!(
        "{:08x}-{:032x}-{:016x}",
        std::process::id(),
        timestamp,
        counter
    )
}

pub(crate) fn current_timestamp_millis() -> u64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    if millis > u128::from(u64::MAX) {
        u64::MAX
    } else {
        millis as u64
    }
}

#[cfg(any(feature = "net", feature = "db"))]
pub(crate) fn duration_millis_saturated(duration: std::time::Duration) -> u64 {
    let millis = duration.as_millis();

    if millis > u128::from(u64::MAX) {
        u64::MAX
    } else {
        millis as u64
    }
}

pub(crate) fn current_timestamp_rfc3339() -> String {
    format_timestamp_millis_as_rfc3339(current_timestamp_millis())
}

fn format_timestamp_millis_as_rfc3339(timestamp_millis: u64) -> String {
    let seconds = (timestamp_millis / 1000) as i64;
    let millis = timestamp_millis % 1000;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    let (year, month, day) = civil_from_days(days);

    if millis == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
    }
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_parameter = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_parameter + 2) / 5 + 1;
    let month = month_parameter + if month_parameter < 10 { 3 } else { -9 };

    year += if month <= 2 { 1 } else { 0 };

    (year as i32, month as u32, day as u32)
}

#[allow(unused_macros)]
macro_rules! log_debug {
    ($($arg:tt)*) => {{
        #[cfg(any(feature = "cli", feature = "net", feature = "db"))]
        {
            tracing::debug!($($arg)*);
        }
        #[cfg(not(any(feature = "cli", feature = "net", feature = "db")))]
        {
            let _ = format_args!($($arg)*);
        }
    }};
}

#[allow(unused_macros)]
macro_rules! log_info {
    ($($arg:tt)*) => {{
        #[cfg(any(feature = "cli", feature = "net", feature = "db"))]
        {
            tracing::info!($($arg)*);
        }
        #[cfg(not(any(feature = "cli", feature = "net", feature = "db")))]
        {
            let _ = format_args!($($arg)*);
        }
    }};
}

#[allow(unused_macros)]
macro_rules! log_warn {
    ($($arg:tt)*) => {{
        #[cfg(any(feature = "cli", feature = "net", feature = "db"))]
        {
            tracing::warn!($($arg)*);
        }
        #[cfg(not(any(feature = "cli", feature = "net", feature = "db")))]
        {
            let _ = format_args!($($arg)*);
        }
    }};
}

#[allow(unused_macros)]
macro_rules! log_error {
    ($($arg:tt)*) => {{
        #[cfg(any(feature = "cli", feature = "net", feature = "db"))]
        {
            tracing::error!($($arg)*);
        }
        #[cfg(not(any(feature = "cli", feature = "net", feature = "db")))]
        {
            let _ = format_args!($($arg)*);
        }
    }};
}

#[allow(unused_imports)]
pub(crate) use log_debug;
#[allow(unused_imports)]
pub(crate) use log_error;
#[allow(unused_imports)]
pub(crate) use log_info;
#[allow(unused_imports)]
pub(crate) use log_warn;

/// Advanced multi-level caching system
pub mod advanced_cache;
/// Advanced memory management system
pub mod advanced_memory;
/// Advanced parallel processing system
pub mod advanced_parallel;
/// Advanced security analysis with OWASP compliance
pub mod advanced_security;
/// AI service layer and provider integrations
#[cfg(feature = "net")]
pub mod ai;
/// Common analysis functionality and helpers
pub mod analysis_common;
/// Utility functions for code analysis
pub mod analysis_utils;
/// Main codebase analyzer functionality
pub mod analyzer;
/// AST transformation and refactoring engine
pub mod ast_transformation;
/// Command-line interface implementation
#[cfg(feature = "cli")]
pub mod cli;
/// Code evolution tracking and analysis
pub mod code_evolution;
/// Code mapping and visualization utilities
pub mod code_map;
/// Command injection vulnerability detection
pub mod command_injection_detector;
/// Code complexity metrics and analysis
pub mod complexity_analysis;
/// Configuration constants and defaults
pub mod constants;
/// Control flow graph construction and analysis
pub mod control_flow;
/// Dependency analysis and vulnerability scanning
pub mod dependency_analysis;
/// Text embeddings and semantic similarity
#[cfg(feature = "ml")]
pub mod embeddings;
/// Enhanced security analysis with compliance checking
#[cfg(all(feature = "net", feature = "db"))]
pub mod enhanced_security;
/// Error types and handling
pub mod error;
/// File caching for performance optimization
pub mod file_cache;
/// Infrastructure and configuration management
#[cfg(any(feature = "net", feature = "db"))]
pub mod infrastructure;
/// Intent mapping between requirements and implementation
pub mod intent_mapping;
/// Programming language support and parsers
pub mod languages;
/// Memory allocation tracking and analysis
pub mod memory_tracker;
/// Tree-sitter parser integration
pub mod parser;
/// Performance analysis and optimization detection
pub mod performance_analysis;
/// Code querying and pattern matching
pub mod query;
/// Code refactoring suggestions and analysis
pub mod refactoring;
/// Security analysis and vulnerability detection
pub mod security;
/// Semantic context analysis and data flow
pub mod semantic_context;
/// Semantic graph construction and querying
pub mod semantic_graph;
/// SQL injection vulnerability detection
pub mod sql_injection_detector;
/// Symbol table construction and management
pub mod symbol_table;
/// Taint analysis for security vulnerability detection
pub mod taint_analysis;
/// Test coverage analysis and gap detection
pub mod test_coverage;
/// Syntax tree manipulation and traversal
pub mod tree;
/// Wiki website generator
#[cfg(feature = "wiki")]
pub mod wiki;
// Re-export commonly used types

// Core analysis types
pub use analyzer::{
    AnalysisConfig, AnalysisDepth, AnalysisResult, CodebaseAnalyzer, FileInfo, Symbol,
};
pub use error::{Error, Result};
pub use languages::Language;
pub use parser::{create_edit, ParseOptions, Parser};
pub use query::{Query, QueryBuilder, QueryCapture, QueryMatch};
pub use tree::{Node, SyntaxTree, TreeCursor, TreeEdit};

// Basic analysis modules
pub use complexity_analysis::{ComplexityAnalyzer, ComplexityMetrics, HalsteadMetrics};
pub use dependency_analysis::{
    Dependency, DependencyAnalysisResult, DependencyAnalyzer, DependencyConfig, PackageManager,
};
pub use performance_analysis::{
    PerformanceAnalysisResult, PerformanceAnalyzer, PerformanceConfig, PerformanceHotspot,
};
pub use refactoring::{
    RefactoringAnalyzer, RefactoringConfig, RefactoringResult, RefactoringSuggestion,
};
pub use test_coverage::{
    MissingTest, TestCoverageAnalyzer, TestCoverageConfig, TestCoverageResult,
};

// Security analysis
pub use advanced_security::{
    AdvancedSecurityAnalyzer as SecurityScanner, AdvancedSecurityConfig as SecurityConfig,
    AdvancedSecurityResult as SecurityScanResult, SecuritySeverity, SecurityVulnerability,
};
#[cfg(all(feature = "net", feature = "db"))]
pub use enhanced_security::{
    EnhancedSecurityConfig, EnhancedSecurityResult, EnhancedSecurityScanner,
};
pub use security::OwaspDetector;
#[cfg(any(feature = "net", feature = "db"))]
pub use security::SecretsDetector;
#[cfg(all(feature = "net", feature = "db"))]
pub use security::VulnerabilityDatabase;
#[cfg(feature = "net")]
pub use security::{AIFalsePositiveFilter, AIFilterConfig, AIFilterResult, AIFilterStatistics};
pub use security::{ConfidenceSource, HeuristicFindingFilter, ScoredFinding, SecurityPipeline};

// AI service layer
#[cfg(feature = "net")]
pub use ai::{
    AIConfig as AIServiceConfig, AIError, AIFeature, AIProvider, AIRequest, AIResponse, AIResult,
    AIService, AIServiceBuilder,
};

pub use ast_transformation::{
    AstTransformationEngine, ExtractedVariableAnalysis, ImpactScope, Position, SemanticValidator,
    Transformation, TransformationConfig, TransformationImpact, TransformationLocation,
    TransformationMetadata, TransformationResult, TransformationType, ValidationConfig,
    ValidationResult, VariableInfo,
};
pub use code_map::{build_call_graph, build_module_graph, CallGraph, ModuleGraph};
// Specialized analysis tools
pub use command_injection_detector::{
    CommandInjectionDetector, CommandInjectionType, CommandInjectionVulnerability,
};
pub use control_flow::{CfgBuilder, CfgNodeType, ControlFlowGraph};
pub use semantic_context::{
    DataFlowAnalysis, SanitizationPoint, SecuritySemanticContext, SemanticContext,
    SemanticContextAnalyzer, TrustLevel, ValidationPoint,
};
pub use semantic_graph::{
    GraphEdge, GraphNode, GraphStatistics, NodeType, QueryConfig, QueryResult, RelationshipType,
    SemanticGraphQuery, SemanticGraphSnapshot,
};
pub use sql_injection_detector::{
    SqlInjectionDetector, SqlInjectionType, SqlInjectionVulnerability,
};
pub use symbol_table::{
    ReferenceType, Scope, ScopeType, SymbolAnalysisResult, SymbolDefinition, SymbolReference,
    SymbolTable, SymbolTableAnalyzer, SymbolType,
};
pub use taint_analysis::{TaintAnalyzer, TaintFlow, TaintSink, TaintSource, VulnerabilityType};

// Advanced AI features
pub use code_evolution::{
    ChangePattern, ChangeType, CodeEvolutionTracker, EvolutionAnalysisResult, EvolutionConfig,
    EvolutionMetrics, EvolutionRecommendation, FileInsight, PatternType,
};
pub use intent_mapping::{
    CodeElement, GapType, Implementation, ImplementationStatus, ImplementationType, IntentMapping,
    IntentMappingSystem, MappingAnalysisResult, MappingConfig, MappingGap, MappingRecommendation,
    MappingType, Priority, Priority as IntentPriority, QualityMetrics, RecommendationType,
    Requirement, RequirementStatus, RequirementType, TraceabilityMatrix, TraceabilityReport,
    ValidationStatus,
};
pub use memory_tracker::{
    AllocationCallStack, AllocationHotspot, AllocationImpact, AllocationLocation,
    AllocationPattern, AllocationType, FragmentationAnalysis, LeakType, LifetimeStatistics,
    MemoryLeakCandidate, MemorySnapshot, MemoryStatistics, MemoryTracker, MemoryTrackingConfig,
    MemoryTrackingResult, UsagePattern,
};

// Utilities
pub use file_cache::{CacheStats, FileCache};

// Re-export tree-sitter types that users might need
pub use tree_sitter::{InputEdit, Point, Range};

// Re-export common types from constants
pub use constants::common::RiskLevel;

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Supported language information
#[derive(Debug, Clone)]
pub struct LanguageInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub file_extensions: &'static [&'static str],
}

/// Get information about all supported languages
pub fn supported_languages() -> Vec<LanguageInfo> {
    vec![LanguageInfo {
        name: "Rust",
        version: "0.21.0",
        file_extensions: &["rs"],
    }]
}

/// Detect language from file extension
pub fn detect_language_from_extension(extension: &str) -> Option<Language> {
    match extension.to_lowercase().as_str() {
        "rs" => Some(Language::Rust),
        _ => None,
    }
}

/// Detect language from file path
pub fn detect_language_from_path(path: &str) -> Option<Language> {
    std::path::Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .and_then(detect_language_from_extension)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_detection() {
        assert_eq!(detect_language_from_extension("rs"), Some(Language::Rust));
        assert_eq!(detect_language_from_extension("js"), None);
        assert_eq!(detect_language_from_extension("py"), None);
        assert_eq!(detect_language_from_extension("ts"), None);
        assert_eq!(detect_language_from_extension("c"), None);
        assert_eq!(detect_language_from_extension("unknown"), None);
    }

    #[test]
    fn test_path_detection() {
        assert_eq!(detect_language_from_path("main.rs"), Some(Language::Rust));
        assert_eq!(
            detect_language_from_path("src/lib.rs"),
            Some(Language::Rust)
        );
        assert_eq!(detect_language_from_path("app.js"), None);
        assert_eq!(detect_language_from_path("script.py"), None);
        assert_eq!(detect_language_from_path("component.ts"), None);
        assert_eq!(detect_language_from_path("header.h"), None);
        assert_eq!(detect_language_from_path("unknown.txt"), None);
    }

    #[test]
    fn test_supported_languages() {
        let languages = supported_languages();
        assert!(!languages.is_empty());
        assert!(languages.iter().any(|lang| lang.name == "Rust"));
        assert!(!languages.iter().any(|lang| lang.name == "JavaScript"));
        assert!(!languages.iter().any(|lang| lang.name == "Python"));
        assert!(!languages.iter().any(|lang| lang.name == "TypeScript"));
        assert!(!languages.iter().any(|lang| lang.name == "C"));
    }

    #[test]
    fn test_format_timestamp_epoch() {
        assert_eq!(
            format_timestamp_millis_as_rfc3339(0),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn test_format_timestamp_preserves_milliseconds() {
        assert_eq!(
            format_timestamp_millis_as_rfc3339(946_684_800_123),
            "2000-01-01T00:00:00.123Z"
        );
    }
}
