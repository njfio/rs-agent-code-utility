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
//! - **Multi-language support**: Parse Rust, Python, JavaScript, TypeScript, Go, C, C++, and more
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
//! let result = analyzer.analyze_file("src/main.rs")?;

//! // Access analysis results
//! println!("Functions found: {}", result.files[0].symbols.len());
//! # Ok(())
//! # }
//! ```
//!
//! ### AI-Powered Analysis
//!
//! ```rust,no_run
//! use rust_tree_sitter::ai::{AIServiceBuilder, AIFeature, AIRequest};
//!
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
//! let result = analyzer.analyze_file("src/main.rs")?;
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

/// Advanced AI-powered code analysis capabilities
pub mod advanced_ai_analysis;
/// Advanced multi-level caching system
pub mod advanced_cache;
/// Advanced memory management system
pub mod advanced_memory;
/// Advanced parallel processing system
pub mod advanced_parallel;
/// Advanced security analysis with OWASP compliance
pub mod advanced_security;
/// AI service layer and provider integrations
pub mod ai;
/// AI-powered code explanation and insights
pub mod ai_analysis;
/// Common analysis functionality and helpers
pub mod analysis_common;
/// Utility functions for code analysis
pub mod analysis_utils;
/// Main codebase analyzer functionality
pub mod analyzer;
/// AST transformation and refactoring engine
pub mod ast_transformation;
/// Command-line interface implementation
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
/// Enhanced security analysis with compliance checking
#[cfg(any(feature = "net", feature = "db"))]
pub mod enhanced_security;
/// Error types and handling
pub mod error;
/// File caching for performance optimization
pub mod file_cache;
/// Infrastructure and configuration management
#[cfg(any(feature = "net", feature = "db"))]
pub mod infrastructure;
/// Intent mapping between requirements and implementation
#[cfg(feature = "ml")]
pub mod intent_mapping;
#[cfg(not(feature = "ml"))]
pub mod intent_mapping_stub;
/// Semantic context analysis and data flow
pub mod semantic_context;
/// SQL injection vulnerability detection
pub mod sql_injection_detector;
/// Symbol table construction and management
pub mod symbol_table;
/// Taint analysis for security vulnerability detection
pub mod taint_analysis;
#[cfg(not(feature = "ml"))]
pub use intent_mapping_stub as intent_mapping;
/// Text embeddings and semantic similarity
#[cfg(feature = "ml")]
pub mod embeddings;
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
/// Automated reasoning and inference engine
pub mod reasoning_engine;
/// Code refactoring suggestions and analysis
pub mod refactoring;
/// Security analysis and vulnerability detection
pub mod security;
/// Semantic graph construction and querying
pub mod semantic_graph;
/// Smart refactoring with AI assistance
pub mod smart_refactoring;
/// Test coverage analysis and gap detection
pub mod test_coverage;
/// Syntax tree manipulation and traversal
pub mod tree;
/// Wiki website generator
pub mod wiki;

/// Integration testing framework
// pub mod integration_testing;
/// Performance benchmarking suite
// pub mod performance_benchmarking;
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
pub use ai_analysis::{
    AIAnalysisResult, AIAnalyzer, AIConfig, CodebaseExplanation, FileExplanation, SymbolExplanation,
};
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
#[cfg(any(feature = "net", feature = "db"))]
pub use enhanced_security::{
    EnhancedSecurityConfig, EnhancedSecurityResult, EnhancedSecurityScanner,
};
pub use security::OwaspDetector;
#[cfg(any(feature = "net", feature = "db"))]
pub use security::{SecretsDetector, VulnerabilityDatabase};

// AI service layer
pub use ai::{
    AIConfig as AIServiceConfig, AIError, AIFeature, AIProvider, AIRequest, AIResponse, AIResult,
    AIService, AIServiceBuilder,
};

// Advanced features
pub use advanced_ai_analysis::{
    AdvancedAIAnalyzer, AdvancedAIConfig, AdvancedAIResult, ArchitecturePattern, SemanticAnalysis,
};
pub use ast_transformation::{
    AstTransformationEngine, ExtractedVariableAnalysis, ImpactScope, Position, SemanticValidator,
    Transformation, TransformationConfig, TransformationImpact, TransformationLocation,
    TransformationMetadata, TransformationResult, TransformationType, ValidationConfig,
    ValidationResult, VariableInfo,
};
pub use code_map::{build_call_graph, build_module_graph, CallGraph, ModuleGraph};
pub use smart_refactoring::{
    CodeSmellFix, SmartRefactoringConfig, SmartRefactoringEngine, SmartRefactoringResult,
};

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
    SemanticGraphQuery,
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
#[cfg(not(feature = "ml"))]
pub use intent_mapping::IntentMappingSystem;
#[cfg(feature = "ml")]
pub use intent_mapping::{
    CodeElement, GapType, Implementation, ImplementationStatus, ImplementationType, IntentMapping,
    IntentMappingSystem, MappingAnalysisResult, MappingConfig, MappingGap, MappingRecommendation,
    MappingType, Priority as IntentPriority, QualityMetrics, RecommendationType, Requirement,
    RequirementStatus, RequirementType, TraceabilityMatrix, TraceabilityReport, ValidationStatus,
};
pub use memory_tracker::{
    AllocationCallStack, AllocationHotspot, AllocationImpact, AllocationLocation,
    AllocationPattern, AllocationType, FragmentationAnalysis, LeakType, LifetimeStatistics,
    MemoryLeakCandidate, MemorySnapshot, MemoryStatistics, MemoryTracker, MemoryTrackingConfig,
    MemoryTrackingResult, UsagePattern,
};
pub use reasoning_engine::{
    AutomatedReasoningEngine, ConstraintSolver, Fact, InferenceEngine, InsightType, KnowledgeBase,
    ReasoningConfig, ReasoningInsight, ReasoningResult, Rule, TheoremProver,
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
    vec![
        LanguageInfo {
            name: "Rust",
            version: "0.21.0",
            file_extensions: &["rs"],
        },
        LanguageInfo {
            name: "JavaScript",
            version: "0.21.0",
            file_extensions: &["js", "mjs", "jsx"],
        },
        LanguageInfo {
            name: "Python",
            version: "0.21.0",
            file_extensions: &["py", "pyi"],
        },
        LanguageInfo {
            name: "C",
            version: "0.21.0",
            file_extensions: &["c", "h"],
        },
        LanguageInfo {
            name: "C++",
            version: "0.22.0",
            file_extensions: &["cpp", "cxx", "cc", "hpp", "hxx"],
        },
        LanguageInfo {
            name: "TypeScript",
            version: "0.21.0",
            file_extensions: &["ts", "tsx", "mts", "cts"],
        },
        LanguageInfo {
            name: "Go",
            version: "0.21.0",
            file_extensions: &["go"],
        },
    ]
}

/// Detect language from file extension
pub fn detect_language_from_extension(extension: &str) -> Option<Language> {
    match extension.to_lowercase().as_str() {
        "rs" => Some(Language::Rust),
        "js" | "mjs" | "jsx" => Some(Language::JavaScript),
        "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
        "py" | "pyi" => Some(Language::Python),
        "c" | "h" => Some(Language::C),
        "cpp" | "cxx" | "cc" | "hpp" | "hxx" => Some(Language::Cpp),
        "go" => Some(Language::Go),
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
        assert_eq!(
            detect_language_from_extension("js"),
            Some(Language::JavaScript)
        );
        assert_eq!(
            detect_language_from_extension("ts"),
            Some(Language::TypeScript)
        );
        assert_eq!(detect_language_from_extension("py"), Some(Language::Python));
        assert_eq!(detect_language_from_extension("go"), Some(Language::Go));
        assert_eq!(detect_language_from_extension("unknown"), None);
    }

    #[test]
    fn test_path_detection() {
        assert_eq!(detect_language_from_path("main.rs"), Some(Language::Rust));
        assert_eq!(
            detect_language_from_path("src/lib.rs"),
            Some(Language::Rust)
        );
        assert_eq!(
            detect_language_from_path("script.py"),
            Some(Language::Python)
        );
        assert_eq!(detect_language_from_path("unknown.txt"), None);
    }

    #[test]
    fn test_supported_languages() {
        let languages = supported_languages();
        assert!(!languages.is_empty());
        assert!(languages.iter().any(|lang| lang.name == "Rust"));
    }
}
