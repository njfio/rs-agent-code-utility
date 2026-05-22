//! # rust_tree_sitter (0.2.0-alpha: in-progress retrieval pivot)
//!
//! Tree-sitter-backed code parsing and analysis primitives, kept lean to feed
//! the upcoming `rts-daemon` + `rts-mcp` retrieval stack (see
//! [`docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md`]).
//!
//! ## Public surface (post-cut)
//!
//! - **Parsing**: [`Parser`], [`SyntaxTree`], [`Node`], [`TreeCursor`], [`Language`]
//! - **Querying**: [`Query`], [`QueryBuilder`], [`QueryMatch`], [`QueryCapture`]
//! - **Analysis**: [`CodebaseAnalyzer`], [`AnalysisConfig`], [`AnalysisResult`], [`FileInfo`], [`Symbol`]
//! - **Symbols**: [`SymbolTable`], [`SymbolDefinition`], [`SymbolReference`]
//! - **Graphs**: [`SemanticGraphQuery`], `code_map::build_call_graph`
//!
//! ## Removed in 0.2.0
//!
//! The 0.1.x outbound AI service layer, security analyzers (taint, SQL/cmd
//! injection, OWASP), refactoring engines, wiki generator, and dev-tooling
//! modules have been archived for the agentic-retrieval pivot. See
//! `archive/README.md` and `CHANGELOG.md` for the full kill list.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig};
//!
//! # fn main() -> Result<(), rust_tree_sitter::Error> {
//! let mut analyzer = CodebaseAnalyzer::new()?;
//! let result = analyzer.analyze_directory("src/")?;
//! for file in &result.files {
//!     println!("{}: {} symbols", file.path.display(), file.symbols.len());
//! }
//! # Ok(())
//! # }
//! ```

// ---------- Surviving modules ----------

/// Shared analysis helpers.
pub mod analysis_common;
/// Code-analysis utility helpers.
pub mod analysis_utils;
/// Codebase analyzer: walks a workspace and produces structured `AnalysisResult`s.
pub mod analyzer;
/// Configuration constants and shared defaults.
pub mod constants;
/// Error types for the crate.
pub mod error;
/// In-memory file content cache.
pub mod file_cache;
/// Programming-language adapters (tree-sitter grammars for 12 languages).
pub mod languages;
/// Personalised PageRank for `Index.Outline` symbol ranking.
pub mod pagerank;
/// Tree-sitter parser wrapper.
pub mod parser;
/// Tree-sitter query API.
pub mod query;
/// Symbol-graph queries for repo-map ranking and reasoning.
pub mod semantic_graph;
/// Per-language signature renderer for `Index.ReadSymbol shape=signature`.
pub mod signature;
/// Syntax-tree traversal helpers.
pub mod tree;

// ---------- Re-exports ----------

// Core analysis types
pub use analyzer::{
    AnalysisConfig, AnalysisDepth, AnalysisResult, CodebaseAnalyzer, FileInfo, Symbol,
};
pub use error::{Error, Result};
pub use languages::Language;
pub use parser::{ParseOptions, Parser, create_edit};
pub use query::{Query, QueryBuilder, QueryCapture, QueryMatch};
pub use tree::{Node, SyntaxTree, TreeCursor, TreeEdit};

// Analysis modules surviving the cut (under review for P4)
pub use semantic_graph::{
    GraphEdge, GraphNode, GraphStatistics, NodeType, QueryConfig, QueryResult, RelationshipType,
    SemanticGraphQuery,
};

// Utilities
pub use constants::common::RiskLevel;
pub use file_cache::{CacheStats, FileCache};

// Tree-sitter type passthroughs
pub use tree_sitter::{InputEdit, Point, Range};

// ---------- Crate-level helpers ----------

/// Library version (matches `Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Display metadata for a supported language.
#[derive(Debug, Clone)]
pub struct LanguageInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub file_extensions: &'static [&'static str],
}

/// Information about all supported languages.
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

/// Detect language from file extension.
pub fn detect_language_from_extension(extension: &str) -> Option<Language> {
    match extension.to_lowercase().as_str() {
        "rs" => Some(Language::Rust),
        "js" | "mjs" | "jsx" | "cjs" => Some(Language::JavaScript),
        "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
        "py" | "pyi" => Some(Language::Python),
        "c" | "h" => Some(Language::C),
        "cpp" | "cxx" | "cc" | "hpp" | "hxx" | "hh" => Some(Language::Cpp),
        "go" => Some(Language::Go),
        "java" => Some(Language::Java),
        "php" | "phtml" => Some(Language::Php),
        "rb" | "rake" => Some(Language::Ruby),
        "swift" => Some(Language::Swift),
        "cs" | "csx" => Some(Language::CSharp),
        _ => None,
    }
}

/// Detect language from a file path.
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
