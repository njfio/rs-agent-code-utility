//! # rust_tree_sitter
//!
//! Tree-sitter-backed parsing primitives consumed by `rts-daemon` and
//! `rts-mcp` to power the agentic-retrieval stack.
//!
//! ## Public surface
//!
//! - **Parsing**: [`Parser`], [`SyntaxTree`], [`Node`], [`TreeCursor`], [`Language`]
//! - **Querying**: [`Query`], [`QueryBuilder`], [`QueryMatch`], [`QueryCapture`]
//! - **Symbols**: the [`Symbol`] payload used by the daemon's serialization layer
//! - **Ranking**: [`pagerank`] (used by `Index.Outline`)
//! - **Signatures**: per-language [`signature::render_rust`] etc. (used by `Index.ReadSymbol`)
//! - **Errors**: [`Error`], [`Result`]
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use rust_tree_sitter::{Language, Parser};
//!
//! # fn main() -> Result<(), rust_tree_sitter::Error> {
//! let parser = Parser::new(Language::Rust)?;
//! let tree = parser.parse("fn main() {}", None)?;
//! println!("root kind: {}", tree.root_node().kind());
//! # Ok(())
//! # }
//! ```

// ---------- Surviving modules ----------

/// Codebase analyzer: walks a workspace and produces structured `AnalysisResult`s.
pub mod analyzer;
/// Configuration constants and shared defaults.
pub mod constants;
/// Error types for the crate.
pub mod error;
/// Programming-language adapters (tree-sitter grammars for 12 languages).
pub mod languages;
/// Personalised PageRank for `Index.Outline` symbol ranking.
pub mod pagerank;
/// Tree-sitter parser wrapper.
pub mod parser;
/// Tree-sitter query API.
pub mod query;
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

// Utilities
pub use constants::common::RiskLevel;

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
