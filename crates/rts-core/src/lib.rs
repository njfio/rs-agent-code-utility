//! # rust_tree_sitter
//!
//! Tree-sitter-backed parsing primitives consumed by `rts-daemon` and
//! `rts-mcp` to power the local code KB.
//!
//! ## Public surface
//!
//! - **Parsing**: [`Parser`], [`SyntaxTree`], [`Node`], [`TreeCursor`], [`Language`]
//! - **Querying**: [`Query`], [`QueryBuilder`], [`QueryMatch`], [`QueryCapture`]
//! - **Facade**: [`parse_content`] + [`ParseOutcome`] — one-call symbol extraction
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

/// Configuration constants and shared defaults.
pub mod constants;
/// Error types for the crate.
pub mod error;
/// Per-language symbol extraction from tree-sitter parse trees.
pub(crate) mod extraction;
/// Programming-language adapters (tree-sitter grammars for 12 languages).
pub mod languages;
/// Personalised PageRank for `Index.Outline` symbol ranking.
pub mod pagerank;
/// Containment-based parent-scope assignment for [`Symbol::parent`].
pub(crate) mod parent_scope;
/// Tree-sitter parser wrapper.
pub mod parser;
/// Tree-sitter query API.
pub mod query;
/// Per-language signature renderer for `Index.ReadSymbol shape=signature`.
pub mod signature;
/// The [`Symbol`] payload produced by [`parse_content`].
pub mod symbol;
/// Syntax-tree traversal helpers.
pub mod tree;
/// Shared primitives for the verification layer (resolution model, fuzzy
/// candidate ranking, use-site reference extraction, signature shapes).
pub mod verify;

// ---------- Re-exports ----------

pub use error::{Error, Result};
pub use languages::Language;
pub use parser::{ParseOptions, Parser, create_edit};
pub use query::{Query, QueryBuilder, QueryCapture, QueryMatch};
pub use symbol::Symbol;
pub use tree::{Node, SyntaxTree, TreeCursor, TreeEdit};
pub use verify::{IndeterminateReason, Resolution};

// ---------- parse_content facade ----------

/// Outcome of [`parse_content`].
///
/// `symbols` carries the extracted symbol records; `partial_errors`
/// carries human-readable notes about known incomplete extraction
/// paths (e.g. Java/C/C++ may successfully parse but currently
/// return an empty `Vec<Symbol>` via TODO-stubbed extractors —
/// surfacing the gap here lets callers distinguish "no symbols in
/// this file" from "extractor doesn't cover this language yet"
/// without re-parsing).
///
/// Today the field is always empty because the extractors don't
/// yet self-report; the type reserves the slot so we don't need a
/// breaking change when they do.
#[derive(Debug, Clone, Default)]
pub struct ParseOutcome {
    /// Symbols extracted from the parse tree, in source order.
    pub symbols: Vec<Symbol>,
    /// Non-fatal extraction warnings (e.g. "Java extractor is a stub").
    /// Empty under v0; reserved for future extractor self-reporting.
    pub partial_errors: Vec<String>,
}

/// Parse `content` for the given `language` and extract symbols.
///
/// Built from primitives (`Parser::new` + `extraction::extract_symbols`)
/// rather than wrapping a `CodebaseAnalyzer` — no per-call hashmap
/// allocation, no caching scaffold, no construction ceremony.
///
/// Behaviorally equivalent to the pre-PR-B
/// `CodebaseAnalyzer::new()?.analyze_content(content, language)`
/// chain that lived at `rts-daemon::writer::ParserPool::parse_and_extract`.
///
/// Returns `Err(Error::ParseError { .. })` on malformed input —
/// the rich `ParseErrorDetails` context from `error.rs` is preserved
/// so the daemon's diagnostics stay intact.
///
/// # Example
///
/// ```rust,no_run
/// use rust_tree_sitter::{parse_content, Language};
///
/// # fn main() -> Result<(), rust_tree_sitter::Error> {
/// let outcome = parse_content("fn foo() {}", Language::Rust)?;
/// assert!(outcome.symbols.iter().any(|s| s.name == "foo"));
/// # Ok(())
/// # }
/// ```
pub fn parse_content(content: &str, language: Language) -> Result<ParseOutcome> {
    let parser = Parser::new(language)?;
    let tree = parser.parse(content, None)?;
    let symbols = extraction::extract_symbols(&tree, content, language)?;
    Ok(ParseOutcome {
        symbols,
        partial_errors: Vec::new(),
    })
}

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
    // Grammar versions track the `tree-sitter-*` pins in this crate's
    // Cargo.toml; extensions mirror `detect_language_from_extension`.
    vec![
        LanguageInfo {
            name: "Rust",
            version: "0.23",
            file_extensions: &["rs"],
        },
        LanguageInfo {
            name: "JavaScript",
            version: "0.23",
            file_extensions: &["js", "mjs", "cjs", "jsx"],
        },
        LanguageInfo {
            name: "TypeScript",
            version: "0.23",
            file_extensions: &["ts", "tsx", "mts", "cts"],
        },
        LanguageInfo {
            name: "Python",
            version: "0.23",
            file_extensions: &["py", "pyi"],
        },
        LanguageInfo {
            name: "C",
            version: "0.23",
            file_extensions: &["c", "h"],
        },
        LanguageInfo {
            name: "C++",
            version: "0.23",
            file_extensions: &["cpp", "cxx", "cc", "hpp", "hxx", "hh"],
        },
        LanguageInfo {
            name: "Go",
            version: "0.23",
            file_extensions: &["go"],
        },
        LanguageInfo {
            name: "Java",
            version: "0.23",
            file_extensions: &["java"],
        },
        LanguageInfo {
            name: "PHP",
            version: "0.23",
            file_extensions: &["php", "phtml"],
        },
        LanguageInfo {
            name: "Ruby",
            version: "0.23",
            file_extensions: &["rb", "rake"],
        },
        LanguageInfo {
            name: "Swift",
            version: "0.7",
            file_extensions: &["swift"],
        },
        LanguageInfo {
            name: "C#",
            version: "0.23",
            file_extensions: &["cs", "csx"],
        },
        LanguageInfo {
            name: "Markdown",
            version: "0.5",
            file_extensions: &["md", "markdown"],
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
        "md" | "markdown" => Some(Language::Markdown),
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

    #[test]
    fn parse_content_extracts_rust_function() {
        let outcome = parse_content("pub fn foo() {}", Language::Rust)
            .expect("parse_content should succeed on valid Rust");
        assert!(
            outcome.symbols.iter().any(|s| s.name == "foo"),
            "expected `foo` in {:?}",
            outcome.symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
        assert!(
            outcome.partial_errors.is_empty(),
            "no partial errors expected on success path"
        );
    }

    #[test]
    fn parse_content_extracts_python_class() {
        let outcome = parse_content("class UserService:\n    pass\n", Language::Python)
            .expect("parse_content should succeed on valid Python");
        assert!(
            outcome
                .symbols
                .iter()
                .any(|s| s.name == "UserService" && s.kind == "class"),
            "expected `UserService` class in {:?}",
            outcome.symbols
        );
    }

    #[test]
    fn parse_content_extracts_go_function() {
        let outcome = parse_content(
            "package demo\n\nfunc GoTarget(name string) int { return len(name) }\n",
            Language::Go,
        )
        .expect("parse_content should succeed on valid Go");
        assert!(
            outcome.symbols.iter().any(|s| s.name == "GoTarget"),
            "expected `GoTarget` in {:?}",
            outcome.symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn parse_content_caller_excludes_called_fn_names() {
        // Regression: a naïve "first identifier descendant" pattern
        // walk would otherwise capture called function names as
        // "variable" symbols. Mirrors the daemon-side writer test.
        let src =
            "pub fn caller_a_one() {\n    let _ = hub_compute(1);\n    let _ = hub_format(2);\n}\n";
        let outcome = parse_content(src, Language::Rust).unwrap();
        let names: Vec<_> = outcome.symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"caller_a_one"),
            "expected `caller_a_one` in {names:?}"
        );
        assert!(
            !names.contains(&"hub_compute"),
            "`hub_compute` is a CALL, not a def, should not appear; got {names:?}"
        );
        assert!(
            !names.contains(&"hub_format"),
            "`hub_format` is a CALL, not a def, should not appear; got {names:?}"
        );
    }

    #[test]
    fn parse_content_extracts_multiple_rust_kinds() {
        // Replaces the B2-era `parse_content_matches_codebase_analyzer_output`
        // equivalence test that pinned the drop-in replacement contract.
        // After B3 deletes `CodebaseAnalyzer`, the contract is implicit
        // (parse_content IS the only path) but the multi-kind sanity
        // check remains valuable.
        let src = "pub fn alpha() {}\npub struct Beta;\nfn gamma() {}\n";
        let outcome = parse_content(src, Language::Rust).unwrap();
        let names: Vec<_> = outcome
            .symbols
            .iter()
            .map(|s| (s.name.as_str(), s.kind.as_str()))
            .collect();
        assert!(names.contains(&("alpha", "function")), "got {names:?}");
        assert!(names.contains(&("Beta", "struct")), "got {names:?}");
        assert!(names.contains(&("gamma", "function")), "got {names:?}");
    }
}
