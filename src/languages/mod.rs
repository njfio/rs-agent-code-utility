//! Language support for tree-sitter parsers

pub mod rust;
pub mod javascript;
pub mod typescript;
pub mod python;
pub mod c;
pub mod cpp;
pub mod go;

use crate::error::{Error, Result};

/// Supported programming languages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// Rust programming language
    Rust,
    /// JavaScript programming language
    JavaScript,
    /// TypeScript programming language
    TypeScript,
    /// Python programming language
    Python,
    /// C programming language
    C,
    /// C++ programming language
    Cpp,
    /// Go programming language
    Go,
}

impl Language {
    /// Get the tree-sitter language for this language
    pub fn tree_sitter_language(&self) -> Result<tree_sitter::Language> {
        match self {
            Language::Rust => Ok(tree_sitter_rust::language()),
            Language::JavaScript => Ok(tree_sitter_javascript::language()),
            Language::TypeScript => Ok(tree_sitter_typescript::language_typescript()),
            Language::Python => Ok(tree_sitter_python::language()),
            Language::C => Ok(tree_sitter_c::language()),
            Language::Cpp => Ok(tree_sitter_cpp::language()),
            Language::Go => Ok(tree_sitter_go::language()),
        }
    }

    /// Get the name of this language
    pub fn name(&self) -> &'static str {
        match self {
            Language::Rust => "Rust",
            Language::JavaScript => "JavaScript",
            Language::TypeScript => "TypeScript",
            Language::Python => "Python",
            Language::C => "C",
            Language::Cpp => "C++",
            Language::Go => "Go",
        }
    }

    /// Get the typical file extensions for this language
    pub fn file_extensions(&self) -> &'static [&'static str] {
        match self {
            Language::Rust => &["rs"],
            Language::JavaScript => &["js", "mjs", "jsx"],
            Language::TypeScript => &["ts", "tsx", "mts", "cts"],
            Language::Python => &["py", "pyi"],
            Language::C => &["c", "h"],
            Language::Cpp => &["cpp", "cxx", "cc", "hpp", "hxx"],
            Language::Go => &["go"],
        }
    }

    /// Get the language version
    pub fn version(&self) -> &'static str {
        match self {
            Language::Rust => "0.21.0",
            Language::JavaScript => "0.21.0",
            Language::TypeScript => "0.21.0",
            Language::Python => "0.21.0",
            Language::C => "0.21.0",
            Language::Cpp => "0.22.0",
            Language::Go => "0.21.0",
        }
    }

    /// Check if this language supports syntax highlighting queries
    pub fn supports_highlights(&self) -> bool {
        match self {
            Language::Rust => true,
            Language::JavaScript => true,
            Language::TypeScript => true,
            Language::Python => true,
            Language::C => true,
            Language::Cpp => true,
            Language::Go => true,
        }
    }

    /// Get syntax highlighting query for this language
    pub fn highlights_query(&self) -> Option<&'static str> {
        match self {
            Language::Rust => Some(tree_sitter_rust::HIGHLIGHTS_QUERY),
            Language::JavaScript => Some(tree_sitter_javascript::HIGHLIGHT_QUERY),
            Language::TypeScript => Some(tree_sitter_typescript::HIGHLIGHTS_QUERY),
            Language::Python => Some(tree_sitter_python::HIGHLIGHTS_QUERY),
            Language::C => Some(tree_sitter_c::HIGHLIGHT_QUERY),
            Language::Cpp => Some(tree_sitter_cpp::HIGHLIGHT_QUERY),
            Language::Go => Some(tree_sitter_go::HIGHLIGHTS_QUERY),
        }
    }

    /// Get injections query for this language (if available)
    pub fn injections_query(&self) -> Option<&'static str> {
        match self {
            Language::Rust => tree_sitter_rust::INJECTIONS_QUERY.into(),
            Language::JavaScript => tree_sitter_javascript::INJECTIONS_QUERY.into(),
            Language::TypeScript => None, // TypeScript injections query not available
            Language::Python => None, // Python doesn't have injections query
            Language::C => None,      // C doesn't have injections query
            Language::Cpp => None,    // C++ doesn't have injections query
            Language::Go => None,     // Go doesn't have injections query
        }
    }

    /// Get locals query for this language (if available)
    pub fn locals_query(&self) -> Option<&'static str> {
        match self {
            Language::Rust => None, // Rust doesn't have locals query in this version
            Language::JavaScript => tree_sitter_javascript::LOCALS_QUERY.into(),
            Language::TypeScript => None, // TypeScript locals query not available
            Language::Python => None, // Python doesn't have locals query
            Language::C => None,      // C doesn't have locals query
            Language::Cpp => None,    // C++ doesn't have locals query
            Language::Go => None,     // Go doesn't have locals query
        }
    }

    /// Get all available languages
    pub fn all() -> Vec<Language> {
        vec![
            Language::Rust,
            Language::JavaScript,
            Language::TypeScript,
            Language::Python,
            Language::C,
            Language::Cpp,
            Language::Go,
        ]
    }
}

/// Detect language from file path based on extension
pub fn detect_language_from_path<P: AsRef<std::path::Path>>(path: P) -> Option<Language> {
    let path = path.as_ref();
    let extension = path.extension()?.to_str()?.to_lowercase();

    for language in Language::all() {
        if language.file_extensions().contains(&extension.as_str()) {
            return Some(language);
        }
    }

    None
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for Language {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "rust" | "rs" => Ok(Language::Rust),
            "javascript" | "js" => Ok(Language::JavaScript),
            "typescript" | "ts" => Ok(Language::TypeScript),
            "python" | "py" => Ok(Language::Python),
            "c" => Ok(Language::C),
            "cpp" | "c++" | "cxx" => Ok(Language::Cpp),
            "go" => Ok(Language::Go),
            _ => Err(Error::invalid_input_error("language", s, "supported language (rust, javascript, typescript, python, c, cpp, go)")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_properties() {
        let rust = Language::Rust;
        assert_eq!(rust.name(), "Rust");
        assert_eq!(rust.file_extensions(), &["rs"]);
        assert!(rust.supports_highlights());
        assert!(rust.highlights_query().is_some());
    }

    #[test]
    fn test_language_parsing() {
        assert_eq!("rust".parse::<Language>().unwrap(), Language::Rust);
        assert_eq!("javascript".parse::<Language>().unwrap(), Language::JavaScript);
        assert_eq!("python".parse::<Language>().unwrap(), Language::Python);
        assert!("unknown".parse::<Language>().is_err());
    }

    #[test]
    fn test_tree_sitter_language() {
        for lang in Language::all() {
            assert!(lang.tree_sitter_language().is_ok());
        }
    }
}
