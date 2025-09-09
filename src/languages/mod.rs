//! Language support for tree-sitter parsers

pub mod c;
pub mod cpp;
pub mod go;
pub mod java;
pub mod javascript;
pub mod kotlin;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;
pub mod swift;
pub mod typescript;

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
    /// Java programming language
    Java,
    /// PHP programming language
    Php,
    /// Ruby programming language
    Ruby,
    /// Swift programming language
    Swift,
    /// Kotlin programming language
    Kotlin,
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
            Language::Java => Ok(tree_sitter_java::language()),
            Language::Php => Ok(tree_sitter_php::language_php()),
            Language::Ruby => Ok(tree_sitter_ruby::language()),
            Language::Swift => Ok(tree_sitter_swift::language()),
            Language::Kotlin => Ok(tree_sitter_kotlin::language()),
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
            Language::Java => "Java",
            Language::Php => "PHP",
            Language::Ruby => "Ruby",
            Language::Swift => "Swift",
            Language::Kotlin => "Kotlin",
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
            Language::Java => &["java"],
            Language::Php => &["php"],
            Language::Ruby => &["rb"],
            Language::Swift => &["swift"],
            Language::Kotlin => &["kt", "kts"],
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
            Language::Java => "0.21.0",
            Language::Php => "0.21.0",
            Language::Ruby => "0.21.0",
            Language::Swift => "0.21.0",
            Language::Kotlin => "0.21.0",
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
            Language::Java => true,
            Language::Php => true,
            Language::Ruby => true,
            Language::Swift => true,
            Language::Kotlin => true,
        }
    }

    /// Get syntax highlighting query for this language
    pub fn highlights_query(&self) -> Option<&'static str> {
        match self {
            Language::Rust => Some(tree_sitter_rust::HIGHLIGHT_QUERY),
            Language::JavaScript => Some(tree_sitter_javascript::HIGHLIGHT_QUERY),
            Language::TypeScript => Some(tree_sitter_typescript::HIGHLIGHT_QUERY),
            Language::Python => Some(tree_sitter_python::HIGHLIGHT_QUERY),
            Language::C => Some(tree_sitter_c::HIGHLIGHT_QUERY),
            Language::Cpp => Some(tree_sitter_cpp::HIGHLIGHT_QUERY),
            Language::Go => Some(tree_sitter_go::HIGHLIGHT_QUERY),
            Language::Java => Some(tree_sitter_java::HIGHLIGHT_QUERY),
            Language::Php => Some(tree_sitter_php::HIGHLIGHT_QUERY),
            Language::Ruby => Some(tree_sitter_ruby::HIGHLIGHT_QUERY),
            Language::Swift => Some(tree_sitter_swift::HIGHLIGHTS_QUERY),
            Language::Kotlin => None, // HIGHLIGHTS_QUERY not available in tree-sitter-kotlin 0.2.11
        }
    }

    /// Get injections query for this language (if available)
    pub fn injections_query(&self) -> Option<&'static str> {
        match self {
            Language::Rust => tree_sitter_rust::INJECTIONS_QUERY.into(),
            Language::JavaScript => tree_sitter_javascript::INJECTION_QUERY.into(),
            Language::TypeScript => None, // TypeScript injections query not available
            Language::Python => None,     // Python doesn't have injections query
            Language::C => None,          // C doesn't have injections query
            Language::Cpp => None,        // C++ doesn't have injections query
            Language::Go => None,         // Go doesn't have injections query
            Language::Java => None,       // Java doesn't have injections query
            Language::Php => None,        // PHP doesn't have injections query
            Language::Ruby => None,       // Ruby doesn't have injections query
            Language::Swift => None,      // Swift doesn't have injections query
            Language::Kotlin => None,     // Kotlin doesn't have injections query
        }
    }

    /// Get locals query for this language (if available)
    pub fn locals_query(&self) -> Option<&'static str> {
        match self {
            Language::Rust => None, // Rust doesn't have locals query in this version
            Language::JavaScript => tree_sitter_javascript::LOCALS_QUERY.into(),
            Language::TypeScript => None, // TypeScript locals query not available
            Language::Python => None,     // Python doesn't have locals query
            Language::C => None,          // C doesn't have locals query
            Language::Cpp => None,        // C++ doesn't have locals query
            Language::Go => None,         // Go doesn't have locals query
            Language::Java => None,       // Java doesn't have locals query
            Language::Php => None,        // PHP doesn't have locals query
            Language::Ruby => None,       // Ruby doesn't have locals query
            Language::Swift => None,      // Swift doesn't have locals query
            Language::Kotlin => None,     // Kotlin doesn't have locals query
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
            Language::Java,
            Language::Php,
            Language::Ruby,
            Language::Swift,
            Language::Kotlin,
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
            "java" => Ok(Language::Java),
            "php" => Ok(Language::Php),
            "ruby" | "rb" => Ok(Language::Ruby),
            "swift" => Ok(Language::Swift),
            "kotlin" | "kt" => Ok(Language::Kotlin),
            _ => Err(Error::invalid_input_error(
                "language",
                s,
                "supported language (rust, javascript, typescript, python, c, cpp, go, java, php, ruby, swift, kotlin)",
            )),
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

        let java = Language::Java;
        assert_eq!(java.name(), "Java");
        assert_eq!(java.file_extensions(), &["java"]);

        let php = Language::Php;
        assert_eq!(php.name(), "PHP");
        assert_eq!(php.file_extensions(), &["php"]);

        let swift = Language::Swift;
        assert_eq!(swift.name(), "Swift");
        assert_eq!(swift.file_extensions(), &["swift"]);
    }

    #[test]
    fn test_language_parsing() {
        assert_eq!("rust".parse::<Language>().unwrap(), Language::Rust);
        assert_eq!(
            "javascript".parse::<Language>().unwrap(),
            Language::JavaScript
        );
        assert_eq!("python".parse::<Language>().unwrap(), Language::Python);
        assert_eq!("java".parse::<Language>().unwrap(), Language::Java);
        assert_eq!("php".parse::<Language>().unwrap(), Language::Php);
        assert_eq!("ruby".parse::<Language>().unwrap(), Language::Ruby);
        assert_eq!("swift".parse::<Language>().unwrap(), Language::Swift);
        assert_eq!("kotlin".parse::<Language>().unwrap(), Language::Kotlin);
        assert!("unknown".parse::<Language>().is_err());
    }

    #[test]
    fn test_tree_sitter_language() {
        for lang in Language::all() {
            assert!(lang.tree_sitter_language().is_ok());
        }
    }

    #[test]
    fn test_new_language_extensions() {
        assert_eq!(Language::Java.file_extensions(), &["java"]);
        assert_eq!(Language::Php.file_extensions(), &["php"]);
        assert_eq!(Language::Ruby.file_extensions(), &["rb"]);
        assert_eq!(Language::Swift.file_extensions(), &["swift"]);
        assert_eq!(Language::Kotlin.file_extensions(), &["kt", "kts"]);
    }
}
