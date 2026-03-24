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
    #[cfg(not(feature = "extended-languages"))]
    fn extended_language_error(&self) -> Error {
        Error::not_supported_with_alternative(
            format!("{} grammar", self.name()),
            "this grammar is behind the `extended-languages` feature",
            "enable the `extended-languages` cargo feature",
        )
    }

    /// Get the tree-sitter language for this language
    pub fn tree_sitter_language(&self) -> Result<tree_sitter::Language> {
        match self {
            Language::Rust => Ok(tree_sitter_rust::language()),
            Language::JavaScript => Ok(tree_sitter_javascript::language()),
            Language::TypeScript => {
                #[cfg(feature = "extended-languages")]
                {
                    Ok(tree_sitter_typescript::language_typescript())
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    Err(self.extended_language_error())
                }
            }
            Language::Python => {
                #[cfg(feature = "extended-languages")]
                {
                    Ok(tree_sitter_python::language())
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    Err(self.extended_language_error())
                }
            }
            Language::C => {
                #[cfg(feature = "extended-languages")]
                {
                    Ok(tree_sitter_c::language())
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    Err(self.extended_language_error())
                }
            }
            Language::Cpp => {
                #[cfg(feature = "extended-languages")]
                {
                    Ok(tree_sitter_cpp::language())
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    Err(self.extended_language_error())
                }
            }
            Language::Go => {
                #[cfg(feature = "extended-languages")]
                {
                    Ok(tree_sitter_go::language())
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    Err(self.extended_language_error())
                }
            }
            Language::Java => {
                #[cfg(feature = "extended-languages")]
                {
                    Ok(tree_sitter_java::language())
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    Err(self.extended_language_error())
                }
            }
            Language::Php => {
                #[cfg(feature = "extended-languages")]
                {
                    Ok(tree_sitter_php::language_php())
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    Err(self.extended_language_error())
                }
            }
            Language::Ruby => {
                #[cfg(feature = "extended-languages")]
                {
                    Ok(tree_sitter_ruby::language())
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    Err(self.extended_language_error())
                }
            }
            Language::Swift => {
                #[cfg(feature = "extended-languages")]
                {
                    Ok(tree_sitter_swift::language())
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    Err(self.extended_language_error())
                }
            }
            Language::Kotlin => {
                #[cfg(feature = "extended-languages")]
                {
                    Ok(tree_sitter_kotlin::language())
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    Err(self.extended_language_error())
                }
            }
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
        self.highlights_query().is_some()
    }

    /// Get syntax highlighting query for this language
    pub fn highlights_query(&self) -> Option<&'static str> {
        match self {
            Language::Rust => Some(tree_sitter_rust::HIGHLIGHT_QUERY),
            Language::JavaScript => Some(tree_sitter_javascript::HIGHLIGHT_QUERY),
            Language::TypeScript => {
                #[cfg(feature = "extended-languages")]
                {
                    Some(tree_sitter_typescript::HIGHLIGHT_QUERY)
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    None
                }
            }
            Language::Python => {
                #[cfg(feature = "extended-languages")]
                {
                    Some(tree_sitter_python::HIGHLIGHT_QUERY)
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    None
                }
            }
            Language::C => {
                #[cfg(feature = "extended-languages")]
                {
                    Some(tree_sitter_c::HIGHLIGHT_QUERY)
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    None
                }
            }
            Language::Cpp => {
                #[cfg(feature = "extended-languages")]
                {
                    Some(tree_sitter_cpp::HIGHLIGHT_QUERY)
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    None
                }
            }
            Language::Go => {
                #[cfg(feature = "extended-languages")]
                {
                    Some(tree_sitter_go::HIGHLIGHT_QUERY)
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    None
                }
            }
            Language::Java => {
                #[cfg(feature = "extended-languages")]
                {
                    Some(tree_sitter_java::HIGHLIGHT_QUERY)
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    None
                }
            }
            Language::Php => {
                #[cfg(feature = "extended-languages")]
                {
                    Some(tree_sitter_php::HIGHLIGHT_QUERY)
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    None
                }
            }
            Language::Ruby => {
                #[cfg(feature = "extended-languages")]
                {
                    Some(tree_sitter_ruby::HIGHLIGHT_QUERY)
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    None
                }
            }
            Language::Swift => {
                #[cfg(feature = "extended-languages")]
                {
                    Some(tree_sitter_swift::HIGHLIGHTS_QUERY)
                }
                #[cfg(not(feature = "extended-languages"))]
                {
                    None
                }
            }
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
        let core_languages = vec![Language::Rust, Language::JavaScript];
        #[cfg(feature = "extended-languages")]
        {
            let mut languages = core_languages;
            languages.extend([
                Language::Python,
                Language::TypeScript,
                Language::C,
                Language::Cpp,
                Language::Go,
                Language::Java,
                Language::Php,
                Language::Ruby,
                Language::Swift,
                Language::Kotlin,
            ]);
            languages
        }
        #[cfg(not(feature = "extended-languages"))]
        {
            core_languages
        }
    }
}

/// Detect language from file path based on extension
pub fn detect_language_from_path<P: AsRef<std::path::Path>>(path: P) -> Option<Language> {
    let path = path.as_ref();
    let extension = path.extension()?.to_str()?.to_lowercase();

    Language::all()
        .into_iter()
        .find(|&language| language.file_extensions().contains(&extension.as_str()))
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

        #[cfg(feature = "extended-languages")]
        let php = Language::Php;
        #[cfg(feature = "extended-languages")]
        assert_eq!(php.name(), "PHP");
        #[cfg(feature = "extended-languages")]
        assert_eq!(php.file_extensions(), &["php"]);

        #[cfg(feature = "extended-languages")]
        let swift = Language::Swift;
        #[cfg(feature = "extended-languages")]
        assert_eq!(swift.name(), "Swift");
        #[cfg(feature = "extended-languages")]
        assert_eq!(swift.file_extensions(), &["swift"]);
    }

    #[test]
    fn test_language_parsing() {
        assert_eq!("rust".parse::<Language>().ok(), Some(Language::Rust));
        assert_eq!(
            "javascript".parse::<Language>().ok(),
            Some(Language::JavaScript)
        );
        assert_eq!("python".parse::<Language>().ok(), Some(Language::Python));
        assert_eq!("java".parse::<Language>().ok(), Some(Language::Java));
        assert_eq!("php".parse::<Language>().ok(), Some(Language::Php));
        assert_eq!("ruby".parse::<Language>().ok(), Some(Language::Ruby));
        assert_eq!("swift".parse::<Language>().ok(), Some(Language::Swift));
        assert_eq!("kotlin".parse::<Language>().ok(), Some(Language::Kotlin));
        assert!("unknown".parse::<Language>().is_err());
    }

    #[test]
    fn test_tree_sitter_language() {
        for lang in Language::all() {
            assert!(lang.tree_sitter_language().is_ok());
        }
    }

    #[cfg(not(feature = "extended-languages"))]
    #[test]
    fn test_extended_languages_require_feature() {
        for lang in [
            Language::Python,
            Language::TypeScript,
            Language::C,
            Language::Cpp,
            Language::Go,
            Language::Java,
            Language::Php,
            Language::Ruby,
            Language::Swift,
            Language::Kotlin,
        ] {
            assert!(lang.tree_sitter_language().is_err());
        }
        assert_eq!(detect_language_from_path("example.py"), None);
        assert_eq!(detect_language_from_path("example.ts"), None);
        assert_eq!(detect_language_from_path("example.c"), None);
        assert_eq!(detect_language_from_path("example.cpp"), None);
        assert_eq!(detect_language_from_path("example.go"), None);
        assert_eq!(detect_language_from_path("example.java"), None);
        assert_eq!(detect_language_from_path("example.php"), None);
        assert_eq!(detect_language_from_path("example.rb"), None);
        assert_eq!(detect_language_from_path("example.swift"), None);
        assert_eq!(detect_language_from_path("example.kt"), None);
    }

    #[test]
    fn test_new_language_extensions() {
        assert_eq!(Language::Java.file_extensions(), &["java"]);

        #[cfg(feature = "extended-languages")]
        let php = Language::Php;
        #[cfg(feature = "extended-languages")]
        assert_eq!(php.name(), "PHP");
        #[cfg(feature = "extended-languages")]
        assert_eq!(php.file_extensions(), &["php"]);

        #[cfg(feature = "extended-languages")]
        let swift = Language::Swift;
        #[cfg(feature = "extended-languages")]
        assert_eq!(swift.name(), "Swift");
        #[cfg(feature = "extended-languages")]
        assert_eq!(swift.file_extensions(), &["swift"]);

        #[cfg(feature = "extended-languages")]
        assert_eq!(Language::Ruby.file_extensions(), &["rb"]);
        #[cfg(feature = "extended-languages")]
        assert_eq!(Language::Kotlin.file_extensions(), &["kt", "kts"]);
    }
}
