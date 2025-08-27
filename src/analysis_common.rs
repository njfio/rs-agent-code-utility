//! Common analysis utilities shared across refactoring, performance, and smart refactoring modules
//! 
//! This module provides shared functionality to eliminate code duplication and improve maintainability.

use crate::{FileInfo, Symbol, Result, Language, Parser, SyntaxTree};
use std::collections::HashMap;

/// Common file analysis patterns shared across modules
pub struct FileAnalyzer;

impl FileAnalyzer {
    /// Analyze file content with error handling and parsing
    pub fn analyze_file_content<F, T>(file: &FileInfo, analyzer: F) -> Result<T>
    where
        F: FnOnce(&str, &str) -> Result<T>,
        T: Default,
    {
        match std::fs::read_to_string(&file.path) {
            Ok(content) => analyzer(&content, &file.language),
            Err(e) => {
                eprintln!("Warning: Failed to read file {}: {}", file.path.display(), e);
                Ok(T::default())
            }
        }
    }

    /// Parse file content using tree-sitter with error handling
    pub fn parse_file_content(content: &str, language: &str) -> Result<SyntaxTree> {
        let lang = Self::string_to_language(language)?;
        let parser = Parser::new(lang)?;
        parser.parse(content, None)
    }

    /// Convert string language name to Language enum
    pub fn string_to_language(language: &str) -> Result<Language> {
        match language.to_lowercase().as_str() {
            "rust" => Ok(Language::Rust),
            "python" => Ok(Language::Python),
            "javascript" => Ok(Language::JavaScript),
            "typescript" => Ok(Language::TypeScript),
            "c" => Ok(Language::C),
            "cpp" | "c++" => Ok(Language::Cpp),
            "go" => Ok(Language::Go),
            _ => Err(crate::error::Error::language_error(language, "language parsing")),
        }
    }

    /// Filter symbols by type with common patterns
    pub fn filter_symbols_by_type<'a>(symbols: &'a [Symbol], symbol_types: &[&str]) -> Vec<&'a Symbol> {
        symbols.iter()
            .filter(|s| symbol_types.contains(&s.kind.as_str()))
            .collect()
    }

    /// Get function and method symbols from file
    pub fn get_function_symbols(file: &FileInfo) -> Vec<&Symbol> {
        Self::filter_symbols_by_type(&file.symbols, &["function", "method"])
    }

    /// Check if file is considered large based on line count
    pub fn is_large_file(file: &FileInfo, threshold: usize) -> bool {
        file.lines > threshold
    }
}

/// Common complexity calculation utilities
pub struct ComplexityAnalyzer;

impl ComplexityAnalyzer {
    /// Calculate function complexity using shared patterns
    pub fn calculate_function_complexity(content: &str, language: &str, _function_name: &str) -> f64 {
        let mut complexity = 1.0;
        
        // Count control flow statements
        complexity += Self::count_control_flow_statements(content, language);
        
        // Count nested structures
        complexity += Self::count_nesting_depth(content, language) as f64 * 0.5;
        
        // Language-specific complexity factors
        complexity += Self::get_language_specific_complexity(content, language);
        
        complexity
    }

    /// Count control flow statements in code
    fn count_control_flow_statements(content: &str, language: &str) -> f64 {
        let control_keywords = match language.to_lowercase().as_str() {
            "rust" => vec!["if", "else", "match", "while", "for", "loop"],
            "python" => vec!["if", "elif", "else", "while", "for", "try", "except"],
            "javascript" | "typescript" => vec!["if", "else", "switch", "while", "for", "try", "catch"],
            "c" | "cpp" | "c++" => vec!["if", "else", "switch", "while", "for", "do"],
            "go" => vec!["if", "else", "switch", "for", "select"],
            _ => vec!["if", "else", "while", "for"],
        };

        let mut count = 0.0;
        for keyword in control_keywords {
            count += content.matches(&format!(" {} ", keyword)).count() as f64;
            count += content.matches(&format!("\t{} ", keyword)).count() as f64;
            count += content.matches(&format!("\n{} ", keyword)).count() as f64;
        }
        
        count
    }

    /// Count maximum nesting depth
    fn count_nesting_depth(content: &str, _language: &str) -> usize {
        let mut max_depth: usize = 0;
        let mut current_depth: usize = 0;

        for ch in content.chars() {
            match ch {
                '{' => {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth);
                },
                '}' => {
                    current_depth = current_depth.saturating_sub(1);
                },
                _ => {}
            }
        }

        max_depth
    }

    /// Get language-specific complexity factors
    fn get_language_specific_complexity(content: &str, language: &str) -> f64 {
        match language.to_lowercase().as_str() {
            "rust" => {
                // Rust-specific patterns
                let mut complexity = 0.0;
                complexity += content.matches("unsafe").count() as f64 * 2.0;
                complexity += content.matches("unwrap()").count() as f64 * 0.5;
                complexity += content.matches("expect(").count() as f64 * 0.3;
                complexity
            },
            "python" => {
                // Python-specific patterns
                let mut complexity = 0.0;
                complexity += content.matches("lambda").count() as f64 * 0.5;
                complexity += content.matches("list comprehension").count() as f64 * 0.3;
                complexity
            },
            "javascript" | "typescript" => {
                // JavaScript-specific patterns
                let mut complexity = 0.0;
                complexity += content.matches("async").count() as f64 * 0.5;
                complexity += content.matches("await").count() as f64 * 0.3;
                complexity += content.matches("Promise").count() as f64 * 0.3;
                complexity
            },
            _ => 0.0,
        }
    }
}

/// Common pattern detection utilities
pub struct PatternAnalyzer;

impl PatternAnalyzer {
    /// Detect duplicate code patterns between functions
    pub fn calculate_function_similarity(func1: &Symbol, func2: &Symbol) -> f64 {
        // Simple similarity based on name patterns and length
        let name_similarity = Self::calculate_name_similarity(&func1.name, &func2.name);
        let length_similarity = Self::calculate_length_similarity(func1, func2);
        
        (name_similarity + length_similarity) / 2.0
    }

    /// Calculate name similarity between two functions
    fn calculate_name_similarity(name1: &str, name2: &str) -> f64 {
        if name1 == name2 {
            return 1.0;
        }
        
        // Check for common prefixes/suffixes
        let common_prefix = Self::longest_common_prefix(name1, name2);
        let common_suffix = Self::longest_common_suffix(name1, name2);
        
        let total_common = common_prefix + common_suffix;
        let max_length = name1.len().max(name2.len());
        
        if max_length == 0 {
            0.0
        } else {
            total_common as f64 / max_length as f64
        }
    }

    /// Calculate length similarity between two functions
    fn calculate_length_similarity(func1: &Symbol, func2: &Symbol) -> f64 {
        let len1 = func1.end_line - func1.start_line;
        let len2 = func2.end_line - func2.start_line;
        
        if len1 == 0 && len2 == 0 {
            return 1.0;
        }
        
        let min_len = len1.min(len2) as f64;
        let max_len = len1.max(len2) as f64;
        
        if max_len == 0.0 {
            1.0
        } else {
            min_len / max_len
        }
    }

    /// Find longest common prefix
    fn longest_common_prefix(s1: &str, s2: &str) -> usize {
        s1.chars()
            .zip(s2.chars())
            .take_while(|(c1, c2)| c1 == c2)
            .count()
    }

    /// Find longest common suffix
    fn longest_common_suffix(s1: &str, s2: &str) -> usize {
        s1.chars()
            .rev()
            .zip(s2.chars().rev())
            .take_while(|(c1, c2)| c1 == c2)
            .count()
    }

    /// Detect string concatenation in loops
    pub fn detect_string_concatenation_in_loops(content: &str) -> bool {
        // Look for patterns like: for ... { ... += ... }
        let lines: Vec<&str> = content.lines().collect();
        let mut in_loop = false;
        
        for line in lines {
            let trimmed = line.trim();
            
            // Check for loop start
            if trimmed.starts_with("for ") || trimmed.starts_with("while ") {
                in_loop = true;
                continue;
            }
            
            // Check for loop end
            if trimmed == "}" && in_loop {
                in_loop = false;
                continue;
            }
            
            // Check for string concatenation in loop
            if in_loop && (trimmed.contains("+=") || trimmed.contains("+ ")) {
                return true;
            }
        }
        
        false
    }

    /// Count nested loops in content
    pub fn count_nested_loops(content: &str, language: &str) -> usize {
        let loop_keywords = match language.to_lowercase().as_str() {
            "rust" => vec!["for ", "while ", "loop "],
            "python" => vec!["for ", "while "],
            "javascript" | "typescript" => vec!["for ", "while "],
            "c" | "cpp" | "c++" => vec!["for ", "while ", "do "],
            "go" => vec!["for "],
            _ => vec!["for ", "while "],
        };

        let mut max_depth: usize = 0;
        let mut current_depth: usize = 0;
        let lines: Vec<&str> = content.lines().collect();
        
        for line in lines {
            let trimmed = line.trim();
            
            // Check for loop start
            for keyword in &loop_keywords {
                if trimmed.starts_with(keyword) {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth);
                    break;
                }
            }
            
            // Check for block end
            if trimmed == "}" {
                current_depth = current_depth.saturating_sub(1);
            }
        }
        
        max_depth
    }
}

/// Common result aggregation utilities
pub struct ResultAggregator;

impl ResultAggregator {
    /// Aggregate results by category with limits
    pub fn limit_results_by_category<T>(
        mut results: Vec<T>, 
        max_per_category: usize,
        get_category: impl Fn(&T) -> String
    ) -> Vec<T> {
        let mut category_counts: HashMap<String, usize> = HashMap::new();
        
        results.retain(|item| {
            let category = get_category(item);
            let count = category_counts.entry(category).or_insert(0);
            
            if *count < max_per_category {
                *count += 1;
                true
            } else {
                false
            }
        });
        
        results
    }

    /// Sort results by confidence/priority
    pub fn sort_by_confidence<T>(mut results: Vec<T>, get_confidence: impl Fn(&T) -> f64) -> Vec<T> {
        results.sort_by(|a, b| {
            get_confidence(b).partial_cmp(&get_confidence(a)).unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }
}
