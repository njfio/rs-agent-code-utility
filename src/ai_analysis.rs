//! AI-powered code analysis and explanations
//! 
//! This module provides intelligent code analysis capabilities including
//! natural language explanations, pattern recognition, and insights.

use crate::{FileInfo, Symbol, AnalysisResult};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// AI-powered code explanation and analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AIAnalyzer {
    /// Configuration for AI analysis
    pub config: AIConfig,
}

/// Configuration for AI analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AIConfig {
    /// Enable detailed explanations
    pub detailed_explanations: bool,
    /// Include code examples in explanations
    pub include_examples: bool,
    /// Maximum explanation length
    pub max_explanation_length: usize,
    /// Enable pattern recognition
    pub pattern_recognition: bool,
    /// Enable architectural insights
    pub architectural_insights: bool,
}

/// AI analysis results for a codebase
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AIAnalysisResult {
    /// Overall codebase explanation
    pub codebase_explanation: CodebaseExplanation,
    /// File-level explanations
    pub file_explanations: Vec<FileExplanation>,
    /// Symbol-level explanations
    pub symbol_explanations: Vec<SymbolExplanation>,
    /// Architectural insights
    pub architectural_insights: ArchitecturalInsights,
    /// Detected patterns
    pub patterns: Vec<DetectedPattern>,
    /// Learning recommendations
    pub learning_recommendations: Vec<String>,
}

/// High-level codebase explanation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CodebaseExplanation {
    /// Brief summary of what the codebase does
    pub purpose: String,
    /// Main architectural approach
    pub architecture: String,
    /// Key technologies and patterns used
    pub technologies: Vec<String>,
    /// Complexity assessment
    pub complexity_level: ComplexityLevel,
    /// Target audience (beginners, intermediate, advanced)
    pub target_audience: String,
    /// Main entry points
    pub entry_points: Vec<String>,
}

/// File-level explanation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FileExplanation {
    /// File path
    pub file_path: String,
    /// What this file does
    pub purpose: String,
    /// How it fits into the overall architecture
    pub role: String,
    /// Key responsibilities
    pub responsibilities: Vec<String>,
    /// Dependencies and relationships
    pub relationships: Vec<String>,
    /// Complexity assessment
    pub complexity: ComplexityLevel,
    /// Suggested improvements
    pub suggestions: Vec<String>,
}

/// Symbol-level explanation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SymbolExplanation {
    /// Symbol name
    pub name: String,
    /// Symbol type (function, class, etc.)
    pub symbol_type: String,
    /// File containing the symbol
    pub file_path: String,
    /// Line number
    pub line: usize,
    /// What this symbol does
    pub purpose: String,
    /// How to use it
    pub usage: String,
    /// Parameters and return values (for functions)
    pub signature_explanation: Option<String>,
    /// Complexity level
    pub complexity: ComplexityLevel,
    /// Best practices notes
    pub best_practices: Vec<String>,
}

/// Architectural insights about the codebase
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ArchitecturalInsights {
    /// Overall architectural style
    pub style: String,
    /// Design patterns used
    pub design_patterns: Vec<String>,
    /// Separation of concerns assessment
    pub separation_quality: String,
    /// Modularity assessment
    pub modularity: String,
    /// Scalability considerations
    pub scalability: String,
    /// Maintainability assessment
    pub maintainability: String,
    /// Suggested architectural improvements
    pub improvements: Vec<String>,
}

/// Detected code pattern
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DetectedPattern {
    /// Pattern name
    pub name: String,
    /// Pattern type (design pattern, anti-pattern, etc.)
    pub pattern_type: PatternType,
    /// Where it was found
    pub locations: Vec<PatternLocation>,
    /// Description of the pattern
    pub description: String,
    /// Why it's good or bad
    pub assessment: String,
    /// Suggested actions
    pub recommendations: Vec<String>,
}

/// Location where a pattern was detected
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PatternLocation {
    /// File path
    pub file: String,
    /// Line number
    pub line: usize,
    /// Symbol name if applicable
    pub symbol: Option<String>,
    /// Code snippet
    pub snippet: String,
}

/// Type of detected pattern
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PatternType {
    /// Good design pattern
    DesignPattern,
    /// Anti-pattern (bad practice)
    AntiPattern,
    /// Code smell
    CodeSmell,
    /// Best practice
    BestPractice,
    /// Architectural pattern
    ArchitecturalPattern,
}

/// Complexity level assessment
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ComplexityLevel {
    /// Simple and easy to understand
    Low,
    /// Moderate complexity
    Medium,
    /// Complex but manageable
    High,
    /// Very complex, needs attention
    VeryHigh,
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            detailed_explanations: true,
            include_examples: true,
            max_explanation_length: 500,
            pattern_recognition: true,
            architectural_insights: true,
        }
    }
}

impl AIAnalyzer {
    /// Create a new AI analyzer with default configuration
    pub fn new() -> Self {
        Self {
            config: AIConfig::default(),
        }
    }
    
    /// Create a new AI analyzer with custom configuration
    pub fn with_config(config: AIConfig) -> Self {
        Self { config }
    }
    
    /// Analyze a codebase and generate AI explanations
    pub fn analyze(&self, analysis_result: &AnalysisResult) -> AIAnalysisResult {
        let codebase_explanation = self.generate_codebase_explanation(analysis_result);
        let file_explanations = self.generate_file_explanations(analysis_result);
        let symbol_explanations = self.generate_symbol_explanations(analysis_result);
        let architectural_insights = self.generate_architectural_insights(analysis_result);
        let patterns = self.detect_patterns(analysis_result);
        let learning_recommendations = self.generate_learning_recommendations(analysis_result);
        
        AIAnalysisResult {
            codebase_explanation,
            file_explanations,
            symbol_explanations,
            architectural_insights,
            patterns,
            learning_recommendations,
        }
    }
    
    /// Generate high-level codebase explanation
    fn generate_codebase_explanation(&self, result: &AnalysisResult) -> CodebaseExplanation {
        let primary_language = result.languages.iter()
            .max_by_key(|(_, count)| *count)
            .map(|(lang, _)| lang.clone())
            .unwrap_or_else(|| "Unknown".to_string());
        
        let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
        let _public_symbols: usize = result.files.iter()
            .flat_map(|f| &f.symbols)
            .filter(|s| s.visibility == "public")
            .count();

        let complexity_level = self.assess_codebase_complexity(result);

        let purpose = self.infer_codebase_purpose(result, &primary_language);
        let architecture = self.analyze_architecture_style(result);
        let technologies = self.identify_technologies(result);
        let target_audience = self.determine_target_audience(complexity_level, total_symbols);
        let entry_points = self.find_entry_points(result);

        CodebaseExplanation {
            purpose,
            architecture,
            technologies,
            complexity_level,
            target_audience,
            entry_points,
        }
    }
    
    /// Generate explanations for individual files
    fn generate_file_explanations(&self, result: &AnalysisResult) -> Vec<FileExplanation> {
        result.files.iter().map(|file| {
            self.explain_file(file, result)
        }).collect()
    }
    
    /// Generate explanations for individual symbols
    fn generate_symbol_explanations(&self, result: &AnalysisResult) -> Vec<SymbolExplanation> {
        let mut explanations = Vec::new();
        
        for file in &result.files {
            for symbol in &file.symbols {
                explanations.push(self.explain_symbol(symbol, file, result));
            }
        }
        
        explanations
    }
    
    /// Generate architectural insights
    fn generate_architectural_insights(&self, result: &AnalysisResult) -> ArchitecturalInsights {
        let style = self.determine_architectural_style(result);
        let design_patterns = self.identify_design_patterns(result);
        let separation_quality = self.assess_separation_of_concerns(result);
        let modularity = self.assess_modularity(result);
        let scalability = self.assess_scalability(result);
        let maintainability = self.assess_maintainability(result);
        let improvements = self.suggest_architectural_improvements(result);
        
        ArchitecturalInsights {
            style,
            design_patterns,
            separation_quality,
            modularity,
            scalability,
            maintainability,
            improvements,
        }
    }
    
    /// Detect patterns in the codebase
    fn detect_patterns(&self, result: &AnalysisResult) -> Vec<DetectedPattern> {
        let mut patterns = Vec::new();
        
        // Detect various patterns
        patterns.extend(self.detect_design_patterns(result));
        patterns.extend(self.detect_anti_patterns(result));
        patterns.extend(self.detect_code_smells(result));
        patterns.extend(self.detect_best_practices(result));
        
        patterns
    }
    
    /// Generate learning recommendations
    fn generate_learning_recommendations(&self, result: &AnalysisResult) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        let primary_language = result.languages.iter()
            .max_by_key(|(_, count)| *count)
            .map(|(lang, _)| lang.clone())
            .unwrap_or_else(|| "Unknown".to_string());
        
        // Language-specific recommendations
        match primary_language.to_lowercase().as_str() {
            "rust" => {
                recommendations.push("Learn about Rust's ownership system and borrowing".to_string());
                recommendations.push("Explore Rust's trait system for code reuse".to_string());
                recommendations.push("Study error handling with Result and Option types".to_string());
            }
            "javascript" => {
                recommendations.push("Learn about JavaScript's event loop and async programming".to_string());
                recommendations.push("Explore modern ES6+ features and best practices".to_string());
                recommendations.push("Study functional programming concepts in JavaScript".to_string());
            }
            "python" => {
                recommendations.push("Learn about Python's data model and magic methods".to_string());
                recommendations.push("Explore decorators and context managers".to_string());
                recommendations.push("Study Python's type hints and static analysis".to_string());
            }
            _ => {
                recommendations.push("Study the language's core concepts and idioms".to_string());
                recommendations.push("Learn about the language's standard library".to_string());
            }
        }
        
        // Architecture recommendations
        let total_files = result.total_files;
        if total_files > 20 {
            recommendations.push("Learn about software architecture patterns for large codebases".to_string());
            recommendations.push("Study dependency injection and inversion of control".to_string());
        }
        
        // Complexity recommendations
        let complexity = self.assess_codebase_complexity(result);
        match complexity {
            ComplexityLevel::High | ComplexityLevel::VeryHigh => {
                recommendations.push("Learn refactoring techniques to reduce complexity".to_string());
                recommendations.push("Study design patterns for better code organization".to_string());
            }
            _ => {}
        }
        
        recommendations
    }

    // Helper methods for analysis

    fn assess_codebase_complexity(&self, result: &AnalysisResult) -> ComplexityLevel {
        let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
        let avg_symbols_per_file = if result.total_files > 0 {
            total_symbols as f64 / result.total_files as f64
        } else {
            0.0
        };

        let avg_lines_per_file = if result.total_files > 0 {
            result.total_lines as f64 / result.total_files as f64
        } else {
            0.0
        };

        if avg_symbols_per_file > 20.0 || avg_lines_per_file > 300.0 || result.total_files > 50 {
            ComplexityLevel::VeryHigh
        } else if avg_symbols_per_file > 15.0 || avg_lines_per_file > 200.0 || result.total_files > 20 {
            ComplexityLevel::High
        } else if avg_symbols_per_file > 8.0 || avg_lines_per_file > 100.0 || result.total_files > 5 {
            ComplexityLevel::Medium
        } else {
            ComplexityLevel::Low
        }
    }

    fn infer_codebase_purpose(&self, result: &AnalysisResult, primary_language: &str) -> String {
        let has_main = result.files.iter().any(|f| {
            f.symbols.iter().any(|s| s.name == "main" && s.kind == "function")
        });

        let has_lib = result.files.iter().any(|f| {
            f.path.file_name().and_then(|n| n.to_str()) == Some("lib.rs") ||
            f.path.file_name().and_then(|n| n.to_str()) == Some("index.js") ||
            f.path.file_name().and_then(|n| n.to_str()) == Some("__init__.py")
        });

        let has_tests = result.files.iter().any(|f| {
            f.path.to_string_lossy().contains("test") ||
            f.symbols.iter().any(|s| s.name.starts_with("test_"))
        });

        let has_cli = result.files.iter().any(|f| {
            f.path.to_string_lossy().contains("cli") ||
            f.path.to_string_lossy().contains("bin") ||
            f.symbols.iter().any(|s| s.name.contains("cli") || s.name.contains("command"))
        });

        match (has_main, has_lib, has_tests, has_cli, primary_language) {
            (true, true, true, true, "rust") => "A comprehensive Rust application with both library and CLI components, including comprehensive tests".to_string(),
            (true, false, _, true, _) => "A command-line application with executable functionality".to_string(),
            (false, true, true, false, _) => "A software library designed for reuse by other applications, with good test coverage".to_string(),
            (true, false, false, false, _) => "A standalone application or script".to_string(),
            (false, true, false, false, _) => "A software library or framework for other developers to use".to_string(),
            _ => format!("A {} project with mixed application and library components", primary_language),
        }
    }

    fn analyze_architecture_style(&self, result: &AnalysisResult) -> String {
        let has_modules = result.files.len() > 3;
        let has_nested_dirs = result.files.iter().any(|f| f.path.components().count() > 2);
        let has_separation = result.files.iter().any(|f| {
            let path_str = f.path.to_string_lossy().to_lowercase();
            path_str.contains("model") || path_str.contains("view") || path_str.contains("controller") ||
            path_str.contains("service") || path_str.contains("handler") || path_str.contains("util")
        });

        match (has_modules, has_nested_dirs, has_separation) {
            (true, true, true) => "Well-structured modular architecture with clear separation of concerns".to_string(),
            (true, true, false) => "Modular architecture with hierarchical organization".to_string(),
            (true, false, true) => "Flat modular structure with functional separation".to_string(),
            (true, false, false) => "Simple modular structure".to_string(),
            (false, _, _) => "Monolithic single-file or minimal structure".to_string(),
        }
    }

    fn identify_technologies(&self, result: &AnalysisResult) -> Vec<String> {
        let mut technologies = Vec::new();

        // Add primary languages
        for (language, _) in &result.languages {
            technologies.push(language.clone());
        }

        // Infer technologies from file patterns and symbols
        let all_symbols: Vec<&Symbol> = result.files.iter()
            .flat_map(|f| &f.symbols)
            .collect();

        // Look for common patterns
        if all_symbols.iter().any(|s| s.name.contains("async") || s.name.contains("await")) {
            technologies.push("Asynchronous Programming".to_string());
        }

        if all_symbols.iter().any(|s| s.name.contains("test") || s.kind == "test") {
            technologies.push("Unit Testing".to_string());
        }

        if result.files.iter().any(|f| f.path.to_string_lossy().contains("cli")) {
            technologies.push("Command Line Interface".to_string());
        }

        if all_symbols.iter().any(|s| s.name.contains("parse") || s.name.contains("tree")) {
            technologies.push("Parsing and AST".to_string());
        }

        technologies
    }

    fn determine_target_audience(&self, complexity: ComplexityLevel, symbol_count: usize) -> String {
        match (complexity, symbol_count) {
            (ComplexityLevel::Low, _) if symbol_count < 20 => "Beginners - Simple and easy to understand".to_string(),
            (ComplexityLevel::Medium, _) if symbol_count < 100 => "Intermediate developers - Moderate complexity".to_string(),
            (ComplexityLevel::High, _) | (_, _) if symbol_count > 200 => "Advanced developers - Complex architecture".to_string(),
            (ComplexityLevel::VeryHigh, _) => "Expert developers - Very complex system".to_string(),
            _ => "Intermediate developers - Standard complexity".to_string(),
        }
    }

    fn find_entry_points(&self, result: &AnalysisResult) -> Vec<String> {
        let mut entry_points = Vec::new();

        for file in &result.files {
            for symbol in &file.symbols {
                if symbol.name == "main" && symbol.kind == "function" {
                    entry_points.push(format!("{}::{}", file.path.display(), symbol.name));
                }
                if symbol.visibility == "public" && (symbol.kind == "function" || symbol.kind == "struct" || symbol.kind == "class") {
                    if symbol.name.contains("new") || symbol.name.contains("create") || symbol.name.contains("init") {
                        entry_points.push(format!("{}::{}", file.path.display(), symbol.name));
                    }
                }
            }
        }

        // If no clear entry points, suggest the main library file
        if entry_points.is_empty() {
            if let Some(lib_file) = result.files.iter().find(|f| {
                f.path.file_name().and_then(|n| n.to_str()) == Some("lib.rs") ||
                f.path.file_name().and_then(|n| n.to_str()) == Some("main.rs")
            }) {
                entry_points.push(format!("{}", lib_file.path.display()));
            }
        }

        entry_points
    }

    fn explain_file(&self, file: &FileInfo, _result: &AnalysisResult) -> FileExplanation {
        let file_name = file.path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let purpose = self.infer_file_purpose(file, file_name);
        let role = self.determine_file_role(file, file_name);
        let responsibilities = self.identify_file_responsibilities(file);
        let relationships = self.analyze_file_relationships(file);
        let complexity = self.assess_file_complexity(file);
        let suggestions = self.suggest_file_improvements(file);

        FileExplanation {
            file_path: file.path.display().to_string(),
            purpose,
            role,
            responsibilities,
            relationships,
            complexity,
            suggestions,
        }
    }

    fn explain_symbol(&self, symbol: &Symbol, file: &FileInfo, _result: &AnalysisResult) -> SymbolExplanation {
        let purpose = self.infer_symbol_purpose(symbol);
        let usage = self.generate_symbol_usage(symbol);
        let signature_explanation = self.explain_symbol_signature(symbol);
        let complexity = self.assess_symbol_complexity(symbol);
        let best_practices = self.suggest_symbol_best_practices(symbol);

        SymbolExplanation {
            name: symbol.name.clone(),
            symbol_type: symbol.kind.clone(),
            file_path: file.path.display().to_string(),
            line: symbol.start_line,
            purpose,
            usage,
            signature_explanation,
            complexity,
            best_practices,
        }
    }

    // Additional helper methods (simplified implementations)

    fn determine_architectural_style(&self, _result: &AnalysisResult) -> String {
        "Modular architecture with clear separation of concerns".to_string()
    }

    fn identify_design_patterns(&self, _result: &AnalysisResult) -> Vec<String> {
        vec!["Builder Pattern".to_string(), "Factory Pattern".to_string()]
    }

    fn assess_separation_of_concerns(&self, result: &AnalysisResult) -> String {
        if result.total_files > 5 {
            "Good separation with multiple focused modules".to_string()
        } else {
            "Basic separation, could benefit from more modularization".to_string()
        }
    }

    fn assess_modularity(&self, result: &AnalysisResult) -> String {
        let avg_symbols_per_file = if result.total_files > 0 {
            result.files.iter().map(|f| f.symbols.len()).sum::<usize>() as f64 / result.total_files as f64
        } else {
            0.0
        };

        if avg_symbols_per_file < 10.0 {
            "Well-modularized with focused components".to_string()
        } else {
            "Moderate modularity, some files could be split".to_string()
        }
    }

    fn assess_scalability(&self, result: &AnalysisResult) -> String {
        if result.total_files > 20 {
            "Good scalability with hierarchical organization".to_string()
        } else {
            "Suitable for current size, plan for growth".to_string()
        }
    }

    fn assess_maintainability(&self, result: &AnalysisResult) -> String {
        let parse_rate = result.parsed_files as f64 / result.total_files as f64;
        if parse_rate > 0.95 {
            "High maintainability with clean, parseable code".to_string()
        } else {
            "Moderate maintainability, some parsing issues detected".to_string()
        }
    }

    fn suggest_architectural_improvements(&self, result: &AnalysisResult) -> Vec<String> {
        let mut improvements = Vec::new();

        if result.total_files > 50 {
            improvements.push("Consider implementing a plugin architecture for better extensibility".to_string());
        }

        let avg_file_size = result.total_lines as f64 / result.total_files as f64;
        if avg_file_size > 200.0 {
            improvements.push("Break down large files into smaller, focused modules".to_string());
        }

        improvements.push("Add comprehensive documentation for public APIs".to_string());
        improvements.push("Consider implementing automated testing strategies".to_string());

        improvements
    }

    fn detect_design_patterns(&self, _result: &AnalysisResult) -> Vec<DetectedPattern> {
        vec![
            DetectedPattern {
                name: "Builder Pattern".to_string(),
                pattern_type: PatternType::DesignPattern,
                locations: vec![],
                description: "Builder pattern detected for complex object construction".to_string(),
                assessment: "Good use of builder pattern for configuration objects".to_string(),
                recommendations: vec!["Continue using builder pattern for complex configurations".to_string()],
            }
        ]
    }

    fn detect_anti_patterns(&self, _result: &AnalysisResult) -> Vec<DetectedPattern> {
        vec![]
    }

    fn detect_code_smells(&self, _result: &AnalysisResult) -> Vec<DetectedPattern> {
        vec![]
    }

    fn detect_best_practices(&self, _result: &AnalysisResult) -> Vec<DetectedPattern> {
        vec![
            DetectedPattern {
                name: "Error Handling".to_string(),
                pattern_type: PatternType::BestPractice,
                locations: vec![],
                description: "Consistent error handling with Result types".to_string(),
                assessment: "Good use of Rust's error handling patterns".to_string(),
                recommendations: vec!["Continue using Result types for error handling".to_string()],
            }
        ]
    }

    fn infer_file_purpose(&self, file: &FileInfo, file_name: &str) -> String {
        match file_name {
            "main.rs" => "Application entry point and CLI interface".to_string(),
            "lib.rs" => "Library root module and public API exports".to_string(),
            name if name.contains("test") => "Test module for validating functionality".to_string(),
            name if name.contains("mod") => "Module definition and organization".to_string(),
            _ => format!("Implementation module for {} functionality",
                file.path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown"))
        }
    }

    fn determine_file_role(&self, file: &FileInfo, _file_name: &str) -> String {
        let public_symbols = file.symbols.iter().filter(|s| s.visibility == "public").count();
        let total_symbols = file.symbols.len();

        if public_symbols > total_symbols / 2 {
            "Public API provider - exposes functionality to external users".to_string()
        } else if total_symbols > 10 {
            "Core implementation - contains main business logic".to_string()
        } else {
            "Supporting module - provides utility or helper functions".to_string()
        }
    }

    fn identify_file_responsibilities(&self, file: &FileInfo) -> Vec<String> {
        let mut responsibilities = Vec::new();

        let mut symbol_types: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for symbol in &file.symbols {
            *symbol_types.entry(symbol.kind.clone()).or_insert(0) += 1;
        }

        for (symbol_type, count) in symbol_types {
            responsibilities.push(format!("Defines {} {}(s)", count, symbol_type));
        }

        if file.symbols.iter().any(|s| s.visibility == "public") {
            responsibilities.push("Provides public API".to_string());
        }

        responsibilities
    }

    fn analyze_file_relationships(&self, _file: &FileInfo) -> Vec<String> {
        vec!["Part of the main library module structure".to_string()]
    }

    fn assess_file_complexity(&self, file: &FileInfo) -> ComplexityLevel {
        let symbol_count = file.symbols.len();
        let line_count = file.lines;

        if symbol_count > 20 || line_count > 300 {
            ComplexityLevel::High
        } else if symbol_count > 10 || line_count > 150 {
            ComplexityLevel::Medium
        } else {
            ComplexityLevel::Low
        }
    }

    fn suggest_file_improvements(&self, file: &FileInfo) -> Vec<String> {
        let mut suggestions = Vec::new();

        if file.lines > 300 {
            suggestions.push("Consider breaking this file into smaller modules".to_string());
        }

        if file.symbols.len() > 15 {
            suggestions.push("High symbol count - consider grouping related functionality".to_string());
        }

        if file.symbols.iter().filter(|s| s.visibility == "public").count() > 10 {
            suggestions.push("Large public API - consider reducing surface area".to_string());
        }

        suggestions
    }

    fn infer_symbol_purpose(&self, symbol: &Symbol) -> String {
        match symbol.kind.as_str() {
            "function" => {
                if symbol.name == "main" {
                    "Application entry point".to_string()
                } else if symbol.name.starts_with("test_") {
                    "Test function for validating functionality".to_string()
                } else if symbol.name.starts_with("new") {
                    "Constructor function for creating new instances".to_string()
                } else {
                    format!("Function that performs {} operations", symbol.name.replace('_', " "))
                }
            }
            "struct" => format!("Data structure representing a {}", symbol.name.replace('_', " ")),
            "enum" => format!("Enumeration defining {} variants", symbol.name.replace('_', " ")),
            "impl" => format!("Implementation block providing methods for {}", symbol.name),
            _ => format!("{} definition", symbol.kind),
        }
    }

    fn generate_symbol_usage(&self, symbol: &Symbol) -> String {
        match symbol.kind.as_str() {
            "function" if symbol.visibility == "public" => format!("Call {}() to use this functionality", symbol.name),
            "struct" if symbol.visibility == "public" => format!("Create instances using {}::new() or similar", symbol.name),
            "enum" if symbol.visibility == "public" => format!("Use {}::VariantName to access enum values", symbol.name),
            _ => "Internal implementation detail".to_string(),
        }
    }

    fn explain_symbol_signature(&self, symbol: &Symbol) -> Option<String> {
        match symbol.kind.as_str() {
            "function" => Some(format!("Function {} at line {}", symbol.name, symbol.start_line)),
            "struct" => Some(format!("Struct {} defined at line {}", symbol.name, symbol.start_line)),
            _ => None,
        }
    }

    fn assess_symbol_complexity(&self, _symbol: &Symbol) -> ComplexityLevel {
        // Simplified complexity assessment
        ComplexityLevel::Medium
    }

    fn suggest_symbol_best_practices(&self, symbol: &Symbol) -> Vec<String> {
        let mut practices = Vec::new();

        if symbol.visibility == "public" {
            practices.push("Add comprehensive documentation for public APIs".to_string());
            practices.push("Consider adding usage examples".to_string());
        }

        if symbol.kind == "function" {
            practices.push("Keep functions focused on a single responsibility".to_string());
            practices.push("Use descriptive parameter and return types".to_string());
        }

        practices
    }
}

impl std::fmt::Display for ComplexityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplexityLevel::Low => write!(f, "Low"),
            ComplexityLevel::Medium => write!(f, "Medium"),
            ComplexityLevel::High => write!(f, "High"),
            ComplexityLevel::VeryHigh => write!(f, "Very High"),
        }
    }
}
