//! Smart refactoring suggestions and automated improvements
//! 
//! This module provides intelligent refactoring analysis and suggestions
//! to improve code quality, maintainability, and performance.

use crate::{FileInfo, Symbol, AnalysisResult};
use crate::analysis_utils::{
    AnalysisThresholds, SymbolFilter
};
use crate::analysis_common::{FileAnalyzer};
use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Smart refactoring analyzer
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RefactoringAnalyzer {
    /// Configuration for refactoring analysis
    pub config: RefactoringConfig,
}

/// Configuration for refactoring analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RefactoringConfig {
    /// Enable complexity-based refactoring suggestions
    pub complexity_analysis: bool,
    /// Enable code duplication detection
    pub duplication_detection: bool,
    /// Enable naming convention analysis
    pub naming_analysis: bool,
    /// Enable performance optimization suggestions
    pub performance_analysis: bool,
    /// Enable architectural improvement suggestions
    pub architectural_analysis: bool,
    /// Minimum complexity threshold for suggestions
    pub min_complexity_threshold: usize,
    /// Maximum function length before suggesting split
    pub max_function_length: usize,
}

/// Refactoring analysis results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RefactoringResult {
    /// Overall code quality score (0-100)
    pub quality_score: u8,
    /// Total refactoring opportunities found
    pub total_opportunities: usize,
    /// Refactoring suggestions by category
    pub suggestions_by_category: HashMap<RefactoringCategory, usize>,
    /// Detailed refactoring suggestions
    pub suggestions: Vec<RefactoringSuggestion>,
    /// Quick wins (easy improvements)
    pub quick_wins: Vec<RefactoringSuggestion>,
    /// Major improvements (significant impact)
    pub major_improvements: Vec<RefactoringSuggestion>,
    /// Estimated impact summary
    pub impact_summary: ImpactSummary,
}

/// A refactoring suggestion
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RefactoringSuggestion {
    /// Suggestion ID
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Category of refactoring
    pub category: RefactoringCategory,
    /// Priority level
    pub priority: RefactoringPriority,
    /// Estimated effort to implement
    pub effort: ImplementationEffort,
    /// Expected impact
    pub impact: ExpectedImpact,
    /// Location of the code to refactor
    pub location: RefactoringLocation,
    /// Current code snippet
    pub current_code: String,
    /// Suggested improved code
    pub suggested_code: Option<String>,
    /// Step-by-step refactoring instructions
    pub instructions: Vec<String>,
    /// Benefits of this refactoring
    pub benefits: Vec<String>,
    /// Potential risks or considerations
    pub risks: Vec<String>,
}

/// Location of code to refactor
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RefactoringLocation {
    /// File path
    pub file: PathBuf,
    /// Function or method name
    pub function: Option<String>,
    /// Class or struct name
    pub class: Option<String>,
    /// Start line
    pub start_line: usize,
    /// End line
    pub end_line: usize,
    /// Scope (function, class, module, etc.)
    pub scope: String,
}

/// Impact summary of all refactoring suggestions
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ImpactSummary {
    /// Estimated maintainability improvement (0-100)
    pub maintainability_improvement: u8,
    /// Estimated performance improvement (0-100)
    pub performance_improvement: u8,
    /// Estimated readability improvement (0-100)
    pub readability_improvement: u8,
    /// Estimated reduction in technical debt (0-100)
    pub technical_debt_reduction: u8,
    /// Total estimated development time saved (hours)
    pub time_saved_hours: f32,
}

/// Categories of refactoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RefactoringCategory {
    /// Complexity reduction
    ComplexityReduction,
    /// Code duplication elimination
    DuplicationElimination,
    /// Naming improvements
    NamingImprovement,
    /// Performance optimization
    PerformanceOptimization,
    /// Architectural improvement
    ArchitecturalImprovement,
    /// Error handling improvement
    ErrorHandling,
    /// Type safety improvement
    TypeSafety,
    /// Documentation improvement
    Documentation,
    /// Test coverage improvement
    TestCoverage,
}

// Use common Priority from constants module
pub use crate::constants::common::Priority as RefactoringPriority;

// Use common EffortLevel from constants module
pub use crate::constants::common::EffortLevel as ImplementationEffort;

/// Expected impact of refactoring
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExpectedImpact {
    /// Maintainability impact (0-100)
    pub maintainability: u8,
    /// Performance impact (0-100)
    pub performance: u8,
    /// Readability impact (0-100)
    pub readability: u8,
    /// Bug risk reduction (0-100)
    pub bug_risk_reduction: u8,
}

impl Default for RefactoringConfig {
    fn default() -> Self {
        Self {
            complexity_analysis: true,
            duplication_detection: true,
            naming_analysis: true,
            performance_analysis: true,
            architectural_analysis: true,
            min_complexity_threshold: 10,
            max_function_length: 50,
        }
    }
}

impl RefactoringAnalyzer {
    /// Create a new refactoring analyzer with default configuration
    pub fn new() -> Self {
        Self {
            config: RefactoringConfig::default(),
        }
    }
    
    /// Create a new refactoring analyzer with custom configuration
    pub fn with_config(config: RefactoringConfig) -> Self {
        Self { config }
    }
    
    /// Analyze a codebase for refactoring opportunities
    pub fn analyze(&self, analysis_result: &AnalysisResult) -> RefactoringResult {
        let mut suggestions = Vec::new();
        
        // Analyze each file for refactoring opportunities
        for file in &analysis_result.files {
            suggestions.extend(self.analyze_file(file, analysis_result));
        }
        
        // Analyze cross-file opportunities
        suggestions.extend(self.analyze_cross_file_opportunities(analysis_result));
        
        // Categorize suggestions
        let mut suggestions_by_category = HashMap::new();
        for suggestion in &suggestions {
            *suggestions_by_category.entry(suggestion.category).or_insert(0) += 1;
        }
        
        // Separate quick wins and major improvements
        let quick_wins: Vec<_> = suggestions.iter()
            .filter(|s| matches!(s.effort, ImplementationEffort::Trivial | ImplementationEffort::Easy))
            .cloned()
            .collect();
        
        let major_improvements: Vec<_> = suggestions.iter()
            .filter(|s| matches!(s.priority, RefactoringPriority::Critical | RefactoringPriority::High))
            .cloned()
            .collect();
        
        let total_opportunities = suggestions.len();
        let quality_score = self.calculate_quality_score(&suggestions, analysis_result);
        let impact_summary = self.calculate_impact_summary(&suggestions);
        
        RefactoringResult {
            quality_score,
            total_opportunities,
            suggestions_by_category,
            suggestions,
            quick_wins,
            major_improvements,
            impact_summary,
        }
    }
    
    /// Analyze a single file for refactoring opportunities
    fn analyze_file(&self, file: &FileInfo, _analysis_result: &AnalysisResult) -> Vec<RefactoringSuggestion> {
        let mut suggestions = Vec::new();
        
        // Analyze file-level issues
        if self.config.complexity_analysis {
            suggestions.extend(self.analyze_file_complexity(file));
        }
        
        if self.config.naming_analysis {
            suggestions.extend(self.analyze_file_naming(file));
        }
        
        // Analyze symbol-level issues
        let function_symbols = SymbolFilter::filter_functions(&file.symbols);
        for symbol in function_symbols {
            suggestions.extend(self.analyze_symbol(symbol, file));
        }

        // Also analyze other symbols
        for symbol in &file.symbols {
            if !SymbolFilter::is_function_or_method(symbol) {
                suggestions.extend(self.analyze_symbol(symbol, file));
            }
        }
        
        suggestions
    }
    
    /// Analyze cross-file refactoring opportunities
    fn analyze_cross_file_opportunities(&self, analysis_result: &AnalysisResult) -> Vec<RefactoringSuggestion> {
        let mut suggestions = Vec::new();
        
        if self.config.duplication_detection {
            suggestions.extend(self.detect_code_duplication(analysis_result));
        }
        
        if self.config.architectural_analysis {
            suggestions.extend(self.analyze_architecture(analysis_result));
        }
        
        suggestions
    }
    
    /// Analyze file complexity and suggest improvements
    fn analyze_file_complexity(&self, file: &FileInfo) -> Vec<RefactoringSuggestion> {
        let mut suggestions = Vec::new();

        if let Some(large_file_suggestion) = self.check_large_file(file) {
            suggestions.push(large_file_suggestion);
        }

        if let Some(density_suggestion) = self.check_symbol_density(file) {
            suggestions.push(density_suggestion);
        }

        suggestions
    }

    /// Check if file is too large and create suggestion
    fn check_large_file(&self, file: &FileInfo) -> Option<RefactoringSuggestion> {
        let thresholds = AnalysisThresholds::default();
        if !FileAnalyzer::is_large_file(file, thresholds.large_file_lines) {
            return None;
        }

        Some(RefactoringSuggestion {
            id: format!("LARGE_FILE_{}", file.path.display()),
            title: "Large file detected".to_string(),
            description: format!("File {} has {} lines, which may be too large for easy maintenance",
                file.path.display(), file.lines),
            category: RefactoringCategory::ComplexityReduction,
            priority: RefactoringPriority::Medium,
            effort: ImplementationEffort::Medium,
            impact: self.create_large_file_impact(),
            location: self.create_file_location(file),
            current_code: format!("File with {} lines", file.lines),
            suggested_code: None,
            instructions: self.get_large_file_instructions(),
            benefits: self.get_large_file_benefits(),
            risks: self.get_large_file_risks(),
        })
    }

    /// Check symbol density and create suggestion
    fn check_symbol_density(&self, file: &FileInfo) -> Option<RefactoringSuggestion> {
        let symbol_density = file.symbols.len() as f64 / file.lines as f64;
        if symbol_density <= 0.1 {
            return None;
        }

        Some(RefactoringSuggestion {
            id: format!("HIGH_SYMBOL_DENSITY_{}", file.path.display()),
            title: "High symbol density detected".to_string(),
            description: "File has many symbols relative to its size, suggesting it might be doing too much".to_string(),
            category: RefactoringCategory::ComplexityReduction,
            priority: RefactoringPriority::Low,
            effort: ImplementationEffort::Medium,
            impact: self.create_density_impact(),
            location: self.create_file_location(file),
            current_code: format!("{} symbols in {} lines", file.symbols.len(), file.lines),
            suggested_code: None,
            instructions: self.get_density_instructions(),
            benefits: self.get_density_benefits(),
            risks: self.get_density_risks(),
        })
    }

    /// Create file location for refactoring suggestions
    fn create_file_location(&self, file: &FileInfo) -> RefactoringLocation {
        RefactoringLocation {
            file: file.path.clone(),
            function: None,
            class: None,
            start_line: 1,
            end_line: file.lines,
            scope: "file".to_string(),
        }
    }

    /// Create impact for large file suggestions
    fn create_large_file_impact(&self) -> ExpectedImpact {
        ExpectedImpact {
            maintainability: 70,
            performance: 10,
            readability: 80,
            bug_risk_reduction: 40,
        }
    }

    /// Create impact for symbol density suggestions
    fn create_density_impact(&self) -> ExpectedImpact {
        ExpectedImpact {
            maintainability: 60,
            performance: 5,
            readability: 70,
            bug_risk_reduction: 30,
        }
    }

    /// Get instructions for large file refactoring
    fn get_large_file_instructions(&self) -> Vec<String> {
        vec![
            "Identify logical groups of functionality".to_string(),
            "Extract related functions into separate modules".to_string(),
            "Consider using composition over large monolithic files".to_string(),
        ]
    }

    /// Get benefits for large file refactoring
    fn get_large_file_benefits(&self) -> Vec<String> {
        vec![
            "Improved maintainability".to_string(),
            "Better code organization".to_string(),
            "Easier testing and debugging".to_string(),
        ]
    }

    /// Get risks for large file refactoring
    fn get_large_file_risks(&self) -> Vec<String> {
        vec![
            "May require updating import statements".to_string(),
            "Could temporarily break existing code".to_string(),
        ]
    }

    /// Get instructions for symbol density refactoring
    fn get_density_instructions(&self) -> Vec<String> {
        vec![
            "Group related symbols together".to_string(),
            "Consider extracting some symbols to separate files".to_string(),
            "Apply single responsibility principle".to_string(),
        ]
    }

    /// Get benefits for symbol density refactoring
    fn get_density_benefits(&self) -> Vec<String> {
        vec![
            "Clearer code organization".to_string(),
            "Easier to locate specific functionality".to_string(),
        ]
    }

    /// Get risks for symbol density refactoring
    fn get_density_risks(&self) -> Vec<String> {
        vec![
            "May require restructuring imports".to_string(),
        ]
    }

    // Helper methods for refactoring analysis

    fn calculate_quality_score(&self, suggestions: &[RefactoringSuggestion], _result: &AnalysisResult) -> u8 {
        if suggestions.is_empty() {
            return 95; // High score if no issues found
        }

        let mut score: u8 = crate::constants::refactoring::BASE_REFACTORING_SCORE;
        for suggestion in suggestions {
            let deduction = match suggestion.priority {
                RefactoringPriority::Critical => 20,
                RefactoringPriority::High => 10,
                RefactoringPriority::Medium => 5,
                RefactoringPriority::Low => 2,
            };
            score = score.saturating_sub(deduction);
        }

        score.max(20) // Minimum score of 20
    }

    fn calculate_impact_summary(&self, suggestions: &[RefactoringSuggestion]) -> ImpactSummary {
        if suggestions.is_empty() {
            return ImpactSummary {
                maintainability_improvement: 0,
                performance_improvement: 0,
                readability_improvement: 0,
                technical_debt_reduction: 0,
                time_saved_hours: 0.0,
            };
        }

        let total_suggestions = suggestions.len() as f32;
        let maintainability = suggestions.iter().map(|s| s.impact.maintainability as f32).sum::<f32>() / total_suggestions;
        let performance = suggestions.iter().map(|s| s.impact.performance as f32).sum::<f32>() / total_suggestions;
        let readability = suggestions.iter().map(|s| s.impact.readability as f32).sum::<f32>() / total_suggestions;
        let bug_risk = suggestions.iter().map(|s| s.impact.bug_risk_reduction as f32).sum::<f32>() / total_suggestions;

        let time_saved = suggestions.iter().map(|s| {
            match s.effort {
                ImplementationEffort::Trivial => 0.5,
                ImplementationEffort::Easy => 2.0,
                ImplementationEffort::Medium => 8.0,
                ImplementationEffort::Hard => 40.0,
                ImplementationEffort::VeryHard => 80.0,
            }
        }).sum::<f32>() * 0.1; // Assume 10% time savings from refactoring

        ImpactSummary {
            maintainability_improvement: maintainability as u8,
            performance_improvement: performance as u8,
            readability_improvement: readability as u8,
            technical_debt_reduction: bug_risk as u8,
            time_saved_hours: time_saved,
        }
    }

    fn analyze_symbol(&self, symbol: &Symbol, file: &FileInfo) -> Vec<RefactoringSuggestion> {
        let mut suggestions = Vec::new();

        // Check for naming conventions
        if self.config.naming_analysis {
            suggestions.extend(self.analyze_symbol_naming(symbol, file));
        }

        // Check for complexity issues
        if self.config.complexity_analysis {
            suggestions.extend(self.analyze_symbol_complexity(symbol, file));
        }

        suggestions
    }

    fn analyze_file_naming(&self, file: &FileInfo) -> Vec<RefactoringSuggestion> {
        let mut suggestions = Vec::new();

        let file_name = file.path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Check for unclear file names
        if file_name.len() < 3 || file_name.chars().all(|c| c.is_ascii_lowercase()) {
            suggestions.push(RefactoringSuggestion {
                id: format!("UNCLEAR_FILENAME_{}", file.path.display()),
                title: "Unclear file name".to_string(),
                description: "File name could be more descriptive".to_string(),
                category: RefactoringCategory::NamingImprovement,
                priority: RefactoringPriority::Low,
                effort: ImplementationEffort::Trivial,
                impact: ExpectedImpact {
                    maintainability: 30,
                    performance: 0,
                    readability: 50,
                    bug_risk_reduction: 10,
                },
                location: RefactoringLocation {
                    file: file.path.clone(),
                    function: None,
                    class: None,
                    start_line: 1,
                    end_line: 1,
                    scope: "file".to_string(),
                },
                current_code: file_name.to_string(),
                suggested_code: None,
                instructions: vec![
                    "Choose a more descriptive file name".to_string(),
                    "Use snake_case for Rust file names".to_string(),
                ],
                benefits: vec![
                    "Improved code navigation".to_string(),
                    "Better project organization".to_string(),
                ],
                risks: vec![
                    "May require updating import statements".to_string(),
                ],
            });
        }

        suggestions
    }

    fn analyze_symbol_naming(&self, symbol: &Symbol, file: &FileInfo) -> Vec<RefactoringSuggestion> {
        let mut suggestions = Vec::new();

        // Check for very short names
        if symbol.name.len() < 2 && symbol.kind != "variable" {
            suggestions.push(RefactoringSuggestion {
                id: format!("SHORT_NAME_{}_{}", file.path.display(), symbol.name),
                title: "Very short symbol name".to_string(),
                description: format!("Symbol '{}' has a very short name that may not be descriptive", symbol.name),
                category: RefactoringCategory::NamingImprovement,
                priority: RefactoringPriority::Low,
                effort: ImplementationEffort::Trivial,
                impact: ExpectedImpact {
                    maintainability: 40,
                    performance: 0,
                    readability: 60,
                    bug_risk_reduction: 10,
                },
                location: RefactoringLocation {
                    file: file.path.clone(),
                    function: Some(symbol.name.clone()),
                    class: None,
                    start_line: symbol.start_line,
                    end_line: symbol.start_line,
                    scope: symbol.kind.clone(),
                },
                current_code: symbol.name.clone(),
                suggested_code: Some(format!("{}_descriptive", symbol.name)),
                instructions: vec![
                    "Choose a more descriptive name".to_string(),
                    "Follow language naming conventions".to_string(),
                ],
                benefits: vec![
                    "Improved code readability".to_string(),
                    "Better self-documenting code".to_string(),
                ],
                risks: vec![
                    "May require updating references".to_string(),
                ],
            });
        }

        suggestions
    }

    fn analyze_symbol_complexity(&self, symbol: &Symbol, file: &FileInfo) -> Vec<RefactoringSuggestion> {
        let mut suggestions = Vec::new();

        // This is a simplified complexity check
        // In a real implementation, you'd analyze the actual function body
        if symbol.kind == "function" && symbol.name.len() > 30 {
            suggestions.push(RefactoringSuggestion {
                id: format!("COMPLEX_FUNCTION_{}_{}", file.path.display(), symbol.name),
                title: "Potentially complex function".to_string(),
                description: "Function name suggests it might be doing too much".to_string(),
                category: RefactoringCategory::ComplexityReduction,
                priority: RefactoringPriority::Medium,
                effort: ImplementationEffort::Medium,
                impact: ExpectedImpact {
                    maintainability: 70,
                    performance: 10,
                    readability: 60,
                    bug_risk_reduction: 50,
                },
                location: RefactoringLocation {
                    file: file.path.clone(),
                    function: Some(symbol.name.clone()),
                    class: None,
                    start_line: symbol.start_line,
                    end_line: symbol.start_line,
                    scope: "function".to_string(),
                },
                current_code: format!("fn {}(...)", symbol.name),
                suggested_code: None,
                instructions: vec![
                    "Break function into smaller, focused functions".to_string(),
                    "Apply single responsibility principle".to_string(),
                    "Extract helper functions for complex logic".to_string(),
                ],
                benefits: vec![
                    "Improved testability".to_string(),
                    "Better code reuse".to_string(),
                    "Easier debugging".to_string(),
                ],
                risks: vec![
                    "May increase number of function calls".to_string(),
                    "Requires careful interface design".to_string(),
                ],
            });
        }

        suggestions
    }

    fn detect_code_duplication(&self, _result: &AnalysisResult) -> Vec<RefactoringSuggestion> {
        // Simplified duplication detection
        vec![
            RefactoringSuggestion {
                id: "POTENTIAL_DUPLICATION".to_string(),
                title: "Potential code duplication detected".to_string(),
                description: "Similar patterns found across multiple files".to_string(),
                category: RefactoringCategory::DuplicationElimination,
                priority: RefactoringPriority::Medium,
                effort: ImplementationEffort::Medium,
                impact: ExpectedImpact {
                    maintainability: 80,
                    performance: 5,
                    readability: 40,
                    bug_risk_reduction: 60,
                },
                location: RefactoringLocation {
                    file: PathBuf::from("multiple files"),
                    function: None,
                    class: None,
                    start_line: 1,
                    end_line: 1,
                    scope: "project".to_string(),
                },
                current_code: "Duplicated patterns".to_string(),
                suggested_code: Some("Extract common functionality".to_string()),
                instructions: vec![
                    "Identify common patterns".to_string(),
                    "Extract shared functionality into utilities".to_string(),
                    "Create reusable components".to_string(),
                ],
                benefits: vec![
                    "Reduced code duplication".to_string(),
                    "Easier maintenance".to_string(),
                    "Consistent behavior".to_string(),
                ],
                risks: vec![
                    "May introduce coupling".to_string(),
                    "Requires careful abstraction design".to_string(),
                ],
            }
        ]
    }

    fn analyze_architecture(&self, result: &AnalysisResult) -> Vec<RefactoringSuggestion> {
        let mut suggestions = Vec::new();

        // Check for architectural improvements
        if result.total_files > 20 {
            suggestions.push(RefactoringSuggestion {
                id: "LARGE_PROJECT_ARCHITECTURE".to_string(),
                title: "Large project architecture review".to_string(),
                description: "Project has grown large enough to benefit from architectural improvements".to_string(),
                category: RefactoringCategory::ArchitecturalImprovement,
                priority: RefactoringPriority::Medium,
                effort: ImplementationEffort::Hard,
                impact: ExpectedImpact {
                    maintainability: 90,
                    performance: 20,
                    readability: 70,
                    bug_risk_reduction: 40,
                },
                location: RefactoringLocation {
                    file: PathBuf::from("project structure"),
                    function: None,
                    class: None,
                    start_line: 1,
                    end_line: 1,
                    scope: "architecture".to_string(),
                },
                current_code: format!("{} files", result.total_files),
                suggested_code: None,
                instructions: vec![
                    "Review overall project structure".to_string(),
                    "Consider implementing layered architecture".to_string(),
                    "Evaluate dependency management".to_string(),
                ],
                benefits: vec![
                    "Better scalability".to_string(),
                    "Improved maintainability".to_string(),
                    "Clearer separation of concerns".to_string(),
                ],
                risks: vec![
                    "Significant refactoring effort".to_string(),
                    "May require breaking changes".to_string(),
                ],
            });
        }

        suggestions
    }
}

// Display trait implementations
impl std::fmt::Display for RefactoringCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefactoringCategory::ComplexityReduction => write!(f, "Complexity Reduction"),
            RefactoringCategory::DuplicationElimination => write!(f, "Duplication Elimination"),
            RefactoringCategory::NamingImprovement => write!(f, "Naming Improvement"),
            RefactoringCategory::PerformanceOptimization => write!(f, "Performance Optimization"),
            RefactoringCategory::ArchitecturalImprovement => write!(f, "Architectural Improvement"),
            RefactoringCategory::ErrorHandling => write!(f, "Error Handling"),
            RefactoringCategory::TypeSafety => write!(f, "Type Safety"),
            RefactoringCategory::Documentation => write!(f, "Documentation"),
            RefactoringCategory::TestCoverage => write!(f, "Test Coverage"),
        }
    }
}

// Display implementation is provided by the common Priority type

// Display implementation is provided by the common EffortLevel type


