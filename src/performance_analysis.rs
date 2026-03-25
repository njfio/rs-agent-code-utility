//! Performance hotspot detection and optimization analysis
//!
//! This module provides comprehensive performance analysis including:
//! - Algorithmic complexity detection
//! - Memory usage patterns analysis
//! - I/O operation optimization
//! - Concurrency and parallelization opportunities
//! - Performance bottleneck identification
#![allow(clippy::only_used_in_recursion)]

use crate::analysis_utils::{ComplexityCalculator, LanguageParser};
use crate::constants::common::RiskLevel;
use crate::constants::performance::*;
use crate::{AnalysisResult, FileInfo, MemoryTracker, MemoryTrackingResult, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Information about loop nesting structure for semantic analysis
#[derive(Debug, Clone)]
struct LoopNestingInfo {
    depth: usize,
    #[allow(dead_code)]
    iteration_variables: Vec<String>,
    data_dependencies: Vec<DataDependency>,
    #[allow(dead_code)]
    loop_types: Vec<LoopType>,
    access_patterns: Vec<AccessPattern>,
}

/// Data dependency information for complexity analysis
#[derive(Debug, Clone)]
struct DataDependency {
    #[allow(dead_code)]
    variable: String,
    dependency_type: DependencyType,
    #[allow(dead_code)]
    scope: String,
}

/// Type of data dependency
#[derive(Debug, Clone)]
enum DependencyType {
    ReadOnly,
    #[allow(dead_code)]
    WriteOnly,
    #[allow(dead_code)]
    ReadWrite,
    IndexBased,
    #[allow(dead_code)]
    SizeDependent,
}

/// Type of loop construct
#[derive(Debug, Clone)]
enum LoopType {
    ForLoop,
    WhileLoop,
    Iterator,
    Recursive,
}

/// Memory access pattern
#[derive(Debug, Clone)]
struct AccessPattern {
    #[allow(dead_code)]
    pattern_type: AccessPatternType,
    complexity: AccessComplexity,
    #[allow(dead_code)]
    description: String,
}

/// Type of access pattern
#[derive(Debug, Clone)]
enum AccessPatternType {
    Sequential,
    #[allow(dead_code)]
    Random,
    Nested,
    #[allow(dead_code)]
    Strided,
    #[allow(dead_code)]
    Sparse,
}

/// Complexity of access pattern
#[derive(Debug, Clone)]
enum AccessComplexity {
    #[allow(dead_code)]
    Constant, // O(1)
    Linear,    // O(n)
    Quadratic, // O(n²)
    #[allow(dead_code)]
    Cubic, // O(n³)
    #[allow(dead_code)]
    Exponential, // O(2^n)
    #[allow(dead_code)]
    Unknown,
}

/// Semantic analysis result for loops
#[derive(Debug, Clone)]
struct SemanticLoopAnalysis {
    description: String,
    pattern_type: String,
    function_name: Option<String>,
    confidence: f64,
    optimization_suggestions: Vec<String>,
}

/// Recursion analysis result
#[derive(Debug, Clone)]
struct RecursionAnalysis {
    complexity_risk: f64,
    pattern_type: String,
    optimization_suggestion: String,
}

/// Performance analyzer for detecting hotspots and optimization opportunities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAnalyzer {
    /// Configuration for performance analysis
    pub config: PerformanceConfig,
}

/// Configuration for performance analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable algorithmic complexity analysis
    pub complexity_analysis: bool,
    /// Enable memory usage analysis
    pub memory_analysis: bool,
    /// Enable I/O operation analysis
    pub io_analysis: bool,
    /// Enable concurrency analysis
    pub concurrency_analysis: bool,
    /// Enable database query analysis
    pub database_analysis: bool,
    /// Minimum complexity threshold for reporting
    pub min_complexity_threshold: usize,
    /// Maximum acceptable function length
    pub max_function_length: usize,
}

/// Results of performance analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAnalysisResult {
    /// Overall performance score (0-100)
    pub performance_score: u8,
    /// Total hotspots detected
    pub total_hotspots: usize,
    /// Hotspots by severity
    pub hotspots_by_severity: HashMap<PerformanceSeverity, usize>,
    /// Detected performance hotspots
    pub hotspots: Vec<PerformanceHotspot>,
    /// Optimization opportunities
    pub optimizations: Vec<OptimizationOpportunity>,
    /// Performance metrics by file
    pub file_metrics: Vec<FilePerformanceMetrics>,
    /// Algorithmic complexity analysis
    pub complexity_analysis: ComplexityAnalysis,
    /// Memory usage analysis
    pub memory_analysis: MemoryAnalysis,
    /// Advanced memory allocation tracking
    pub memory_tracking: Option<MemoryTrackingResult>,
    /// Concurrency analysis
    pub concurrency_analysis: ConcurrencyAnalysis,
    /// Performance recommendations
    pub recommendations: Vec<PerformanceRecommendation>,
}

/// A performance hotspot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceHotspot {
    /// Hotspot ID
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Hotspot category
    pub category: HotspotCategory,
    /// Severity level
    pub severity: PerformanceSeverity,
    /// Performance impact estimation
    pub impact: PerformanceImpact,
    /// Location of the hotspot
    pub location: HotspotLocation,
    /// Code snippet causing the issue
    pub code_snippet: String,
    /// Suggested optimization
    pub optimization: String,
    /// Expected improvement
    pub expected_improvement: ExpectedImprovement,
    /// Implementation difficulty
    pub difficulty: OptimizationDifficulty,
    /// Related patterns or anti-patterns
    pub patterns: Vec<String>,
}

/// Location of a performance hotspot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotLocation {
    /// File path
    pub file: String,
    /// Function or method name
    pub function: Option<String>,
    /// Start line
    pub start_line: usize,
    /// End line
    pub end_line: usize,
    /// Scope context
    pub scope: String,
}

/// Categories of performance hotspots
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HotspotCategory {
    /// Algorithmic complexity issues
    AlgorithmicComplexity,
    /// Memory allocation and usage
    MemoryUsage,
    /// I/O operations
    IOOperations,
    /// Database queries
    DatabaseQueries,
    /// Network operations
    NetworkOperations,
    /// Concurrency and synchronization
    Concurrency,
    /// String operations
    StringOperations,
    /// Collection operations
    Collections,
    /// File system operations
    FileSystem,
    /// CPU-intensive operations
    CPUIntensive,
}

/// Performance severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PerformanceSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Performance impact assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceImpact {
    /// CPU impact (0-100)
    pub cpu_impact: u8,
    /// Memory impact (0-100)
    pub memory_impact: u8,
    /// I/O impact (0-100)
    pub io_impact: u8,
    /// Network impact (0-100)
    pub network_impact: u8,
    /// Overall impact score (0-100)
    pub overall_impact: u8,
}

/// Expected improvement from optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedImprovement {
    /// Performance improvement percentage
    pub performance_gain: f64,
    /// Memory usage reduction percentage
    pub memory_reduction: f64,
    /// Execution time reduction percentage
    pub time_reduction: f64,
    /// Confidence level in the improvement estimate
    pub confidence: ConfidenceLevel,
}

/// Confidence levels for performance estimates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
}

/// Optimization difficulty levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationDifficulty {
    Trivial,
    Easy,
    Medium,
    Hard,
    VeryHard,
}

/// An optimization opportunity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationOpportunity {
    /// Opportunity ID
    pub id: String,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Optimization type
    pub optimization_type: OptimizationType,
    /// Priority level
    pub priority: OptimizationPriority,
    /// Affected files
    pub affected_files: Vec<String>,
    /// Implementation steps
    pub implementation_steps: Vec<String>,
    /// Expected benefits
    pub benefits: Vec<String>,
    /// Potential risks
    pub risks: Vec<String>,
    /// Estimated effort
    pub effort_estimate: EffortEstimate,
}

/// Types of optimizations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationType {
    /// Algorithm optimization
    Algorithm,
    /// Data structure optimization
    DataStructure,
    /// Memory optimization
    Memory,
    /// I/O optimization
    IO,
    /// Concurrency optimization
    Concurrency,
    /// Caching optimization
    Caching,
    /// Database optimization
    Database,
}

/// Optimization priority levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Effort estimation for optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffortEstimate {
    /// Estimated hours
    pub hours: f64,
    /// Complexity level
    pub complexity: OptimizationDifficulty,
    /// Required expertise level
    pub expertise_level: ExpertiseLevel,
}

/// Required expertise levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExpertiseLevel {
    Beginner,
    Intermediate,
    Advanced,
    Expert,
}

/// Performance metrics for a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePerformanceMetrics {
    /// File path
    pub file: PathBuf,
    /// Performance score for this file
    pub performance_score: u8,
    /// Cyclomatic complexity
    pub cyclomatic_complexity: f64,
    /// Function count
    pub function_count: usize,
    /// Average function length
    pub average_function_length: f64,
    /// Nested loop count
    pub nested_loops: usize,
    /// Recursive function count
    pub recursive_functions: usize,
    /// Memory allocation patterns
    pub memory_allocations: usize,
    /// I/O operation count
    pub io_operations: usize,
    /// Database query count
    pub database_queries: usize,
}

/// Algorithmic complexity analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityAnalysis {
    /// Average complexity across codebase
    pub average_complexity: f64,
    /// Maximum complexity found
    pub max_complexity: f64,
    /// Functions with high complexity
    pub high_complexity_functions: Vec<ComplexFunction>,
    /// Nested loop analysis
    pub nested_loops: Vec<NestedLoopAnalysis>,
    /// Recursive function analysis
    pub recursive_functions: Vec<RecursiveFunction>,
}

/// A function with high complexity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexFunction {
    /// Function name
    pub name: String,
    /// File location
    pub file: String,
    /// Line number
    pub line: usize,
    /// Complexity score
    pub complexity: f64,
    /// Suggested improvements
    pub improvements: Vec<String>,
}

/// Nested loop analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestedLoopAnalysis {
    /// Location
    pub location: HotspotLocation,
    /// Nesting depth
    pub depth: usize,
    /// Estimated time complexity
    pub time_complexity: String,
    /// Optimization suggestions
    pub optimizations: Vec<String>,
}

/// Recursive function analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveFunction {
    /// Function name
    pub name: String,
    /// Location
    pub location: HotspotLocation,
    /// Recursion type
    pub recursion_type: RecursionType,
    /// Potential for optimization
    pub optimization_potential: OptimizationPotential,
}

/// Types of recursion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecursionType {
    Direct,
    Indirect,
    TailRecursion,
    MutualRecursion,
}

/// Optimization potential levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationPotential {
    High,
    Medium,
    Low,
    None,
}

/// Memory usage analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryAnalysis {
    /// Memory allocation hotspots
    pub allocation_hotspots: Vec<MemoryHotspot>,
    /// Memory leak potential
    pub leak_potential: Vec<MemoryLeakRisk>,
    /// Inefficient data structures
    pub inefficient_structures: Vec<InefficiientDataStructure>,
    /// Memory optimization opportunities
    pub optimizations: Vec<MemoryOptimization>,
}

/// Memory allocation hotspot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryHotspot {
    /// Location
    pub location: HotspotLocation,
    /// Allocation type
    pub allocation_type: AllocationType,
    /// Frequency estimate
    pub frequency: AllocationFrequency,
    /// Size estimate
    pub size_estimate: SizeEstimate,
}

/// Types of memory allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AllocationType {
    HeapAllocation,
    VectorReallocation,
    StringAllocation,
    CollectionGrowth,
    BoxAllocation,
}

/// Allocation frequency levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AllocationFrequency {
    VeryHigh,
    High,
    Medium,
    Low,
}

/// Size estimation for allocations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SizeEstimate {
    Large,
    Medium,
    Small,
    Unknown,
}

/// Memory leak risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLeakRisk {
    /// Location
    pub location: HotspotLocation,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Description
    pub description: String,
    /// Mitigation strategies
    pub mitigation: Vec<String>,
}

// RiskLevel is now imported from crate::constants::common

/// Inefficient data structure usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InefficiientDataStructure {
    /// Location
    pub location: HotspotLocation,
    /// Current structure
    pub current_structure: String,
    /// Suggested alternative
    pub suggested_alternative: String,
    /// Performance improvement
    pub improvement: String,
}

/// Memory optimization opportunity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOptimization {
    /// Optimization title
    pub title: String,
    /// Description
    pub description: String,
    /// Affected locations
    pub locations: Vec<HotspotLocation>,
    /// Expected memory savings
    pub memory_savings: String,
}

/// Concurrency analysis results
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConcurrencyAnalysis {
    /// Parallelization opportunities
    pub parallelization_opportunities: Vec<ParallelizationOpportunity>,
    /// Synchronization issues
    pub synchronization_issues: Vec<SynchronizationIssue>,
    /// Thread safety concerns
    pub thread_safety_concerns: Vec<ThreadSafetyConcern>,
    /// Async/await optimization opportunities
    pub async_optimizations: Vec<AsyncOptimization>,
}

/// Parallelization opportunity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelizationOpportunity {
    /// Location
    pub location: HotspotLocation,
    /// Opportunity type
    pub opportunity_type: ParallelizationType,
    /// Expected speedup
    pub expected_speedup: f64,
    /// Implementation approach
    pub approach: String,
}

/// Types of parallelization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParallelizationType {
    DataParallelism,
    TaskParallelism,
    PipelineParallelism,
    AsyncProcessing,
}

/// Synchronization issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynchronizationIssue {
    /// Location
    pub location: HotspotLocation,
    /// Issue type
    pub issue_type: SynchronizationIssueType,
    /// Severity
    pub severity: PerformanceSeverity,
    /// Description
    pub description: String,
    /// Solution
    pub solution: String,
}

/// Types of synchronization issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SynchronizationIssueType {
    Deadlock,
    RaceCondition,
    Contention,
    OverSynchronization,
}

/// Thread safety concern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSafetyConcern {
    /// Location
    pub location: HotspotLocation,
    /// Concern type
    pub concern_type: ThreadSafetyIssue,
    /// Risk assessment
    pub risk: RiskLevel,
    /// Recommendation
    pub recommendation: String,
}

/// Types of thread safety issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreadSafetyIssue {
    SharedMutableState,
    UnsafeAccess,
    NonAtomicOperations,
    GlobalState,
}

/// Async/await optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncOptimization {
    /// Location
    pub location: HotspotLocation,
    /// Optimization type
    pub optimization_type: AsyncOptimizationType,
    /// Description
    pub description: String,
    /// Implementation
    pub implementation: String,
}

/// Types of async optimizations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AsyncOptimizationType {
    AwaitOptimization,
    ConcurrentExecution,
    StreamProcessing,
    BatchProcessing,
}

/// Performance recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceRecommendation {
    /// Recommendation category
    pub category: String,
    /// Recommendation text
    pub recommendation: String,
    /// Priority level
    pub priority: OptimizationPriority,
    /// Affected components
    pub affected_components: Vec<String>,
    /// Implementation difficulty
    pub difficulty: OptimizationDifficulty,
    /// Expected impact
    pub expected_impact: ExpectedImprovement,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            complexity_analysis: true,
            memory_analysis: true,
            io_analysis: true,
            concurrency_analysis: true,
            database_analysis: true,
            min_complexity_threshold: 10,
            max_function_length: 50,
        }
    }
}

impl Default for PerformanceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceAnalyzer {
    fn resolved_file_info(&self, file: &FileInfo, root_path: &Path) -> FileInfo {
        if file.path.is_absolute() {
            return file.clone();
        }

        let mut resolved = file.clone();
        resolved.path = root_path.join(&file.path);
        resolved
    }

    /// Create a new performance analyzer with default configuration
    pub fn new() -> Self {
        Self {
            config: PerformanceConfig::default(),
        }
    }

    /// Create a new performance analyzer with custom configuration
    pub fn with_config(config: PerformanceConfig) -> Self {
        Self { config }
    }

    /// Analyze performance hotspots in a codebase
    pub fn analyze(&self, analysis_result: &AnalysisResult) -> Result<PerformanceAnalysisResult> {
        let mut hotspots = Vec::new();
        let mut file_metrics = Vec::new();

        // Analyze each file for performance issues
        for file in &analysis_result.files {
            let resolved_file = self.resolved_file_info(file, &analysis_result.root_path);
            let metrics = self.analyze_file_performance(&resolved_file)?;
            file_metrics.push(metrics);

            hotspots.extend(self.detect_file_hotspots(&resolved_file)?);
        }

        // Perform cross-file analysis
        hotspots.extend(self.detect_cross_file_hotspots(analysis_result)?);

        // Generate optimization opportunities
        let optimizations = self.generate_optimizations(&hotspots, analysis_result)?;

        // Categorize hotspots by severity
        let mut hotspots_by_severity = HashMap::new();
        for hotspot in &hotspots {
            *hotspots_by_severity.entry(hotspot.severity).or_insert(0) += 1;
        }

        // Perform specialized analyses
        let complexity_analysis = if self.config.complexity_analysis {
            self.analyze_complexity(analysis_result)?
        } else {
            ComplexityAnalysis::default()
        };

        let memory_analysis = if self.config.memory_analysis {
            self.analyze_memory_usage(analysis_result)?
        } else {
            MemoryAnalysis::default()
        };

        // Advanced memory allocation tracking
        let memory_tracking = if self.config.memory_analysis {
            let mut memory_tracker = MemoryTracker::new();
            memory_tracker
                .analyze_memory_allocations(analysis_result)
                .ok()
        } else {
            None
        };

        let concurrency_analysis = if self.config.concurrency_analysis {
            self.analyze_concurrency(analysis_result)?
        } else {
            ConcurrencyAnalysis::default()
        };

        // Generate recommendations
        let recommendations = self.generate_recommendations(&hotspots, &optimizations)?;

        // Calculate overall performance score
        let performance_score = self.calculate_performance_score(&hotspots, &file_metrics);

        Ok(PerformanceAnalysisResult {
            performance_score,
            total_hotspots: hotspots.len(),
            hotspots_by_severity,
            hotspots,
            optimizations,
            file_metrics,
            complexity_analysis,
            memory_analysis,
            memory_tracking,
            concurrency_analysis,
            recommendations,
        })
    }

    /// Analyze performance metrics for a single file
    fn analyze_file_performance(&self, file: &FileInfo) -> Result<FilePerformanceMetrics> {
        let function_lengths: Vec<usize> = file
            .symbols
            .iter()
            .filter(|s| s.kind == "function")
            .map(|s| s.end_line.saturating_sub(s.start_line) + 1)
            .collect();
        let function_count = function_lengths.len();
        let average_function_length = if function_count > 0 {
            function_lengths.iter().sum::<usize>() as f64 / function_count as f64
        } else {
            0.0
        };

        // Simplified complexity calculation
        let cyclomatic_complexity = self.calculate_file_complexity(file);

        // Count various performance-related patterns
        let nested_loops = self.count_nested_loops_in_file(file);
        let recursive_functions = self.count_recursive_functions(file);
        let memory_allocations = self.count_memory_allocations(file);
        let io_operations = self.count_io_operations(file);
        let database_queries = self.count_database_queries(file);

        // Calculate performance score for this file
        let performance_score = self.calculate_file_performance_score(
            cyclomatic_complexity,
            average_function_length,
            nested_loops,
            memory_allocations,
            io_operations,
        );

        Ok(FilePerformanceMetrics {
            file: file.path.clone(),
            performance_score,
            cyclomatic_complexity,
            function_count,
            average_function_length,
            nested_loops,
            recursive_functions,
            memory_allocations,
            io_operations,
            database_queries,
        })
    }

    /// Detect performance hotspots in a file
    fn detect_file_hotspots(&self, file: &FileInfo) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        // Check for long functions
        for symbol in &file.symbols {
            if symbol.kind == "function" {
                let function_length = symbol.end_line.saturating_sub(symbol.start_line) + 1;

                if function_length > self.config.max_function_length {
                    hotspots.push(PerformanceHotspot {
                        id: format!("LONG_FUNCTION_{}_{}", file.path.display(), symbol.name),
                        title: "Long function detected".to_string(),
                        description: format!(
                            "Function '{}' is {} lines long, which may impact performance",
                            symbol.name, function_length
                        ),
                        category: HotspotCategory::AlgorithmicComplexity,
                        severity: if function_length > FUNCTION_LENGTH_HIGH_THRESHOLD {
                            PerformanceSeverity::High
                        } else {
                            PerformanceSeverity::Medium
                        },
                        impact: PerformanceImpact {
                            cpu_impact: 60,
                            memory_impact: 30,
                            io_impact: 10,
                            network_impact: 0,
                            overall_impact: 50,
                        },
                        location: HotspotLocation {
                            file: file.path.display().to_string(),
                            function: Some(symbol.name.clone()),
                            start_line: symbol.start_line,
                            end_line: symbol.end_line,
                            scope: "function".to_string(),
                        },
                        code_snippet: format!("fn {}(...) {{ ... }}", symbol.name),
                        optimization: "Break down into smaller, focused functions".to_string(),
                        expected_improvement: ExpectedImprovement {
                            performance_gain: 15.0,
                            memory_reduction: 5.0,
                            time_reduction: 10.0,
                            confidence: ConfidenceLevel::Medium,
                        },
                        difficulty: OptimizationDifficulty::Medium,
                        patterns: vec!["Long Method".to_string(), "God Function".to_string()],
                    });
                }
            }
        }

        // Try to read and parse the file for real hotspot detection
        if let Ok(content) = std::fs::read_to_string(&file.path) {
            hotspots.extend(self.detect_ast_hotspots(&content, file)?);
        }

        Ok(hotspots)
    }

    /// Detect hotspots using AST analysis
    fn detect_ast_hotspots(
        &self,
        content: &str,
        file: &FileInfo,
    ) -> Result<Vec<PerformanceHotspot>> {
        use crate::{Language, Parser};

        let lang = match file.language.to_lowercase().as_str() {
            "rust" => Language::Rust,
            "python" => Language::Python,
            "javascript" => Language::JavaScript,
            "typescript" => Language::TypeScript,
            "c" => Language::C,
            "cpp" | "c++" => Language::Cpp,
            "go" => Language::Go,
            _ => return Ok(Vec::new()),
        };

        let parser = match Parser::new(lang) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "Warning: Failed to create parser for {}: {}",
                    file.language, e
                );
                return Ok(Vec::new()); // Continue analysis without AST-based hotspots
            }
        };

        let tree = match parser.parse(content, None) {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "Warning: Failed to parse {} for hotspot detection: {}",
                    file.path.display(),
                    e
                );
                return Ok(Vec::new()); // Continue analysis without AST-based hotspots
            }
        };

        let mut hotspots = Vec::new();

        // Detect nested loops
        hotspots.extend(self.detect_nested_loop_hotspots(&tree, content, file)?);

        // Detect memory allocation hotspots
        hotspots.extend(self.detect_memory_hotspots(&tree, content, file)?);

        // Detect high complexity functions
        hotspots.extend(self.detect_complexity_hotspots(&tree, content, file)?);

        Ok(hotspots)
    }

    /// Detect nested loop hotspots using semantic AST analysis (optimized)
    fn detect_nested_loop_hotspots(
        &self,
        tree: &crate::SyntaxTree,
        content: &str,
        file: &FileInfo,
    ) -> Result<Vec<PerformanceHotspot>> {
        self.detect_semantic_complexity_patterns(tree, content, file)
    }

    /// Detect semantic complexity patterns using advanced AST analysis
    /// Identifies O(n²), O(n³), and other algorithmic complexity patterns with high accuracy
    fn detect_semantic_complexity_patterns(
        &self,
        tree: &crate::SyntaxTree,
        content: &str,
        file: &FileInfo,
    ) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();
        let root_node = tree.inner().root_node();

        // Analyze nested iteration patterns
        let nested_patterns = self.analyze_nested_iteration_patterns(&root_node, content, file)?;
        hotspots.extend(nested_patterns);

        // Analyze recursive complexity patterns
        let recursive_patterns =
            self.analyze_recursive_complexity_patterns(&root_node, content, file)?;
        hotspots.extend(recursive_patterns);

        // Analyze data structure access patterns
        let access_patterns =
            self.analyze_data_structure_access_patterns(&root_node, content, file)?;
        hotspots.extend(access_patterns);

        // Analyze algorithmic anti-patterns
        let antipatterns = self.analyze_algorithmic_antipatterns(&root_node, content, file)?;
        hotspots.extend(antipatterns);

        Ok(hotspots)
    }

    /// Analyze nested iteration patterns for O(n²) and O(n³) complexity
    fn analyze_nested_iteration_patterns(
        &self,
        node: &tree_sitter::Node,
        content: &str,
        file: &FileInfo,
    ) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        // Find all loop constructs and analyze their nesting
        let loop_nodes = self.find_loop_nodes(node, file);

        for loop_node in &loop_nodes {
            let nesting_info = self.analyze_loop_nesting(loop_node, content, file)?;

            if nesting_info.depth >= 2 {
                let complexity_order = nesting_info.depth;
                let function_name = self.find_enclosing_function_name_for_ts_node(
                    loop_node,
                    content,
                    &file.language,
                );
                let semantic_analysis =
                    self.perform_semantic_loop_analysis(&nesting_info, function_name)?;

                let severity = match complexity_order {
                    2 => PerformanceSeverity::Medium,
                    3 => PerformanceSeverity::High,
                    _ => PerformanceSeverity::Critical,
                };

                let confidence = self.calculate_complexity_confidence(&semantic_analysis);

                hotspots.push(PerformanceHotspot {
                    id: format!("NESTED_LOOP_O_N{}", complexity_order),
                    title: format!("O(n^{}) Algorithmic Complexity Detected", complexity_order),
                    description: format!(
                        "Nested loop pattern with {} levels detected. {}. Confidence: {:.1}%",
                        nesting_info.depth,
                        semantic_analysis.description,
                        confidence * 100.0
                    ),
                    category: HotspotCategory::AlgorithmicComplexity,
                    severity,
                    impact: PerformanceImpact {
                        cpu_impact: (complexity_order * 30).min(100) as u8,
                        memory_impact: (complexity_order * 15).min(100) as u8,
                        io_impact: 0,
                        network_impact: 0,
                        overall_impact: (complexity_order * 25).min(100) as u8,
                    },
                    location: HotspotLocation {
                        file: file.path.display().to_string(),
                        function: semantic_analysis.function_name.clone(),
                        start_line: loop_node.start_position().row + 1,
                        end_line: loop_node.end_position().row + 1,
                        scope: "nested_loops".to_string(),
                    },
                    code_snippet: self.extract_code_snippet(content, loop_node),
                    optimization: self
                        .generate_complexity_optimization(&semantic_analysis, complexity_order),
                    expected_improvement: ExpectedImprovement {
                        performance_gain: (complexity_order as f64 * 25.0).min(90.0),
                        memory_reduction: (complexity_order as f64 * 10.0).min(50.0),
                        time_reduction: (complexity_order as f64 * 30.0).min(95.0),
                        confidence: if confidence > 0.8 {
                            ConfidenceLevel::High
                        } else {
                            ConfidenceLevel::Medium
                        },
                    },
                    difficulty: match complexity_order {
                        3.. => OptimizationDifficulty::VeryHard,
                        2 => OptimizationDifficulty::Hard,
                        _ => OptimizationDifficulty::Medium,
                    },
                    patterns: vec![
                        format!("O(n^{}) Complexity", complexity_order),
                        "Nested Iteration".to_string(),
                        semantic_analysis.pattern_type,
                    ],
                });
            }
        }

        Ok(hotspots)
    }

    /// Find all loop nodes in the AST
    fn find_loop_nodes<'a>(
        &self,
        node: &tree_sitter::Node<'a>,
        file: &FileInfo,
    ) -> Vec<tree_sitter::Node<'a>> {
        let mut loop_nodes = Vec::new();
        let _cursor = node.walk();

        let loop_patterns = match file.language.to_lowercase().as_str() {
            "rust" => vec![
                "for_expression",
                "while_expression",
                "while_let_expression",
                "loop_expression",
            ],
            "python" => vec!["for_statement", "while_statement"],
            "javascript" | "typescript" => vec![
                "for_statement",
                "for_in_statement",
                "for_of_statement",
                "while_statement",
                "do_statement",
            ],
            "c" | "cpp" | "c++" => vec!["for_statement", "while_statement", "do_statement"],
            "go" => vec!["for_statement"],
            _ => vec!["for_statement", "while_statement"],
        };

        self.traverse_for_loops(node, &loop_patterns, &mut loop_nodes);
        loop_nodes
    }

    /// Recursively traverse AST to find loop nodes
    fn traverse_for_loops<'a>(
        &self,
        node: &tree_sitter::Node<'a>,
        patterns: &[&str],
        loop_nodes: &mut Vec<tree_sitter::Node<'a>>,
    ) {
        if patterns.contains(&node.kind()) {
            loop_nodes.push(*node);
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.traverse_for_loops(&child, patterns, loop_nodes);
            }
        }
    }

    /// Analyze the nesting structure of a loop
    fn analyze_loop_nesting(
        &self,
        loop_node: &tree_sitter::Node,
        content: &str,
        file: &FileInfo,
    ) -> Result<LoopNestingInfo> {
        let current_node = *loop_node;
        let depth = self.loop_depth_for_ts_node(&current_node, file);

        // Extract iteration variables and analyze dependencies
        let iteration_variables = self.extract_iteration_variables(&current_node, content, file)?;
        let data_dependencies =
            self.analyze_data_dependencies(&current_node, &iteration_variables, content, file)?;

        Ok(LoopNestingInfo {
            depth,
            iteration_variables,
            data_dependencies,
            loop_types: self.classify_loop_types(&current_node, file),
            access_patterns: self.analyze_access_patterns(&current_node, content, file)?,
        })
    }

    /// Extract iteration variables from a loop node
    fn extract_iteration_variables(
        &self,
        node: &tree_sitter::Node,
        content: &str,
        _file: &FileInfo,
    ) -> Result<Vec<String>> {
        let mut variables = Vec::new();

        let body_start = node
            .child_by_field_name("body")
            .map(|body| body.start_byte())
            .unwrap_or(node.end_byte());

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.is_named() && child.end_byte() <= body_start {
                    self.collect_identifier_texts_from_ts_node(&child, content, &mut variables);
                }
            }
        }

        variables.sort();
        variables.dedup();

        Ok(variables)
    }

    /// Analyze data dependencies between iteration variables
    fn analyze_data_dependencies(
        &self,
        node: &tree_sitter::Node,
        iteration_vars: &[String],
        content: &str,
        file: &FileInfo,
    ) -> Result<Vec<DataDependency>> {
        let mut dependencies = Vec::new();

        let wrapped_node = crate::Node::new(*node, content);
        let index_nodes = self.find_index_nodes_in_subtree(wrapped_node, &file.language);

        for var in iteration_vars {
            if index_nodes
                .iter()
                .any(|index_node| self.node_contains_identifier(index_node, var))
            {
                dependencies.push(DataDependency {
                    variable: var.clone(),
                    dependency_type: DependencyType::IndexBased,
                    scope: "loop_body".to_string(),
                });
                continue;
            }

            if self.node_contains_identifier(&wrapped_node, var) {
                dependencies.push(DataDependency {
                    variable: var.clone(),
                    dependency_type: DependencyType::ReadOnly,
                    scope: "loop_body".to_string(),
                });
            }
        }

        Ok(dependencies)
    }

    /// Classify the types of loops found
    fn classify_loop_types(&self, node: &tree_sitter::Node, file: &FileInfo) -> Vec<LoopType> {
        let mut types = Vec::new();

        match node.kind() {
            "for_expression" | "for_statement" | "for_in_statement" | "for_of_statement" => {
                types.push(LoopType::ForLoop);
            }
            "while_expression" | "while_statement" | "while_let_expression" => {
                types.push(LoopType::WhileLoop);
            }
            "loop_expression" => {
                types.push(LoopType::Iterator);
            }
            _ => {
                // Check if it's a recursive pattern
                if let Some(parent) = node.parent() {
                    if self
                        .function_node_kinds(&file.language)
                        .iter()
                        .any(|kind| *kind == parent.kind())
                    {
                        types.push(LoopType::Recursive);
                    }
                }
            }
        }

        types
    }

    /// Analyze memory access patterns within loops
    fn analyze_access_patterns(
        &self,
        node: &tree_sitter::Node,
        content: &str,
        file: &FileInfo,
    ) -> Result<Vec<AccessPattern>> {
        let mut patterns = Vec::new();

        let wrapped_node = crate::Node::new(*node, content);
        let index_nodes = self.find_index_nodes_in_subtree(wrapped_node, &file.language);

        if !index_nodes.is_empty() {
            patterns.push(AccessPattern {
                pattern_type: AccessPatternType::Sequential,
                complexity: AccessComplexity::Linear,
                description: "Indexed collection access detected".to_string(),
            });
        }

        if index_nodes
            .iter()
            .any(|index_node| self.has_nested_index_access(index_node, &file.language))
        {
            patterns.push(AccessPattern {
                pattern_type: AccessPatternType::Nested,
                complexity: AccessComplexity::Quadratic,
                description: "Nested indexed access detected".to_string(),
            });
        }

        Ok(patterns)
    }

    /// Perform semantic analysis of loop structure
    fn perform_semantic_loop_analysis(
        &self,
        nesting_info: &LoopNestingInfo,
        function_name: Option<String>,
    ) -> Result<SemanticLoopAnalysis> {
        let mut confidence: f64 = 0.5; // Base confidence
        let description;
        let pattern_type;
        let mut optimization_suggestions = Vec::new();

        // Analyze nesting depth
        match nesting_info.depth {
            2 => {
                description = "Quadratic complexity pattern detected with nested loops".to_string();
                pattern_type = "O(n²) Nested Loops".to_string();
                confidence += 0.3;
                optimization_suggestions
                    .push("Consider using hash maps or sets for lookups".to_string());
                optimization_suggestions
                    .push("Evaluate if inner loop can be eliminated".to_string());
            }
            3 => {
                description =
                    "Cubic complexity pattern detected with triple-nested loops".to_string();
                pattern_type = "O(n³) Triple Nested Loops".to_string();
                confidence += 0.4;
                optimization_suggestions
                    .push("Critical: Consider algorithmic redesign".to_string());
                optimization_suggestions
                    .push("Look for dynamic programming opportunities".to_string());
                optimization_suggestions
                    .push("Consider matrix operations or vectorization".to_string());
            }
            depth if depth > 3 => {
                description = format!(
                    "Exponential complexity pattern detected with {}-level nesting",
                    depth
                );
                pattern_type = format!("O(n^{}) Highly Nested Loops", depth);
                confidence += 0.5;
                optimization_suggestions.push("URGENT: Algorithmic redesign required".to_string());
                optimization_suggestions.push("Consider divide-and-conquer approaches".to_string());
            }
            _ => {
                description = "Linear complexity pattern detected".to_string();
                pattern_type = "O(n) Single Loop".to_string();
            }
        }

        // Analyze access patterns for additional confidence
        for pattern in &nesting_info.access_patterns {
            match pattern.complexity {
                AccessComplexity::Quadratic => confidence += 0.2,
                AccessComplexity::Cubic => confidence += 0.3,
                AccessComplexity::Linear => confidence += 0.1,
                _ => {}
            }
        }

        // Analyze data dependencies
        let has_index_dependencies = nesting_info
            .data_dependencies
            .iter()
            .any(|dep| matches!(dep.dependency_type, DependencyType::IndexBased));

        if has_index_dependencies {
            confidence += 0.1;
            optimization_suggestions
                .push("Index-based dependencies detected - consider iterator patterns".to_string());
        }

        confidence = confidence.min(1.0); // Cap at 100%

        Ok(SemanticLoopAnalysis {
            description,
            pattern_type,
            function_name,
            confidence,
            optimization_suggestions,
        })
    }

    /// Calculate confidence level for complexity detection
    fn calculate_complexity_confidence(&self, analysis: &SemanticLoopAnalysis) -> f64 {
        analysis.confidence
    }

    /// Generate optimization suggestions based on complexity analysis
    fn generate_complexity_optimization(
        &self,
        analysis: &SemanticLoopAnalysis,
        complexity_order: usize,
    ) -> String {
        let base_suggestions = &analysis.optimization_suggestions;

        let mut optimization = match complexity_order {
            2 => "Consider algorithmic improvements: use hash maps for O(1) lookups, eliminate inner loop if possible, or use more efficient data structures.".to_string(),
            3 => "CRITICAL: Redesign algorithm to avoid cubic complexity. Consider dynamic programming, memoization, or divide-and-conquer approaches.".to_string(),
            _ => "URGENT: Exponential complexity detected. Complete algorithmic redesign required.".to_string(),
        };

        if !base_suggestions.is_empty() {
            optimization.push_str(" Specific suggestions: ");
            optimization.push_str(&base_suggestions.join(", "));
        }

        optimization
    }

    /// Extract code snippet from a tree-sitter node
    fn extract_code_snippet(&self, content: &str, node: &tree_sitter::Node) -> String {
        node.utf8_text(content.as_bytes())
            .unwrap_or("Code snippet unavailable")
            .lines()
            .take(10) // Limit to 10 lines
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Analyze recursive complexity patterns
    fn analyze_recursive_complexity_patterns(
        &self,
        node: &tree_sitter::Node,
        content: &str,
        file: &FileInfo,
    ) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        // Find function definitions that call themselves
        let function_nodes = self.find_function_nodes(node, file);

        for func_node in function_nodes {
            if let Some(func_name) = self.extract_function_name(&func_node, content, file) {
                if self.is_recursive_function(&func_node, &func_name, content, &file.language) {
                    let recursion_analysis =
                        self.analyze_recursion_complexity(&func_node, &func_name, content, file)?;

                    if recursion_analysis.complexity_risk > 0.7 {
                        hotspots.push(PerformanceHotspot {
                            id: format!("RECURSIVE_COMPLEXITY_{}", func_name),
                            title: format!("High Complexity Recursion in {}", func_name),
                            description: format!(
                                "Recursive function with potential exponential complexity. Risk level: {:.1}%",
                                recursion_analysis.complexity_risk * 100.0
                            ),
                            category: HotspotCategory::AlgorithmicComplexity,
                            severity: if recursion_analysis.complexity_risk > 0.9 {
                                PerformanceSeverity::Critical
                            } else {
                                PerformanceSeverity::High
                            },
                            impact: PerformanceImpact {
                                cpu_impact: 90,
                                memory_impact: 70,
                                io_impact: 0,
                                network_impact: 0,
                                overall_impact: 85,
                            },
                            location: HotspotLocation {
                                file: file.path.display().to_string(),
                                function: Some(func_name.clone()),
                                start_line: func_node.start_position().row + 1,
                                end_line: func_node.end_position().row + 1,
                                scope: "function".to_string(),
                            },
                            code_snippet: self.extract_code_snippet(content, &func_node),
                            optimization: recursion_analysis.optimization_suggestion,
                            expected_improvement: ExpectedImprovement {
                                performance_gain: 80.0,
                                memory_reduction: 60.0,
                                time_reduction: 85.0,
                                confidence: ConfidenceLevel::High,
                            },
                            difficulty: OptimizationDifficulty::Hard,
                            patterns: vec![
                                "Recursive Function".to_string(),
                                recursion_analysis.pattern_type,
                                "Exponential Complexity Risk".to_string(),
                            ],
                        });
                    }
                }
            }
        }

        Ok(hotspots)
    }

    /// Analyze data structure access patterns for complexity issues
    fn analyze_data_structure_access_patterns(
        &self,
        node: &tree_sitter::Node,
        content: &str,
        file: &FileInfo,
    ) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        for loop_node in self.find_loop_nodes(node, file) {
            let wrapped_loop = crate::Node::new(loop_node, content);
            let linear_ops =
                self.find_linear_operation_nodes_in_subtree(wrapped_loop, &file.language);

            if linear_ops.is_empty() {
                continue;
            }

            let index_nodes = self.find_index_nodes_in_subtree(wrapped_loop, &file.language);
            let start_point = loop_node.start_position();
            let end_point = loop_node.end_position();

            hotspots.push(PerformanceHotspot {
                id: format!(
                    "LINEAR_OPS_IN_LOOP_{}_{}_{}",
                    file.path.display(),
                    start_point.row,
                    start_point.column
                ),
                title: "Linear Operations in Loop (O(n²) Pattern)".to_string(),
                description:
                    "Linear-time collection operations inside loops create quadratic behavior"
                        .to_string(),
                category: HotspotCategory::AlgorithmicComplexity,
                severity: if self.loop_depth_for_ts_node(&loop_node, file) >= 2 {
                    PerformanceSeverity::High
                } else {
                    PerformanceSeverity::Medium
                },
                impact: PerformanceImpact {
                    cpu_impact: 80,
                    memory_impact: 20,
                    io_impact: 0,
                    network_impact: 0,
                    overall_impact: 70,
                },
                location: HotspotLocation {
                    file: file.path.display().to_string(),
                    function: self.find_enclosing_function_name(
                        &wrapped_loop,
                        content,
                        &file.language,
                    ),
                    start_line: start_point.row + 1,
                    end_line: end_point.row + 1,
                    scope: "data_structure_access".to_string(),
                },
                code_snippet: self.extract_code_snippet(content, &loop_node),
                optimization: "Replace linear scans with hash-based lookups or precomputed indexes"
                    .to_string(),
                expected_improvement: ExpectedImprovement {
                    performance_gain: 75.0,
                    memory_reduction: 10.0,
                    time_reduction: 80.0,
                    confidence: ConfidenceLevel::High,
                },
                difficulty: OptimizationDifficulty::Medium,
                patterns: if index_nodes.is_empty() {
                    vec![
                        "O(n²) Data Access".to_string(),
                        "Linear Scan in Loop".to_string(),
                    ]
                } else {
                    vec![
                        "O(n²) Data Access".to_string(),
                        "Linear Scan in Loop".to_string(),
                        "Indexed Access in Loop".to_string(),
                    ]
                },
            });
        }

        Ok(hotspots)
    }

    /// Analyze algorithmic anti-patterns
    fn analyze_algorithmic_antipatterns(
        &self,
        node: &tree_sitter::Node,
        content: &str,
        file: &FileInfo,
    ) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        for loop_node in self.find_loop_nodes(node, file) {
            if self.loop_depth_for_ts_node(&loop_node, file) < 2 {
                continue;
            }

            let wrapped_loop = crate::Node::new(loop_node, content);
            if !self.contains_swap_operation(wrapped_loop, content, &file.language) {
                continue;
            }

            let start_point = loop_node.start_position();
            let end_point = loop_node.end_position();
            hotspots.push(PerformanceHotspot {
                id: format!(
                    "INEFFICIENT_SORTING_{}_{}_{}",
                    file.path.display(),
                    start_point.row,
                    start_point.column
                ),
                title: "Inefficient Sorting Algorithm Detected".to_string(),
                description:
                    "Nested loop swapping pattern detected; this is likely an O(n²) manual sort"
                        .to_string(),
                category: HotspotCategory::AlgorithmicComplexity,
                severity: PerformanceSeverity::Medium,
                impact: PerformanceImpact {
                    cpu_impact: 70,
                    memory_impact: 10,
                    io_impact: 0,
                    network_impact: 0,
                    overall_impact: 60,
                },
                location: HotspotLocation {
                    file: file.path.display().to_string(),
                    function: self.find_enclosing_function_name(
                        &wrapped_loop,
                        content,
                        &file.language,
                    ),
                    start_line: start_point.row + 1,
                    end_line: end_point.row + 1,
                    scope: "sorting_algorithm".to_string(),
                },
                code_snippet: self.extract_code_snippet(content, &loop_node),
                optimization:
                    "Use built-in sorting functions (O(n log n)) instead of manual sorting loops"
                        .to_string(),
                expected_improvement: ExpectedImprovement {
                    performance_gain: 60.0,
                    memory_reduction: 5.0,
                    time_reduction: 70.0,
                    confidence: ConfidenceLevel::High,
                },
                difficulty: OptimizationDifficulty::Easy,
                patterns: vec![
                    "O(n²) Sorting".to_string(),
                    "Algorithmic Anti-pattern".to_string(),
                ],
            });
        }

        Ok(hotspots)
    }

    /// Find function nodes in the AST
    fn find_function_nodes<'a>(
        &self,
        node: &tree_sitter::Node<'a>,
        file: &FileInfo,
    ) -> Vec<tree_sitter::Node<'a>> {
        let mut function_nodes = Vec::new();

        let function_patterns = self.function_node_kinds(&file.language);

        self.traverse_for_functions(node, &function_patterns, &mut function_nodes);
        function_nodes
    }

    /// Recursively traverse AST to find function nodes
    fn traverse_for_functions<'a>(
        &self,
        node: &tree_sitter::Node<'a>,
        patterns: &[&str],
        function_nodes: &mut Vec<tree_sitter::Node<'a>>,
    ) {
        if patterns.contains(&node.kind()) {
            function_nodes.push(*node);
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.traverse_for_functions(&child, patterns, function_nodes);
            }
        }
    }

    /// Extract function name from a function node
    fn extract_function_name(
        &self,
        node: &tree_sitter::Node,
        content: &str,
        _file: &FileInfo,
    ) -> Option<String> {
        // Look for identifier nodes within the function declaration
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    if let Ok(name) = child.utf8_text(content.as_bytes()) {
                        return Some(name.to_string());
                    }
                }
            }
        }
        None
    }

    /// Check if a function is recursive
    fn is_recursive_function(
        &self,
        node: &tree_sitter::Node,
        func_name: &str,
        content: &str,
        language: &str,
    ) -> bool {
        self.function_contains_recursive_call(crate::Node::new(*node, content), func_name, language)
    }

    /// Analyze recursion complexity
    fn analyze_recursion_complexity(
        &self,
        node: &tree_sitter::Node,
        func_name: &str,
        content: &str,
        _file: &FileInfo,
    ) -> Result<RecursionAnalysis> {
        let mut complexity_risk: f64 = 0.5; // Base risk
        let mut pattern_type = "Direct Recursion".to_string();
        let mut optimization_suggestion = "Consider iterative approach or memoization".to_string();

        if let Ok(text) = node.utf8_text(content.as_bytes()) {
            // Count recursive calls
            let recursive_calls = text.matches(&format!("{}(", func_name)).count() - 1; // Subtract definition

            if recursive_calls > 2 {
                complexity_risk += 0.3;
                pattern_type = "Multiple Recursive Calls".to_string();
                optimization_suggestion =
                    "CRITICAL: Multiple recursive calls detected - consider dynamic programming"
                        .to_string();
            }

            // Check for base case
            let has_base_case = text.contains("return")
                && (text.contains("if") || text.contains("match") || text.contains("when"));

            if !has_base_case {
                complexity_risk += 0.4;
                optimization_suggestion =
                    "URGENT: No clear base case detected - infinite recursion risk".to_string();
            }

            // Check for tail recursion
            let lines: Vec<&str> = text.lines().collect();
            let last_meaningful_line = lines
                .iter()
                .rev()
                .find(|line| !line.trim().is_empty() && !line.trim().starts_with('}'))
                .unwrap_or(&"");

            if last_meaningful_line.contains(&format!("{}(", func_name)) {
                pattern_type = "Tail Recursion".to_string();
                complexity_risk -= 0.2; // Tail recursion is better
                optimization_suggestion =
                    "Consider converting tail recursion to iteration".to_string();
            }
        }

        Ok(RecursionAnalysis {
            complexity_risk: complexity_risk.min(1.0),
            pattern_type,
            optimization_suggestion,
        })
    }

    /// Detect memory allocation hotspots using AST analysis (optimized)
    fn detect_memory_hotspots(
        &self,
        tree: &crate::SyntaxTree,
        content: &str,
        file: &FileInfo,
    ) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::with_capacity(16); // Pre-allocate for common case

        for allocation in self.collect_allocation_nodes(tree, &file.language) {
            let start_point = allocation.start_position();
            let end_point = allocation.end_position();
            let in_loop = self.is_inside_loop(&allocation, &file.language);
            let allocation_label = self.describe_allocation_node(&allocation, &file.language);

            hotspots.push(PerformanceHotspot {
                id: format!(
                    "MEMORY_ALLOC_{}_{}_{}",
                    file.path.display(),
                    start_point.row,
                    start_point.column
                ),
                title: if in_loop {
                    "Memory allocation in loop".to_string()
                } else {
                    "Memory allocation detected".to_string()
                },
                description: if in_loop {
                    format!("{allocation_label} inside a loop can create memory churn")
                } else {
                    format!("{allocation_label} detected; consider reusing or pre-allocating")
                },
                category: HotspotCategory::MemoryUsage,
                severity: if in_loop {
                    PerformanceSeverity::High
                } else {
                    PerformanceSeverity::Medium
                },
                impact: PerformanceImpact {
                    cpu_impact: if in_loop { 40 } else { 20 },
                    memory_impact: if in_loop { 90 } else { 60 },
                    io_impact: 0,
                    network_impact: 0,
                    overall_impact: if in_loop { 70 } else { 40 },
                },
                location: HotspotLocation {
                    file: file.path.display().to_string(),
                    function: self.find_enclosing_function_name(
                        &allocation,
                        content,
                        &file.language,
                    ),
                    start_line: start_point.row + 1,
                    end_line: end_point.row + 1,
                    scope: "allocation".to_string(),
                },
                code_snippet: allocation.text().unwrap_or("allocation").to_string(),
                optimization: if in_loop {
                    "Move allocation outside the loop or pre-allocate reusable storage".to_string()
                } else {
                    "Consider pre-allocating or reusing the allocated structure".to_string()
                },
                expected_improvement: ExpectedImprovement {
                    performance_gain: if in_loop { 40.0 } else { 20.0 },
                    memory_reduction: if in_loop { 60.0 } else { 30.0 },
                    time_reduction: if in_loop { 35.0 } else { 15.0 },
                    confidence: if in_loop {
                        ConfidenceLevel::High
                    } else {
                        ConfidenceLevel::Medium
                    },
                },
                difficulty: OptimizationDifficulty::Easy,
                patterns: if in_loop {
                    vec![
                        "Allocation in Loop".to_string(),
                        allocation_label,
                        "Memory Churn".to_string(),
                    ]
                } else {
                    vec!["Memory Allocation".to_string(), allocation_label]
                },
            });
        }

        Ok(hotspots)
    }

    /// Detect high complexity function hotspots
    fn detect_complexity_hotspots(
        &self,
        tree: &crate::SyntaxTree,
        content: &str,
        file: &FileInfo,
    ) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        // Find function definitions
        let function_patterns = self.function_node_kinds(&file.language);

        for pattern in function_patterns {
            let functions = tree.find_nodes_by_kind(pattern);
            for func_node in functions {
                let complexity =
                    self.calculate_function_complexity(&func_node, content, &file.language);

                if complexity > self.config.min_complexity_threshold as f64 {
                    let start_point = func_node.start_position();
                    let end_point = func_node.end_position();

                    // Try to extract function name
                    let function_name =
                        self.extract_function_name_from_node(&func_node, content, &file.language);

                    hotspots.push(PerformanceHotspot {
                        id: format!(
                            "HIGH_COMPLEXITY_{}_{}_{}",
                            file.path.display(),
                            start_point.row,
                            start_point.column
                        ),
                        title: "High complexity function".to_string(),
                        description: format!(
                            "Function '{}' has cyclomatic complexity of {:.1}",
                            function_name, complexity
                        ),
                        category: HotspotCategory::AlgorithmicComplexity,
                        severity: if complexity > 15.0 {
                            PerformanceSeverity::Critical
                        } else if complexity > 10.0 {
                            PerformanceSeverity::High
                        } else {
                            PerformanceSeverity::Medium
                        },
                        impact: PerformanceImpact {
                            cpu_impact: (complexity * COMPLEXITY_CPU_MULTIPLIER).min(MAX_CPU_IMPACT)
                                as u8,
                            memory_impact: 20,
                            io_impact: 0,
                            network_impact: 0,
                            overall_impact: (complexity * COMPLEXITY_OVERALL_MULTIPLIER)
                                .min(MAX_OVERALL_IMPACT)
                                as u8,
                        },
                        location: HotspotLocation {
                            file: file.path.display().to_string(),
                            function: Some(function_name.clone()),
                            start_line: start_point.row + 1,
                            end_line: end_point.row + 1,
                            scope: "function".to_string(),
                        },
                        code_snippet: format!("fn {}(...) {{ ... }}", function_name),
                        optimization:
                            "Break down into smaller functions, reduce nesting, or simplify logic"
                                .to_string(),
                        expected_improvement: ExpectedImprovement {
                            performance_gain: 30.0,
                            memory_reduction: 10.0,
                            time_reduction: 25.0,
                            confidence: ConfidenceLevel::Medium,
                        },
                        difficulty: OptimizationDifficulty::Medium,
                        patterns: vec![
                            "High Complexity".to_string(),
                            format!("Complexity: {:.1}", complexity),
                        ],
                    });
                }
            }
        }

        Ok(hotspots)
    }

    /// Calculate complexity for a specific function node
    fn calculate_function_complexity(
        &self,
        func_node: &crate::Node,
        _content: &str,
        language: &str,
    ) -> f64 {
        let mut complexity = 1.0; // Base complexity

        // Define control flow patterns for different languages
        let control_patterns = match language.to_lowercase().as_str() {
            "rust" => vec![
                "if_expression",
                "if_let_expression",
                "while_expression",
                "while_let_expression",
                "for_expression",
                "loop_expression",
                "match_expression",
                "match_arm",
                "try_expression",
                "catch_clause",
            ],
            "python" => vec![
                "if_statement",
                "elif_clause",
                "while_statement",
                "for_statement",
                "try_statement",
                "except_clause",
                "with_statement",
                "match_statement",
                "case_clause",
            ],
            "javascript" | "typescript" => vec![
                "if_statement",
                "while_statement",
                "for_statement",
                "for_in_statement",
                "for_of_statement",
                "switch_statement",
                "case_clause",
                "try_statement",
                "catch_clause",
                "conditional_expression",
            ],
            "c" | "cpp" | "c++" => vec![
                "if_statement",
                "while_statement",
                "for_statement",
                "do_statement",
                "switch_statement",
                "case_statement",
                "conditional_expression",
            ],
            "go" => vec![
                "if_statement",
                "for_statement",
                "switch_statement",
                "type_switch_statement",
                "case_clause",
                "select_statement",
                "communication_clause",
            ],
            _ => vec![
                "if_statement",
                "while_statement",
                "for_statement",
                "switch_statement",
            ],
        };

        // Count control flow nodes within this function
        for pattern in control_patterns {
            let nodes = self.find_nodes_in_subtree(func_node, pattern);
            complexity += nodes.len() as f64;
        }

        complexity
    }

    /// Extract function name from crate::Node (different from tree_sitter::Node)
    fn extract_function_name_from_node(
        &self,
        func_node: &crate::Node,
        _content: &str,
        language: &str,
    ) -> String {
        match language.to_lowercase().as_str() {
            "rust" | "python" => func_node
                .child_by_field_name("name")
                .and_then(|name_node| name_node.text().ok())
                .map(str::to_string)
                .unwrap_or_else(|| "unknown".to_string()),
            "javascript" | "typescript" => {
                if let Some(name_node) = func_node.child_by_field_name("name") {
                    name_node.text().unwrap_or("unknown").to_string()
                } else if func_node.kind() == "arrow_function" {
                    func_node
                        .parent()
                        .and_then(|parent| {
                            (parent.kind() == "variable_declarator")
                                .then(|| parent.child_by_field_name("name"))
                        })
                        .flatten()
                        .and_then(|name_node| name_node.text().ok())
                        .map(str::to_string)
                        .unwrap_or_else(|| "anonymous".to_string())
                } else {
                    "anonymous".to_string()
                }
            }
            _ => "unknown".to_string(),
        }
    }

    /// Find nodes of a specific kind within a subtree
    fn find_nodes_in_subtree<'a>(
        &self,
        root: &crate::Node<'a>,
        kind: &str,
    ) -> Vec<crate::Node<'a>> {
        let mut nodes = Vec::new();
        self.collect_nodes_recursive(root, kind, &mut nodes);
        nodes
    }

    /// Recursively collect nodes of a specific kind
    fn collect_nodes_recursive<'a>(
        &self,
        node: &crate::Node<'a>,
        target_kind: &str,
        nodes: &mut Vec<crate::Node<'a>>,
    ) {
        if node.kind() == target_kind {
            nodes.push(*node);
        }

        for child in node.children() {
            self.collect_nodes_recursive(&child, target_kind, nodes);
        }
    }

    fn loop_depth_for_ts_node(&self, node: &tree_sitter::Node, file: &FileInfo) -> usize {
        let loop_patterns = LanguageParser::get_loop_patterns(&file.language);
        let mut depth = 0;
        let mut current = Some(*node);
        while let Some(candidate) = current {
            if loop_patterns
                .iter()
                .any(|pattern| *pattern == candidate.kind())
            {
                depth += 1;
            }
            current = candidate.parent();
        }
        depth
    }

    fn is_loop_kind(&self, kind: &str, language: &str) -> bool {
        LanguageParser::get_loop_patterns(language).contains(&kind)
    }

    /// Check if a node is inside a loop
    fn is_inside_loop(&self, node: &crate::Node, language: &str) -> bool {
        let mut current = node.parent();
        while let Some(parent) = current {
            if self.is_loop_kind(parent.kind(), language) {
                return true;
            }
            current = parent.parent();
        }
        false
    }

    fn collect_identifier_texts_from_ts_node(
        &self,
        node: &tree_sitter::Node,
        content: &str,
        identifiers: &mut Vec<String>,
    ) {
        if node.kind() == "identifier" {
            if let Ok(identifier) = node.utf8_text(content.as_bytes()) {
                identifiers.push(identifier.to_string());
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_identifier_texts_from_ts_node(&child, content, identifiers);
            }
        }
    }

    fn find_enclosing_function_name_for_ts_node(
        &self,
        node: &tree_sitter::Node,
        content: &str,
        language: &str,
    ) -> Option<String> {
        self.find_enclosing_function_name(&crate::Node::new(*node, content), content, language)
    }

    fn find_enclosing_function_name(
        &self,
        node: &crate::Node,
        content: &str,
        language: &str,
    ) -> Option<String> {
        let function_patterns = LanguageParser::get_function_patterns(language);
        let mut current = Some(*node);

        while let Some(candidate) = current {
            if function_patterns
                .iter()
                .any(|pattern| *pattern == candidate.kind())
            {
                return Some(self.extract_function_name_from_node(&candidate, content, language));
            }
            current = candidate.parent();
        }

        None
    }

    fn call_target_text(&self, node: &crate::Node) -> Option<String> {
        ["function", "constructor", "macro"]
            .iter()
            .find_map(|field| node.child_by_field_name(field))
            .and_then(|target| target.text().ok())
            .map(str::to_string)
    }

    fn parse_file_syntax_tree(&self, file: &FileInfo) -> Option<crate::SyntaxTree> {
        let content = std::fs::read_to_string(&file.path).ok()?;
        let parsed_language = self.parse_language(&file.language)?;
        self.create_syntax_tree(&content, parsed_language)
    }

    fn function_node_kinds(&self, language: &str) -> Vec<&'static str> {
        match language.to_lowercase().as_str() {
            "rust" => vec!["function_item"],
            "python" => vec!["function_definition", "async_function_definition"],
            "javascript" | "typescript" => vec![
                "function_declaration",
                "function_expression",
                "arrow_function",
                "method_definition",
            ],
            "c" | "cpp" | "c++" => vec!["function_definition"],
            "go" => vec!["function_declaration", "method_declaration"],
            _ => vec!["function_definition"],
        }
    }

    fn call_node_kinds(&self, language: &str) -> Vec<&'static str> {
        match language.to_lowercase().as_str() {
            "rust" | "javascript" | "typescript" | "c" | "cpp" | "c++" | "go" => {
                vec!["call_expression"]
            }
            "python" => vec!["call"],
            _ => Vec::new(),
        }
    }

    fn collect_function_nodes<'a>(
        &self,
        tree: &'a crate::SyntaxTree,
        language: &str,
    ) -> Vec<crate::Node<'a>> {
        let mut seen = HashSet::new();
        let mut functions = Vec::new();

        for kind in self.function_node_kinds(language) {
            for node in tree.find_nodes_by_kind(kind) {
                if seen.insert((node.start_byte(), node.end_byte())) {
                    functions.push(node);
                }
            }
        }

        functions
    }

    fn collect_call_nodes<'a>(
        &self,
        tree: &'a crate::SyntaxTree,
        language: &str,
    ) -> Vec<crate::Node<'a>> {
        self.collect_call_nodes_in_subtree(tree.root_node(), language)
    }

    fn collect_call_nodes_in_subtree<'a>(
        &self,
        root: crate::Node<'a>,
        language: &str,
    ) -> Vec<crate::Node<'a>> {
        let mut seen = HashSet::new();
        let mut calls = Vec::new();

        for kind in self.call_node_kinds(language) {
            for node in root.find_descendants(|candidate| candidate.kind() == kind) {
                if seen.insert((node.start_byte(), node.end_byte())) {
                    calls.push(node);
                }
            }
        }

        calls
    }

    fn target_segments(&self, target: &str) -> Vec<String> {
        target
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|segment| !segment.is_empty())
            .map(|segment| segment.to_ascii_lowercase())
            .collect()
    }

    fn call_leaf_identifier(&self, target: &str) -> Option<String> {
        self.target_segments(target).into_iter().last()
    }

    fn is_database_segment(&self, segment: &str) -> bool {
        matches!(
            segment,
            "db" | "database"
                | "conn"
                | "connection"
                | "pool"
                | "cursor"
                | "client"
                | "transaction"
                | "tx"
                | "stmt"
                | "statement"
                | "engine"
                | "session"
                | "sqlx"
                | "diesel"
                | "sequelize"
                | "knex"
                | "postgres"
                | "mysql"
                | "sqlite"
        )
    }

    fn call_contains_sql_literal(&self, node: &crate::Node) -> bool {
        const SQL_KEYWORDS: [&str; 6] = ["SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "FROM"];

        node.find_descendants(|candidate| {
            matches!(
                candidate.kind(),
                "string_literal"
                    | "raw_string_literal"
                    | "string"
                    | "template_string"
                    | "interpreted_string_literal"
            )
        })
        .into_iter()
        .filter_map(|literal| literal.text().ok())
        .map(|literal| literal.to_ascii_uppercase())
        .any(|literal| SQL_KEYWORDS.iter().any(|keyword| literal.contains(keyword)))
    }

    fn function_contains_recursive_call(
        &self,
        function_node: crate::Node<'_>,
        function_name: &str,
        language: &str,
    ) -> bool {
        let expected_name = function_name.to_ascii_lowercase();

        self.collect_call_nodes_in_subtree(function_node, language)
            .into_iter()
            .filter_map(|call_node| self.call_target_text(&call_node))
            .filter_map(|target| self.call_leaf_identifier(&target))
            .any(|leaf| leaf == expected_name)
    }

    fn is_io_call_node(&self, node: &crate::Node, language: &str) -> bool {
        let target = self
            .call_target_text(node)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if target.is_empty() {
            return false;
        }

        match language.to_lowercase().as_str() {
            "rust" => {
                matches!(
                    target.as_str(),
                    "std::fs::read"
                        | "std::fs::read_to_string"
                        | "std::fs::write"
                        | "std::fs::copy"
                        | "tokio::fs::read"
                        | "tokio::fs::read_to_string"
                        | "tokio::fs::write"
                ) || target.ends_with("::open")
                    || target.ends_with("::create")
                    || target.ends_with(".read")
                    || target.ends_with(".read_to_string")
                    || target.ends_with(".read_to_end")
                    || target.ends_with(".read_exact")
                    || target.ends_with(".write")
                    || target.ends_with(".write_all")
                    || target.ends_with(".flush")
                    || target.ends_with(".sync_all")
                    || target.ends_with(".sync_data")
            }
            "python" => {
                target == "open"
                    || target.ends_with(".open")
                    || target.ends_with(".read")
                    || target.ends_with(".read_text")
                    || target.ends_with(".read_bytes")
                    || target.ends_with(".write")
                    || target.ends_with(".write_text")
                    || target.ends_with(".write_bytes")
                    || target.ends_with(".flush")
            }
            "javascript" | "typescript" => {
                matches!(
                    target.as_str(),
                    "fs.readfile"
                        | "fs.readfilesync"
                        | "fs.writefile"
                        | "fs.writefilesync"
                        | "fetch"
                ) || target.ends_with(".readfile")
                    || target.ends_with(".readfilesync")
                    || target.ends_with(".writefile")
                    || target.ends_with(".writefilesync")
                    || target.ends_with(".appendfile")
                    || target.ends_with(".createreadstream")
                    || target.ends_with(".createwritestream")
            }
            "go" => {
                matches!(
                    target.as_str(),
                    "os.readfile" | "os.writefile" | "os.open" | "os.create" | "io.readall"
                ) || target.ends_with(".read")
                    || target.ends_with(".write")
            }
            "c" | "cpp" | "c++" => {
                matches!(
                    target.as_str(),
                    "fopen" | "fread" | "fwrite" | "read" | "write"
                ) || target.ends_with(".open")
            }
            _ => false,
        }
    }

    fn is_database_call_node(&self, node: &crate::Node, language: &str) -> bool {
        let target = self
            .call_target_text(node)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if target.is_empty() {
            return false;
        }

        let segments = self.target_segments(&target);
        let has_database_context = segments
            .iter()
            .any(|segment| self.is_database_segment(segment));
        let has_sql_literal = self.call_contains_sql_literal(node);

        match language.to_lowercase().as_str() {
            "rust" => {
                matches!(
                    target.as_str(),
                    "sqlx::query" | "sqlx::query_as" | "sqlx::query_scalar" | "diesel::sql_query"
                ) || target.ends_with(".query")
                    || target.ends_with(".query_as")
                    || target.ends_with(".query_one")
                    || target.ends_with(".query_all")
                    || target.ends_with(".fetch_one")
                    || target.ends_with(".fetch_all")
                    || target.ends_with(".fetch_optional")
                    || ((target.ends_with(".execute") || target.ends_with(".prepare"))
                        && (has_database_context || has_sql_literal))
            }
            "python" => {
                target.ends_with(".read_sql")
                    || ((target.ends_with(".execute")
                        || target.ends_with(".executemany")
                        || target.ends_with(".prepare"))
                        && (has_database_context || has_sql_literal))
                    || (target.ends_with(".query") && has_database_context)
            }
            "javascript" | "typescript" => {
                matches!(target.as_str(), "sequelize.query" | "knex.raw")
                    || (target.ends_with(".query") && has_database_context)
                    || ((target.ends_with(".execute")
                        || target.ends_with(".prepare")
                        || target.ends_with(".raw"))
                        && (has_database_context || has_sql_literal))
            }
            "go" => {
                (target.ends_with(".query")
                    || target.ends_with(".queryrow")
                    || target.ends_with(".exec")
                    || target.ends_with(".prepare"))
                    && (has_database_context || has_sql_literal)
            }
            "c" | "cpp" | "c++" => matches!(
                target.as_str(),
                "sqlite3_exec" | "mysql_query" | "pqexec" | "sqlite3_prepare_v2"
            ),
            _ => false,
        }
    }

    fn is_reference_cycle_call_node(&self, node: &crate::Node, language: &str) -> bool {
        if !language.eq_ignore_ascii_case("rust") {
            return false;
        }

        let target = self.call_target_text(node).unwrap_or_default();
        if !target.ends_with("Rc::new") {
            return false;
        }

        node.find_descendant(|candidate| {
            candidate.start_byte() != node.start_byte()
                && candidate.kind() == "call_expression"
                && self
                    .call_target_text(candidate)
                    .map(|candidate_target| candidate_target.ends_with("RefCell::new"))
                    .unwrap_or(false)
        })
        .is_some()
    }

    fn is_explicit_leak_call_node(&self, node: &crate::Node, language: &str) -> bool {
        if !language.eq_ignore_ascii_case("rust") {
            return false;
        }

        let target = self.call_target_text(node).unwrap_or_default();
        let segments = self.target_segments(&target);
        let leaf = segments.last().map(String::as_str);

        matches!(leaf, Some("leak")) && segments.iter().any(|segment| segment == "box")
            || matches!(leaf, Some("forget")) && segments.iter().any(|segment| segment == "mem")
    }

    fn is_allocation_node(&self, node: &crate::Node, language: &str) -> bool {
        let target = self.call_target_text(node).unwrap_or_default();

        match language.to_lowercase().as_str() {
            "rust" => match node.kind() {
                "macro_invocation" => matches!(target.as_str(), "vec" | "format"),
                "call_expression" => {
                    matches!(
                        target.as_str(),
                        "Vec::new" | "HashMap::new" | "String::new" | "Box::new" | "BTreeMap::new"
                    ) || target.ends_with(".clone")
                        || target.ends_with(".to_string")
                        || target.contains(".collect")
                }
                _ => false,
            },
            "python" => match node.kind() {
                "list_comprehension" | "dictionary_comprehension" => true,
                "call" => matches!(
                    target.as_str(),
                    "list" | "dict" | "set" | "tuple" | "bytearray"
                ),
                _ => false,
            },
            "javascript" | "typescript" => node.kind() == "new_expression",
            "c" | "cpp" | "c++" => matches!(
                target.as_str(),
                "malloc" | "calloc" | "realloc" | "new" | "new[]"
            ),
            "go" => matches!(target.as_str(), "make" | "new"),
            _ => false,
        }
    }

    fn describe_allocation_node(&self, node: &crate::Node, language: &str) -> String {
        let target = self
            .call_target_text(node)
            .unwrap_or_else(|| "allocation".to_string());

        match language.to_lowercase().as_str() {
            "rust" if node.kind() == "macro_invocation" => format!("{target}! macro"),
            _ => target,
        }
    }

    fn collect_allocation_nodes<'a>(
        &self,
        tree: &'a crate::SyntaxTree,
        language: &str,
    ) -> Vec<crate::Node<'a>> {
        let allocation_kinds = match language.to_lowercase().as_str() {
            "rust" => vec!["call_expression", "macro_invocation"],
            "python" => vec!["call", "list_comprehension", "dictionary_comprehension"],
            "javascript" | "typescript" => vec!["new_expression"],
            "c" | "cpp" | "c++" | "go" => vec!["call_expression"],
            _ => Vec::new(),
        };

        let mut seen = HashSet::new();
        let mut allocations = Vec::new();

        for kind in allocation_kinds {
            for node in tree.find_nodes_by_kind(kind) {
                if self.is_allocation_node(&node, language)
                    && seen.insert((node.start_byte(), node.end_byte()))
                {
                    allocations.push(node);
                }
            }
        }

        allocations
    }

    fn find_index_nodes_in_subtree<'a>(
        &self,
        root: crate::Node<'a>,
        language: &str,
    ) -> Vec<crate::Node<'a>> {
        root.find_descendants(|candidate| self.is_index_kind(candidate.kind(), language))
    }

    fn find_linear_operation_nodes_in_subtree<'a>(
        &self,
        root: crate::Node<'a>,
        language: &str,
    ) -> Vec<crate::Node<'a>> {
        let call_kinds = match language.to_lowercase().as_str() {
            "python" => vec!["call"],
            "rust" | "javascript" | "typescript" | "c" | "cpp" | "c++" | "go" => {
                vec!["call_expression"]
            }
            _ => Vec::new(),
        };

        let mut seen = HashSet::new();
        let mut linear_ops = Vec::new();

        for kind in call_kinds {
            for node in root.find_descendants(|candidate| candidate.kind() == kind) {
                if !seen.insert((node.start_byte(), node.end_byte())) {
                    continue;
                }

                let target = self.call_target_text(&node).unwrap_or_default();
                let is_linear_op = match language.to_lowercase().as_str() {
                    "rust" => {
                        target.ends_with(".find")
                            || target.ends_with(".contains")
                            || target.ends_with(".position")
                            || target.ends_with(".any")
                    }
                    "python" => target.ends_with(".index"),
                    "javascript" | "typescript" => {
                        target.ends_with(".find")
                            || target.ends_with(".findIndex")
                            || target.ends_with(".includes")
                            || target.ends_with(".indexOf")
                            || target.ends_with(".search")
                    }
                    _ => matches!(target.as_str(), "find" | "contains" | "search"),
                };

                if is_linear_op {
                    linear_ops.push(node);
                }
            }
        }

        linear_ops
    }

    fn contains_swap_operation(&self, root: crate::Node, _source: &str, language: &str) -> bool {
        let call_kinds = match language.to_lowercase().as_str() {
            "python" => vec!["call"],
            "rust" | "javascript" | "typescript" | "c" | "cpp" | "c++" | "go" => {
                vec!["call_expression"]
            }
            _ => Vec::new(),
        };

        call_kinds.into_iter().any(|kind| {
            root.find_descendants(|candidate| candidate.kind() == kind)
                .into_iter()
                .any(|node| {
                    let target = self.call_target_text(&node).unwrap_or_default();
                    target == "swap" || target.ends_with(".swap") || target.ends_with("::swap")
                })
        })
    }

    fn node_contains_identifier(&self, node: &crate::Node, identifier: &str) -> bool {
        node.find_descendant(|candidate| {
            candidate.kind() == "identifier"
                && candidate
                    .text()
                    .ok()
                    .map(|text| text == identifier)
                    .unwrap_or(false)
        })
        .is_some()
    }

    fn has_nested_index_access(&self, index_node: &crate::Node, language: &str) -> bool {
        index_node
            .parent()
            .map(|parent| self.is_index_kind(parent.kind(), language))
            .unwrap_or(false)
    }

    fn is_index_kind(&self, kind: &str, language: &str) -> bool {
        match language.to_lowercase().as_str() {
            "rust" | "go" => kind == "index_expression",
            "python" => kind == "subscript",
            "javascript" | "typescript" | "c" | "cpp" | "c++" => kind == "subscript_expression",
            _ => false,
        }
    }

    /// Detect cross-file performance hotspots
    fn detect_cross_file_hotspots(
        &self,
        analysis_result: &AnalysisResult,
    ) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        // Check for potential architectural issues
        if analysis_result.total_files > LARGE_CODEBASE_THRESHOLD {
            hotspots.push(PerformanceHotspot {
                id: "LARGE_CODEBASE".to_string(),
                title: "Large codebase detected".to_string(),
                description: format!(
                    "Codebase has {} files which may impact compilation and runtime performance",
                    analysis_result.total_files
                ),
                category: HotspotCategory::AlgorithmicComplexity,
                severity: PerformanceSeverity::Low,
                impact: PerformanceImpact {
                    cpu_impact: 20,
                    memory_impact: 30,
                    io_impact: 40,
                    network_impact: 0,
                    overall_impact: 30,
                },
                location: HotspotLocation {
                    file: "project structure".to_string(),
                    function: None,
                    start_line: 1,
                    end_line: 1,
                    scope: "project".to_string(),
                },
                code_snippet: format!("{} files in project", analysis_result.total_files),
                optimization: "Consider modularization and lazy loading strategies".to_string(),
                expected_improvement: ExpectedImprovement {
                    performance_gain: 10.0,
                    memory_reduction: 15.0,
                    time_reduction: 20.0,
                    confidence: ConfidenceLevel::Low,
                },
                difficulty: OptimizationDifficulty::VeryHard,
                patterns: vec!["Monolithic Architecture".to_string()],
            });
        }

        Ok(hotspots)
    }

    /// Generate optimization opportunities
    fn generate_optimizations(
        &self,
        hotspots: &[PerformanceHotspot],
        _analysis_result: &AnalysisResult,
    ) -> Result<Vec<OptimizationOpportunity>> {
        let mut optimizations = Vec::new();

        // Group hotspots by category and generate optimizations
        let mut complexity_hotspots = 0;
        let mut memory_hotspots = 0;

        for hotspot in hotspots {
            match hotspot.category {
                HotspotCategory::AlgorithmicComplexity => complexity_hotspots += 1,
                HotspotCategory::MemoryUsage => memory_hotspots += 1,
                _ => {}
            }
        }

        if complexity_hotspots > 0 {
            optimizations.push(OptimizationOpportunity {
                id: "ALGORITHM_OPTIMIZATION".to_string(),
                title: "Algorithm optimization opportunity".to_string(),
                description: format!(
                    "Found {} algorithmic complexity issues that can be optimized",
                    complexity_hotspots
                ),
                optimization_type: OptimizationType::Algorithm,
                priority: OptimizationPriority::High,
                affected_files: hotspots
                    .iter()
                    .filter(|h| h.category == HotspotCategory::AlgorithmicComplexity)
                    .map(|h| h.location.file.clone())
                    .collect(),
                implementation_steps: vec![
                    "Profile the identified functions to confirm performance impact".to_string(),
                    "Analyze algorithm complexity and identify bottlenecks".to_string(),
                    "Research and implement more efficient algorithms".to_string(),
                    "Benchmark before and after changes".to_string(),
                ],
                benefits: vec![
                    "Reduced CPU usage".to_string(),
                    "Faster execution times".to_string(),
                    "Better scalability".to_string(),
                ],
                risks: vec![
                    "May increase code complexity".to_string(),
                    "Requires thorough testing".to_string(),
                ],
                effort_estimate: EffortEstimate {
                    hours: 16.0,
                    complexity: OptimizationDifficulty::Hard,
                    expertise_level: ExpertiseLevel::Advanced,
                },
            });
        }

        if memory_hotspots > 0 {
            optimizations.push(OptimizationOpportunity {
                id: "MEMORY_OPTIMIZATION".to_string(),
                title: "Memory usage optimization".to_string(),
                description: format!(
                    "Found {} memory usage issues that can be optimized",
                    memory_hotspots
                ),
                optimization_type: OptimizationType::Memory,
                priority: OptimizationPriority::Medium,
                affected_files: hotspots
                    .iter()
                    .filter(|h| h.category == HotspotCategory::MemoryUsage)
                    .map(|h| h.location.file.clone())
                    .collect(),
                implementation_steps: vec![
                    "Profile memory usage patterns".to_string(),
                    "Implement object pooling where appropriate".to_string(),
                    "Pre-allocate collections with known sizes".to_string(),
                    "Consider using more efficient data structures".to_string(),
                ],
                benefits: vec![
                    "Reduced memory allocation overhead".to_string(),
                    "Lower garbage collection pressure".to_string(),
                    "More predictable performance".to_string(),
                ],
                risks: vec![
                    "May increase code complexity".to_string(),
                    "Potential for memory leaks if not handled properly".to_string(),
                ],
                effort_estimate: EffortEstimate {
                    hours: 8.0,
                    complexity: OptimizationDifficulty::Medium,
                    expertise_level: ExpertiseLevel::Intermediate,
                },
            });
        }

        Ok(optimizations)
    }

    // Helper methods for analysis

    fn calculate_file_complexity(&self, file: &FileInfo) -> f64 {
        // Try to read and parse the file for real complexity calculation
        if let Ok(content) = std::fs::read_to_string(&file.path) {
            let ast_complexity = self.calculate_ast_complexity(&content, &file.language);
            if ast_complexity > 1.0 {
                ast_complexity
            } else {
                // Fallback to simplified calculation if AST parsing failed
                let symbol_complexity = file.symbols.len() as f64 * 1.5;
                let size_complexity = (file.lines as f64 / LINES_PER_COMPLEXITY_UNIT).max(1.0);
                symbol_complexity + size_complexity
            }
        } else {
            // Fallback to simplified calculation
            let symbol_complexity = file.symbols.len() as f64 * 1.5;
            let size_complexity = (file.lines as f64 / LINES_PER_COMPLEXITY_UNIT).max(1.0);
            symbol_complexity + size_complexity
        }
    }

    /// Calculate cyclomatic complexity using AST analysis
    fn calculate_ast_complexity(&self, content: &str, language: &str) -> f64 {
        let lang = match self.parse_language(language) {
            Some(l) => l,
            None => return 1.0,
        };

        let tree = match self.create_syntax_tree(content, lang) {
            Some(t) => t,
            None => return 1.0,
        };

        self.calculate_cyclomatic_complexity(&tree, content, language)
    }

    /// Parse language string to Language enum
    fn parse_language(&self, language: &str) -> Option<crate::Language> {
        LanguageParser::parse_language(language)
    }

    /// Create syntax tree from content and language
    fn create_syntax_tree(
        &self,
        content: &str,
        lang: crate::Language,
    ) -> Option<crate::SyntaxTree> {
        LanguageParser::create_syntax_tree(content, lang)
    }

    /// Calculate cyclomatic complexity from AST
    fn calculate_cyclomatic_complexity(
        &self,
        tree: &crate::SyntaxTree,
        _content: &str,
        language: &str,
    ) -> f64 {
        ComplexityCalculator::calculate_cyclomatic_complexity(tree, language)
    }

    /// Detect nested loops using AST analysis
    fn detect_nested_loops(&self, content: &str, language: &str) -> usize {
        let Some(parsed_language) = self.parse_language(language) else {
            return 0;
        };
        let Some(tree) = self.create_syntax_tree(content, parsed_language) else {
            return 0;
        };
        let mut max_depth = 0usize;

        for kind in LanguageParser::get_loop_patterns(language) {
            for node in tree.find_nodes_by_kind(kind) {
                let mut depth = 0usize;
                let mut current = Some(node);
                while let Some(candidate) = current {
                    if self.is_loop_kind(candidate.kind(), language) {
                        depth += 1;
                    }
                    current = candidate.parent();
                }
                max_depth = max_depth.max(depth);
            }
        }

        max_depth.saturating_sub(1)
    }

    /// Count nested loops in a file using AST analysis
    fn count_nested_loops_in_file(&self, file: &FileInfo) -> usize {
        std::fs::read_to_string(&file.path)
            .ok()
            .map(|content| self.detect_nested_loops(&content, &file.language))
            .unwrap_or(0)
    }

    fn count_recursive_functions(&self, file: &FileInfo) -> usize {
        let Some(tree) = self.parse_file_syntax_tree(file) else {
            return 0;
        };

        self.collect_function_nodes(&tree, &file.language)
            .into_iter()
            .filter_map(|function_node| {
                let function_name = self.extract_function_name_from_node(
                    &function_node,
                    tree.source(),
                    &file.language,
                );
                match function_name.as_str() {
                    "" | "unknown" | "anonymous" => None,
                    _ => Some((function_node, function_name)),
                }
            })
            .filter(|(function_node, function_name)| {
                self.function_contains_recursive_call(*function_node, function_name, &file.language)
            })
            .count()
    }

    fn count_memory_allocations(&self, file: &FileInfo) -> usize {
        std::fs::read_to_string(&file.path)
            .ok()
            .map(|content| self.detect_memory_allocations(&content, &file.language))
            .unwrap_or(0)
    }

    /// Detect memory allocations using AST analysis
    fn detect_memory_allocations(&self, content: &str, language: &str) -> usize {
        let Some(parsed_language) = self.parse_language(language) else {
            return 0;
        };
        let Some(tree) = self.create_syntax_tree(content, parsed_language) else {
            return 0;
        };

        self.count_allocation_patterns(&tree, content, language)
    }

    /// Count memory allocation patterns in AST
    fn count_allocation_patterns(
        &self,
        tree: &crate::SyntaxTree,
        _content: &str,
        language: &str,
    ) -> usize {
        self.collect_allocation_nodes(tree, language).len()
    }

    fn count_io_operations(&self, file: &FileInfo) -> usize {
        let Some(tree) = self.parse_file_syntax_tree(file) else {
            return 0;
        };

        self.collect_call_nodes(&tree, &file.language)
            .into_iter()
            .filter(|call_node| self.is_io_call_node(call_node, &file.language))
            .count()
    }

    fn count_database_queries(&self, file: &FileInfo) -> usize {
        let Some(tree) = self.parse_file_syntax_tree(file) else {
            return 0;
        };

        self.collect_call_nodes(&tree, &file.language)
            .into_iter()
            .filter(|call_node| self.is_database_call_node(call_node, &file.language))
            .count()
    }

    fn calculate_file_performance_score(
        &self,
        complexity: f64,
        avg_function_length: f64,
        nested_loops: usize,
        memory_allocations: usize,
        io_operations: usize,
    ) -> u8 {
        let mut score = BASE_PERFORMANCE_SCORE;

        // Deduct points for various performance issues
        score -= (complexity / 10.0).min(30.0);
        score -= (avg_function_length / 10.0).min(20.0);
        score -= (nested_loops as f64 * 15.0).min(25.0);
        score -= (memory_allocations as f64 * 5.0).min(15.0);
        score -= (io_operations as f64 * 3.0).min(10.0);

        score.max(0.0) as u8
    }

    fn analyze_complexity(&self, analysis_result: &AnalysisResult) -> Result<ComplexityAnalysis> {
        let mut total_complexity: f64 = 0.0;
        let mut max_complexity: f64 = 0.0;
        let mut high_complexity_functions = Vec::new();
        let mut function_count = 0;

        for file in &analysis_result.files {
            let resolved_file = self.resolved_file_info(file, &analysis_result.root_path);
            let file_complexity = self.calculate_file_complexity(&resolved_file);
            total_complexity += file_complexity;
            max_complexity = max_complexity.max(file_complexity);

            // Calculate complexity per function based on file content analysis
            if let Ok(content) = std::fs::read_to_string(&resolved_file.path) {
                let function_complexities =
                    self.analyze_function_complexities(&content, &resolved_file.language);

                for (func_name, complexity) in function_complexities {
                    function_count += 1;

                    if complexity > self.config.min_complexity_threshold as f64 {
                        high_complexity_functions.push(ComplexFunction {
                            name: func_name,
                            file: resolved_file.path.display().to_string(),
                            line: 1, // Simplified - would need AST to get exact line
                            complexity,
                            improvements: vec![
                                "Break down into smaller functions".to_string(),
                                "Reduce nesting levels".to_string(),
                                "Extract complex logic into helper functions".to_string(),
                            ],
                        });
                    }
                }
            } else {
                // Fallback to symbol-based analysis
                for symbol in &resolved_file.symbols {
                    if symbol.kind == "function" {
                        function_count += 1;
                        let func_complexity =
                            file_complexity / resolved_file.symbols.len().max(1) as f64;

                        if func_complexity > self.config.min_complexity_threshold as f64 {
                            high_complexity_functions.push(ComplexFunction {
                                name: symbol.name.clone(),
                                file: resolved_file.path.display().to_string(),
                                line: symbol.start_line,
                                complexity: func_complexity,
                                improvements: vec![
                                    "Break down into smaller functions".to_string(),
                                    "Reduce nesting levels".to_string(),
                                    "Extract complex logic into helper functions".to_string(),
                                ],
                            });
                        }
                    }
                }
            }
        }

        let average_complexity = if function_count > 0 {
            total_complexity / function_count as f64
        } else {
            0.0
        };

        Ok(ComplexityAnalysis {
            average_complexity,
            max_complexity,
            high_complexity_functions,
            nested_loops: Vec::new(),        // Simplified
            recursive_functions: Vec::new(), // Simplified
        })
    }

    /// Analyze function complexities using AST traversal
    fn analyze_function_complexities(&self, content: &str, language: &str) -> Vec<(String, f64)> {
        let Some(parsed_language) = self.parse_language(language) else {
            return Vec::new();
        };
        let Some(tree) = self.create_syntax_tree(content, parsed_language) else {
            return Vec::new();
        };

        self.collect_function_nodes(&tree, language)
            .into_iter()
            .map(|function_node| {
                let function_name =
                    self.extract_function_name_from_node(&function_node, tree.source(), language);
                let complexity =
                    self.calculate_function_complexity(&function_node, tree.source(), language);
                (function_name, complexity)
            })
            .collect()
    }

    fn analyze_memory_usage(&self, analysis_result: &AnalysisResult) -> Result<MemoryAnalysis> {
        let mut allocation_hotspots = Vec::new();
        let mut leak_potential = Vec::new();

        // Analyze each file for memory patterns
        for file in &analysis_result.files {
            let resolved_file = self.resolved_file_info(file, &analysis_result.root_path);
            if let Ok(content) = std::fs::read_to_string(&resolved_file.path) {
                let hotspots = self.detect_memory_allocation_patterns(
                    &content,
                    &resolved_file.language,
                    &resolved_file,
                );
                allocation_hotspots.extend(hotspots);

                let leaks = self.detect_potential_memory_leaks(
                    &content,
                    &resolved_file.language,
                    &resolved_file,
                );
                leak_potential.extend(leaks);
            }
        }

        Ok(MemoryAnalysis {
            allocation_hotspots,
            leak_potential,
            inefficient_structures: Vec::new(),
            optimizations: vec![
                MemoryOptimization {
                    title: "Pre-allocate collections".to_string(),
                    description: "Use Vec::with_capacity() when the size is known in advance".to_string(),
                    locations: Vec::new(),
                    memory_savings: "10-30% reduction in allocation overhead".to_string(),
                },
                MemoryOptimization {
                    title: "Use string interning".to_string(),
                    description: "For frequently used strings, consider string interning to reduce memory usage".to_string(),
                    locations: Vec::new(),
                    memory_savings: "20-50% reduction in string memory usage".to_string(),
                },
            ],
        })
    }

    /// Detect memory allocation patterns using AST analysis
    fn detect_memory_allocation_patterns(
        &self,
        content: &str,
        language: &str,
        file: &FileInfo,
    ) -> Vec<MemoryHotspot> {
        let Some(parsed_language) = self.parse_language(language) else {
            return Vec::new();
        };
        let Some(tree) = self.create_syntax_tree(content, parsed_language) else {
            return Vec::new();
        };

        self.collect_allocation_nodes(&tree, language)
            .into_iter()
            .map(|allocation| MemoryHotspot {
                location: HotspotLocation {
                    file: file.path.display().to_string(),
                    function: self.find_enclosing_function_name(&allocation, content, language),
                    start_line: allocation.start_position().row + 1,
                    end_line: allocation.end_position().row + 1,
                    scope: "allocation".to_string(),
                },
                allocation_type: AllocationType::HeapAllocation,
                frequency: if self.is_inside_loop(&allocation, language) {
                    AllocationFrequency::High
                } else {
                    AllocationFrequency::Medium
                },
                size_estimate: SizeEstimate::Unknown,
            })
            .collect()
    }

    /// Detect potential memory leaks using AST call analysis
    fn detect_potential_memory_leaks(
        &self,
        content: &str,
        language: &str,
        file: &FileInfo,
    ) -> Vec<MemoryLeakRisk> {
        let Some(parsed_language) = self.parse_language(language) else {
            return Vec::new();
        };
        let Some(tree) = self.create_syntax_tree(content, parsed_language) else {
            return Vec::new();
        };

        self.collect_call_nodes(&tree, language)
            .into_iter()
            .filter_map(|call_node| {
                let start_line = call_node.start_position().row + 1;
                let end_line = call_node.end_position().row + 1;
                let function = self.find_enclosing_function_name(&call_node, content, language);

                if self.is_reference_cycle_call_node(&call_node, language) {
                    Some(MemoryLeakRisk {
                        location: HotspotLocation {
                            file: file.path.display().to_string(),
                            function,
                            start_line,
                            end_line,
                            scope: "reference_cycle".to_string(),
                        },
                        risk_level: RiskLevel::Medium,
                        description: "Rc<RefCell<T>> can create reference cycles".to_string(),
                        mitigation: vec![
                            "Consider using Weak references to break cycles".to_string()
                        ],
                    })
                } else if self.is_explicit_leak_call_node(&call_node, language) {
                    Some(MemoryLeakRisk {
                        location: HotspotLocation {
                            file: file.path.display().to_string(),
                            function,
                            start_line,
                            end_line,
                            scope: "intentional_leak".to_string(),
                        },
                        risk_level: RiskLevel::High,
                        description: "Explicit memory leak detected".to_string(),
                        mitigation: vec!["Ensure this is intentional and necessary".to_string()],
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn analyze_concurrency(
        &self,
        _analysis_result: &AnalysisResult,
    ) -> Result<ConcurrencyAnalysis> {
        // Simplified concurrency analysis
        Ok(ConcurrencyAnalysis {
            parallelization_opportunities: vec![ParallelizationOpportunity {
                location: HotspotLocation {
                    file: "data_processing.rs".to_string(),
                    function: Some("process_items".to_string()),
                    start_line: 1,
                    end_line: 50,
                    scope: "function".to_string(),
                },
                opportunity_type: ParallelizationType::DataParallelism,
                expected_speedup: 3.5,
                approach: "Use rayon for parallel iteration over data collections".to_string(),
            }],
            synchronization_issues: Vec::new(),
            thread_safety_concerns: Vec::new(),
            async_optimizations: Vec::new(),
        })
    }

    fn generate_recommendations(
        &self,
        hotspots: &[PerformanceHotspot],
        optimizations: &[OptimizationOpportunity],
    ) -> Result<Vec<PerformanceRecommendation>> {
        let mut recommendations = Vec::new();

        // Analyze hotspots by category
        let memory_hotspots = hotspots
            .iter()
            .filter(|h| h.category == HotspotCategory::MemoryUsage)
            .count();
        let complexity_hotspots = hotspots
            .iter()
            .filter(|h| h.category == HotspotCategory::AlgorithmicComplexity)
            .count();
        let io_hotspots = hotspots
            .iter()
            .filter(|h| h.category == HotspotCategory::IOOperations)
            .count();
        let critical_hotspots = hotspots
            .iter()
            .filter(|h| h.severity == PerformanceSeverity::Critical)
            .count();

        // Memory-specific recommendations
        if memory_hotspots > 0 {
            recommendations.push(PerformanceRecommendation {
                category: "Memory Optimization".to_string(),
                recommendation: format!("Optimize {} memory allocation hotspots to reduce memory churn and improve performance", memory_hotspots),
                priority: OptimizationPriority::High,
                affected_components: hotspots.iter()
                    .filter(|h| h.category == HotspotCategory::MemoryUsage)
                    .map(|h| h.location.file.clone())
                    .collect(),
                difficulty: OptimizationDifficulty::Medium,
                expected_impact: ExpectedImprovement {
                    performance_gain: 30.0,
                    memory_reduction: 50.0,
                    time_reduction: 25.0,
                    confidence: ConfidenceLevel::High,
                },
            });
        }

        // Complexity-specific recommendations
        if complexity_hotspots > 0 {
            recommendations.push(PerformanceRecommendation {
                category: "Complexity Reduction".to_string(),
                recommendation: format!("Refactor {} high-complexity functions to improve maintainability and performance", complexity_hotspots),
                priority: OptimizationPriority::Medium,
                affected_components: hotspots.iter()
                    .filter(|h| h.category == HotspotCategory::AlgorithmicComplexity)
                    .map(|h| h.location.file.clone())
                    .collect(),
                difficulty: OptimizationDifficulty::Hard,
                expected_impact: ExpectedImprovement {
                    performance_gain: 20.0,
                    memory_reduction: 10.0,
                    time_reduction: 35.0,
                    confidence: ConfidenceLevel::Medium,
                },
            });
        }

        // I/O-specific recommendations
        if io_hotspots > 0 {
            recommendations.push(PerformanceRecommendation {
                category: "I/O Optimization".to_string(),
                recommendation: format!(
                    "Optimize {} I/O operations using buffering, async patterns, or batching",
                    io_hotspots
                ),
                priority: OptimizationPriority::High,
                affected_components: hotspots
                    .iter()
                    .filter(|h| h.category == HotspotCategory::IOOperations)
                    .map(|h| h.location.file.clone())
                    .collect(),
                difficulty: OptimizationDifficulty::Medium,
                expected_impact: ExpectedImprovement {
                    performance_gain: 40.0,
                    memory_reduction: 15.0,
                    time_reduction: 60.0,
                    confidence: ConfidenceLevel::High,
                },
            });
        }

        // Critical issues
        if critical_hotspots > 0 {
            recommendations.push(PerformanceRecommendation {
                category: "Critical Performance Issues".to_string(),
                recommendation: format!(
                    "Address {} critical performance hotspots immediately",
                    critical_hotspots
                ),
                priority: OptimizationPriority::Critical,
                affected_components: hotspots
                    .iter()
                    .filter(|h| h.severity == PerformanceSeverity::Critical)
                    .map(|h| h.location.file.clone())
                    .collect(),
                difficulty: OptimizationDifficulty::Hard,
                expected_impact: ExpectedImprovement {
                    performance_gain: 40.0,
                    memory_reduction: 20.0,
                    time_reduction: 50.0,
                    confidence: ConfidenceLevel::High,
                },
            });
        }

        // General optimization opportunities
        if !optimizations.is_empty() {
            recommendations.push(PerformanceRecommendation {
                category: "Optimization Opportunities".to_string(),
                recommendation: format!(
                    "Implement {} identified optimization opportunities",
                    optimizations.len()
                ),
                priority: OptimizationPriority::Medium,
                affected_components: optimizations
                    .iter()
                    .flat_map(|o| o.affected_files.clone())
                    .collect(),
                difficulty: OptimizationDifficulty::Medium,
                expected_impact: ExpectedImprovement {
                    performance_gain: 25.0,
                    memory_reduction: 15.0,
                    time_reduction: 30.0,
                    confidence: ConfidenceLevel::Medium,
                },
            });
        }

        // Always include monitoring recommendation
        recommendations.push(PerformanceRecommendation {
            category: "Performance Monitoring".to_string(),
            recommendation: "Implement performance monitoring and profiling in production"
                .to_string(),
            priority: OptimizationPriority::Medium,
            affected_components: vec!["monitoring".to_string(), "profiling".to_string()],
            difficulty: OptimizationDifficulty::Medium,
            expected_impact: ExpectedImprovement {
                performance_gain: 10.0,
                memory_reduction: 5.0,
                time_reduction: 15.0,
                confidence: ConfidenceLevel::High,
            },
        });

        Ok(recommendations)
    }

    fn calculate_performance_score(
        &self,
        hotspots: &[PerformanceHotspot],
        file_metrics: &[FilePerformanceMetrics],
    ) -> u8 {
        if file_metrics.is_empty() {
            return 50; // Default score
        }

        let avg_file_score = file_metrics
            .iter()
            .map(|m| m.performance_score as f64)
            .sum::<f64>()
            / file_metrics.len() as f64;

        // Deduct points for hotspots
        let mut score = avg_file_score;
        for hotspot in hotspots {
            let deduction = match hotspot.severity {
                PerformanceSeverity::Critical => 15.0,
                PerformanceSeverity::High => 10.0,
                PerformanceSeverity::Medium => 5.0,
                PerformanceSeverity::Low => 2.0,
                PerformanceSeverity::Info => 1.0,
            };
            score -= deduction;
        }

        score.clamp(0.0, crate::constants::scoring::MAX_SCORE) as u8
    }
}

// Default implementations
impl Default for ComplexityAnalysis {
    fn default() -> Self {
        Self {
            average_complexity: 0.0,
            max_complexity: 0.0,
            high_complexity_functions: Vec::new(),
            nested_loops: Vec::new(),
            recursive_functions: Vec::new(),
        }
    }
}

// Display implementations
impl std::fmt::Display for PerformanceSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PerformanceSeverity::Critical => write!(f, "Critical"),
            PerformanceSeverity::High => write!(f, "High"),
            PerformanceSeverity::Medium => write!(f, "Medium"),
            PerformanceSeverity::Low => write!(f, "Low"),
            PerformanceSeverity::Info => write!(f, "Info"),
        }
    }
}

impl std::fmt::Display for OptimizationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptimizationPriority::Critical => write!(f, "Critical"),
            OptimizationPriority::High => write!(f, "High"),
            OptimizationPriority::Medium => write!(f, "Medium"),
            OptimizationPriority::Low => write!(f, "Low"),
        }
    }
}

impl std::fmt::Display for OptimizationDifficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptimizationDifficulty::Trivial => write!(f, "Trivial"),
            OptimizationDifficulty::Easy => write!(f, "Easy"),
            OptimizationDifficulty::Medium => write!(f, "Medium"),
            OptimizationDifficulty::Hard => write!(f, "Hard"),
            OptimizationDifficulty::VeryHard => write!(f, "Very Hard"),
        }
    }
}
