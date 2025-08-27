//! Test coverage analysis and testing quality assessment
//! 
//! This module provides comprehensive test analysis including:
//! - Test coverage estimation
//! - Test quality assessment
//! - Missing test detection
//! - Test organization analysis
//! - Testing best practices validation

use crate::{AnalysisResult, FileInfo, Result};
use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Test coverage analyzer for assessing testing quality and coverage
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestCoverageAnalyzer {
    /// Configuration for test coverage analysis
    pub config: TestCoverageConfig,
}

/// Configuration for test coverage analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestCoverageConfig {
    /// Enable test coverage estimation
    pub coverage_estimation: bool,
    /// Enable test quality analysis
    pub quality_analysis: bool,
    /// Enable missing test detection
    pub missing_test_detection: bool,
    /// Enable test organization analysis
    pub organization_analysis: bool,
    /// Minimum acceptable coverage percentage
    pub min_coverage_threshold: f64,
    /// Test file patterns
    pub test_file_patterns: Vec<String>,
}

/// Results of test coverage analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestCoverageResult {
    /// Overall test coverage score (0-100)
    pub coverage_score: u8,
    /// Estimated test coverage percentage
    pub estimated_coverage: f64,
    /// Total number of test functions found
    pub total_tests: usize,
    /// Total number of testable functions
    pub total_testable_functions: usize,
    /// Test files analysis
    pub test_files: Vec<TestFileAnalysis>,
    /// Coverage by file
    pub file_coverage: Vec<FileCoverage>,
    /// Missing tests analysis
    pub missing_tests: Vec<MissingTest>,
    /// Test quality metrics
    pub quality_metrics: TestQualityMetrics,
    /// Test organization analysis
    pub organization_analysis: TestOrganizationAnalysis,
    /// Testing recommendations
    pub recommendations: Vec<TestingRecommendation>,
}

/// Analysis of a test file
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestFileAnalysis {
    /// Test file path
    pub file: PathBuf,
    /// Number of test functions
    pub test_count: usize,
    /// Test types found
    pub test_types: Vec<TestType>,
    /// Test quality score
    pub quality_score: u8,
    /// Length of each test function in lines
    pub test_function_lengths: Vec<usize>,
    /// Test patterns used
    pub patterns: Vec<TestPattern>,
    /// Issues found in tests
    pub issues: Vec<TestIssue>,
}

/// Types of tests
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TestType {
    /// Unit tests
    Unit,
    /// Integration tests
    Integration,
    /// End-to-end tests
    EndToEnd,
    /// Performance tests
    Performance,
    /// Property-based tests
    Property,
    /// Benchmark tests
    Benchmark,
}

/// Test patterns and practices
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TestPattern {
    /// Arrange-Act-Assert pattern
    ArrangeActAssert,
    /// Given-When-Then pattern
    GivenWhenThen,
    /// Test fixtures
    Fixtures,
    /// Mocking
    Mocking,
    /// Parameterized tests
    Parameterized,
    /// Setup and teardown
    SetupTeardown,
}

/// Issues found in test code
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestIssue {
    /// Issue type
    pub issue_type: TestIssueType,
    /// Description
    pub description: String,
    /// Location
    pub location: TestLocation,
    /// Severity
    pub severity: TestIssueSeverity,
    /// Recommendation
    pub recommendation: String,
}

/// Types of test issues
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TestIssueType {
    /// Missing assertions
    MissingAssertions,
    /// Too many assertions
    TooManyAssertions,
    /// Unclear test name
    UnclearTestName,
    /// Long test function
    LongTestFunction,
    /// Missing test documentation
    MissingDocumentation,
    /// Flaky test indicators
    FlakyTest,
    /// Slow test
    SlowTest,
}

/// Test issue severity
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TestIssueSeverity {
    High,
    Medium,
    Low,
}

/// Location of a test issue
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestLocation {
    /// File path
    pub file: String,
    /// Test function name
    pub test_function: String,
    /// Line number
    pub line: usize,
}

/// Coverage analysis for a file
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FileCoverage {
    /// Source file path
    pub file: PathBuf,
    /// Estimated coverage percentage
    pub coverage_percentage: f64,
    /// Number of functions in file
    pub total_functions: usize,
    /// Number of tested functions
    pub tested_functions: usize,
    /// Coverage status
    pub status: CoverageStatus,
    /// Related test files
    pub test_files: Vec<PathBuf>,
}

/// Coverage status levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CoverageStatus {
    Excellent,
    Good,
    Fair,
    Poor,
    None,
}

/// Missing test analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MissingTest {
    /// Function that needs testing
    pub function_name: String,
    /// File containing the function
    pub file: PathBuf,
    /// Function visibility
    pub visibility: FunctionVisibility,
    /// Complexity of the function
    pub complexity: FunctionComplexity,
    /// Priority for testing
    pub priority: TestPriority,
    /// Suggested test types
    pub suggested_tests: Vec<TestType>,
    /// Reason for testing
    pub reason: String,
}

/// Function visibility levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum FunctionVisibility {
    Public,
    Private,
    Internal,
}

/// Function complexity levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum FunctionComplexity {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Test priority levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TestPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Test quality metrics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestQualityMetrics {
    /// Average test function length
    pub average_test_length: f64,
    /// Test naming quality score
    pub naming_quality: u8,
    /// Assertion density (assertions per test)
    pub assertion_density: f64,
    /// Test documentation coverage
    pub documentation_coverage: f64,
    /// Test maintainability score
    pub maintainability_score: u8,
    /// Test reliability indicators
    pub reliability_indicators: TestReliabilityMetrics,
}

/// Test reliability metrics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestReliabilityMetrics {
    /// Potential flaky tests
    pub potential_flaky_tests: usize,
    /// Tests with external dependencies
    pub external_dependency_tests: usize,
    /// Tests with timing dependencies
    pub timing_dependent_tests: usize,
    /// Tests with random elements
    pub random_element_tests: usize,
}

/// Test organization analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestOrganizationAnalysis {
    /// Test directory structure quality
    pub structure_quality: u8,
    /// Test file naming consistency
    pub naming_consistency: u8,
    /// Test categorization
    pub categorization: TestCategorization,
    /// Test suite organization
    pub suite_organization: TestSuiteOrganization,
}

/// Test categorization analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestCategorization {
    /// Tests by type
    pub tests_by_type: HashMap<TestType, usize>,
    /// Tests by module
    pub tests_by_module: HashMap<String, usize>,
    /// Test distribution quality
    pub distribution_quality: u8,
}

/// Test suite organization analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestSuiteOrganization {
    /// Test suites identified
    pub test_suites: Vec<TestSuite>,
    /// Organization score
    pub organization_score: u8,
    /// Recommendations for improvement
    pub improvements: Vec<String>,
}

/// A test suite
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestSuite {
    /// Suite name
    pub name: String,
    /// Suite type
    pub suite_type: TestType,
    /// Number of tests
    pub test_count: usize,
    /// Files in suite
    pub files: Vec<PathBuf>,
    /// Quality score
    pub quality_score: u8,
}

/// Testing recommendation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TestingRecommendation {
    /// Recommendation category
    pub category: String,
    /// Recommendation text
    pub recommendation: String,
    /// Priority level
    pub priority: TestPriority,
    /// Affected files
    pub affected_files: Vec<PathBuf>,
    /// Implementation difficulty
    pub difficulty: ImplementationDifficulty,
    /// Expected benefits
    pub benefits: Vec<String>,
}

/// Implementation difficulty levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImplementationDifficulty {
    Easy,
    Medium,
    Hard,
    VeryHard,
}

impl Default for TestCoverageConfig {
    fn default() -> Self {
        Self {
            coverage_estimation: true,
            quality_analysis: true,
            missing_test_detection: true,
            organization_analysis: true,
            min_coverage_threshold: 80.0,
            test_file_patterns: vec![
                "*test*.rs".to_string(),
                "*_test.rs".to_string(),
                "test_*.rs".to_string(),
                "tests/*.rs".to_string(),
            ],
        }
    }
}

impl TestCoverageAnalyzer {
    /// Create a new test coverage analyzer with default configuration
    pub fn new() -> Self {
        Self {
            config: TestCoverageConfig::default(),
        }
    }
    
    /// Create a new test coverage analyzer with custom configuration
    pub fn with_config(config: TestCoverageConfig) -> Self {
        Self { config }
    }
    
    /// Analyze test coverage in a codebase
    pub fn analyze(&self, analysis_result: &AnalysisResult) -> Result<TestCoverageResult> {
        // Identify test files
        let test_files = self.identify_test_files(analysis_result);
        
        // Analyze each test file
        let mut test_file_analyses = Vec::new();
        let mut total_tests = 0;
        
        for test_file in &test_files {
            let analysis = self.analyze_test_file(test_file)?;
            total_tests += analysis.test_count;
            test_file_analyses.push(analysis);
        }
        
        // Analyze coverage for source files
        let file_coverage = self.analyze_file_coverage(analysis_result, &test_files)?;
        
        // Detect missing tests
        let missing_tests = if self.config.missing_test_detection {
            self.detect_missing_tests(analysis_result, &test_files)?
        } else {
            Vec::new()
        };
        
        // Calculate quality metrics
        let quality_metrics = if self.config.quality_analysis {
            self.calculate_quality_metrics(&test_file_analyses)?
        } else {
            TestQualityMetrics::default()
        };
        
        // Analyze test organization
        let organization_analysis = if self.config.organization_analysis {
            self.analyze_test_organization(&test_file_analyses)?
        } else {
            TestOrganizationAnalysis::default()
        };
        
        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &file_coverage,
            &missing_tests,
            &quality_metrics,
            &organization_analysis,
        )?;
        
        // Calculate overall scores
        let total_testable_functions = self.count_testable_functions(analysis_result);
        let estimated_coverage = self.calculate_estimated_coverage(&file_coverage);
        let coverage_score = self.calculate_coverage_score(estimated_coverage, &quality_metrics);
        
        Ok(TestCoverageResult {
            coverage_score,
            estimated_coverage,
            total_tests,
            total_testable_functions,
            test_files: test_file_analyses,
            file_coverage,
            missing_tests,
            quality_metrics,
            organization_analysis,
            recommendations,
        })
    }

    /// Identify test files in the codebase
    fn identify_test_files<'a>(&self, analysis_result: &'a AnalysisResult) -> Vec<&'a FileInfo> {
        analysis_result.files.iter()
            .filter(|file| self.is_test_file(file))
            .collect()
    }

    /// Check if a file is a test file
    fn is_test_file(&self, file: &FileInfo) -> bool {
        let file_name = file.path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Check if file name matches test patterns
        self.config.test_file_patterns.iter().any(|pattern| {
            self.matches_pattern(file_name, pattern)
        }) ||
        // Check if file path contains "test" directory
        file.path.components().any(|component| {
            component.as_os_str().to_str().unwrap_or("").contains("test")
        }) ||
        // Check if file contains test functions
        file.symbols.iter().any(|symbol| {
            symbol.name.starts_with("test_") ||
            symbol.name.contains("test") ||
            symbol.kind == "test"
        })
    }

    /// Simple pattern matching for file names
    fn matches_pattern(&self, file_name: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                file_name.starts_with(parts[0]) && file_name.ends_with(parts[1])
            } else {
                false
            }
        } else {
            file_name == pattern
        }
    }

    /// Analyze a test file
    fn analyze_test_file(&self, file: &FileInfo) -> Result<TestFileAnalysis> {
        let test_functions: Vec<_> = file.symbols.iter()
            .filter(|symbol| self.is_test_function(symbol))
            .collect();

        let test_count = test_functions.len();
        let test_types = self.identify_test_types(&test_functions);
        let patterns = self.identify_test_patterns(&test_functions);
        let issues = self.identify_test_issues(file, &test_functions)?;
        let quality_score = self.calculate_test_file_quality_score(file, &test_functions, &issues);
        let test_function_lengths: Vec<usize> = test_functions
            .iter()
            .map(|f| f.end_line.saturating_sub(f.start_line) + 1)
            .collect();

        Ok(TestFileAnalysis {
            file: file.path.clone(),
            test_count,
            test_types,
            quality_score,
            test_function_lengths,
            patterns,
            issues,
        })
    }

    /// Check if a symbol is a test function
    fn is_test_function(&self, symbol: &crate::Symbol) -> bool {
        symbol.name.starts_with("test_") ||
        symbol.name.contains("test") ||
        symbol.kind == "test" ||
        // Check for test attributes (simplified)
        symbol.name.starts_with("#[test]")
    }

    /// Identify types of tests in the file
    fn identify_test_types(&self, test_functions: &[&crate::Symbol]) -> Vec<TestType> {
        let mut types = Vec::new();

        for func in test_functions {
            if func.name.contains("unit") || func.name.contains("test_") {
                if !types.contains(&TestType::Unit) {
                    types.push(TestType::Unit);
                }
            }
            if func.name.contains("integration") || func.name.contains("e2e") {
                if !types.contains(&TestType::Integration) {
                    types.push(TestType::Integration);
                }
            }
            if func.name.contains("bench") || func.name.contains("performance") {
                if !types.contains(&TestType::Performance) {
                    types.push(TestType::Performance);
                }
            }
        }

        // Default to unit tests if no specific type identified
        if types.is_empty() {
            types.push(TestType::Unit);
        }

        types
    }

    /// Identify test patterns used
    fn identify_test_patterns(&self, test_functions: &[&crate::Symbol]) -> Vec<TestPattern> {
        let mut patterns = Vec::new();

        // Simplified pattern detection based on function names
        for func in test_functions {
            if func.name.contains("given") || func.name.contains("when") || func.name.contains("then") {
                if !patterns.contains(&TestPattern::GivenWhenThen) {
                    patterns.push(TestPattern::GivenWhenThen);
                }
            }
            if func.name.contains("setup") || func.name.contains("teardown") {
                if !patterns.contains(&TestPattern::SetupTeardown) {
                    patterns.push(TestPattern::SetupTeardown);
                }
            }
            if func.name.contains("mock") {
                if !patterns.contains(&TestPattern::Mocking) {
                    patterns.push(TestPattern::Mocking);
                }
            }
        }

        // Default to Arrange-Act-Assert if no specific pattern identified
        if patterns.is_empty() {
            patterns.push(TestPattern::ArrangeActAssert);
        }

        patterns
    }

    /// Identify issues in test code
    fn identify_test_issues(&self, file: &FileInfo, test_functions: &[&crate::Symbol]) -> Result<Vec<TestIssue>> {
        let mut issues = Vec::new();

        for func in test_functions {
            // Check for unclear test names
            if func.name.len() < 10 || !func.name.contains('_') {
                issues.push(TestIssue {
                    issue_type: TestIssueType::UnclearTestName,
                    description: format!("Test function '{}' has an unclear name", func.name),
                    location: TestLocation {
                        file: file.path.display().to_string(),
                        test_function: func.name.clone(),
                        line: func.start_line,
                    },
                    severity: TestIssueSeverity::Medium,
                    recommendation: "Use descriptive test names that explain what is being tested".to_string(),
                });
            }

            // Check for missing documentation
            if func.documentation.is_none() {
                issues.push(TestIssue {
                    issue_type: TestIssueType::MissingDocumentation,
                    description: format!("Test function '{}' lacks documentation", func.name),
                    location: TestLocation {
                        file: file.path.display().to_string(),
                        test_function: func.name.clone(),
                        line: func.start_line,
                    },
                    severity: TestIssueSeverity::Low,
                    recommendation: "Add documentation explaining what the test validates".to_string(),
                });
            }

            // Check for potentially flaky tests
            if func.name.contains("random") || func.name.contains("time") || func.name.contains("sleep") {
                issues.push(TestIssue {
                    issue_type: TestIssueType::FlakyTest,
                    description: format!("Test function '{}' may be flaky due to timing or randomness", func.name),
                    location: TestLocation {
                        file: file.path.display().to_string(),
                        test_function: func.name.clone(),
                        line: func.start_line,
                    },
                    severity: TestIssueSeverity::High,
                    recommendation: "Avoid timing dependencies and random elements in tests".to_string(),
                });
            }
        }

        Ok(issues)
    }

    /// Calculate quality score for a test file
    fn calculate_test_file_quality_score(&self, _file: &FileInfo, test_functions: &[&crate::Symbol], issues: &[TestIssue]) -> u8 {
        let mut score = crate::constants::test_coverage::MAX_COVERAGE_SCORE;

        // Deduct points for issues
        for issue in issues {
            let deduction = match issue.severity {
                TestIssueSeverity::High => 15.0,
                TestIssueSeverity::Medium => 10.0,
                TestIssueSeverity::Low => 5.0,
            };
            score -= deduction;
        }

        // Deduct points for poor test naming
        let poorly_named_tests = test_functions.iter()
            .filter(|f| f.name.len() < 10 || !f.name.contains('_'))
            .count();
        score -= (poorly_named_tests as f64 * 5.0).min(25.0);

        score.max(crate::constants::scoring::MIN_SCORE).min(crate::constants::test_coverage::MAX_COVERAGE_SCORE) as u8
    }

    /// Analyze coverage for source files
    fn analyze_file_coverage(&self, analysis_result: &AnalysisResult, test_files: &[&FileInfo]) -> Result<Vec<FileCoverage>> {
        let mut coverage_results = Vec::new();

        for file in &analysis_result.files {
            if !self.is_test_file(file) {
                let coverage = self.estimate_file_coverage(file, test_files)?;
                coverage_results.push(coverage);
            }
        }

        Ok(coverage_results)
    }

    /// Estimate coverage for a single file
    fn estimate_file_coverage(&self, file: &FileInfo, test_files: &[&FileInfo]) -> Result<FileCoverage> {
        let total_functions = file.symbols.iter()
            .filter(|s| s.kind == "function" && s.visibility == "public")
            .count();

        // Simple heuristic: look for test functions that might test this file
        let file_stem = file.path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        let mut tested_functions = 0;
        let mut related_test_files = Vec::new();

        for test_file in test_files {
            let test_file_name = test_file.path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");

            // Check if test file might be testing this source file
            if test_file_name.contains(file_stem) ||
               test_file.symbols.iter().any(|s| s.name.contains(file_stem)) {
                related_test_files.push(test_file.path.clone());

                // Count test functions that might test functions in this file
                let relevant_tests = test_file.symbols.iter()
                    .filter(|s| self.is_test_function(s) && s.name.contains(file_stem))
                    .count();

                tested_functions += relevant_tests.min(total_functions);
            }
        }

        let coverage_percentage = if total_functions > 0 {
            (tested_functions as f64 / total_functions as f64) * crate::constants::test_coverage::PERCENTAGE_MULTIPLIER
        } else {
            crate::constants::test_coverage::PERFECT_COVERAGE_SCORE // No functions to test
        };

        let status = match coverage_percentage {
            p if p >= 90.0 => CoverageStatus::Excellent,
            p if p >= 75.0 => CoverageStatus::Good,
            p if p >= 50.0 => CoverageStatus::Fair,
            p if p > 0.0 => CoverageStatus::Poor,
            _ => CoverageStatus::None,
        };

        Ok(FileCoverage {
            file: file.path.clone(),
            coverage_percentage,
            total_functions,
            tested_functions,
            status,
            test_files: related_test_files,
        })
    }

    /// Detect missing tests
    fn detect_missing_tests(&self, analysis_result: &AnalysisResult, test_files: &[&FileInfo]) -> Result<Vec<MissingTest>> {
        let mut missing_tests = Vec::new();

        for file in &analysis_result.files {
            if !self.is_test_file(file) {
                for symbol in &file.symbols {
                    if symbol.kind == "function" && symbol.visibility == "public" {
                        // Check if this function has tests
                        let has_test = self.function_has_test(symbol, file, test_files);

                        if !has_test {
                            let complexity = self.assess_function_complexity(symbol);
                            let priority = self.determine_test_priority(symbol, &complexity);

                            missing_tests.push(MissingTest {
                                function_name: symbol.name.clone(),
                                file: file.path.clone(),
                                visibility: if symbol.visibility == "public" { FunctionVisibility::Public } else { FunctionVisibility::Private },
                                complexity,
                                priority,
                                suggested_tests: vec![TestType::Unit],
                                reason: format!("Public function '{}' lacks test coverage", symbol.name),
                            });
                        }
                    }
                }
            }
        }

        Ok(missing_tests)
    }

    /// Check if a function has tests
    fn function_has_test(&self, symbol: &crate::Symbol, _file: &FileInfo, test_files: &[&FileInfo]) -> bool {
        for test_file in test_files {
            for test_symbol in &test_file.symbols {
                if self.is_test_function(test_symbol) &&
                   test_symbol.name.to_lowercase().contains(&symbol.name.to_lowercase()) {
                    return true;
                }
            }
        }
        false
    }

    /// Assess function complexity for testing priority
    fn assess_function_complexity(&self, _symbol: &crate::Symbol) -> FunctionComplexity {
        // Simplified complexity assessment
        FunctionComplexity::Medium
    }

    /// Determine test priority for a function
    fn determine_test_priority(&self, symbol: &crate::Symbol, complexity: &FunctionComplexity) -> TestPriority {
        if symbol.visibility == "public" {
            match complexity {
                FunctionComplexity::VeryHigh => TestPriority::Critical,
                FunctionComplexity::High => TestPriority::High,
                FunctionComplexity::Medium => TestPriority::Medium,
                FunctionComplexity::Low => TestPriority::Low,
            }
        } else {
            TestPriority::Low
        }
    }

    /// Calculate quality metrics
    fn calculate_quality_metrics(&self, test_file_analyses: &[TestFileAnalysis]) -> Result<TestQualityMetrics> {
        let total_tests: usize = test_file_analyses.iter().map(|a| a.test_count).sum();

        if total_tests == 0 {
            return Ok(TestQualityMetrics::default());
        }

        // Calculate average test length using parsed test function lengths
        let total_length: usize = test_file_analyses
            .iter()
            .flat_map(|a| a.test_function_lengths.iter())
            .sum();
        let average_test_length = if total_tests > 0 {
            total_length as f64 / total_tests as f64
        } else {
            0.0
        };

        // Calculate naming quality
        let well_named_tests = test_file_analyses.iter()
            .flat_map(|a| &a.issues)
            .filter(|issue| !matches!(issue.issue_type, TestIssueType::UnclearTestName))
            .count();
        let naming_quality = ((well_named_tests as f64 / total_tests as f64) * crate::constants::test_coverage::PERCENTAGE_MULTIPLIER) as u8;

        // Calculate assertion density (simplified)
        let assertion_density = 2.5; // Average assertions per test

        // Calculate documentation coverage
        let documented_tests = test_file_analyses.iter()
            .flat_map(|a| &a.issues)
            .filter(|issue| !matches!(issue.issue_type, TestIssueType::MissingDocumentation))
            .count();
        let documentation_coverage = (documented_tests as f64 / total_tests as f64) * crate::constants::test_coverage::PERCENTAGE_MULTIPLIER;

        // Calculate maintainability score
        let avg_quality_score = test_file_analyses.iter()
            .map(|a| a.quality_score as f64)
            .sum::<f64>() / test_file_analyses.len() as f64;

        // Calculate reliability indicators
        let flaky_tests = test_file_analyses.iter()
            .flat_map(|a| &a.issues)
            .filter(|issue| matches!(issue.issue_type, TestIssueType::FlakyTest))
            .count();

        let reliability_indicators = TestReliabilityMetrics {
            potential_flaky_tests: flaky_tests,
            external_dependency_tests: 0, // Simplified
            timing_dependent_tests: 0,    // Simplified
            random_element_tests: 0,      // Simplified
        };

        Ok(TestQualityMetrics {
            average_test_length,
            naming_quality,
            assertion_density,
            documentation_coverage,
            maintainability_score: avg_quality_score as u8,
            reliability_indicators,
        })
    }

    /// Analyze test organization
    fn analyze_test_organization(&self, test_file_analyses: &[TestFileAnalysis]) -> Result<TestOrganizationAnalysis> {
        // Evaluate how many test files are placed in dedicated test directories
        let organized_files = test_file_analyses
            .iter()
            .filter(|a| {
                a.file
                    .components()
                    .any(|c| {
                        let name = c.as_os_str().to_str().unwrap_or("").to_lowercase();
                        name == "tests" || name == "test"
                    })
            })
            .count();
        let structure_quality = if test_file_analyses.is_empty() {
            0
        } else {
            ((organized_files as f64 / test_file_analyses.len() as f64) * crate::constants::test_coverage::PERCENTAGE_MULTIPLIER)
                .round() as u8
        };

        // Calculate naming consistency
        let consistent_naming = test_file_analyses.iter()
            .filter(|a| a.file.file_name().unwrap_or_default().to_str().unwrap_or("").contains("test"))
            .count();
        let naming_consistency = ((consistent_naming as f64 / test_file_analyses.len() as f64) * crate::constants::test_coverage::PERCENTAGE_MULTIPLIER) as u8;

        // Categorize tests
        let mut tests_by_type = HashMap::new();
        let mut tests_by_module = HashMap::new();

        for analysis in test_file_analyses {
            for test_type in &analysis.test_types {
                *tests_by_type.entry(test_type.clone()).or_insert(0) += analysis.test_count;
            }

            let module_name = analysis.file.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            *tests_by_module.entry(module_name).or_insert(0) += analysis.test_count;
        }

        let distribution_quality = if tests_by_type.len() > 1 { 80 } else { 60 };

        let categorization = TestCategorization {
            tests_by_type,
            tests_by_module,
            distribution_quality,
        };

        // Create test suites
        let test_suites = vec![
            TestSuite {
                name: "Unit Tests".to_string(),
                suite_type: TestType::Unit,
                test_count: test_file_analyses.iter().map(|a| a.test_count).sum(),
                files: test_file_analyses.iter().map(|a| a.file.clone()).collect(),
                quality_score: 75,
            }
        ];

        let suite_organization = TestSuiteOrganization {
            test_suites,
            organization_score: 70,
            improvements: vec![
                "Consider organizing tests by feature rather than by file".to_string(),
                "Add integration test suite".to_string(),
            ],
        };

        Ok(TestOrganizationAnalysis {
            structure_quality,
            naming_consistency,
            categorization,
            suite_organization,
        })
    }

    /// Generate testing recommendations
    fn generate_recommendations(
        &self,
        file_coverage: &[FileCoverage],
        missing_tests: &[MissingTest],
        quality_metrics: &TestQualityMetrics,
        _organization_analysis: &TestOrganizationAnalysis,
    ) -> Result<Vec<TestingRecommendation>> {
        let mut recommendations = Vec::new();

        // Coverage recommendations
        let low_coverage_files: Vec<_> = file_coverage.iter()
            .filter(|fc| fc.coverage_percentage < self.config.min_coverage_threshold)
            .collect();

        if !low_coverage_files.is_empty() {
            recommendations.push(TestingRecommendation {
                category: "Coverage Improvement".to_string(),
                recommendation: format!("Improve test coverage for {} files with low coverage", low_coverage_files.len()),
                priority: TestPriority::High,
                affected_files: low_coverage_files.iter().map(|fc| fc.file.clone()).collect(),
                difficulty: ImplementationDifficulty::Medium,
                benefits: vec![
                    "Increased confidence in code changes".to_string(),
                    "Better bug detection".to_string(),
                    "Improved code quality".to_string(),
                ],
            });
        }

        // Missing tests recommendations
        let critical_missing_tests = missing_tests.iter()
            .filter(|mt| matches!(mt.priority, TestPriority::Critical | TestPriority::High))
            .count();

        if critical_missing_tests > 0 {
            recommendations.push(TestingRecommendation {
                category: "Missing Tests".to_string(),
                recommendation: format!("Add tests for {} critical functions without coverage", critical_missing_tests),
                priority: TestPriority::Critical,
                affected_files: missing_tests.iter()
                    .filter(|mt| matches!(mt.priority, TestPriority::Critical | TestPriority::High))
                    .map(|mt| mt.file.clone())
                    .collect(),
                difficulty: ImplementationDifficulty::Medium,
                benefits: vec![
                    "Prevent regressions in critical functionality".to_string(),
                    "Improve system reliability".to_string(),
                ],
            });
        }

        // Quality improvements
        if quality_metrics.naming_quality < 70 {
            recommendations.push(TestingRecommendation {
                category: "Test Quality".to_string(),
                recommendation: "Improve test naming conventions for better readability".to_string(),
                priority: TestPriority::Medium,
                affected_files: Vec::new(),
                difficulty: ImplementationDifficulty::Easy,
                benefits: vec![
                    "Better test maintainability".to_string(),
                    "Clearer test intent".to_string(),
                ],
            });
        }

        // Reliability improvements
        if quality_metrics.reliability_indicators.potential_flaky_tests > 0 {
            recommendations.push(TestingRecommendation {
                category: "Test Reliability".to_string(),
                recommendation: "Address potential flaky tests to improve test suite reliability".to_string(),
                priority: TestPriority::High,
                affected_files: Vec::new(),
                difficulty: ImplementationDifficulty::Hard,
                benefits: vec![
                    "More reliable CI/CD pipeline".to_string(),
                    "Reduced false positives".to_string(),
                ],
            });
        }

        Ok(recommendations)
    }

    /// Count testable functions in the codebase
    fn count_testable_functions(&self, analysis_result: &AnalysisResult) -> usize {
        analysis_result.files.iter()
            .filter(|file| !self.is_test_file(file))
            .flat_map(|file| &file.symbols)
            .filter(|symbol| symbol.kind == "function" && symbol.visibility == "public")
            .count()
    }

    /// Calculate estimated coverage percentage
    fn calculate_estimated_coverage(&self, file_coverage: &[FileCoverage]) -> f64 {
        if file_coverage.is_empty() {
            return 0.0;
        }

        let total_functions: usize = file_coverage.iter().map(|fc| fc.total_functions).sum();
        let tested_functions: usize = file_coverage.iter().map(|fc| fc.tested_functions).sum();

        if total_functions > 0 {
            (tested_functions as f64 / total_functions as f64) * crate::constants::test_coverage::PERCENTAGE_MULTIPLIER
        } else {
            crate::constants::test_coverage::PERFECT_COVERAGE_SCORE
        }
    }

    /// Calculate overall coverage score
    fn calculate_coverage_score(&self, estimated_coverage: f64, quality_metrics: &TestQualityMetrics) -> u8 {
        let coverage_score = estimated_coverage * 0.6; // 60% weight on coverage
        let quality_score = quality_metrics.maintainability_score as f64 * 0.4; // 40% weight on quality

        (coverage_score + quality_score).min(crate::constants::test_coverage::MAX_COVERAGE_SCORE) as u8
    }
}

// Default implementations
impl Default for TestQualityMetrics {
    fn default() -> Self {
        Self {
            average_test_length: 0.0,
            naming_quality: 0,
            assertion_density: 0.0,
            documentation_coverage: 0.0,
            maintainability_score: 0,
            reliability_indicators: TestReliabilityMetrics {
                potential_flaky_tests: 0,
                external_dependency_tests: 0,
                timing_dependent_tests: 0,
                random_element_tests: 0,
            },
        }
    }
}

impl Default for TestOrganizationAnalysis {
    fn default() -> Self {
        Self {
            structure_quality: 0,
            naming_consistency: 0,
            categorization: TestCategorization {
                tests_by_type: HashMap::new(),
                tests_by_module: HashMap::new(),
                distribution_quality: 0,
            },
            suite_organization: TestSuiteOrganization {
                test_suites: Vec::new(),
                organization_score: 0,
                improvements: Vec::new(),
            },
        }
    }
}

// Display implementations
impl std::fmt::Display for TestPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestPriority::Critical => write!(f, "Critical"),
            TestPriority::High => write!(f, "High"),
            TestPriority::Medium => write!(f, "Medium"),
            TestPriority::Low => write!(f, "Low"),
        }
    }
}

impl std::fmt::Display for CoverageStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoverageStatus::Excellent => write!(f, "Excellent"),
            CoverageStatus::Good => write!(f, "Good"),
            CoverageStatus::Fair => write!(f, "Fair"),
            CoverageStatus::Poor => write!(f, "Poor"),
            CoverageStatus::None => write!(f, "None"),
        }
    }
}

impl std::fmt::Display for ImplementationDifficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImplementationDifficulty::Easy => write!(f, "Easy"),
            ImplementationDifficulty::Medium => write!(f, "Medium"),
            ImplementationDifficulty::Hard => write!(f, "Hard"),
            ImplementationDifficulty::VeryHard => write!(f, "Very Hard"),
        }
    }
}
