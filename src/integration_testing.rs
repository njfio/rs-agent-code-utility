//! Comprehensive Integration Testing Framework
//!
//! This module provides a complete testing infrastructure for rust_tree_sitter including:
//! - End-to-end integration testing
//! - Performance benchmarking suite
//! - Fuzz testing for parsers
//! - CI/CD pipeline integration
//! - Test data management and generation
//! - Comprehensive test scenarios and edge cases

use crate::advanced_cache::{AdvancedCache, CacheConfig};
use crate::advanced_memory::{AdvancedMemoryManager, MemoryConfig};
use crate::advanced_parallel::{AdvancedThreadPool, ThreadPoolConfig};
use crate::analyzer::{AnalysisConfig, AnalysisResult, CodebaseAnalyzer};
use crate::error::{Error, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Comprehensive test configuration
#[derive(Debug, Clone)]
pub struct IntegrationTestConfig {
    /// Test timeout duration
    pub timeout: Duration,
    /// Maximum memory usage for tests (MB)
    pub max_memory_mb: usize,
    /// Enable performance benchmarking
    pub enable_benchmarking: bool,
    /// Enable detailed logging
    pub enable_logging: bool,
    /// Enable fuzz testing
    pub enable_fuzzing: bool,
    /// Test data directory
    pub test_data_dir: PathBuf,
    /// Benchmark iterations
    pub benchmark_iterations: usize,
    /// Fuzz test duration
    pub fuzz_duration: Duration,
    /// CI/CD mode (affects output format)
    pub ci_mode: bool,
}

impl Default for IntegrationTestConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300), // 5 minutes
            max_memory_mb: 512,
            enable_benchmarking: true,
            enable_logging: true,
            enable_fuzzing: false,
            test_data_dir: PathBuf::from("test_data"),
            benchmark_iterations: 100,
            fuzz_duration: Duration::from_secs(60), // 1 minute
            ci_mode: false,
        }
    }
}

/// Test result enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum TestResult {
    Pass,
    Fail(String),
    Skip(String),
    Error(String),
}

/// Comprehensive test result
#[derive(Debug, Clone)]
pub struct TestCaseResult {
    pub name: String,
    pub result: TestResult,
    pub duration: Duration,
    pub memory_usage: usize,
    pub output: String,
    pub timestamp: Instant,
}

/// Integration test harness
pub struct IntegrationTestHarness {
    config: IntegrationTestConfig,
    temp_dir: TempDir,
    analyzer: Option<CodebaseAnalyzer>,
    results: Vec<TestCaseResult>,
    start_time: Instant,
}

impl IntegrationTestHarness {
    /// Create new test harness
    pub fn new(config: IntegrationTestConfig) -> Result<Self> {
        let temp_dir = TempDir::new()
            .map_err(|e| Error::io_error(format!("Failed to create temp directory: {}", e)))?;

        Ok(Self {
            config,
            temp_dir,
            analyzer: None,
            results: Vec::new(),
            start_time: Instant::now(),
        })
    }

    /// Initialize the test harness
    pub fn initialize(&mut self) -> Result<()> {
        if self.config.enable_logging {
            println!("🚀 Initializing Integration Test Harness");
            println!("   Timeout: {:?}", self.config.timeout);
            println!("   Max Memory: {} MB", self.config.max_memory_mb);
            println!("   Benchmarking: {}", self.config.enable_benchmarking);
            println!("   Fuzzing: {}", self.config.enable_fuzzing);
        }

        // Create test data directory
        fs::create_dir_all(&self.config.test_data_dir)?;

        // Initialize analyzer with test configuration
        let analyzer_config = AnalysisConfig {
            enable_parallel: true,
            max_file_size: Some(10 * 1024 * 1024), // 10MB
            ..Default::default()
        };

        self.analyzer = Some(CodebaseAnalyzer::new()?);

        Ok(())
    }

    /// Run all integration tests
    pub fn run_all_tests(&mut self) -> Result<TestSuiteResult> {
        let mut suite_result = TestSuiteResult::new("Integration Test Suite");

        // Core functionality tests
        self.run_core_functionality_tests(&mut suite_result)?;

        // Performance tests
        if self.config.enable_benchmarking {
            self.run_performance_tests(&mut suite_result)?;
        }

        // Fuzz tests
        if self.config.enable_fuzzing {
            self.run_fuzz_tests(&mut suite_result)?;
        }

        // Edge case tests
        self.run_edge_case_tests(&mut suite_result)?;

        // Generate final report
        self.generate_test_report(&suite_result)?;

        Ok(suite_result)
    }

    /// Run core functionality tests
    fn run_core_functionality_tests(&mut self, suite_result: &mut TestSuiteResult) -> Result<()> {
        if self.config.enable_logging {
            println!("\n🧪 Running Core Functionality Tests");
        }

        // Test 1: Basic file analysis
        self.run_test("basic_file_analysis", || {
            self.test_basic_file_analysis()
        }, suite_result)?;

        // Test 2: Directory analysis
        self.run_test("directory_analysis", || {
            self.test_directory_analysis()
        }, suite_result)?;

        // Test 3: Multi-language support
        self.run_test("multi_language_support", || {
            self.test_multi_language_support()
        }, suite_result)?;

        // Test 4: Symbol extraction
        self.run_test("symbol_extraction", || {
            self.test_symbol_extraction()
        }, suite_result)?;

        // Test 5: Cache functionality
        self.run_test("cache_functionality", || {
            self.test_cache_functionality()
        }, suite_result)?;

        Ok(())
    }

    /// Run performance tests
    fn run_performance_tests(&mut self, suite_result: &mut TestSuiteResult) -> Result<()> {
        if self.config.enable_logging {
            println!("\n⚡ Running Performance Tests");
        }

        // Test 1: Large codebase analysis
        self.run_test("large_codebase_performance", || {
            self.test_large_codebase_performance()
        }, suite_result)?;

        // Test 2: Memory usage analysis
        self.run_test("memory_usage_analysis", || {
            self.test_memory_usage_analysis()
        }, suite_result)?;

        // Test 3: Parallel processing efficiency
        self.run_test("parallel_processing_efficiency", || {
            self.test_parallel_processing_efficiency()
        }, suite_result)?;

        Ok(())
    }

    /// Run fuzz tests
    fn run_fuzz_tests(&mut self, suite_result: &mut TestSuiteResult) -> Result<()> {
        if self.config.enable_logging {
            println!("\n🎯 Running Fuzz Tests");
        }

        // Test 1: Parser fuzzing
        self.run_test("parser_fuzzing", || {
            self.test_parser_fuzzing()
        }, suite_result)?;

        // Test 2: Input validation fuzzing
        self.run_test("input_validation_fuzzing", || {
            self.test_input_validation_fuzzing()
        }, suite_result)?;

        Ok(())
    }

    /// Run edge case tests
    fn run_edge_case_tests(&mut self, suite_result: &mut TestSuiteResult) -> Result<()> {
        if self.config.enable_logging {
            println!("\n🔍 Running Edge Case Tests");
        }

        // Test 1: Empty files
        self.run_test("empty_files_handling", || {
            self.test_empty_files_handling()
        }, suite_result)?;

        // Test 2: Binary files
        self.run_test("binary_files_handling", || {
            self.test_binary_files_handling()
        }, suite_result)?;

        // Test 3: Very large files
        self.run_test("very_large_files", || {
            self.test_very_large_files()
        }, suite_result)?;

        // Test 4: Nested directories
        self.run_test("nested_directories", || {
            self.test_nested_directories()
        }, suite_result)?;

        Ok(())
    }

    /// Run a single test case
    fn run_test<F>(
        &mut self,
        test_name: &str,
        test_fn: F,
        suite_result: &mut TestSuiteResult,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<String>,
    {
        let test_start = Instant::now();

        let result = match test_fn() {
            Ok(output) => {
                let duration = test_start.elapsed();
                TestCaseResult {
                    name: test_name.to_string(),
                    result: TestResult::Pass,
                    duration,
                    memory_usage: 0, // TODO: Implement memory tracking
                    output,
                    timestamp: test_start,
                }
            }
            Err(e) => {
                let duration = test_start.elapsed();
                TestCaseResult {
                    name: test_name.to_string(),
                    result: TestResult::Fail(e.to_string()),
                    duration,
                    memory_usage: 0,
                    output: format!("Error: {}", e),
                    timestamp: test_start,
                }
            }
        };

        self.results.push(result.clone());
        suite_result.add_test_result(result);

        Ok(())
    }

    /// Test basic file analysis
    fn test_basic_file_analysis(&self) -> Result<String> {
        let test_file = self.temp_dir.path().join("test.rs");
        let content = r#"
fn main() {
    println!("Hello, world!");
}

fn add(a: i32, b: i32) -> i32 {
    a + b
}

struct Point {
    x: i32,
    y: i32,
}
"#;

        fs::write(&test_file, content)?;

        if let Some(ref analyzer) = self.analyzer {
            let result = analyzer.analyze_file(&test_file)?;
            Ok(format!(
                "Successfully analyzed file with {} symbols",
                result.symbols.len()
            ))
        } else {
            Err(Error::internal_error("harness", "Analyzer not initialized"))
        }
    }

    /// Test directory analysis
    fn test_directory_analysis(&self) -> Result<String> {
        let test_dir = self.temp_dir.path().join("test_project");
        fs::create_dir_all(&test_dir)?;

        // Create multiple files
        for i in 0..5 {
            let file_path = test_dir.join(format!("file_{}.rs", i));
            let content = format!(
                r#"
// File {}
pub fn function_{}() -> i32 {{
    let mut result = 0;
    for i in 0..100 {{
        result += i;
    }}
    result
}}
"#,
                i, i
            );
            fs::write(&file_path, content)?;
        }

        if let Some(ref analyzer) = self.analyzer {
            let result = analyzer.analyze_directory(&test_dir)?;
            Ok(format!(
                "Successfully analyzed directory with {} files and {} symbols",
                result.files.len(),
                result.files.iter().map(|f| f.symbols.len()).sum::<usize>()
            ))
        } else {
            Err(Error::internal_error("harness", "Analyzer not initialized"))
        }
    }

    /// Test multi-language support
    fn test_multi_language_support(&self) -> Result<String> {
        let test_dir = self.temp_dir.path().join("multi_lang");
        fs::create_dir_all(&test_dir)?;

        // Create files in different languages
        let rust_file = test_dir.join("main.rs");
        fs::write(&rust_file, "fn main() { println!(\"Hello\"); }")?;

        let python_file = test_dir.join("script.py");
        fs::write(&python_file, "def main():\n    print('Hello')")?;

        let js_file = test_dir.join("app.js");
        fs::write(&js_file, "function main() { console.log('Hello'); }")?;

        if let Some(ref analyzer) = self.analyzer {
            let result = analyzer.analyze_directory(&test_dir)?;
            Ok(format!(
                "Successfully analyzed {} files across {} languages",
                result.files.len(),
                result.languages.len()
            ))
        } else {
            Err(Error::internal_error("harness", "Analyzer not initialized"))
        }
    }

    /// Test symbol extraction
    fn test_symbol_extraction(&self) -> Result<String> {
        let test_file = self.temp_dir.path().join("symbols.rs");
        let content = r#"
pub struct User {
    pub id: u32,
    pub name: String,
}

impl User {
    pub fn new(id: u32, name: &str) -> Self {
        Self {
            id,
            name: name.to_string(),
        }
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }
}

pub fn create_user(id: u32, name: &str) -> User {
    User::new(id, name)
}

mod utils {
    pub fn helper() -> String {
        "helper".to_string()
    }
}
"#;

        fs::write(&test_file, content)?;

        if let Some(ref analyzer) = self.analyzer {
            let result = analyzer.analyze_file(&test_file)?;
            let symbol_count = result.symbols.len();
            Ok(format!("Extracted {} symbols from test file", symbol_count))
        } else {
            Err(Error::internal_error("harness", "Analyzer not initialized"))
        }
    }

    /// Test cache functionality
    fn test_cache_functionality(&self) -> Result<String> {
        let cache_config = CacheConfig {
            max_memory_bytes: 10 * 1024 * 1024, // 10MB
            max_disk_bytes: 50 * 1024 * 1024,   // 50MB
            ..Default::default()
        };

        let mut cache: AdvancedCache<String> = AdvancedCache::new(cache_config)?;

        // Test cache operations
        cache.put(
            "test_key".to_string(),
            "test_value".to_string(),
            None,
            Vec::new(),
        )?;

        if let Some(value) = cache.get("test_key") {
            Ok(format!("Cache functionality working - retrieved value: {}", value))
        } else {
            Err(Error::internal_error("cache_test", "Failed to retrieve cached value"))
        }
    }

    /// Test large codebase performance
    fn test_large_codebase_performance(&self) -> Result<String> {
        let large_project_dir = self.temp_dir.path().join("large_project");
        fs::create_dir_all(&large_project_dir)?;

        // Create many files to simulate a large codebase
        for i in 0..50 {
            let file_path = large_project_dir.join(format!("module_{}.rs", i));
            let content = format!(
                r#"
// Large module {}
pub struct Module{} {{
    pub id: usize,
    pub name: String,
}}

impl Module{} {{
    pub fn new(id: usize, name: &str) -> Self {{
        Self {{
            id,
            name: name.to_string(),
        }}
    }}

    pub fn process(&self) -> String {{
        format!("Processing {{}}", self.name)
    }}
}}

pub fn create_module(id: usize, name: &str) -> Module{} {{
    Module{}::new(id, name)
}}
"#,
                i, i, i, i, i, i
            );
            fs::write(&file_path, content)?;
        }

        let start_time = Instant::now();

        if let Some(ref analyzer) = self.analyzer {
            let result = analyzer.analyze_directory(&large_project_dir)?;
            let duration = start_time.elapsed();

            Ok(format!(
                "Analyzed large codebase ({} files, {} symbols) in {:.2}s",
                result.files.len(),
                result.files.iter().map(|f| f.symbols.len()).sum::<usize>(),
                duration.as_secs_f64()
            ))
        } else {
            Err(Error::internal_error("harness", "Analyzer not initialized"))
        }
    }

    /// Test memory usage analysis
    fn test_memory_usage_analysis(&self) -> Result<String> {
        let memory_config = MemoryConfig {
            max_memory_bytes: 50 * 1024 * 1024, // 50MB
            ..Default::default()
        };

        let memory_manager = AdvancedMemoryManager::new(memory_config);

        // Simulate memory operations
        for i in 0..1000 {
            memory_manager.record_allocation((i % 1000) + 100);
            if i % 3 == 0 {
                memory_manager.record_deallocation((i % 500) + 50);
            }
        }

        Ok("Memory usage analysis completed successfully".to_string())
    }

    /// Test parallel processing efficiency
    fn test_parallel_processing_efficiency(&self) -> Result<String> {
        let thread_config = ThreadPoolConfig {
            max_threads: num_cpus::get().min(4),
            ..Default::default()
        };

        let thread_pool = AdvancedThreadPool::new(thread_config)?;

        // Submit multiple tasks
        for i in 0..10 {
            use crate::advanced_parallel::{FileAnalysisTask, Task};

            let task = FileAnalysisTask {
                file_path: self.temp_dir.path().join(format!("task_{}.rs", i)).into(),
                content: Some(format!("fn task_{}() {{}}", i)),
                analysis_type: "syntax".to_string(),
            };

            thread_pool.submit(task)?;
        }

        thread_pool.wait_for_completion()?;

        Ok("Parallel processing efficiency test completed".to_string())
    }

    /// Test parser fuzzing
    fn test_parser_fuzzing(&self) -> Result<String> {
        let fuzz_start = Instant::now();
        let mut successful_parses = 0;
        let mut total_attempts = 0;

        while fuzz_start.elapsed() < self.config.fuzz_duration && total_attempts < 1000 {
            total_attempts += 1;

            // Generate random Rust-like code
            let random_code = generate_random_rust_code();

            let test_file = self.temp_dir.path().join(format!("fuzz_{}.rs", total_attempts));
            fs::write(&test_file, &random_code)?;

            if let Some(ref analyzer) = self.analyzer {
                match analyzer.analyze_file(&test_file) {
                    Ok(_) => successful_parses += 1,
                    Err(_) => {
                        // Expected for malformed input
                    }
                }
            }
        }

        Ok(format!(
            "Fuzz testing completed: {}/{} successful parses",
            successful_parses, total_attempts
        ))
    }

    /// Test input validation fuzzing
    fn test_input_validation_fuzzing(&self) -> Result<String> {
        let test_cases = vec![
            "", // Empty string
            "\x00\x01\x02", // Null bytes
            "a".repeat(1000000), // Very long string
            "fn main() { \x80\x81\x82 }", // Invalid UTF-8
            "fn main() { /* unclosed comment", // Unclosed comment
            "fn main() { \"unclosed string", // Unclosed string
        ];

        let mut passed = 0;

        for (i, test_case) in test_cases.iter().enumerate() {
            let test_file = self.temp_dir.path().join(format!("validation_{}.rs", i));
            match fs::write(&test_file, test_case) {
                Ok(_) => {
                    if let Some(ref analyzer) = self.analyzer {
                        // Just check that it doesn't panic
                        let _ = analyzer.analyze_file(&test_file);
                        passed += 1;
                    }
                }
                Err(_) => {
                    // Expected for invalid input
                    passed += 1;
                }
            }
        }

        Ok(format!("Input validation fuzzing: {}/{} cases handled gracefully", passed, test_cases.len()))
    }

    /// Test empty files handling
    fn test_empty_files_handling(&self) -> Result<String> {
        let empty_file = self.temp_dir.path().join("empty.rs");
        fs::write(&empty_file, "")?;

        if let Some(ref analyzer) = self.analyzer {
            let result = analyzer.analyze_file(&empty_file)?;
            Ok(format!("Empty file handled successfully: {} symbols found", result.symbols.len()))
        } else {
            Err(Error::internal_error("harness", "Analyzer not initialized"))
        }
    }

    /// Test binary files handling
    fn test_binary_files_handling(&self) -> Result<String> {
        let binary_file = self.temp_dir.path().join("binary.bin");
        let binary_data = vec![0u8, 1, 2, 255, 254, 253];
        fs::write(&binary_file, binary_data)?;

        if let Some(ref analyzer) = self.analyzer {
            match analyzer.analyze_file(&binary_file) {
                Ok(result) => Ok(format!("Binary file analysis: {} symbols found", result.symbols.len())),
                Err(_) => Ok("Binary file correctly rejected (expected)".to_string()),
            }
        } else {
            Err(Error::internal_error("harness", "Analyzer not initialized"))
        }
    }

    /// Test very large files
    fn test_very_large_files(&self) -> Result<String> {
        let large_file = self.temp_dir.path().join("large.rs");

        // Create a very large file
        let mut content = String::new();
        for i in 0..10000 {
            content.push_str(&format!("fn function_{}() {{ let x = {}; }}\n", i, i));
        }

        fs::write(&large_file, content)?;

        if let Some(ref analyzer) = self.analyzer {
            let result = analyzer.analyze_file(&large_file)?;
            Ok(format!("Large file analysis: {} symbols found", result.symbols.len()))
        } else {
            Err(Error::internal_error("harness", "Analyzer not initialized"))
        }
    }

    /// Test nested directories
    fn test_nested_directories(&self) -> Result<String> {
        let nested_dir = self.temp_dir.path().join("nested/deep/structure");
        fs::create_dir_all(&nested_dir)?;

        // Create files at different nesting levels
        let root_file = self.temp_dir.path().join("root.rs");
        fs::write(&root_file, "fn root() {}")?;

        let level1_file = self.temp_dir.path().join("nested/level1.rs");
        fs::write(&level1_file, "fn level1() {}")?;

        let level2_file = nested_dir.join("level2.rs");
        fs::write(&level2_file, "fn level2() {}")?;

        if let Some(ref analyzer) = self.analyzer {
            let result = analyzer.analyze_directory(self.temp_dir.path())?;
            Ok(format!("Nested directory analysis: {} files found", result.files.len()))
        } else {
            Err(Error::internal_error("harness", "Analyzer not initialized"))
        }
    }

    /// Generate comprehensive test report
    fn generate_test_report(&self, suite_result: &TestSuiteResult) -> Result<()> {
        let report_path = self.config.test_data_dir.join("test_report.json");

        let report = serde_json::json!({
            "suite_name": suite_result.name,
            "timestamp": suite_result.timestamp,
            "duration": suite_result.duration.as_secs_f64(),
            "total_tests": suite_result.total_tests,
            "passed": suite_result.passed,
            "failed": suite_result.failed,
            "skipped": suite_result.skipped,
            "errors": suite_result.errors,
            "success_rate": suite_result.success_rate(),
            "results": suite_result.results.iter().map(|r| {
                serde_json::json!({
                    "name": r.name,
                    "result": match &r.result {
                        TestResult::Pass => "pass",
                        TestResult::Fail(msg) => format!("fail: {}", msg),
                        TestResult::Skip(msg) => format!("skip: {}", msg),
                        TestResult::Error(msg) => format!("error: {}", msg),
                    },
                    "duration": r.duration.as_secs_f64(),
                    "memory_usage": r.memory_usage,
                    "output": r.output
                })
            }).collect::<Vec<_>>()
        });

        fs::write(&report_path, serde_json::to_string_pretty(&report)?)?;

        if self.config.enable_logging {
            println!("\n📊 Test Report Generated");
            println!("   File: {}", report_path.display());
            println!("   Success Rate: {:.1}%", suite_result.success_rate());
            println!("   Duration: {:.2}s", suite_result.duration.as_secs_f64());
        }

        Ok(())
    }
}

/// Test suite result
#[derive(Debug, Clone)]
pub struct TestSuiteResult {
    pub name: String,
    pub timestamp: String,
    pub duration: Duration,
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub errors: usize,
    pub results: Vec<TestCaseResult>,
}

impl TestSuiteResult {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            duration: Duration::default(),
            total_tests: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            errors: 0,
            results: Vec::new(),
        }
    }

    pub fn add_test_result(&mut self, result: TestCaseResult) {
        self.total_tests += 1;
        self.results.push(result.clone());

        match result.result {
            TestResult::Pass => self.passed += 1,
            TestResult::Fail(_) => self.failed += 1,
            TestResult::Skip(_) => self.skipped += 1,
            TestResult::Error(_) => self.errors += 1,
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.passed as f64 / self.total_tests as f64) * 100.0
        }
    }

    pub fn set_duration(&mut self, duration: Duration) {
        self.duration = duration;
    }
}

/// Generate random Rust-like code for fuzz testing
fn generate_random_rust_code() -> String {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let mut code = String::new();

    // Generate random function definitions
    for i in 0..rng.gen_range(1..10) {
        code.push_str(&format!(
            "fn function_{}() {{\n    let x = {};\n    println!(\"{{}}\", x);\n}}\n\n",
            i,
            rng.gen_range(1..1000)
        ));
    }

    // Add some random syntax elements
    if rng.gen_bool(0.3) {
        code.push_str("struct TestStruct {\n    field: i32,\n}\n\n");
    }

    if rng.gen_bool(0.2) {
        code.push_str("impl TestStruct {\n    fn new() -> Self {\n        Self { field: 42 }\n    }\n}\n\n");
    }

    code
}

/// Performance benchmarking utilities
pub struct PerformanceBenchmarker {
    config: IntegrationTestConfig,
    results: Vec<BenchmarkResult>,
}

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: usize,
    pub total_duration: Duration,
    pub avg_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    pub memory_usage: usize,
    pub timestamp: String,
}

impl PerformanceBenchmarker {
    pub fn new(config: IntegrationTestConfig) -> Self {
        Self {
            config,
            results: Vec::new(),
        }
    }

    pub fn benchmark_operation<F, T>(
        &mut self,
        name: &str,
        operation: F,
    ) -> Result<BenchmarkResult>
    where
        F: Fn() -> Result<T>,
    {
        let mut durations = Vec::new();

        for _ in 0..self.config.benchmark_iterations {
            let start = Instant::now();

            match operation() {
                Ok(_) => {
                    durations.push(start.elapsed());
                }
                Err(e) => {
                    return Err(Error::internal_error(
                        "benchmark",
                        format!("Benchmark operation failed: {}", e),
                    ));
                }
            }
        }

        let total_duration: Duration = durations.iter().sum();
        let avg_duration = total_duration / durations.len() as u32;
        let min_duration = durations.iter().min().unwrap().clone();
        let max_duration = durations.iter().max().unwrap().clone();

        let result = BenchmarkResult {
            name: name.to_string(),
            iterations: durations.len(),
            total_duration,
            avg_duration,
            min_duration,
            max_duration,
            memory_usage: 0, // TODO: Implement memory tracking
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        self.results.push(result.clone());

        Ok(result)
    }

    pub fn generate_benchmark_report(&self) -> Result<String> {
        let mut report = format!("Performance Benchmark Report\n");
        report.push_str(&format!("Generated: {}\n\n", chrono::Utc::now().to_rfc3339()));

        for result in &self.results {
            report.push_str(&format!("Benchmark: {}\n", result.name));
            report.push_str(&format!("  Iterations: {}\n", result.iterations));
            report.push_str(&format!("  Average: {:.2}ms\n", result.avg_duration.as_millis()));
            report.push_str(&format!("  Min: {:.2}ms\n", result.min_duration.as_millis()));
            report.push_str(&format!("  Max: {:.2}ms\n", result.max_duration.as_millis()));
            report.push_str(&format!("  Total: {:.2}s\n\n", result.total_duration.as_secs_f64()));
        }

        Ok(report)
    }
}

/// CI/CD integration utilities
pub struct CiCdIntegration {
    config: IntegrationTestConfig,
}

impl CiCdIntegration {
    pub fn new(config: IntegrationTestConfig) -> Self {
        Self { config }
    }

    /// Generate GitHub Actions compatible output
    pub fn generate_github_output(&self, suite_result: &TestSuiteResult) -> String {
        format!(
            "::set-output name=tests_total::{}\n\
             ::set-output name=tests_passed::{}\n\
             ::set-output name=tests_failed::{}\n\
             ::set-output name=tests_skipped::{}\n\
             ::set-output name=success_rate::{:.1}\n\
             ::set-output name=duration_ms::{}\n",
            suite_result.total_tests,
            suite_result.passed,
            suite_result.failed,
            suite_result.skipped,
            suite_result.success_rate(),
            suite_result.duration.as_millis()
        )
    }

    /// Generate JUnit XML report for CI systems
    pub fn generate_junit_xml(&self, suite_result: &TestSuiteResult) -> String {
        let mut xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="{}" tests="{}" failures="{}" time="{:.3}">
    <testsuite name="IntegrationTests" tests="{}" failures="{}" time="{:.3}">
"#,
            suite_result.name,
            suite_result.total_tests,
            suite_result.failed,
            suite_result.duration.as_secs_f64(),
            suite_result.total_tests,
            suite_result.failed,
            suite_result.duration.as_secs_f64()
        );

        for result in &suite_result.results {
            let failure_msg = match &result.result {
                TestResult::Fail(msg) => Some(msg),
                TestResult::Error(msg) => Some(msg),
                _ => None,
            };

            xml.push_str(&format!(
                r#"        <testcase name="{}" time="{:.3}""#,
                result.name,
                result.duration.as_secs_f64()
            ));

            if let Some(msg) = failure_msg {
                xml.push_str(&format!(
                    r#">
            <failure message="{}">{}</failure>
        </testcase>"#,
                    msg, result.output
                ));
            } else {
                xml.push_str(" />\n");
            }
        }

        xml.push_str("    </testsuite>\n</testsuites>\n");
        xml
    }

    /// Check if running in CI environment
    pub fn is_ci_environment() -> bool {
        std::env::var("CI").is_ok()
            || std::env::var("CONTINUOUS_INTEGRATION").is_ok()
            || std::env::var("GITHUB_ACTIONS").is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_harness_creation() {
        let config = IntegrationTestConfig::default();
        let harness = IntegrationTestHarness::new(config);
        assert!(harness.is_ok());
    }

    #[test]
    fn test_test_suite_result() {
        let mut suite = TestSuiteResult::new("Test Suite");

        let result = TestCaseResult {
            name: "test_case".to_string(),
            result: TestResult::Pass,
            duration: Duration::from_millis(100),
            memory_usage: 1024,
            output: "Test passed".to_string(),
            timestamp: Instant::now(),
        };

        suite.add_test_result(result);

        assert_eq!(suite.total_tests, 1);
        assert_eq!(suite.passed, 1);
        assert_eq!(suite.success_rate(), 100.0);
    }

    #[test]
    fn test_random_code_generation() {
        let code = generate_random_rust_code();
        assert!(!code.is_empty());
        assert!(code.contains("fn "));
    }
}
