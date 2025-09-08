//! Integration testing framework for rust_tree_sitter
//!
//! This module provides comprehensive integration testing capabilities including:
//! - End-to-end functionality testing
//! - Component interaction testing
//! - Performance benchmarking
//! - Real-world scenario testing
//! - Error handling and edge case testing
//! - CI/CD integration utilities

use crate::advanced_cache::{AdvancedCache, CacheConfig};
use crate::advanced_memory::{AdvancedMemoryManager, MemoryConfig};
use crate::advanced_parallel::{AdvancedThreadPool, ThreadPoolConfig};
use crate::analyzer::{AnalysisConfig, AnalysisResult, CodebaseAnalyzer};
use crate::error::{Error, Result};
// use crate::languages::Language; // Temporarily commented out
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
// use std::sync::Arc; // Temporarily commented out
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Integration test configuration
#[derive(Debug, Clone)]
pub struct IntegrationTestConfig {
    /// Test timeout duration
    pub timeout: Duration,
    /// Maximum memory usage for tests
    pub max_memory_mb: usize,
    /// Enable performance benchmarking
    pub enable_benchmarking: bool,
    /// Enable detailed logging
    pub enable_logging: bool,
    /// Test data directory
    pub test_data_dir: PathBuf,
}

impl Default for IntegrationTestConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300), // 5 minutes
            max_memory_mb: 512,
            enable_benchmarking: true,
            enable_logging: true,
            test_data_dir: PathBuf::from("test_data"),
        }
    }
}

/// Test scenario definition
#[derive(Debug, Clone)]
pub struct TestScenario {
    /// Scenario name
    pub name: String,
    /// Scenario description
    pub description: String,
    /// Setup function
    pub setup: fn(&mut IntegrationTestHarness) -> Result<()>,
    /// Test execution function
    pub execute: fn(&mut IntegrationTestHarness) -> Result<TestResult>,
    /// Cleanup function
    pub cleanup: fn(&mut IntegrationTestHarness) -> Result<()>,
    /// Expected execution time
    pub expected_duration: Duration,
    /// Memory requirements
    pub memory_requirement_mb: usize,
}

/// Test result
#[derive(Debug, Clone)]
pub struct TestResult {
    /// Test passed/failed
    pub success: bool,
    /// Execution duration
    pub duration: Duration,
    /// Memory usage in MB
    pub memory_usage_mb: usize,
    /// Performance metrics
    pub metrics: HashMap<String, f64>,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Additional data
    pub data: HashMap<String, String>,
}

/// Performance benchmark result
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Benchmark name
    pub name: String,
    /// Operations per second
    pub ops_per_second: f64,
    /// Average latency
    pub avg_latency_ms: f64,
    /// P95 latency
    pub p95_latency_ms: f64,
    /// Memory usage
    pub memory_usage_mb: usize,
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
}

/// Integration test harness
pub struct IntegrationTestHarness {
    /// Test configuration
    config: IntegrationTestConfig,
    /// Temporary directory for test data
    temp_dir: TempDir,
    /// Codebase analyzer
    analyzer: Option<CodebaseAnalyzer>,
    /// Advanced cache
    cache: Option<AdvancedCache<String>>,
    /// Thread pool
    thread_pool: Option<AdvancedThreadPool>,
    /// Memory manager
    memory_manager: Option<AdvancedMemoryManager>,
    /// Test results
    results: Vec<TestResult>,
    /// Performance metrics
    performance_data: HashMap<String, Vec<Duration>>,
    /// Start time
    start_time: Instant,
}

impl IntegrationTestHarness {
    /// Create new test harness
    pub fn new(config: IntegrationTestConfig) -> Result<Self> {
        let temp_dir = TempDir::new()?;

        Ok(Self {
            config,
            temp_dir,
            analyzer: None,
            cache: None,
            thread_pool: None,
            memory_manager: None,
            results: Vec::new(),
            performance_data: HashMap::new(),
            start_time: Instant::now(),
        })
    }

    /// Initialize components
    pub fn initialize(&mut self) -> Result<()> {
        // Initialize memory manager
        let memory_config = MemoryConfig {
            max_memory_bytes: self.config.max_memory_mb * 1024 * 1024,
            ..Default::default()
        };
        self.memory_manager = Some(AdvancedMemoryManager::new(memory_config));

        // Initialize cache
        let cache_config = CacheConfig {
            max_memory_bytes: 50 * 1024 * 1024, // 50MB
            max_disk_bytes: 100 * 1024 * 1024,  // 100MB
            ..Default::default()
        };
        self.cache = Some(AdvancedCache::new(cache_config)?);

        // Initialize thread pool
        let thread_config = ThreadPoolConfig {
            max_threads: 4,
            max_memory_per_thread: 25 * 1024 * 1024, // 25MB per thread
            ..Default::default()
        };
        self.thread_pool = Some(AdvancedThreadPool::new(thread_config)?);

        // Initialize analyzer
        let analyzer_config = AnalysisConfig {
            enable_parallel: true,
            max_file_size: Some(10 * 1024 * 1024), // 10MB
            ..Default::default()
        };
        self.analyzer = Some(CodebaseAnalyzer::new()?);

        Ok(())
    }

    /// Get temporary directory path
    pub fn temp_dir(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Create test project structure
    pub fn create_test_project(
        &self,
        name: &str,
        files: HashMap<String, String>,
    ) -> Result<PathBuf> {
        let project_dir = self.temp_dir.path().join(name);
        fs::create_dir_all(&project_dir)?;

        for (file_path, content) in files {
            let full_path = project_dir.join(file_path);
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(full_path, content)?;
        }

        Ok(project_dir)
    }

    /// Run analysis on test project
    pub fn analyze_project(&mut self, project_path: &Path) -> Result<AnalysisResult> {
        if let Some(ref mut analyzer) = self.analyzer {
            analyzer.analyze_directory(&project_path)
        } else {
            Err(Error::internal_error("harness", "Analyzer not initialized"))
        }
    }

    /// Run performance benchmark
    pub fn benchmark_operation<F, T>(
        &mut self,
        name: &str,
        iterations: usize,
        operation: F,
    ) -> Result<BenchmarkResult>
    where
        F: Fn() -> Result<T>,
    {
        let mut durations = Vec::with_capacity(iterations);
        let mut errors = 0;

        for _ in 0..iterations {
            let start = Instant::now();
            match operation() {
                Ok(_) => {
                    durations.push(start.elapsed());
                }
                Err(_) => {
                    errors += 1;
                }
            }
        }

        if durations.is_empty() {
            return Err(Error::internal_error(
                "benchmark",
                format!("All {} iterations failed", iterations),
            ));
        }

        // Calculate metrics
        durations.sort();
        let total_duration: Duration = durations.iter().sum();
        let avg_duration = total_duration / durations.len() as u32;
        let p95_index = (durations.len() as f64 * 0.95) as usize;
        let p95_duration = durations[p95_index];

        let ops_per_second = if avg_duration.as_nanos() > 0 {
            1_000_000_000.0 / avg_duration.as_nanos() as f64
        } else {
            0.0
        };

        Ok(BenchmarkResult {
            name: name.to_string(),
            ops_per_second,
            avg_latency_ms: avg_duration.as_millis() as f64,
            p95_latency_ms: p95_duration.as_millis() as f64,
            memory_usage_mb: self.get_memory_usage(),
            cpu_usage_percent: 0.0, // TODO: Implement CPU monitoring
        })
    }

    /// Get current memory usage
    pub fn get_memory_usage(&self) -> usize {
        if let Some(ref memory_manager) = self.memory_manager {
            memory_manager.memory_stats().current_usage_bytes / (1024 * 1024)
        } else {
            0
        }
    }

    /// Run integration test scenario
    pub fn run_scenario(&mut self, scenario: &TestScenario) -> Result<TestResult> {
        let scenario_start = Instant::now();

        // Setup
        (scenario.setup)(self)?;

        // Execute
        let result = (scenario.execute)(self);

        // Cleanup
        if let Err(e) = (scenario.cleanup)(self) {
            eprintln!(
                "Warning: Cleanup failed for scenario {}: {}",
                scenario.name, e
            );
        }

        let duration = scenario_start.elapsed();

        match result {
            Ok(mut test_result) => {
                test_result.duration = duration;
                test_result.memory_usage_mb = self.get_memory_usage();
                self.results.push(test_result.clone());
                Ok(test_result)
            }
            Err(e) => {
                let test_result = TestResult {
                    success: false,
                    duration,
                    memory_usage_mb: self.get_memory_usage(),
                    metrics: HashMap::new(),
                    error_message: Some(e.to_string()),
                    data: HashMap::new(),
                };
                self.results.push(test_result.clone());
                Ok(test_result)
            }
        }
    }

    /// Get all test results
    pub fn results(&self) -> &[TestResult] {
        &self.results
    }

    /// Generate test report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str("# Integration Test Report\n\n");

        report.push_str(&format!("Total Tests: {}\n", self.results.len()));
        let passed = self.results.iter().filter(|r| r.success).count();
        let failed = self.results.len() - passed;
        report.push_str(&format!("Passed: {}\n", passed));
        report.push_str(&format!("Failed: {}\n", failed));
        report.push_str(&format!(
            "Success Rate: {:.1}%\n\n",
            (passed as f64 / self.results.len() as f64) * 100.0
        ));

        for result in &self.results {
            report.push_str(&format!(
                "## {}\n",
                result
                    .data
                    .get("scenario_name")
                    .unwrap_or(&"Unknown".to_string())
            ));
            report.push_str(&format!(
                "Status: {}\n",
                if result.success {
                    "✅ PASSED"
                } else {
                    "❌ FAILED"
                }
            ));
            report.push_str(&format!(
                "Duration: {:.2}s\n",
                result.duration.as_secs_f64()
            ));
            report.push_str(&format!("Memory Usage: {} MB\n", result.memory_usage_mb));

            if !result.metrics.is_empty() {
                report.push_str("Metrics:\n");
                for (key, value) in &result.metrics {
                    report.push_str(&format!("  {}: {:.2}\n", key, value));
                }
            }

            if let Some(ref error) = result.error_message {
                report.push_str(&format!("Error: {}\n", error));
            }

            report.push_str("\n");
        }

        report
    }
}

/// Predefined test scenarios
pub struct TestScenarios;

impl TestScenarios {
    /// Basic functionality test
    pub fn basic_analysis() -> TestScenario {
        TestScenario {
            name: "basic_analysis".to_string(),
            description: "Test basic code analysis functionality".to_string(),
            setup: |harness| {
                let files = HashMap::from([
                    (
                        "src/lib.rs",
                        r#"
pub fn hello() -> &'static str {
    "Hello, World!"
}

pub fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#,
                    ),
                    (
                        "src/main.rs",
                        r#"
fn main() {
    println!("{}", hello());
    println!("Sum: {}", add(5, 3));
}
"#,
                    ),
                ]);
                harness.create_test_project("basic_test", files)?;
                Ok(())
            },
            execute: |harness| {
                let project_path = harness.temp_dir().join("basic_test");
                let result = harness.analyze_project(&project_path)?;

                let mut test_result = TestResult {
                    success: result.total_files == 2 && result.parsed_files == 2,
                    duration: Duration::default(),
                    memory_usage_mb: 0,
                    metrics: HashMap::from([
                        ("total_files".to_string(), result.total_files as f64),
                        ("parsed_files".to_string(), result.parsed_files as f64),
                        ("total_lines".to_string(), result.total_lines as f64),
                    ]),
                    error_message: None,
                    data: HashMap::from([
                        ("scenario_name".to_string(), "Basic Analysis".to_string()),
                        ("language".to_string(), "Rust".to_string()),
                    ]),
                };

                Ok(test_result)
            },
            cleanup: |_| Ok(()),
            expected_duration: Duration::from_secs(5),
            memory_requirement_mb: 50,
        }
    }

    /// Large codebase performance test
    pub fn large_codebase_analysis() -> TestScenario {
        TestScenario {
            name: "large_codebase".to_string(),
            description: "Test analysis performance on large codebase".to_string(),
            setup: |harness| {
                let mut files = HashMap::new();

                // Create multiple modules with substantial code
                for i in 0..10 {
                    let content = format!(
                        r#"
// Module {}
pub mod module_{} {{
    pub fn function_{}(x: i32) -> i32 {{
        let mut result = x;
        for _ in 0..1000 {{
            result += 1;
        }}
        result
    }}

    pub struct Struct{} {{
        pub field: i32,
    }}

    impl Struct{} {{
        pub fn new(value: i32) -> Self {{
            Self {{ field: value }}
        }}

        pub fn process(&self) -> i32 {{
            self.field * 2
        }}
    }}
}}
"#,
                        i, i, i, i, i
                    );

                    files.insert(format!("src/module_{}.rs", i), content.clone());
                }

                harness.create_test_project("large_test", files)?;
                Ok(())
            },
            execute: |harness| {
                let project_path = harness.temp_dir().join("large_test");
                let start = Instant::now();
                let result = harness.analyze_project(&project_path)?;
                let analysis_duration = start.elapsed();

                let mut test_result = TestResult {
                    success: result.parsed_files > 5,
                    duration: Duration::default(),
                    memory_usage_mb: 0,
                    metrics: HashMap::from([
                        (
                            "analysis_time_ms".to_string(),
                            analysis_duration.as_millis() as f64,
                        ),
                        (
                            "files_per_second".to_string(),
                            result.total_files as f64 / analysis_duration.as_secs_f64(),
                        ),
                        ("total_files".to_string(), result.total_files as f64),
                        ("parsed_files".to_string(), result.parsed_files as f64),
                    ]),
                    error_message: None,
                    data: HashMap::from([
                        (
                            "scenario_name".to_string(),
                            "Large Codebase Analysis".to_string(),
                        ),
                        ("size".to_string(), "10 modules".to_string()),
                    ]),
                };

                Ok(test_result)
            },
            cleanup: |_| Ok(()),
            expected_duration: Duration::from_secs(30),
            memory_requirement_mb: 200,
        }
    }

    /// Error handling test
    pub fn error_handling() -> TestScenario {
        TestScenario {
            name: "error_handling".to_string(),
            description: "Test error handling with malformed code".to_string(),
            setup: |harness| {
                let files = HashMap::from([
                    (
                        "src/good.rs",
                        r#"
pub fn valid_function() -> i32 {
    42
}
"#,
                    ),
                    (
                        "src/bad.rs",
                        r#"
// This file has syntax errors
pub fn broken_function() {
    let x = ;
    if true {
        println!("unclosed
    }
}
"#,
                    ),
                ]);
                harness.create_test_project("error_test", files)?;
                Ok(())
            },
            execute: |harness| {
                let project_path = harness.temp_dir().join("error_test");
                let result = harness.analyze_project(&project_path)?;

                // Should parse good.rs but fail on bad.rs
                let mut test_result = TestResult {
                    success: result.parsed_files == 1 && result.error_files == 1,
                    duration: Duration::default(),
                    memory_usage_mb: 0,
                    metrics: HashMap::from([
                        ("parsed_files".to_string(), result.parsed_files as f64),
                        ("error_files".to_string(), result.error_files as f64),
                        ("total_files".to_string(), result.total_files as f64),
                    ]),
                    error_message: None,
                    data: HashMap::from([
                        ("scenario_name".to_string(), "Error Handling".to_string()),
                        (
                            "expected_behavior".to_string(),
                            "Parse valid, reject invalid".to_string(),
                        ),
                    ]),
                };

                Ok(test_result)
            },
            cleanup: |_| Ok(()),
            expected_duration: Duration::from_secs(10),
            memory_requirement_mb: 50,
        }
    }
}

/// Integration test runner
pub struct IntegrationTestRunner {
    harness: IntegrationTestHarness,
    scenarios: Vec<TestScenario>,
}

impl IntegrationTestRunner {
    /// Create new test runner
    pub fn new(config: IntegrationTestConfig) -> Result<Self> {
        let harness = IntegrationTestHarness::new(config)?;
        Ok(Self {
            harness,
            scenarios: Vec::new(),
        })
    }

    /// Add test scenario
    pub fn add_scenario(&mut self, scenario: TestScenario) {
        self.scenarios.push(scenario);
    }

    /// Add default scenarios
    pub fn add_default_scenarios(&mut self) {
        self.add_scenario(TestScenarios::basic_analysis());
        self.add_scenario(TestScenarios::large_codebase_analysis());
        self.add_scenario(TestScenarios::error_handling());
    }

    /// Run all scenarios
    pub fn run_all(&mut self) -> Result<()> {
        self.harness.initialize()?;

        println!("🚀 Starting Integration Tests");
        println!("================================");

        let mut passed = 0;
        let mut failed = 0;

        for scenario in &self.scenarios {
            println!("Running scenario: {}", scenario.name);

            match self.harness.run_scenario(scenario) {
                Ok(result) => {
                    if result.success {
                        println!(
                            "✅ PASSED ({}ms, {}MB)",
                            result.duration.as_millis(),
                            result.memory_usage_mb
                        );
                        passed += 1;
                    } else {
                        println!(
                            "❌ FAILED ({}ms, {}MB)",
                            result.duration.as_millis(),
                            result.memory_usage_mb
                        );
                        if let Some(ref error) = result.error_message {
                            println!("   Error: {}", error);
                        }
                        failed += 1;
                    }
                }
                Err(e) => {
                    println!("❌ ERROR: {}", e);
                    failed += 1;
                }
            }
        }

        println!("\n📊 Test Results");
        println!("===============");
        println!("Total: {}", self.scenarios.len());
        println!("Passed: {}", passed);
        println!("Failed: {}", failed);
        println!(
            "Success Rate: {:.1}%",
            (passed as f64 / self.scenarios.len() as f64) * 100.0
        );

        if failed > 0 {
            println!("\n📋 Detailed Report");
            println!("{}", self.harness.generate_report());
        }

        Ok(())
    }

    /// Get test harness for direct access
    pub fn harness(&mut self) -> &mut IntegrationTestHarness {
        &mut self.harness
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harness_initialization() {
        let config = IntegrationTestConfig::default();
        let mut harness = IntegrationTestHarness::new(config).unwrap();
        harness.initialize().unwrap();

        assert!(harness.analyzer.is_some());
        assert!(harness.cache.is_some());
        assert!(harness.thread_pool.is_some());
        assert!(harness.memory_manager.is_some());
    }

    #[test]
    fn test_project_creation() {
        let config = IntegrationTestConfig::default();
        let harness = IntegrationTestHarness::new(config).unwrap();

        let files = HashMap::from([
            ("src/lib.rs", "pub fn test() {}"),
            ("Cargo.toml", "[package]\nname = \"test\""),
        ]);

        let project_path = harness.create_test_project("test_project", files).unwrap();
        assert!(project_path.exists());
        assert!(project_path.join("src/lib.rs").exists());
        assert!(project_path.join("Cargo.toml").exists());
    }

    #[test]
    fn test_runner_with_default_scenarios() {
        let config = IntegrationTestConfig {
            timeout: Duration::from_secs(60),
            enable_benchmarking: false,
            ..Default::default()
        };

        let mut runner = IntegrationTestRunner::new(config).unwrap();
        runner.add_default_scenarios();

        assert_eq!(runner.scenarios.len(), 3);
        assert_eq!(runner.scenarios[0].name, "basic_analysis");
        assert_eq!(runner.scenarios[1].name, "large_codebase");
        assert_eq!(runner.scenarios[2].name, "error_handling");
    }
}
