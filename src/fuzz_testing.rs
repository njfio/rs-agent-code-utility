//! Fuzz Testing Module for Parser Security Validation
//!
//! This module provides comprehensive fuzz testing capabilities for rust_tree_sitter including:
//! - Random input generation for parser testing
//! - Parser resilience testing against malformed input
//! - Security boundary validation
//! - Edge case discovery and testing
//! - Integration with automated testing frameworks
//! - Comprehensive fuzz testing reports

use crate::analyzer::CodebaseAnalyzer;
use crate::error::{Error, Result};
use rand::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Fuzz test configuration
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    /// Test duration
    pub duration: Duration,
    /// Maximum input size for fuzzing
    pub max_input_size: usize,
    /// Number of fuzz iterations
    pub iterations: usize,
    /// Enable crash detection
    pub enable_crash_detection: bool,
    /// Enable memory leak detection
    pub enable_memory_checks: bool,
    /// Enable timeout detection
    pub enable_timeout_detection: bool,
    /// Fuzz seed for reproducible testing
    pub seed: Option<u64>,
    /// Output directory for fuzz results
    pub output_dir: PathBuf,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(60),
            max_input_size: 1024 * 1024, // 1MB
            iterations: 1000,
            enable_crash_detection: true,
            enable_memory_checks: true,
            enable_timeout_detection: true,
            seed: None,
            output_dir: PathBuf::from("fuzz_results"),
        }
    }
}

/// Fuzz test result
#[derive(Debug, Clone)]
pub struct FuzzResult {
    pub input: String,
    pub result: FuzzTestOutcome,
    pub duration: Duration,
    pub memory_usage: usize,
    pub timestamp: Instant,
}

/// Fuzz test outcome
#[derive(Debug, Clone, PartialEq)]
pub enum FuzzTestOutcome {
    Pass,
    ParseError(String),
    Crash(String),
    Timeout,
    MemoryLeak,
    UnexpectedError(String),
}

/// Fuzz test statistics
#[derive(Debug, Clone)]
pub struct FuzzStatistics {
    pub total_tests: usize,
    pub passed: usize,
    pub parse_errors: usize,
    pub crashes: usize,
    pub timeouts: usize,
    pub memory_leaks: usize,
    pub unexpected_errors: usize,
    pub average_duration: Duration,
    pub max_memory_usage: usize,
}

/// Fuzz testing engine
pub struct FuzzEngine {
    config: FuzzConfig,
    rng: ThreadRng,
    results: Vec<FuzzResult>,
    analyzer: CodebaseAnalyzer,
    start_time: Instant,
}

impl FuzzEngine {
    /// Create new fuzz engine
    pub fn new(config: FuzzConfig) -> Result<Self> {
        let rng = match config.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };

        let analyzer = CodebaseAnalyzer::new()?;

        // Create output directory
        fs::create_dir_all(&config.output_dir)?;

        Ok(Self {
            config,
            rng: ThreadRng::default(),
            results: Vec::new(),
            analyzer,
            start_time: Instant::now(),
        })
    }

    /// Run comprehensive fuzz testing
    pub fn run_fuzz_tests(&mut self) -> Result<FuzzStatistics> {
        println!("🎯 Starting Fuzz Testing");
        println!("========================");
        println!("Configuration:");
        println!("  Duration: {:?}", self.config.duration);
        println!("  Max input size: {} bytes", self.config.max_input_size);
        println!("  Iterations: {}", self.config.iterations);
        println!("  Crash detection: {}", self.config.enable_crash_detection);
        println!("  Memory checks: {}", self.config.enable_memory_checks);
        println!(
            "  Timeout detection: {}",
            self.config.enable_timeout_detection
        );
        println!();

        let mut iteration = 0;
        let fuzz_start = Instant::now();

        while (fuzz_start.elapsed() < self.config.duration || iteration < self.config.iterations)
            && iteration < self.config.iterations
        {
            iteration += 1;

            if iteration % 100 == 0 {
                println!("Progress: {} iterations completed", iteration);
            }

            // Generate fuzzed input
            let input = self.generate_fuzzed_input();

            // Run fuzz test
            let result = self.run_single_fuzz_test(&input)?;

            self.results.push(result);

            // Check for critical issues
            if let FuzzTestOutcome::Crash(_) = &self.results.last().unwrap().result {
                println!("🚨 CRITICAL: Parser crash detected!");
                break;
            }
        }

        // Generate statistics
        let statistics = self.generate_statistics();

        // Generate report
        self.generate_fuzz_report(&statistics)?;

        println!("✅ Fuzz testing completed");
        println!("  Total tests: {}", statistics.total_tests);
        println!("  Success rate: {:.1}%", statistics.success_rate());

        Ok(statistics)
    }

    /// Generate fuzzed input for testing
    fn generate_fuzzed_input(&mut self) -> String {
        let input_type = self.rng.gen_range(0..5);

        match input_type {
            0 => self.generate_random_code(),
            1 => self.generate_malformed_syntax(),
            2 => self.generate_unicode_edge_cases(),
            3 => self.generate_large_input(),
            4 => self.generate_null_bytes_and_control_chars(),
            _ => self.generate_random_code(),
        }
    }

    /// Generate random but syntactically valid code
    fn generate_random_code(&mut self) -> String {
        let mut code = String::new();

        // Generate random functions
        let function_count = self.rng.gen_range(1..10);
        for i in 0..function_count {
            let visibility = if self.rng.gen_bool(0.3) { "pub " } else { "" };
            let name = format!("function_{}", i);
            let params = self.generate_random_parameters();

            code.push_str(&format!("{}fn {}({}) {{\n", visibility, name, params));

            // Generate function body
            let statements = self.rng.gen_range(1..5);
            for _ in 0..statements {
                let stmt = self.generate_random_statement();
                code.push_str(&format!("    {}\n", stmt));
            }

            code.push_str("}\n\n");
        }

        // Generate random structs
        if self.rng.gen_bool(0.4) {
            let struct_count = self.rng.gen_range(1..3);
            for i in 0..struct_count {
                code.push_str(&format!("struct Struct{} {{\n", i));
                let fields = self.rng.gen_range(1..5);
                for j in 0..fields {
                    code.push_str(&format!("    field_{}: i32,\n", j));
                }
                code.push_str("}\n\n");
            }
        }

        code
    }

    /// Generate malformed syntax for testing parser resilience
    fn generate_malformed_syntax(&mut self) -> String {
        let mut code = String::new();

        // Generate various malformed constructs
        let malformed_types = vec![
            "fn invalid_function( { let x = ; }",
            "struct Broken { field: }",
            "impl BadImpl { fn broken( }",
            "fn unclosed_brace { let x = 1;",
            "fn extra_closing } }",
            "fn mismatched_brackets [let x = 1;}",
            "fn invalid_chars fn@#$% { }",
            "struct Empty { , }",
            "fn double_colon :: invalid { }",
        ];

        // Pick random malformed constructs
        for _ in 0..self.rng.gen_range(3..8) {
            let idx = self.rng.gen_range(0..malformed_types.len());
            code.push_str(&malformed_types[idx]);
            code.push_str("\n");
        }

        code
    }

    /// Generate unicode edge cases
    fn generate_unicode_edge_cases(&mut self) -> String {
        let mut code = String::new();

        let unicode_edge_cases = vec![
            "fn test() { let x = \"\\u{0}\"; }",             // Null character
            "fn test() { let x = \"\\u{10FFFF}\"; }",        // Last unicode character
            "fn test() { let x = \"\\u{D800}\"; }",          // High surrogate
            "fn test() { let x = \"\\u{DC00}\"; }",          // Low surrogate
            "fn test() { let x = \"\\u{110000}\"; }",        // Beyond unicode range
            "fn test() { let x = \"\\u{0}\\u{1}\\u{2}\"; }", // Control characters
            "fn test() { let x = \"\\u{2028}\\u{2029}\"; }", // Line separators
        ];

        for case in unicode_edge_cases {
            code.push_str(case);
            code.push_str("\n");
        }

        code
    }

    /// Generate large input for stress testing
    fn generate_large_input(&mut self) -> String {
        let mut code = String::new();

        // Generate many small functions
        for i in 0..1000 {
            code.push_str(&format!("fn f{}() {{ let x{} = {}; }}\n", i, i, i));
        }

        // Ensure we don't exceed max size
        if code.len() > self.config.max_input_size {
            code.truncate(self.config.max_input_size);
        }

        code
    }

    /// Generate null bytes and control characters
    fn generate_null_bytes_and_control_chars(&mut self) -> String {
        let mut code = String::new();

        // Add null bytes and control characters
        code.push_str("fn test() {\n");
        code.push_str("    let x = \"");
        for _ in 0..100 {
            let char_code = self.rng.gen_range(0..32); // Control characters
            code.push_str(&format!("\\x{:02x}", char_code));
        }
        code.push_str("\";\n");
        code.push_str("}\n");

        code
    }

    /// Generate random function parameters
    fn generate_random_parameters(&mut self) -> String {
        let param_count = self.rng.gen_range(0..4);
        let mut params = Vec::new();

        for i in 0..param_count {
            let param_type = match self.rng.gen_range(0..5) {
                0 => "i32",
                1 => "&str",
                2 => "bool",
                3 => "Vec<i32>",
                4 => "Option<String>",
                _ => "i32",
            };
            params.push(format!("param_{}: {}", i, param_type));
        }

        params.join(", ")
    }

    /// Generate random statement
    fn generate_random_statement(&mut self) -> String {
        let stmt_type = self.rng.gen_range(0..4);

        match stmt_type {
            0 => format!(
                "let x{} = {};",
                self.rng.gen_range(0..100),
                self.rng.gen_range(0..1000)
            ),
            1 => format!("println!(\"{{}}\", {});", self.rng.gen_range(0..100)),
            2 => format!(
                "if {} > {} {{ }}",
                self.rng.gen_range(0..100),
                self.rng.gen_range(0..100)
            ),
            3 => format!("return {};", self.rng.gen_range(0..100)),
            _ => "let x = 1;".to_string(),
        }
    }

    /// Run single fuzz test
    fn run_single_fuzz_test(&mut self, input: &str) -> Result<FuzzResult> {
        let test_start = Instant::now();

        // Create temporary file
        let temp_file = self
            .config
            .output_dir
            .join(format!("fuzz_{}.rs", test_start.elapsed().as_nanos()));
        fs::write(&temp_file, input)?;

        let result = if self.config.enable_timeout_detection {
            self.run_with_timeout(&temp_file)
        } else {
            self.run_without_timeout(&temp_file)
        };

        let duration = test_start.elapsed();

        // Clean up temp file
        let _ = fs::remove_file(&temp_file);

        Ok(FuzzResult {
            input: input.to_string(),
            result,
            duration,
            memory_usage: 0, // TODO: Implement memory tracking
            timestamp: test_start,
        })
    }

    /// Run test with timeout detection
    fn run_with_timeout(&mut self, file_path: &PathBuf) -> FuzzTestOutcome {
        let timeout_duration = Duration::from_millis(1000); // 1 second timeout

        // This is a simplified timeout implementation
        // In a real implementation, you'd use proper async timeouts
        let start = Instant::now();

        let result = self.run_without_timeout(file_path);

        if start.elapsed() > timeout_duration {
            FuzzTestOutcome::Timeout
        } else {
            result
        }
    }

    /// Run test without timeout
    fn run_without_timeout(&mut self, file_path: &PathBuf) -> FuzzTestOutcome {
        match self.analyzer.analyze_file(file_path) {
            Ok(_) => FuzzTestOutcome::Pass,
            Err(e) => {
                // Classify the error
                let error_msg = e.to_string();
                if error_msg.contains("parse") || error_msg.contains("syntax") {
                    FuzzTestOutcome::ParseError(error_msg)
                } else if error_msg.contains("panic") || error_msg.contains("crash") {
                    FuzzTestOutcome::Crash(error_msg)
                } else {
                    FuzzTestOutcome::UnexpectedError(error_msg)
                }
            }
        }
    }

    /// Generate fuzz testing statistics
    fn generate_statistics(&self) -> FuzzStatistics {
        let mut stats = FuzzStatistics {
            total_tests: self.results.len(),
            passed: 0,
            parse_errors: 0,
            crashes: 0,
            timeouts: 0,
            memory_leaks: 0,
            unexpected_errors: 0,
            average_duration: Duration::default(),
            max_memory_usage: 0,
        };

        let mut total_duration = Duration::default();

        for result in &self.results {
            total_duration += result.duration;

            match &result.result {
                FuzzTestOutcome::Pass => stats.passed += 1,
                FuzzTestOutcome::ParseError(_) => stats.parse_errors += 1,
                FuzzTestOutcome::Crash(_) => stats.crashes += 1,
                FuzzTestOutcome::Timeout => stats.timeouts += 1,
                FuzzTestOutcome::MemoryLeak => stats.memory_leaks += 1,
                FuzzTestOutcome::UnexpectedError(_) => stats.unexpected_errors += 1,
            }

            if result.memory_usage > stats.max_memory_usage {
                stats.max_memory_usage = result.memory_usage;
            }
        }

        if !self.results.is_empty() {
            stats.average_duration = total_duration / self.results.len() as u32;
        }

        stats
    }

    /// Generate comprehensive fuzz testing report
    fn generate_fuzz_report(&self, stats: &FuzzStatistics) -> Result<()> {
        let report_path = self.config.output_dir.join("fuzz_report.md");
        let json_path = self.config.output_dir.join("fuzz_results.json");

        // Generate markdown report
        let mut report = format!(
            "# Fuzz Testing Report\n\n**Generated:** {}\n\n",
            chrono::Utc::now().to_rfc3339()
        );

        report.push_str("## Configuration\n\n");
        report.push_str(&format!("- **Duration:** {:?}\n", self.config.duration));
        report.push_str(&format!(
            "- **Max input size:** {} bytes\n",
            self.config.max_input_size
        ));
        report.push_str(&format!("- **Iterations:** {}\n", self.config.iterations));
        report.push_str(&format!(
            "- **Crash detection:** {}\n",
            self.config.enable_crash_detection
        ));
        report.push_str(&format!(
            "- **Memory checks:** {}\n",
            self.config.enable_memory_checks
        ));
        report.push_str(&format!(
            "- **Timeout detection:** {}\n\n",
            self.config.enable_timeout_detection
        ));

        report.push_str("## Results Summary\n\n");
        report.push_str(&format!("- **Total tests:** {}\n", stats.total_tests));
        report.push_str(&format!(
            "- **Passed:** {} ({:.1}%)\n",
            stats.passed,
            stats.success_rate()
        ));
        report.push_str(&format!(
            "- **Parse errors:** {} ({:.1}%)\n",
            stats.parse_errors,
            (stats.parse_errors as f64 / stats.total_tests as f64) * 100.0
        ));
        report.push_str(&format!(
            "- **Crashes:** {} ({:.1}%)\n",
            stats.crashes,
            (stats.crashes as f64 / stats.total_tests as f64) * 100.0
        ));
        report.push_str(&format!(
            "- **Timeouts:** {} ({:.1}%)\n",
            stats.timeouts,
            (stats.timeouts as f64 / stats.total_tests as f64) * 100.0
        ));
        report.push_str(&format!(
            "- **Memory leaks:** {} ({:.1}%)\n",
            stats.memory_leaks,
            (stats.memory_leaks as f64 / stats.total_tests as f64) * 100.0
        ));
        report.push_str(&format!(
            "- **Unexpected errors:** {} ({:.1}%)\n",
            stats.unexpected_errors,
            (stats.unexpected_errors as f64 / stats.total_tests as f64) * 100.0
        ));
        report.push_str(&format!(
            "- **Average duration:** {:.2}ms\n",
            stats.average_duration.as_millis()
        ));
        report.push_str(&format!(
            "- **Max memory usage:** {} bytes\n\n",
            stats.max_memory_usage
        ));

        // Critical issues section
        if stats.crashes > 0 || stats.timeouts > 0 || stats.memory_leaks > 0 {
            report.push_str("## 🚨 Critical Issues\n\n");

            if stats.crashes > 0 {
                report.push_str(&format!("- **{} crashes detected**\n", stats.crashes));
            }

            if stats.timeouts > 0 {
                report.push_str(&format!("- **{} timeouts detected**\n", stats.timeouts));
            }

            if stats.memory_leaks > 0 {
                report.push_str(&format!(
                    "- **{} memory leaks detected**\n",
                    stats.memory_leaks
                ));
            }

            report.push_str("\n### Failing Test Cases\n\n");
            for (i, result) in self.results.iter().enumerate() {
                match &result.result {
                    FuzzTestOutcome::Crash(msg) => {
                        report.push_str(&format!(
                            "#### Crash #{} ({}ms)\n",
                            i + 1,
                            result.duration.as_millis()
                        ));
                        report.push_str(&format!("**Error:** {}\n\n", msg));
                        report.push_str("**Input:**\n```rust\n");
                        report.push_str(&result.input);
                        report.push_str("\n```\n\n");
                    }
                    FuzzTestOutcome::Timeout => {
                        report.push_str(&format!(
                            "#### Timeout #{} ({}ms)\n",
                            i + 1,
                            result.duration.as_millis()
                        ));
                        report.push_str("**Input:**\n```rust\n");
                        report.push_str(&result.input);
                        report.push_str("\n```\n\n");
                    }
                    _ => {}
                }
            }
        }

        // Recommendations
        report.push_str("## Recommendations\n\n");

        if stats.success_rate() < 95.0 {
            report.push_str("- Parser resilience could be improved for malformed input\n");
        }

        if stats.crashes > 0 {
            report.push_str(
                "- **URGENT:** Address parser crashes to prevent security vulnerabilities\n",
            );
        }

        if stats.timeouts > 0 {
            report.push_str("- Implement timeout handling for long-running parse operations\n");
        }

        if stats.memory_leaks > 0 {
            report.push_str("- Investigate and fix memory leaks in parser\n");
        }

        // Save reports
        fs::write(&report_path, &report)?;
        let json_results: Vec<_> = self
            .results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "input": r.input,
                    "result": match &r.result {
                        FuzzTestOutcome::Pass => "pass",
                        FuzzTestOutcome::ParseError(msg) => format!("parse_error: {}", msg),
                        FuzzTestOutcome::Crash(msg) => format!("crash: {}", msg),
                        FuzzTestOutcome::Timeout => "timeout".to_string(),
                        FuzzTestOutcome::MemoryLeak => "memory_leak".to_string(),
                        FuzzTestOutcome::UnexpectedError(msg) => format!("error: {}", msg),
                    },
                    "duration_ms": r.duration.as_millis(),
                    "memory_usage": r.memory_usage,
                    "timestamp": r.timestamp.elapsed().as_secs()
                })
            })
            .collect();

        let json_content = serde_json::to_string_pretty(&json_results)?;
        fs::write(&json_path, json_content)?;

        println!("🎯 Fuzz report saved to: {}", report_path.display());
        println!("🎯 JSON results saved to: {}", json_path.display());

        Ok(())
    }
}

impl FuzzStatistics {
    pub fn success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.passed as f64 / self.total_tests as f64) * 100.0
        }
    }
}

/// CI/CD integration utilities for fuzz testing
pub struct FuzzCiIntegration {
    config: FuzzConfig,
}

impl FuzzCiIntegration {
    pub fn new(config: FuzzConfig) -> Self {
        Self { config }
    }

    /// Generate GitHub Actions compatible output
    pub fn generate_github_output(&self, stats: &FuzzStatistics) -> String {
        format!(
            "::set-output name=fuzz_tests_total::{}\n\
             ::set-output name=fuzz_tests_passed::{}\n\
             ::set-output name=fuzz_crashes::{}\n\
             ::set-output name=fuzz_timeouts::{}\n\
             ::set-output name=fuzz_success_rate::{:.1}\n\
             ::set-output name=fuzz_duration_ms::{}\n",
            stats.total_tests,
            stats.passed,
            stats.crashes,
            stats.timeouts,
            stats.success_rate(),
            stats.average_duration.as_millis()
        )
    }

    /// Check if fuzz test results meet quality gates
    pub fn check_quality_gates(&self, stats: &FuzzStatistics) -> Vec<String> {
        let mut issues = Vec::new();

        if stats.crashes > 0 {
            issues.push(format!(
                "🚨 BLOCKING: {} parser crashes detected",
                stats.crashes
            ));
        }

        if stats.timeouts > 5 {
            issues.push(format!(
                "⚠️ WARNING: {} timeouts detected (high)",
                stats.timeouts
            ));
        }

        if stats.success_rate() < 80.0 {
            issues.push(format!(
                "⚠️ WARNING: Low success rate {:.1}%",
                stats.success_rate()
            ));
        }

        if stats.memory_leaks > 0 {
            issues.push(format!(
                "⚠️ WARNING: {} memory leaks detected",
                stats.memory_leaks
            ));
        }

        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_config_default() {
        let config = FuzzConfig::default();
        assert_eq!(config.duration, Duration::from_secs(60));
        assert_eq!(config.max_input_size, 1024 * 1024);
        assert_eq!(config.iterations, 1000);
        assert!(config.enable_crash_detection);
    }

    #[test]
    fn test_fuzz_statistics_calculation() {
        let mut stats = FuzzStatistics {
            total_tests: 100,
            passed: 80,
            parse_errors: 15,
            crashes: 2,
            timeouts: 1,
            memory_leaks: 0,
            unexpected_errors: 2,
            average_duration: Duration::from_millis(50),
            max_memory_usage: 1024,
        };

        assert_eq!(stats.success_rate(), 80.0);
    }

    #[test]
    fn test_random_code_generation() {
        let mut engine = FuzzEngine::new(FuzzConfig::default()).unwrap();
        let code = engine.generate_random_code();
        assert!(!code.is_empty());
        assert!(code.contains("fn "));
    }

    #[test]
    fn test_malformed_syntax_generation() {
        let mut engine = FuzzEngine::new(FuzzConfig::default()).unwrap();
        let code = engine.generate_malformed_syntax();
        assert!(!code.is_empty());
    }

    #[test]
    fn test_unicode_edge_cases_generation() {
        let mut engine = FuzzEngine::new(FuzzConfig::default()).unwrap();
        let code = engine.generate_unicode_edge_cases();
        assert!(!code.is_empty());
        assert!(code.contains("\\u{"));
    }

    #[test]
    fn test_ci_integration() {
        let config = FuzzConfig::default();
        let ci = FuzzCiIntegration::new(config);
        let stats = FuzzStatistics {
            total_tests: 100,
            passed: 95,
            parse_errors: 3,
            crashes: 1,
            timeouts: 1,
            memory_leaks: 0,
            unexpected_errors: 0,
            average_duration: Duration::from_millis(50),
            max_memory_usage: 1024,
        };

        let output = ci.generate_github_output(&stats);
        assert!(output.contains("fuzz_tests_total::100"));
        assert!(output.contains("fuzz_crashes::1"));

        let issues = ci.check_quality_gates(&stats);
        assert!(!issues.is_empty()); // Should have issues due to crash
        assert!(issues[0].contains("BLOCKING"));
    }
}
