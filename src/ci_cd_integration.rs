use crate::error::{Error, Result};
use crate::fuzz_testing::{FuzzConfig, FuzzEngine, FuzzStatistics};
use crate::integration_testing::{IntegrationTestConfig, IntegrationTestHarness, TestSuiteResult};
use crate::performance_benchmarking::{
    BenchmarkConfig, BenchmarkResult, PerformanceBenchmarkSuite,
};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// CI/CD integration configuration
#[derive(Debug, Clone)]
pub struct CiCdConfig {
    /// CI platform (github, gitlab, jenkins, etc.)
    pub platform: String,
    /// Enable test result reporting
    pub enable_reporting: bool,
    /// Enable quality gates
    pub enable_quality_gates: bool,
    /// Enable performance regression detection
    pub enable_performance_regression: bool,
    /// Enable coverage reporting
    pub enable_coverage: bool,
    /// Quality gate thresholds
    pub quality_thresholds: QualityThresholds,
    /// Output directory for CI artifacts
    pub output_dir: PathBuf,
    /// Notification settings
    pub notifications: NotificationConfig,
}

#[derive(Debug, Clone)]
pub struct QualityThresholds {
    /// Minimum test success rate (%)
    pub min_test_success_rate: f64,
    /// Maximum allowed performance regression (%)
    pub max_performance_regression: f64,
    /// Maximum allowed crashes in fuzz testing
    pub max_fuzz_crashes: usize,
    /// Minimum code coverage (%)
    pub min_coverage: f64,
    /// Maximum allowed build warnings
    pub max_warnings: usize,
}

#[derive(Debug, Clone)]
pub struct NotificationConfig {
    /// Enable Slack notifications
    pub enable_slack: bool,
    /// Slack webhook URL
    pub slack_webhook: Option<String>,
    /// Enable email notifications
    pub enable_email: bool,
    /// Email recipients
    pub email_recipients: Vec<String>,
    /// Notify on failures only
    pub notify_on_failure_only: bool,
}

impl Default for CiCdConfig {
    fn default() -> Self {
        Self {
            platform: "github".to_string(),
            enable_reporting: true,
            enable_quality_gates: true,
            enable_performance_regression: true,
            enable_coverage: true,
            quality_thresholds: QualityThresholds::default(),
            output_dir: PathBuf::from("ci_artifacts"),
            notifications: NotificationConfig::default(),
        }
    }
}

impl Default for QualityThresholds {
    fn default() -> Self {
        Self {
            min_test_success_rate: 95.0,
            max_performance_regression: 10.0,
            max_fuzz_crashes: 0,
            min_coverage: 80.0,
            max_warnings: 50,
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enable_slack: false,
            slack_webhook: None,
            enable_email: false,
            email_recipients: Vec::new(),
            notify_on_failure_only: true,
        }
    }
}

/// CI/CD integration engine
pub struct CiCdEngine {
    config: CiCdConfig,
    test_results: Option<TestSuiteResult>,
    benchmark_results: Option<Vec<BenchmarkResult>>,
    fuzz_results: Option<FuzzStatistics>,
    quality_gate_results: Vec<QualityGateResult>,
}

#[derive(Debug, Clone)]
pub struct QualityGateResult {
    pub gate_name: String,
    pub status: QualityGateStatus,
    pub message: String,
    pub blocking: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum QualityGateStatus {
    Pass,
    Fail,
    Warning,
}

impl CiCdEngine {
    /// Create new CI/CD engine
    pub fn new(config: CiCdConfig) -> Result<Self> {
        // Create output directory
        fs::create_dir_all(&config.output_dir)?;

        Ok(Self {
            config,
            test_results: None,
            benchmark_results: None,
            fuzz_results: None,
            quality_gate_results: Vec::new(),
        })
    }

    /// Run complete CI/CD pipeline
    pub fn run_pipeline(&mut self) -> Result<PipelineResult> {
        println!("🚀 Starting CI/CD Pipeline");
        println!("=========================");

        let mut pipeline_result = PipelineResult::new();

        // Step 1: Run integration tests
        if let Ok(test_result) = self.run_integration_tests() {
            self.test_results = Some(test_result.clone());
            pipeline_result.test_success = test_result.total_tests == test_result.passed;
            pipeline_result.test_duration = test_result.duration;
        }

        // Step 2: Run performance benchmarks
        if let Ok(benchmark_results) = self.run_performance_benchmarks() {
            self.benchmark_results = Some(benchmark_results.clone());
            pipeline_result.benchmark_success = true;
        }

        // Step 3: Run fuzz tests
        if let Ok(fuzz_results) = self.run_fuzz_tests() {
            self.fuzz_results = Some(fuzz_results.clone());
            pipeline_result.fuzz_success = fuzz_results.crashes == 0;
        }

        // Step 4: Check quality gates
        self.check_quality_gates();
        pipeline_result.quality_gates_passed = self.quality_gates_passed();

        // Step 5: Generate reports
        self.generate_reports()?;

        // Step 6: Send notifications
        self.send_notifications(&pipeline_result)?;

        // Step 7: Generate CI outputs
        self.generate_ci_outputs(&pipeline_result)?;

        println!("✅ CI/CD Pipeline completed");
        println!(
            "  Tests: {}",
            if pipeline_result.test_success {
                "✅"
            } else {
                "❌"
            }
        );
        println!(
            "  Benchmarks: {}",
            if pipeline_result.benchmark_success {
                "✅"
            } else {
                "❌"
            }
        );
        println!(
            "  Fuzz Tests: {}",
            if pipeline_result.fuzz_success {
                "✅"
            } else {
                "❌"
            }
        );
        println!(
            "  Quality Gates: {}",
            if pipeline_result.quality_gates_passed {
                "✅"
            } else {
                "❌"
            }
        );

        Ok(pipeline_result)
    }

    /// Run integration tests
    fn run_integration_tests(&self) -> Result<TestSuiteResult> {
        println!("\n🧪 Running Integration Tests");

        let test_config = IntegrationTestConfig {
            timeout: std::time::Duration::from_secs(300),
            max_memory_mb: 256,
            enable_benchmarking: false,
            enable_logging: false,
            enable_fuzzing: false,
            test_data_dir: self.config.output_dir.join("test_data"),
            benchmark_iterations: 10,
            fuzz_duration: std::time::Duration::from_secs(10),
            ci_mode: true,
        };

        let mut harness = IntegrationTestHarness::new(test_config)?;
        harness.initialize()?;
        harness.run_all_tests()
    }

    /// Run performance benchmarks
    fn run_performance_benchmarks(&self) -> Result<Vec<BenchmarkResult>> {
        println!("\n⚡ Running Performance Benchmarks");

        let benchmark_config = BenchmarkConfig {
            iterations: 50,
            warmup_iterations: 5,
            max_duration: std::time::Duration::from_secs(120),
            enable_memory_profiling: true,
            enable_cpu_profiling: false,
            confidence_level: 0.95,
            output_dir: self.config.output_dir.join("benchmarks"),
            enable_progress_reporting: false,
            operation_timeout: std::time::Duration::from_secs(10),
        };

        let mut suite = PerformanceBenchmarkSuite::new(benchmark_config)?;
        suite.run_all_benchmarks()?;

        Ok(suite.results().to_vec())
    }

    /// Run fuzz tests
    fn run_fuzz_tests(&self) -> Result<FuzzStatistics> {
        println!("\n🎯 Running Fuzz Tests");

        let fuzz_config = FuzzConfig {
            duration: std::time::Duration::from_secs(30),
            max_input_size: 100 * 1024, // 100KB
            iterations: 500,
            enable_crash_detection: true,
            enable_memory_checks: true,
            enable_timeout_detection: true,
            seed: Some(42), // Deterministic for CI
            output_dir: self.config.output_dir.join("fuzz"),
        };

        let mut engine = FuzzEngine::new(fuzz_config)?;
        engine.run_fuzz_tests()
    }

    /// Check quality gates
    fn check_quality_gates(&mut self) {
        // Test success rate gate
        if let Some(test_results) = &self.test_results {
            let success_rate = test_results.success_rate();
            let status = if success_rate >= self.config.quality_thresholds.min_test_success_rate {
                QualityGateStatus::Pass
            } else {
                QualityGateStatus::Fail
            };

            self.quality_gate_results.push(QualityGateResult {
                gate_name: "Test Success Rate".to_string(),
                status,
                message: format!(
                    "Test success rate: {:.1}% (required: {:.1}%)",
                    success_rate, self.config.quality_thresholds.min_test_success_rate
                ),
                blocking: true,
            });
        }

        // Fuzz crash gate
        if let Some(fuzz_results) = &self.fuzz_results {
            let status = if fuzz_results.crashes <= self.config.quality_thresholds.max_fuzz_crashes
            {
                QualityGateStatus::Pass
            } else {
                QualityGateStatus::Fail
            };

            self.quality_gate_results.push(QualityGateResult {
                gate_name: "Fuzz Test Crashes".to_string(),
                status,
                message: format!(
                    "Fuzz test crashes: {} (max allowed: {})",
                    fuzz_results.crashes, self.config.quality_thresholds.max_fuzz_crashes
                ),
                blocking: true,
            });
        }

        // Performance regression gate
        if let Some(benchmark_results) = &self.benchmark_results {
            for result in benchmark_results {
                if !result.regression_indicators.is_empty() {
                    self.quality_gate_results.push(QualityGateResult {
                        gate_name: format!("Performance Regression - {}", result.name),
                        status: QualityGateStatus::Warning,
                        message: result.regression_indicators.join("; "),
                        blocking: false,
                    });
                }
            }
        }
    }

    /// Check if all quality gates passed
    fn quality_gates_passed(&self) -> bool {
        self.quality_gate_results
            .iter()
            .all(|gate| match gate.status {
                QualityGateStatus::Pass => true,
                QualityGateStatus::Fail => false,
                QualityGateStatus::Warning => !gate.blocking,
            })
    }

    /// Generate comprehensive reports
    fn generate_reports(&self) -> Result<()> {
        let reports_dir = self.config.output_dir.join("reports");
        fs::create_dir_all(&reports_dir)?;

        // Generate summary report
        self.generate_summary_report(&reports_dir)?;

        // Generate detailed test report
        if let Some(test_results) = &self.test_results {
            self.generate_test_report(test_results, &reports_dir)?;
        }

        // Generate benchmark report
        if let Some(benchmark_results) = &self.benchmark_results {
            self.generate_benchmark_report(benchmark_results, &reports_dir)?;
        }

        // Generate fuzz report
        if let Some(fuzz_results) = &self.fuzz_results {
            self.generate_fuzz_report(fuzz_results, &reports_dir)?;
        }

        // Generate quality gate report
        self.generate_quality_gate_report(&reports_dir)?;

        Ok(())
    }

    /// Generate summary report
    fn generate_summary_report(&self, reports_dir: &PathBuf) -> Result<()> {
        let summary_path = reports_dir.join("pipeline_summary.md");

        let mut summary = "# CI/CD Pipeline Summary\n\n".to_string();
        summary.push_str(&format!(
            "**Generated:** {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        // Pipeline status
        summary.push_str("## Pipeline Status\n\n");

        if let Some(test_results) = &self.test_results {
            summary.push_str(&format!(
                "- **Tests:** {} ({:.1}% success rate)\n",
                if test_results.failed == 0 {
                    "✅ PASSED"
                } else {
                    "❌ FAILED"
                },
                test_results.success_rate()
            ));
        }

        if let Some(benchmark_results) = &self.benchmark_results {
            summary.push_str(&format!(
                "- **Benchmarks:** ✅ COMPLETED ({} benchmarks)\n",
                benchmark_results.len()
            ));
        }

        if let Some(fuzz_results) = &self.fuzz_results {
            summary.push_str(&format!(
                "- **Fuzz Tests:** {} ({} crashes)\n",
                if fuzz_results.crashes == 0 {
                    "✅ PASSED"
                } else {
                    "❌ FAILED"
                },
                fuzz_results.crashes
            ));
        }

        summary.push_str(&format!(
            "- **Quality Gates:** {}\n\n",
            if self.quality_gates_passed() {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        ));

        // Quality gates section
        if !self.quality_gate_results.is_empty() {
            summary.push_str("## Quality Gates\n\n");
            for gate in &self.quality_gate_results {
                let status_emoji = match gate.status {
                    QualityGateStatus::Pass => "✅",
                    QualityGateStatus::Fail => "❌",
                    QualityGateStatus::Warning => "⚠️",
                };
                summary.push_str(&format!(
                    "- {} **{}:** {}\n",
                    status_emoji, gate.gate_name, gate.message
                ));
            }
            summary.push_str("\n");
        }

        fs::write(&summary_path, &summary)?;
        println!("📊 Summary report saved to: {}", summary_path.display());

        Ok(())
    }

    /// Generate detailed test report
    fn generate_test_report(
        &self,
        test_results: &TestSuiteResult,
        reports_dir: &PathBuf,
    ) -> Result<()> {
        let test_report_path = reports_dir.join("test_report.md");

        let mut report = "# Test Report\n\n".to_string();
        report.push_str(&format!(
            "**Generated:** {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        report.push_str("## Summary\n\n");
        report.push_str(&format!(
            "- **Total Tests:** {}\n",
            test_results.total_tests
        ));
        report.push_str(&format!(
            "- **Passed:** {} ({:.1}%)\n",
            test_results.passed,
            test_results.success_rate()
        ));
        report.push_str(&format!("- **Failed:** {}\n", test_results.failed));
        report.push_str(&format!("- **Skipped:** {}\n", test_results.skipped));
        report.push_str(&format!("- **Errors:** {}\n", test_results.errors));
        report.push_str(&format!(
            "- **Duration:** {:.2}s\n\n",
            test_results.duration.as_secs_f64()
        ));

        // Detailed results
        if !test_results.results.is_empty() {
            report.push_str("## Test Results\n\n");
            report.push_str("| Test | Status | Duration | Details |\n");
            report.push_str("|------|--------|----------|--------|\n");

            for result in &test_results.results {
                let status = match result.result {
                    crate::integration_testing::TestResult::Pass => "✅ PASS",
                    crate::integration_testing::TestResult::Fail(_) => "❌ FAIL",
                    crate::integration_testing::TestResult::Skip(_) => "⏭️ SKIP",
                    crate::integration_testing::TestResult::Error(_) => "💥 ERROR",
                };

                let details = match &result.result {
                    crate::integration_testing::TestResult::Pass => "Success".to_string(),
                    crate::integration_testing::TestResult::Fail(msg) => msg.clone(),
                    crate::integration_testing::TestResult::Skip(msg) => msg.clone(),
                    crate::integration_testing::TestResult::Error(msg) => msg.clone(),
                };

                report.push_str(&format!(
                    "| {} | {} | {:.2}s | {} |\n",
                    result.name,
                    status,
                    result.duration.as_secs_f64(),
                    details
                ));
            }
        }

        fs::write(&test_report_path, &report)?;
        Ok(())
    }

    /// Generate benchmark report
    fn generate_benchmark_report(
        &self,
        benchmark_results: &[BenchmarkResult],
        reports_dir: &PathBuf,
    ) -> Result<()> {
        let benchmark_report_path = reports_dir.join("benchmark_report.md");

        let mut report = "# Performance Benchmark Report\n\n".to_string();
        report.push_str(&format!(
            "**Generated:** {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        for result in benchmark_results {
            report.push_str(&format!("## {}\n\n", result.name));
            report.push_str(&format!("- **Iterations:** {}\n", result.iterations));
            report.push_str(&format!(
                "- **Average:** {:.2}ms\n",
                result.avg_duration.as_millis()
            ));
            report.push_str(&format!(
                "- **Min:** {:.2}ms\n",
                result.min_duration.as_millis()
            ));
            report.push_str(&format!(
                "- **Max:** {:.2}ms\n",
                result.max_duration.as_millis()
            ));

            if !result.regression_indicators.is_empty() {
                report.push_str("- **Regressions:**\n");
                for indicator in &result.regression_indicators {
                    report.push_str(&format!("  - {}\n", indicator));
                }
            }
            report.push_str("\n");
        }

        fs::write(&benchmark_report_path, &report)?;
        Ok(())
    }

    /// Generate fuzz report
    fn generate_fuzz_report(
        &self,
        fuzz_results: &FuzzStatistics,
        reports_dir: &PathBuf,
    ) -> Result<()> {
        let fuzz_report_path = reports_dir.join("fuzz_report.md");

        let mut report = "# Fuzz Testing Report\n\n".to_string();
        report.push_str(&format!(
            "**Generated:** {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        report.push_str("## Summary\n\n");
        report.push_str(&format!(
            "- **Total Tests:** {}\n",
            fuzz_results.total_tests
        ));
        report.push_str(&format!(
            "- **Success Rate:** {:.1}%\n",
            fuzz_results.success_rate()
        ));
        report.push_str(&format!("- **Crashes:** {}\n", fuzz_results.crashes));
        report.push_str(&format!("- **Timeouts:** {}\n", fuzz_results.timeouts));
        report.push_str(&format!(
            "- **Memory Leaks:** {}\n",
            fuzz_results.memory_leaks
        ));

        fs::write(&fuzz_report_path, &report)?;
        Ok(())
    }

    /// Generate quality gate report
    fn generate_quality_gate_report(&self, reports_dir: &PathBuf) -> Result<()> {
        let quality_report_path = reports_dir.join("quality_gates_report.md");

        let mut report = "# Quality Gates Report\n\n".to_string();
        report.push_str(&format!(
            "**Generated:** {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        for gate in &self.quality_gate_results {
            let status_emoji = match gate.status {
                QualityGateStatus::Pass => "✅",
                QualityGateStatus::Fail => "❌",
                QualityGateStatus::Warning => "⚠️",
            };

            report.push_str(&format!("## {} {}\n\n", status_emoji, gate.gate_name));
            report.push_str(&format!(
                "**Status:** {}\n",
                match gate.status {
                    QualityGateStatus::Pass => "PASSED",
                    QualityGateStatus::Fail => "FAILED",
                    QualityGateStatus::Warning => "WARNING",
                }
            ));
            report.push_str(&format!("**Message:** {}\n", gate.message));
            report.push_str(&format!(
                "**Blocking:** {}\n\n",
                if gate.blocking { "Yes" } else { "No" }
            ));
        }

        fs::write(&quality_report_path, &report)?;
        Ok(())
    }

    /// Send notifications
    fn send_notifications(&self, pipeline_result: &PipelineResult) -> Result<()> {
        if !self.config.notifications.enable_slack && !self.config.notifications.enable_email {
            return Ok(());
        }

        let has_failures = !pipeline_result.test_success
            || !pipeline_result.benchmark_success
            || !pipeline_result.fuzz_success
            || !pipeline_result.quality_gates_passed;

        if self.config.notifications.notify_on_failure_only && !has_failures {
            return Ok(());
        }

        let message = self.generate_notification_message(pipeline_result);

        // Send Slack notification
        if self.config.notifications.enable_slack {
            if let Some(webhook_url) = &self.config.notifications.slack_webhook {
                self.send_slack_notification(webhook_url, &message)?;
            }
        }

        // Send email notification
        if self.config.notifications.enable_email
            && !self.config.notifications.email_recipients.is_empty()
        {
            self.send_email_notification(&self.config.notifications.email_recipients, &message)?;
        }

        Ok(())
    }

    /// Generate notification message
    fn generate_notification_message(&self, pipeline_result: &PipelineResult) -> String {
        let status = if pipeline_result.is_success() {
            "✅ SUCCESS"
        } else {
            "❌ FAILURE"
        };

        let mut message = format!(
            "CI/CD Pipeline {} - {}\n\n",
            status,
            chrono::Utc::now().to_rfc3339()
        );

        message.push_str(&format!(
            "Tests: {}\n",
            if pipeline_result.test_success {
                "✅"
            } else {
                "❌"
            }
        ));
        message.push_str(&format!(
            "Benchmarks: {}\n",
            if pipeline_result.benchmark_success {
                "✅"
            } else {
                "❌"
            }
        ));
        message.push_str(&format!(
            "Fuzz Tests: {}\n",
            if pipeline_result.fuzz_success {
                "✅"
            } else {
                "❌"
            }
        ));
        message.push_str(&format!(
            "Quality Gates: {}\n",
            if pipeline_result.quality_gates_passed {
                "✅"
            } else {
                "❌"
            }
        ));

        if let Some(test_results) = &self.test_results {
            message.push_str(&format!(
                "\nTest Results: {}/{} passed ({:.1}%)",
                test_results.passed,
                test_results.total_tests,
                test_results.success_rate()
            ));
        }

        message
    }

    /// Send Slack notification
    fn send_slack_notification(&self, webhook_url: &str, message: &str) -> Result<()> {
        // In a real implementation, this would make an HTTP request to Slack
        println!("📢 Slack notification would be sent to: {}", webhook_url);
        println!("Message: {}", message);
        Ok(())
    }

    /// Send email notification
    fn send_email_notification(&self, recipients: &[String], message: &str) -> Result<()> {
        // In a real implementation, this would send emails
        println!("📧 Email notification would be sent to: {:?}", recipients);
        println!("Message: {}", message);
        Ok(())
    }

    /// Generate CI platform outputs
    fn generate_ci_outputs(&self, pipeline_result: &PipelineResult) -> Result<()> {
        match self.config.platform.as_str() {
            "github" => self.generate_github_outputs(pipeline_result),
            "gitlab" => self.generate_gitlab_outputs(pipeline_result),
            "jenkins" => self.generate_jenkins_outputs(pipeline_result),
            _ => Ok(()),
        }
    }

    /// Generate GitHub Actions outputs
    fn generate_github_outputs(&self, pipeline_result: &PipelineResult) -> Result<()> {
        println!(
            "::set-output name=pipeline_success::{}",
            pipeline_result.is_success()
        );
        println!(
            "::set-output name=tests_success::{}",
            pipeline_result.test_success
        );
        println!(
            "::set-output name=benchmarks_success::{}",
            pipeline_result.benchmark_success
        );
        println!(
            "::set-output name=fuzz_success::{}",
            pipeline_result.fuzz_success
        );
        println!(
            "::set-output name=quality_gates_passed::{}",
            pipeline_result.quality_gates_passed
        );

        if let Some(test_results) = &self.test_results {
            println!(
                "::set-output name=test_success_rate::{:.1}",
                test_results.success_rate()
            );
            println!(
                "::set-output name=test_duration_ms::{}",
                test_results.duration.as_millis()
            );
        }

        if let Some(fuzz_results) = &self.fuzz_results {
            println!("::set-output name=fuzz_crashes::{}", fuzz_results.crashes);
            println!(
                "::set-output name=fuzz_success_rate::{:.1}",
                fuzz_results.success_rate()
            );
        }

        Ok(())
    }

    /// Generate GitLab CI outputs
    fn generate_gitlab_outputs(&self, pipeline_result: &PipelineResult) -> Result<()> {
        println!("PIPELINE_SUCCESS={}", pipeline_result.is_success());
        println!("TESTS_SUCCESS={}", pipeline_result.test_success);
        println!(
            "QUALITY_GATES_PASSED={}",
            pipeline_result.quality_gates_passed
        );

        Ok(())
    }

    /// Generate Jenkins outputs
    fn generate_jenkins_outputs(&self, pipeline_result: &PipelineResult) -> Result<()> {
        println!("PIPELINE_SUCCESS={}", pipeline_result.is_success());

        Ok(())
    }
}

/// Pipeline execution result
#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub test_success: bool,
    pub benchmark_success: bool,
    pub fuzz_success: bool,
    pub quality_gates_passed: bool,
    pub test_duration: std::time::Duration,
}

impl PipelineResult {
    pub fn new() -> Self {
        Self {
            test_success: false,
            benchmark_success: false,
            fuzz_success: false,
            quality_gates_passed: false,
            test_duration: std::time::Duration::default(),
        }
    }

    pub fn is_success(&self) -> bool {
        self.test_success
            && self.benchmark_success
            && self.fuzz_success
            && self.quality_gates_passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ci_cd_config_default() {
        let config = CiCdConfig::default();
        assert_eq!(config.platform, "github");
        assert!(config.enable_reporting);
        assert!(config.enable_quality_gates);
    }

    #[test]
    fn test_quality_thresholds_default() {
        let thresholds = QualityThresholds::default();
        assert_eq!(thresholds.min_test_success_rate, 95.0);
        assert_eq!(thresholds.max_fuzz_crashes, 0);
    }

    #[test]
    fn test_pipeline_result_success() {
        let mut result = PipelineResult::new();
        result.test_success = true;
        result.benchmark_success = true;
        result.fuzz_success = true;
        result.quality_gates_passed = true;

        assert!(result.is_success());
    }

    #[test]
    fn test_pipeline_result_failure() {
        let mut result = PipelineResult::new();
        result.test_success = false;
        result.benchmark_success = true;
        result.fuzz_success = true;
        result.quality_gates_passed = true;

        assert!(!result.is_success());
    }

    #[test]
    fn test_quality_gate_result() {
        let gate = QualityGateResult {
            gate_name: "Test Gate".to_string(),
            status: QualityGateStatus::Pass,
            message: "All tests passed".to_string(),
            blocking: true,
        };

        assert_eq!(gate.gate_name, "Test Gate");
        assert_eq!(gate.status, QualityGateStatus::Pass);
        assert!(gate.blocking);
    }
}
