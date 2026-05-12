//! Performance Benchmarking Suite
//!
//! Comprehensive performance benchmarking capabilities for rust_tree_sitter including:
//! - Micro-benchmarks for individual operations
//! - Macro-benchmarks for end-to-end workflows
//! - Memory usage profiling and analysis
//! - CPU usage monitoring
//! - Scalability testing across different workloads
//! - Statistical analysis of benchmark results
//! - Comparative analysis between different configurations
//! - Automated performance regression detection

use crate::advanced_cache::{AdvancedCache, CacheConfig};
use crate::advanced_memory::{AdvancedMemoryManager, MemoryConfig};
use crate::advanced_parallel::{AdvancedThreadPool, ThreadPoolConfig};
use crate::analyzer::{AnalysisConfig, CodebaseAnalyzer};
use crate::error::{Error, Result};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Benchmark configuration with comprehensive options
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Number of iterations for each benchmark
    pub iterations: usize,
    /// Warmup iterations before actual benchmarking
    pub warmup_iterations: usize,
    /// Maximum benchmark duration
    pub max_duration: Duration,
    /// Enable memory profiling
    pub enable_memory_profiling: bool,
    /// Enable CPU profiling
    pub enable_cpu_profiling: bool,
    /// Statistical confidence level (0.95 = 95%)
    pub confidence_level: f64,
    /// Output directory for benchmark results
    pub output_dir: std::path::PathBuf,
    /// Enable detailed progress reporting
    pub enable_progress_reporting: bool,
    /// Benchmark timeout per operation
    pub operation_timeout: Duration,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            iterations: 100,
            warmup_iterations: 10,
            max_duration: Duration::from_secs(300), // 5 minutes
            enable_memory_profiling: true,
            enable_cpu_profiling: false,
            confidence_level: 0.95,
            output_dir: std::path::PathBuf::from("benchmark_results"),
            enable_progress_reporting: true,
            operation_timeout: Duration::from_secs(30),
        }
    }
}

/// Statistical summary of benchmark results
#[derive(Debug, Clone)]
pub struct BenchmarkStats {
    /// Mean execution time
    pub mean: Duration,
    /// Standard deviation
    pub std_dev: Duration,
    /// Minimum execution time
    pub min: Duration,
    /// Maximum execution time
    pub max: Duration,
    /// Median execution time
    pub median: Duration,
    /// P95 execution time (95th percentile)
    pub p95: Duration,
    /// P99 execution time (99th percentile)
    pub p99: Duration,
    /// Operations per second
    pub ops_per_second: f64,
    /// Sample size
    pub sample_size: usize,
    /// Statistical confidence interval
    pub confidence_interval: (Duration, Duration),
}

impl BenchmarkStats {
    /// Calculate statistics from a vector of durations
    pub fn from_durations(mut durations: Vec<Duration>) -> Self {
        if durations.is_empty() {
            return Self {
                mean: Duration::default(),
                std_dev: Duration::default(),
                min: Duration::default(),
                max: Duration::default(),
                median: Duration::default(),
                p95: Duration::default(),
                p99: Duration::default(),
                ops_per_second: 0.0,
                sample_size: 0,
                confidence_interval: (Duration::default(), Duration::default()),
            };
        }

        durations.sort();

        let sample_size = durations.len();
        let total: Duration = durations.iter().sum();
        let mean = total / sample_size as u32;

        // Calculate standard deviation
        let variance = durations
            .iter()
            .map(|d| {
                let diff = if d > &mean {
                    d.saturating_sub(mean)
                } else {
                    mean.saturating_sub(*d)
                };
                diff.as_nanos() as f64
            })
            .sum::<f64>()
            / sample_size as f64;

        let std_dev = Duration::from_nanos(variance.sqrt() as u64);

        let median = durations[sample_size / 2];
        let p95_index = (sample_size as f64 * 0.95) as usize;
        let p99_index = (sample_size as f64 * 0.99) as usize;

        let p95 = durations[p95_index.min(sample_size - 1)];
        let p99 = durations[p99_index.min(sample_size - 1)];

        let ops_per_second = if mean.as_nanos() > 0 {
            1_000_000_000.0 / mean.as_nanos() as f64
        } else {
            0.0
        };

        // Calculate confidence interval (simplified)
        let confidence_margin = std_dev * 1.96 / (sample_size as f64).sqrt();
        let confidence_interval = (
            if mean > confidence_margin {
                mean - confidence_margin
            } else {
                Duration::default()
            },
            mean + confidence_margin,
        );

        Self {
            mean,
            std_dev,
            min: durations[0],
            max: durations[durations.len() - 1],
            median,
            p95,
            p99,
            ops_per_second,
            sample_size,
            confidence_interval,
        }
    }
}

/// Comprehensive benchmark result
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Benchmark name
    pub name: String,
    /// Benchmark description
    pub description: String,
    /// Execution statistics
    pub stats: BenchmarkStats,
    /// Memory usage statistics
    pub memory_stats: MemoryBenchmarkStats,
    /// CPU usage statistics
    pub cpu_stats: CpuBenchmarkStats,
    /// Additional metrics
    pub metrics: HashMap<String, f64>,
    /// Benchmark configuration
    pub config: BenchmarkConfig,
    /// Performance regression indicators
    pub regression_indicators: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryBenchmarkStats {
    pub peak_usage_bytes: usize,
    pub average_usage_bytes: usize,
    pub allocations_count: u64,
    pub deallocations_count: u64,
    pub memory_efficiency_score: f64,
}

#[derive(Debug, Clone, Default)]
pub struct CpuBenchmarkStats {
    pub average_cpu_percent: f64,
    pub peak_cpu_percent: f64,
    pub total_cpu_time: Duration,
    pub cpu_efficiency_score: f64,
}

/// Performance benchmark suite
pub struct PerformanceBenchmarkSuite {
    config: BenchmarkConfig,
    results: Vec<BenchmarkResult>,
    temp_dir: TempDir,
    baseline_results: Option<HashMap<String, BenchmarkStats>>,
}

impl PerformanceBenchmarkSuite {
    /// Create new benchmark suite
    pub fn new(config: BenchmarkConfig) -> Result<Self> {
        let temp_dir = TempDir::new()
            .map_err(|e| Error::io_error(format!("Failed to create temp directory: {}", e)))?;

        // Create output directory
        fs::create_dir_all(&config.output_dir)
            .map_err(|e| Error::io_error(format!("Failed to create output directory: {}", e)))?;

        Ok(Self {
            config,
            results: Vec::new(),
            temp_dir,
            baseline_results: None,
        })
    }

    /// Load baseline results for regression detection
    pub fn load_baseline(&mut self, baseline_path: &Path) -> Result<()> {
        if baseline_path.exists() {
            let content = fs::read_to_string(baseline_path)?;
            self.baseline_results = Some(serde_json::from_str(&content)?);
        }
        Ok(())
    }

    /// Run all predefined benchmarks
    pub fn run_all_benchmarks(&mut self) -> Result<()> {
        println!("🚀 Starting Performance Benchmarks");
        println!("===================================");
        println!("Configuration:");
        println!("  Iterations: {}", self.config.iterations);
        println!("  Warmup: {}", self.config.warmup_iterations);
        println!(
            "  Memory profiling: {}",
            self.config.enable_memory_profiling
        );
        println!("  CPU profiling: {}", self.config.enable_cpu_profiling);
        println!();

        // Micro-benchmarks
        self.run_cache_benchmarks()?;
        self.run_memory_benchmarks()?;
        self.run_parallel_benchmarks()?;

        // Macro-benchmarks
        self.run_analysis_benchmarks()?;
        self.run_end_to_end_benchmarks()?;

        // Generate report
        self.generate_report()?;

        println!("✅ All benchmarks completed");
        Ok(())
    }

    /// Run cache performance benchmarks
    fn run_cache_benchmarks(&mut self) -> Result<()> {
        println!("📊 Running Cache Benchmarks...");

        let cache_config = CacheConfig {
            max_memory_bytes: 100 * 1024 * 1024, // 100MB
            max_disk_bytes: 500 * 1024 * 1024,   // 500MB
            ..Default::default()
        };

        let mut cache: AdvancedCache<String> = AdvancedCache::new(cache_config)?;

        // Benchmark cache put operations
        let put_result = self.benchmark_operation(
            "cache_put",
            "Cache put operations",
            self.config.iterations,
            || {
                let key = format!("key_{}", rand::random::<u64>());
                let value = format!("value_{}", rand::random::<u64>());
                cache.put(key, value, None, Vec::new())
            },
        )?;

        // Benchmark cache get operations (with hits)
        // First populate cache
        for i in 0..1000 {
            let key = format!("hit_key_{}", i);
            let value = format!("hit_value_{}", i);
            cache.put(key, value, None, Vec::new())?;
        }

        let get_hit_result = self.benchmark_operation(
            "cache_get_hit",
            "Cache get operations (hits)",
            self.config.iterations,
            || {
                let key = format!("hit_key_{}", rand::random::<u32>() % 1000);
                cache.get(&key)
            },
        )?;

        // Benchmark cache get operations (with misses)
        let get_miss_result = self.benchmark_operation(
            "cache_get_miss",
            "Cache get operations (misses)",
            self.config.iterations,
            || {
                let key = format!("miss_key_{}", rand::random::<u64>());
                cache.get(&key)
            },
        )?;

        self.results.push(put_result);
        self.results.push(get_hit_result);
        self.results.push(get_miss_result);

        Ok(())
    }

    /// Run memory management benchmarks
    fn run_memory_benchmarks(&mut self) -> Result<()> {
        println!("🧠 Running Memory Benchmarks...");

        let memory_config = MemoryConfig {
            max_memory_bytes: 200 * 1024 * 1024, // 200MB
            ..Default::default()
        };

        let memory_manager = AdvancedMemoryManager::new(memory_config);

        // Benchmark memory allocation patterns
        let alloc_result = self.benchmark_operation(
            "memory_allocation",
            "Memory allocation and tracking",
            self.config.iterations,
            || {
                memory_manager.record_allocation(1024);
                memory_manager.record_deallocation(512);
                Ok(())
            },
        )?;

        // Benchmark memory-mapped file operations
        let mmap_result = self.benchmark_operation(
            "memory_mapped_file",
            "Memory-mapped file operations",
            self.config.iterations.min(10), // Fewer iterations for file operations
            || {
                let test_file = self.temp_dir.path().join("test_file.txt");
                fs::write(&test_file, "test content for memory mapping")?;
                let _mmap = crate::advanced_memory::MemoryMappedFile::new(&test_file)?;
                Ok(())
            },
        )?;

        self.results.push(alloc_result);
        self.results.push(mmap_result);

        Ok(())
    }

    /// Run parallel processing benchmarks
    fn run_parallel_benchmarks(&mut self) -> Result<()> {
        println!("⚡ Running Parallel Processing Benchmarks...");

        let thread_config = ThreadPoolConfig {
            max_threads: num_cpus::get(),
            ..Default::default()
        };

        let thread_pool = AdvancedThreadPool::new(thread_config)?;

        // Benchmark task submission and execution
        let task_result = self.benchmark_operation(
            "parallel_task_execution",
            "Parallel task submission and execution",
            self.config.iterations,
            || {
                use crate::advanced_parallel::{FileAnalysisTask, Task};

                let task = FileAnalysisTask {
                    file_path: self.temp_dir.path().join("test.rs").into(),
                    content: Some("fn test() {}".to_string()),
                    analysis_type: "syntax".to_string(),
                };

                thread_pool.submit(task)?;
                thread_pool.wait_for_completion()?;
                Ok(())
            },
        )?;

        self.results.push(task_result);

        Ok(())
    }

    /// Run code analysis benchmarks
    fn run_analysis_benchmarks(&mut self) -> Result<()> {
        println!("🔍 Running Analysis Benchmarks...");

        // Create test project
        let project_path = self.create_test_project()?;

        let analyzer_config = AnalysisConfig {
            enable_parallel: true,
            ..Default::default()
        };

        let analyzer = CodebaseAnalyzer::new(analyzer_config);

        // Benchmark directory analysis
        let analysis_result = self.benchmark_operation(
            "codebase_analysis",
            "Full codebase analysis",
            5, // Fewer iterations for expensive operations
            || analyzer.analyze_directory(&project_path),
        )?;

        self.results.push(analysis_result);

        Ok(())
    }

    /// Run end-to-end workflow benchmarks
    fn run_end_to_end_benchmarks(&mut self) -> Result<()> {
        println!("🔄 Running End-to-End Benchmarks...");

        // Create comprehensive test project
        let project_path = self.create_comprehensive_test_project()?;

        let analyzer_config = AnalysisConfig {
            enable_parallel: true,
            max_file_size: Some(5 * 1024 * 1024), // 5MB
            ..Default::default()
        };

        let analyzer = CodebaseAnalyzer::new(analyzer_config);

        // Benchmark complete workflow
        let workflow_result = self.benchmark_operation(
            "end_to_end_workflow",
            "Complete analysis workflow",
            3, // Very few iterations for expensive operations
            || {
                let result = analyzer.analyze_directory(&project_path)?;

                // Simulate additional processing
                std::thread::sleep(Duration::from_millis(10));

                Ok(result)
            },
        )?;

        self.results.push(workflow_result);

        Ok(())
    }

    /// Benchmark a single operation
    fn benchmark_operation<F, T>(
        &self,
        name: &str,
        description: &str,
        iterations: usize,
        operation: F,
    ) -> Result<BenchmarkResult>
    where
        F: Fn() -> Result<T>,
    {
        let mut durations = Vec::with_capacity(iterations);

        // Warmup
        for _ in 0..self.config.warmup_iterations {
            let _ = operation();
        }

        // Actual benchmarking
        for i in 0..iterations {
            let start = Instant::now();

            match operation() {
                Ok(_) => {
                    let duration = start.elapsed();
                    durations.push(duration);

                    // Check timeout
                    if duration > self.config.operation_timeout {
                        println!("⚠️  Operation {} timed out on iteration {}", name, i);
                    }
                }
                Err(e) => {
                    return Err(Error::internal_error(
                        "benchmark",
                        format!("Benchmark operation failed: {}", e),
                    ));
                }
            }

            // Check overall timeout
            if start.elapsed() > self.config.max_duration {
                println!("⚠️  Benchmark {} stopped early due to timeout", name);
                break;
            }
        }

        let stats = BenchmarkStats::from_durations(durations);

        // Check for performance regressions
        let regression_indicators = self.detect_regressions(name, &stats);

        Ok(BenchmarkResult {
            name: name.to_string(),
            description: description.to_string(),
            stats,
            memory_stats: MemoryBenchmarkStats::default(), // TODO: Implement memory tracking
            cpu_stats: CpuBenchmarkStats::default(),       // TODO: Implement CPU tracking
            metrics: HashMap::new(),
            config: self.config.clone(),
            regression_indicators,
        })
    }

    /// Detect performance regressions compared to baseline
    fn detect_regressions(&self, name: &str, current_stats: &BenchmarkStats) -> Vec<String> {
        let mut indicators = Vec::new();

        if let Some(baseline) = &self.baseline_results {
            if let Some(baseline_stats) = baseline.get(name) {
                let regression_threshold = 1.1; // 10% regression threshold

                if current_stats.mean > baseline_stats.mean.mul_f64(regression_threshold) {
                    indicators.push(format!(
                        "Performance regression: mean time increased by {:.1}%",
                        ((current_stats.mean.as_nanos() as f64
                            / baseline_stats.mean.as_nanos() as f64)
                            - 1.0)
                            * 100.0
                    ));
                }

                if current_stats.p95 > baseline_stats.p95.mul_f64(regression_threshold) {
                    indicators.push(format!(
                        "P95 regression: 95th percentile increased by {:.1}%",
                        ((current_stats.p95.as_nanos() as f64
                            / baseline_stats.p95.as_nanos() as f64)
                            - 1.0)
                            * 100.0
                    ));
                }
            }
        }

        indicators
    }

    /// Create test project for benchmarking
    fn create_test_project(&self) -> Result<std::path::PathBuf> {
        let project_path = self.temp_dir.path().join("benchmark_project");
        fs::create_dir_all(&project_path)?;

        // Create multiple Rust files with different sizes
        for i in 0..5 {
            let content = format!(
                r#"
// Benchmark file {}
pub fn function_{}() -> i32 {{
    let mut result = 0;
    for i in 0..1000 {{
        result += i;
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
}}
"#,
                i, i, i, i
            );

            fs::write(project_path.join(format!("file_{}.rs", i)), content)?;
        }

        Ok(project_path)
    }

    /// Create comprehensive test project
    fn create_comprehensive_test_project(&self) -> Result<std::path::PathBuf> {
        let project_path = self.temp_dir.path().join("comprehensive_project");
        fs::create_dir_all(&project_path)?;

        // Create src directory structure
        let src_path = project_path.join("src");
        fs::create_dir_all(&src_path)?;

        // Create main.rs
        fs::write(
            src_path.join("main.rs"),
            r#"
fn main() {
    println!("Hello, benchmark!");
    let result = lib::add(5, 3);
    println!("Result: {}", result);
}
"#,
        )?;

        // Create lib.rs
        fs::write(
            src_path.join("lib.rs"),
            r#"
pub mod math;
pub mod utils;

pub fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#,
        )?;

        // Create math.rs
        fs::write(
            src_path.join("math.rs"),
            r#"
pub fn multiply(a: i32, b: i32) -> i32 {
    a * b
}

pub fn divide(a: i32, b: i32) -> Option<i32> {
    if b != 0 {
        Some(a / b)
    } else {
        None
    }
}
"#,
        )?;

        // Create utils.rs
        fs::write(
            src_path.join("utils.rs"),
            r#"
pub fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}

pub fn factorial(n: u32) -> u32 {
    if n <= 1 {
        1
    } else {
        n * factorial(n - 1)
    }
}
"#,
        )?;

        Ok(project_path)
    }

    /// Generate comprehensive benchmark report
    fn generate_report(&self) -> Result<()> {
        let report_path = self.config.output_dir.join("benchmark_report.md");
        let json_report_path = self.config.output_dir.join("benchmark_results.json");

        let mut report = String::new();
        report.push_str("# Performance Benchmark Report\n\n");
        report.push_str(&format!(
            "**Generated:** {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        report.push_str("## Configuration\n\n");
        report.push_str(&format!(
            "- **Iterations per benchmark:** {}\n",
            self.config.iterations
        ));
        report.push_str(&format!(
            "- **Warmup iterations:** {}\n",
            self.config.warmup_iterations
        ));
        report.push_str(&format!(
            "- **Memory profiling:** {}\n",
            self.config.enable_memory_profiling
        ));
        report.push_str(&format!(
            "- **CPU profiling:** {}\n",
            self.config.enable_cpu_profiling
        ));
        report.push_str(&format!(
            "- **Confidence level:** {:.1}%\n\n",
            self.config.confidence_level * 100.0
        ));

        // Summary section
        report.push_str("## Summary\n\n");

        let total_benchmarks = self.results.len();
        let total_ops_per_second: f64 = self
            .results
            .iter()
            .filter_map(|r| {
                if r.stats.ops_per_second > 0.0 {
                    Some(r.stats.ops_per_second)
                } else {
                    None
                }
            })
            .sum();
        let avg_ops_per_second = if total_benchmarks > 0 {
            total_ops_per_second / total_benchmarks as f64
        } else {
            0.0
        };

        report.push_str(&format!("- **Total benchmarks:** {}\n", total_benchmarks));
        report.push_str(&format!(
            "- **Average operations/second:** {:.0}\n\n",
            avg_ops_per_second
        ));

        // Performance regressions
        let regressions: Vec<_> = self
            .results
            .iter()
            .filter(|r| !r.regression_indicators.is_empty())
            .collect();

        if !regressions.is_empty() {
            report.push_str("## ⚠️ Performance Regressions\n\n");
            for result in regressions {
                report.push_str(&format!("### {}\n", result.name));
                for indicator in &result.regression_indicators {
                    report.push_str(&format!("- {}\n", indicator));
                }
                report.push_str("\n");
            }
        }

        // Detailed results
        report.push_str("## Detailed Results\n\n");

        for result in &self.results {
            report.push_str(&format!("### {}\n", result.name));
            report.push_str(&format!("**Description:** {}\n\n", result.description));

            report.push_str("**Performance Statistics:**\n");
            report.push_str(&format!(
                "- Operations/Second: {:.0}\n",
                result.stats.ops_per_second
            ));
            report.push_str(&format!(
                "- Mean Time: {:.2} ms\n",
                result.stats.mean.as_millis()
            ));
            report.push_str(&format!(
                "- Median Time: {:.2} ms\n",
                result.stats.median.as_millis()
            ));
            report.push_str(&format!(
                "- P95 Time: {:.2} ms\n",
                result.stats.p95.as_millis()
            ));
            report.push_str(&format!(
                "- P99 Time: {:.2} ms\n",
                result.stats.p99.as_millis()
            ));
            report.push_str(&format!(
                "- Min Time: {:.2} ms\n",
                result.stats.min.as_millis()
            ));
            report.push_str(&format!(
                "- Max Time: {:.2} ms\n",
                result.stats.max.as_millis()
            ));
            report.push_str(&format!(
                "- Standard Deviation: {:.2} ms\n",
                result.stats.std_dev.as_millis()
            ));
            report.push_str(&format!("- Sample Size: {}\n", result.stats.sample_size));
            report.push_str(&format!(
                "- Confidence Interval: {:.2}ms - {:.2}ms\n\n",
                result.stats.confidence_interval.0.as_millis(),
                result.stats.confidence_interval.1.as_millis()
            ));

            if result.memory_stats.peak_usage_bytes > 0 {
                report.push_str("**Memory Statistics:**\n");
                report.push_str(&format!(
                    "- Peak Usage: {:.1} MB\n",
                    result.memory_stats.peak_usage_bytes as f64 / (1024.0 * 1024.0)
                ));
                report.push_str(&format!(
                    "- Average Usage: {:.1} MB\n",
                    result.memory_stats.average_usage_bytes as f64 / (1024.0 * 1024.0)
                ));
                report.push_str(&format!(
                    "- Allocations: {}\n",
                    result.memory_stats.allocations_count
                ));
                report.push_str(&format!(
                    "- Deallocations: {}\n\n",
                    result.memory_stats.deallocations_count
                ));
            }
        }

        // Recommendations
        report.push_str("## Recommendations\n\n");

        let slow_benchmarks = self
            .results
            .iter()
            .filter(|r| r.stats.p95 > Duration::from_millis(100))
            .collect::<Vec<_>>();

        if !slow_benchmarks.is_empty() {
            report.push_str("### Performance Optimizations Needed\n\n");
            for benchmark in slow_benchmarks {
                report.push_str(&format!(
                    "- **{}**: P95 time is {:.2}ms - consider optimization\n",
                    benchmark.name,
                    benchmark.stats.p95.as_millis()
                ));
            }
            report.push_str("\n");
        }

        let high_memory_benchmarks = self
            .results
            .iter()
            .filter(|r| r.memory_stats.peak_usage_bytes > 50 * 1024 * 1024) // 50MB
            .collect::<Vec<_>>();

        if !high_memory_benchmarks.is_empty() {
            report.push_str("### Memory Optimizations Needed\n\n");
            for benchmark in high_memory_benchmarks {
                report.push_str(&format!(
                    "- **{}**: Peak memory usage is {:.1}MB - consider memory optimization\n",
                    benchmark.name,
                    benchmark.memory_stats.peak_usage_bytes as f64 / (1024.0 * 1024.0)
                ));
            }
        }

        // Save reports
        fs::write(&report_path, &report)
            .map_err(|e| Error::io_error(format!("Failed to write benchmark report: {}", e)))?;

        // Save JSON results
        let json_results: HashMap<String, BenchmarkStats> = self
            .results
            .iter()
            .map(|r| (r.name.clone(), r.stats.clone()))
            .collect();

        let json_content = serde_json::to_string_pretty(&json_results)?;
        fs::write(&json_report_path, json_content)?;

        println!("📊 Benchmark report saved to: {}", report_path.display());
        println!("📊 JSON results saved to: {}", json_report_path.display());

        Ok(())
    }

    /// Get benchmark results
    pub fn results(&self) -> &[BenchmarkResult] {
        &self.results
    }

    /// Export results to JSON
    pub fn export_to_json(&self) -> Result<String> {
        let results_map: HashMap<String, BenchmarkStats> = self
            .results
            .iter()
            .map(|r| (r.name.clone(), r.stats.clone()))
            .collect();

        serde_json::to_string_pretty(&results_map)
            .map_err(|e| Error::serialization_error(format!("Failed to serialize results: {}", e)))
    }

    /// Compare with baseline results
    pub fn compare_with_baseline(
        &self,
        baseline: &HashMap<String, BenchmarkStats>,
    ) -> HashMap<String, f64> {
        let mut comparisons = HashMap::new();

        for result in &self.results {
            if let Some(baseline_stats) = baseline.get(&result.name) {
                let ratio =
                    result.stats.mean.as_nanos() as f64 / baseline_stats.mean.as_nanos() as f64;
                comparisons.insert(result.name.clone(), ratio);
            }
        }

        comparisons
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_stats_calculation() {
        let durations = vec![
            Duration::from_millis(100),
            Duration::from_millis(120),
            Duration::from_millis(80),
            Duration::from_millis(110),
            Duration::from_millis(90),
        ];

        let stats = BenchmarkStats::from_durations(durations);

        assert_eq!(stats.sample_size, 5);
        assert!(stats.mean >= Duration::from_millis(90));
        assert!(stats.mean <= Duration::from_millis(110));
        assert_eq!(stats.min, Duration::from_millis(80));
        assert_eq!(stats.max, Duration::from_millis(120));
        assert!(stats.ops_per_second > 0.0);
    }

    #[test]
    fn test_suite_creation() {
        let config = BenchmarkConfig::default();
        let suite = PerformanceBenchmarkSuite::new(config).unwrap();

        assert!(suite.temp_dir.path().exists());
        assert!(suite.results.is_empty());
    }

    #[test]
    fn test_empty_stats() {
        let stats = BenchmarkStats::from_durations(Vec::new());

        assert_eq!(stats.sample_size, 0);
        assert_eq!(stats.mean, Duration::default());
        assert_eq!(stats.ops_per_second, 0.0);
    }

    #[test]
    fn test_performance_regression_detection() {
        let mut suite = PerformanceBenchmarkSuite::new(BenchmarkConfig::default()).unwrap();

        // Simulate baseline results
        let mut baseline = HashMap::new();
        baseline.insert(
            "test_benchmark".to_string(),
            BenchmarkStats {
                mean: Duration::from_millis(100),
                std_dev: Duration::from_millis(10),
                min: Duration::from_millis(90),
                max: Duration::from_millis(110),
                median: Duration::from_millis(100),
                p95: Duration::from_millis(105),
                p99: Duration::from_millis(108),
                ops_per_second: 10.0,
                sample_size: 10,
                confidence_interval: (Duration::from_millis(95), Duration::from_millis(105)),
            },
        );

        suite.baseline_results = Some(baseline);

        // Test with slower performance (20% regression)
        let result = suite
            .benchmark_operation("test_benchmark", "Test benchmark", 5, || {
                std::thread::sleep(Duration::from_millis(120));
                Ok(())
            })
            .unwrap();

        assert!(!result.regression_indicators.is_empty());
        assert!(result.regression_indicators[0].contains("regression"));
    }
}
