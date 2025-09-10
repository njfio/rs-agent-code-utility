//! Security command implementation
//!
//! Provides comprehensive security vulnerability scanning with configurable output formats.

use crate::ai::AIServiceBuilder;
use crate::cli::error::{validate_format, validate_path, CliError, CliResult};
use crate::cli::output::OutputFormat;
use crate::cli::utils::{
    create_analysis_config, create_progress_bar, parse_severity, print_success,
    severity_meets_threshold, validate_output_path,
};
use crate::security::{AstSecurityAnalyzer, MLFalsePositiveFilter};
use crate::{CodebaseAnalyzer, SecurityScanner};
use colored::*;
use std::path::PathBuf;
use std::sync::Arc;

/// Execute the security command
pub async fn execute(
    path: &PathBuf,
    format: &str,
    min_severity: &str,
    output: Option<&PathBuf>,
    summary_only: bool,
    compliance: bool,
    depth: &str,
    // Whether to enable heavy security scanning during initial parsing
    enable_security: bool,
    include_tests: bool,
    include_examples: bool,
    include_non_code: bool,
) -> CliResult<()> {
    // Validate inputs
    validate_path(path)?;
    validate_format(format, &["table", "json", "markdown"])?;
    let severity_threshold = parse_severity(min_severity)?;

    if let Some(output_path) = output {
        validate_output_path(output_path)?;
    }

    // Create progress bar
    let pb = create_progress_bar("Running security scan...");

    // Configure analyzer
    let mut config = create_analysis_config(1024, 20, depth, false, None, None, None, enable_security)?;

    // Epic 2: Source scoping and defaults (security-focused)
    // Exclude non-code and ancillary directories by default
    if !include_tests {
        for d in ["tests", "test", "spec", "specs"] {
            if !config.exclude_dirs.contains(&d.to_string()) {
                config.exclude_dirs.push(d.to_string());
            }
        }
    }
    if !include_examples {
        for d in ["examples", "example", "demo", "demos"] {
            if !config.exclude_dirs.contains(&d.to_string()) {
                config.exclude_dirs.push(d.to_string());
            }
        }
    }
    // Always ignore infra metadata
    for d in [".github", "cache"] {
        if !config.exclude_dirs.contains(&d.to_string()) {
            config.exclude_dirs.push(d.to_string());
        }
    }
    // Exclude docs and markdown by default unless explicitly included
    if !include_non_code {
        if !config.exclude_dirs.contains(&"docs".to_string()) {
            config.exclude_dirs.push("docs".to_string());
        }
        for ext in ["md", "markdown"] {
            if !config.exclude_extensions.contains(&ext.to_string()) {
                config.exclude_extensions.push(ext.to_string());
            }
        }
    }
    let mut analyzer =
        CodebaseAnalyzer::with_config(config).map_err(|e| CliError::Security(e.to_string()))?;

    // Run analysis first to get file content
    pb.set_message("Analyzing codebase...");
    let analysis_result = analyzer
        .analyze_directory(path)
        .map_err(|e| CliError::Security(e.to_string()))?;

    // Filter out paths/files that slipped through directory-level excludes
    let filtered_analysis_result = filter_analysis_result(
        analysis_result,
        include_tests,
        include_examples,
        include_non_code,
    );

    // Run security analysis
    pb.set_message("Scanning for vulnerabilities...");

    // Create AI-powered security scanner with false positive filtering
    pb.set_message("Initializing AI security scanner...");

    let ai_service = Arc::new(
        AIServiceBuilder::new()
            .with_mock_providers(true) // Use mock for CLI to avoid API keys
            .build()
            .await
            .map_err(|e| CliError::Security(format!("Failed to initialize AI service: {}", e)))?,
    );

    let ml_filter = Arc::new(MLFalsePositiveFilter::new());
    let ast_analyzer = Arc::new(
        AstSecurityAnalyzer::new()
            .map_err(|e| CliError::Security(format!("Failed to create AST analyzer: {}", e)))?,
    );

    let security_scanner = SecurityScanner::with_ai_filtering(ai_service, ml_filter, ast_analyzer)
        .await
        .map_err(|e| CliError::Security(format!("Failed to create AI security scanner: {}", e)))?;

    pb.set_message("Running AI-powered security analysis...");
    let security_result = security_scanner
        .analyze(&filtered_analysis_result)
        .map_err(|e| CliError::Security(e.to_string()))?;

    pb.finish_with_message("Security scan complete!");

    // Filter vulnerabilities by severity
    let filtered_vulnerabilities: Vec<_> = security_result
        .vulnerabilities
        .iter()
        .filter(|vuln| severity_meets_threshold(&severity_threshold, &vuln.severity))
        .collect();

    // Display results based on format
    let output_format =
        OutputFormat::from_str(format).map_err(|e| CliError::UnsupportedFormat(e))?;

    match output_format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&security_result)?;
            if let Some(output_path) = output {
                std::fs::write(output_path, &json)?;
                print_success(&format!(
                    "Security report saved to {}",
                    output_path.display()
                ));
            } else {
                println!("{}", json);
            }
        }
        OutputFormat::Markdown => {
            print_security_markdown(
                &security_result,
                summary_only,
                compliance,
                &filtered_vulnerabilities,
            );
            if let Some(output_path) = output {
                let markdown = render_security_markdown(
                    &security_result,
                    summary_only,
                    compliance,
                    &filtered_vulnerabilities,
                );
                std::fs::write(output_path, markdown)?;
                print_success(&format!(
                    "Security report saved to {}",
                    output_path.display()
                ));
            }
        }
        OutputFormat::Table | _ => {
            print_security_table(
                &security_result,
                summary_only,
                compliance,
                &filtered_vulnerabilities,
            );
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&security_result)?;
                std::fs::write(output_path, json)?;
                print_success(&format!(
                    "Security report saved to {}",
                    output_path.display()
                ));
            }
        }
    }

    Ok(())
}

fn filter_analysis_result(
    mut result: crate::AnalysisResult,
    include_tests: bool,
    include_examples: bool,
    include_non_code: bool,
) -> crate::AnalysisResult {
    let mut files = Vec::with_capacity(result.files.len());
    let mut total_lines = 0usize;
    let mut parsed_files = 0usize;
    let mut error_files = 0usize;
    use std::collections::HashMap;
    let mut languages: HashMap<String, usize> = HashMap::new();

    for f in result.files.into_iter() {
        let path_str = f.path.to_string_lossy().to_lowercase();
        let fname = f
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let ext = f
            .path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Tests filtering
        if !include_tests {
            if path_str.contains("/tests/")
                || fname.starts_with("test_")
                || fname.ends_with("_test.rs")
                || path_str.contains("/spec/")
                || path_str.contains("/specs/")
            {
                continue;
            }
        }
        // Examples/demo filtering
        if !include_examples {
            if path_str.contains("/examples/")
                || path_str.contains("/example/")
                || path_str.contains("/demo/")
                || path_str.contains("/demos/")
            {
                continue;
            }
        }
        // Non-code filtering
        if !include_non_code {
            if path_str.contains("/docs/") || ext == "md" || ext == "markdown" {
                continue;
            }
        }

        total_lines += f.lines;
        if f.parsed_successfully {
            parsed_files += 1;
        }
        if !f.parse_errors.is_empty() {
            error_files += 1;
        }
        *languages.entry(f.language.clone()).or_insert(0) += 1;
        files.push(f);
    }

    result.total_files = files.len();
    result.parsed_files = parsed_files;
    result.error_files = error_files;
    result.total_lines = total_lines;
    result.languages = languages;
    result.files = files;
    result.sort_stable();
    result
}

fn print_security_table(
    security_result: &crate::SecurityScanResult,
    summary_only: bool,
    compliance: bool,
    filtered_vulnerabilities: &[&crate::SecurityVulnerability],
) {
    println!("\n{}", "🔍 SECURITY SCAN RESULTS".bright_red().bold());
    println!("{}", "=".repeat(60).bright_red());

    println!("\n{}", "📊 SUMMARY".bright_yellow().bold());
    println!(
        "Security Score: {}/100",
        if security_result.security_score >= 80 {
            security_result.security_score.to_string().bright_green()
        } else if security_result.security_score >= 60 {
            security_result.security_score.to_string().bright_yellow()
        } else {
            security_result.security_score.to_string().bright_red()
        }
    );
    println!(
        "Total Vulnerabilities: {}",
        if filtered_vulnerabilities.is_empty() {
            filtered_vulnerabilities.len().to_string().bright_green()
        } else {
            filtered_vulnerabilities.len().to_string().bright_red()
        }
    );

    // Show vulnerabilities by severity
    println!("\n{}", "🚨 BY SEVERITY".bright_yellow().bold());
    for (severity, count) in &security_result.vulnerabilities_by_severity {
        let color = match severity {
            crate::SecuritySeverity::Critical => "bright_red",
            crate::SecuritySeverity::High => "red",
            crate::SecuritySeverity::Medium => "yellow",
            crate::SecuritySeverity::Low => "blue",
            crate::SecuritySeverity::Info => "bright_black",
        };
        println!("  {:?}: {}", severity, count.to_string().color(color));
    }

    if !summary_only && !filtered_vulnerabilities.is_empty() {
        println!("\n{}", "🔍 VULNERABILITIES FOUND".bright_yellow().bold());
        for (i, vuln) in filtered_vulnerabilities.iter().enumerate() {
            println!(
                "\n{} {}",
                format!("{}.", i + 1).bright_cyan(),
                vuln.title.bright_white().bold()
            );
            let sev = format!("{:?}", vuln.severity).bright_red();
            let conf = format!("{:?}", vuln.confidence).bright_yellow();
            println!(
                "   Severity: {} | Confidence: {}",
                sev,
                conf
            );
            println!(
                "   Location: {}:{}",
                vuln.location.file.display().to_string().bright_blue(),
                vuln.location.start_line.to_string().bright_green()
            );
            println!("   Description: {}", vuln.description.bright_white());
            println!("   Fix: {}", vuln.remediation.summary.bright_green());
        }
    }

    if compliance {
        println!("\n{}", "📋 COMPLIANCE STATUS".bright_yellow().bold());
        println!(
            "OWASP Score: {}/100",
            security_result.compliance.owasp_score
        );
        println!(
            "Overall Status: {}",
            format!("{:?}", security_result.compliance.overall_status)
        );
    }

    if !security_result.recommendations.is_empty() {
        println!("\n{}", "💡 RECOMMENDATIONS".bright_yellow().bold());
        for (i, rec) in security_result.recommendations.iter().enumerate() {
            let prio = format!("{:?}", rec.priority).bright_yellow();
            println!(
                "{}. {} (Priority: {})",
                format!("{}", i + 1).bright_cyan(),
                rec.recommendation.bright_white(),
                prio
            );
        }
    }
}

fn print_security_markdown(
    security_result: &crate::SecurityScanResult,
    summary_only: bool,
    compliance: bool,
    filtered_vulnerabilities: &[&crate::SecurityVulnerability],
) {
    println!("# 🔍 Security Scan Report\n");

    println!("## 📊 Executive Summary\n");
    println!(
        "- **Security Score**: {}/100",
        security_result.security_score
    );
    println!(
        "- **Total Vulnerabilities**: {}",
        filtered_vulnerabilities.len()
    );

    println!("\n### Vulnerabilities by Severity\n");
    for (severity, count) in &security_result.vulnerabilities_by_severity {
        println!("- **{:?}**: {}", severity, count);
    }

    if !summary_only && !filtered_vulnerabilities.is_empty() {
        println!("\n## 🚨 Detailed Findings\n");
        for (i, vuln) in filtered_vulnerabilities.iter().enumerate() {
            println!("### {}. {}\n", i + 1, vuln.title);
            println!("- **Severity**: {:?}", vuln.severity);
            println!(
                "- **Location**: `{}:{}`",
                vuln.location.file.display(),
                vuln.location.start_line
            );
            println!("- **Description**: {}", vuln.description);
            println!("- **Fix**: {}\n", vuln.remediation.summary);
        }
    }

    if compliance {
        println!("## 📋 Compliance Status\n");
        println!(
            "- **OWASP Score**: {}/100",
            security_result.compliance.owasp_score
        );
        println!(
            "- **Overall Status**: {:?}\n",
            security_result.compliance.overall_status
        );
    }
}

fn render_security_markdown(
    security_result: &crate::SecurityScanResult,
    summary_only: bool,
    compliance: bool,
    filtered_vulnerabilities: &[&crate::SecurityVulnerability],
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    writeln!(out, "# 🔍 Security Scan Report\n").unwrap();

    writeln!(out, "## 📊 Executive Summary\n").unwrap();
    writeln!(
        out,
        "- **Security Score**: {}/100",
        security_result.security_score
    )
    .unwrap();
    writeln!(
        out,
        "- **Total Vulnerabilities**: {}",
        filtered_vulnerabilities.len()
    )
    .unwrap();

    writeln!(out, "\n### Vulnerabilities by Severity\n").unwrap();
    for (severity, count) in &security_result.vulnerabilities_by_severity {
        writeln!(out, "- **{:?}**: {}", severity, count).unwrap();
    }

    if !summary_only && !filtered_vulnerabilities.is_empty() {
        writeln!(out, "\n## 🚨 Detailed Findings\n").unwrap();
        for (i, vuln) in filtered_vulnerabilities.iter().enumerate() {
            writeln!(out, "### {}. {}\n", i + 1, vuln.title).unwrap();
            writeln!(out, "- **Severity**: {:?}", vuln.severity).unwrap();
            writeln!(
                out,
                "- **Location**: `{}:{}`",
                vuln.location.file.display(),
                vuln.location.start_line
            )
            .unwrap();
            writeln!(out, "- **Description**: {}", vuln.description).unwrap();
            writeln!(out, "- **Fix**: {}\n", vuln.remediation.summary).unwrap();
        }
    }

    if compliance {
        writeln!(out, "## 📋 Compliance Status\n").unwrap();
        writeln!(
            out,
            "- **OWASP Score**: {}/100",
            security_result.compliance.owasp_score
        )
        .unwrap();
        writeln!(
            out,
            "- **Overall Status**: {:?}\n",
            security_result.compliance.overall_status
        )
        .unwrap();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_security_command_validation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let result = execute(
            &path,
            "table",
            "low",
            None,
            false,
            false,
            "full",
            false, // enable_security
            false, // include_tests
            false, // include_examples
            false, // include_non_code
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_security_command_invalid_severity() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let result = execute(
            &path,
            "table",
            "invalid_severity",
            None,
            false,
            false,
            "full",
            false, // enable_security
            false,
            false,
            false,
        )
        .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CliError::InvalidArgs(_)));
    }
}
