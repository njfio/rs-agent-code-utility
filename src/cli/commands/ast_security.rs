//! AST-based security analysis command implementation
//!
//! Provides intelligent security vulnerability scanning using AST parsing
//! and semantic analysis to reduce false positives and improve accuracy.

use crate::cli::error::{validate_format, validate_path, CliError, CliResult};
use crate::cli::output::OutputFormat;
use crate::cli::utils::{
    ast_severity_meets_threshold, create_progress_bar, parse_ast_severity, print_success,
    validate_output_path,
};
use crate::languages::Language;
use crate::security::ast_analyzer::{AstSecurityAnalyzer, SecurityFinding, SecuritySeverity};
use colored::*;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, warn};

/// Execute the AST-based security command
pub async fn execute(
    path: &PathBuf,
    format: &str,
    min_severity: &str,
    output: Option<&PathBuf>,
    summary_only: bool,
    language_filter: Option<&str>,
    include_tests: bool,
    include_examples: bool,
) -> CliResult<()> {
    // Validate inputs
    validate_path(path)?;
    validate_format(format, &["table", "json", "markdown", "sarif"])?;
    let severity_threshold = parse_ast_severity(min_severity)?;

    if let Some(output_path) = output {
        validate_output_path(output_path)?;
    }

    // Parse language filter
    let language_filter = if let Some(lang_str) = language_filter {
        Some(
            lang_str
                .parse::<Language>()
                .map_err(|_| CliError::InvalidArgs(format!("Invalid language: {}", lang_str)))?,
        )
    } else {
        None
    };

    // Create progress bar
    let pb = create_progress_bar("Running AST-based security analysis...");

    // Initialize AST-based security analyzer
    pb.set_message("Initializing AST analyzer...");
    let analyzer = AstSecurityAnalyzer::new()
        .map_err(|e| CliError::Security(format!("Failed to initialize AST analyzer: {}", e)))?;

    // Discover files to analyze
    pb.set_message("Discovering source files...");
    let files_to_analyze = discover_files(path, language_filter, include_tests, include_examples)?;

    if files_to_analyze.is_empty() {
        pb.finish_with_message("No files found to analyze");
        println!(
            "{}",
            "No source files found matching criteria.".bright_yellow()
        );
        return Ok(());
    }

    info!("Found {} files to analyze", files_to_analyze.len());

    // Analyze files
    pb.set_message("Analyzing files with AST parsing...");
    let mut all_findings = Vec::new();
    let mut analyzed_files = 0;
    let mut failed_files = 0;

    for (file_path, language) in &files_to_analyze {
        pb.set_message(format!("Analyzing {}...", file_path.display()));

        match analyzer.analyze_file(file_path, *language).await {
            Ok(mut findings) => {
                // Filter by severity
                findings.retain(|f| ast_severity_meets_threshold(&severity_threshold, &f.severity));
                all_findings.append(&mut findings);
                analyzed_files += 1;
            }
            Err(e) => {
                warn!("Failed to analyze {}: {}", file_path.display(), e);
                failed_files += 1;
            }
        }
    }

    pb.finish_with_message(format!(
        "Analysis complete! Analyzed {} files, {} findings",
        analyzed_files,
        all_findings.len()
    ));

    // Sort findings by severity and file
    all_findings.sort_by(|a, b| match b.severity.cmp(&a.severity) {
        std::cmp::Ordering::Equal => a.file_path.cmp(&b.file_path),
        other => other,
    });

    // Display results based on format
    let output_format =
        OutputFormat::from_str(format).map_err(|e| CliError::UnsupportedFormat(e))?;

    match output_format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&all_findings)?;
            if let Some(output_path) = output {
                std::fs::write(output_path, &json)?;
                print_success(&format!(
                    "AST security report saved to {}",
                    output_path.display()
                ));
            } else {
                println!("{}", json);
            }
        }
        OutputFormat::Sarif => {
            let sarif = generate_sarif_report(&all_findings, path)?;
            if let Some(output_path) = output {
                std::fs::write(output_path, &sarif)?;
                print_success(&format!(
                    "SARIF security report saved to {}",
                    output_path.display()
                ));
            } else {
                println!("{}", sarif);
            }
        }
        OutputFormat::Markdown => {
            print_ast_security_markdown(&all_findings, summary_only, analyzed_files, failed_files);
            if let Some(output_path) = output {
                let markdown = render_ast_security_markdown(
                    &all_findings,
                    summary_only,
                    analyzed_files,
                    failed_files,
                );
                std::fs::write(output_path, markdown)?;
                print_success(&format!(
                    "AST security report saved to {}",
                    output_path.display()
                ));
            }
        }
        OutputFormat::Table | _ => {
            print_ast_security_table(&all_findings, summary_only, analyzed_files, failed_files);
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&all_findings)?;
                std::fs::write(output_path, json)?;
                print_success(&format!(
                    "AST security report saved to {}",
                    output_path.display()
                ));
            }
        }
    }

    // Print summary statistics
    print_security_summary(&all_findings, analyzed_files, failed_files);

    Ok(())
}

/// Discover files to analyze based on criteria
fn discover_files(
    path: &PathBuf,
    language_filter: Option<Language>,
    include_tests: bool,
    include_examples: bool,
) -> CliResult<Vec<(PathBuf, Language)>> {
    let mut files = Vec::new();

    fn is_hidden_or_ignored(entry: &walkdir::DirEntry) -> bool {
        entry
            .file_name()
            .to_str()
            .map_or(false, |s| s.starts_with('.'))
            || entry.path().components().any(|c| {
                c.as_os_str().to_str().map_or(false, |s| {
                    s == "target" || s == "node_modules" || s == "__pycache__" || s == ".git"
                })
            })
    }

    fn should_skip_file(
        entry: &walkdir::DirEntry,
        include_tests: bool,
        include_examples: bool,
    ) -> bool {
        let file_name = entry.file_name().to_str().unwrap_or("");

        // Skip test files if not requested
        if !include_tests && (file_name.contains("test") || file_name.contains("spec")) {
            return true;
        }

        // Skip example files if not requested
        if !include_examples
            && (file_name.contains("example")
                || file_name.contains("demo")
                || file_name.contains("sample"))
        {
            return true;
        }

        false
    }

    for entry in walkdir::WalkDir::new(path)
        .into_iter()
        .filter_entry(|e| !is_hidden_or_ignored(e))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        if should_skip_file(&entry, include_tests, include_examples) {
            continue;
        }

        if let Some(language) = crate::languages::detect_language_from_path(entry.path()) {
            if language_filter.is_none() || language_filter == Some(language) {
                files.push((entry.path().to_path_buf(), language));
            }
        }
    }

    Ok(files)
}

/// Print AST security results in table format
fn print_ast_security_table(
    findings: &[SecurityFinding],
    summary_only: bool,
    analyzed_files: usize,
    failed_files: usize,
) {
    println!(
        "\n{}",
        "🔍 AST-BASED SECURITY ANALYSIS".bright_green().bold()
    );
    println!("{}", "=".repeat(80).bright_green());

    println!("\n{}", "📊 ANALYSIS SUMMARY".bright_yellow().bold());
    println!(
        "Files Analyzed: {}",
        analyzed_files.to_string().bright_green()
    );
    println!("Files Failed: {}", failed_files.to_string().bright_red());
    println!(
        "Total Findings: {}",
        findings.len().to_string().bright_cyan()
    );

    // Group findings by severity
    let mut severity_counts = HashMap::new();
    for finding in findings {
        *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
    }

    println!("\n{}", "🚨 FINDINGS BY SEVERITY".bright_yellow().bold());
    for severity in &[
        SecuritySeverity::Critical,
        SecuritySeverity::High,
        SecuritySeverity::Medium,
        SecuritySeverity::Low,
        SecuritySeverity::Info,
    ] {
        let count = severity_counts.get(severity).copied().unwrap_or(0);
        let color = match severity {
            SecuritySeverity::Critical => "bright_red",
            SecuritySeverity::High => "red",
            SecuritySeverity::Medium => "yellow",
            SecuritySeverity::Low => "blue",
            SecuritySeverity::Info => "bright_black",
        };
        println!("  {:?}: {}", severity, count.to_string().color(color));
    }

    if !summary_only && !findings.is_empty() {
        println!("\n{}", "🔍 DETAILED FINDINGS".bright_yellow().bold());
        for (i, finding) in findings.iter().enumerate() {
            println!(
                "\n{} {}",
                format!("{}.", i + 1).bright_cyan(),
                finding.title.bright_white().bold()
            );

            let severity_color = match finding.severity {
                SecuritySeverity::Critical => "bright_red",
                SecuritySeverity::High => "red",
                SecuritySeverity::Medium => "yellow",
                SecuritySeverity::Low => "blue",
                SecuritySeverity::Info => "bright_black",
            };

            println!(
                "   Severity: {} | Confidence: {:.1}% | CWE: {}",
                format!("{:?}", finding.severity).color(severity_color),
                (finding.confidence * 100.0).round(),
                finding.cwe_id.as_deref().unwrap_or("N/A").bright_blue()
            );

            println!(
                "   Location: {}:{}",
                finding.file_path.bright_blue(),
                finding.line_number.to_string().bright_green()
            );

            println!("   Description: {}", finding.description.bright_white());

            if !finding.code_snippet.is_empty() {
                println!("   Code: {}", finding.code_snippet.bright_black());
            }

            println!("   Fix: {}", finding.remediation.bright_green());
        }
    }
}

/// Print AST security results in markdown format
fn print_ast_security_markdown(
    findings: &[SecurityFinding],
    summary_only: bool,
    analyzed_files: usize,
    failed_files: usize,
) {
    println!("# 🔍 AST-Based Security Analysis Report\n");

    println!("## 📊 Executive Summary\n");
    println!("- **Files Analyzed**: {}", analyzed_files);
    println!("- **Files Failed**: {}", failed_files);
    println!("- **Total Findings**: {}", findings.len());

    // Group findings by severity
    let mut severity_counts = HashMap::new();
    for finding in findings {
        *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
    }

    println!("\n### Findings by Severity\n");
    for severity in &[
        SecuritySeverity::Critical,
        SecuritySeverity::High,
        SecuritySeverity::Medium,
        SecuritySeverity::Low,
        SecuritySeverity::Info,
    ] {
        let count = severity_counts.get(severity).copied().unwrap_or(0);
        println!("- **{:?}**: {}", severity, count);
    }

    if !summary_only && !findings.is_empty() {
        println!("\n## 🚨 Detailed Findings\n");
        for (i, finding) in findings.iter().enumerate() {
            println!("### {}. {}\n", i + 1, finding.title);
            println!("- **Severity**: {:?}", finding.severity);
            println!("- **Confidence**: {:.1}%", finding.confidence * 100.0);
            println!("- **CWE**: {}", finding.cwe_id.as_deref().unwrap_or("N/A"));
            println!(
                "- **Location**: `{}:{}`",
                finding.file_path, finding.line_number
            );
            println!("- **Description**: {}", finding.description);

            if !finding.code_snippet.is_empty() {
                println!("- **Code**:\n```rust\n{}\n```", finding.code_snippet);
            }

            println!("- **Fix**: {}\n", finding.remediation);
        }
    }
}

/// Render AST security results as markdown string
fn render_ast_security_markdown(
    findings: &[SecurityFinding],
    summary_only: bool,
    analyzed_files: usize,
    failed_files: usize,
) -> String {
    use std::fmt::Write;
    let mut out = String::new();

    writeln!(out, "# 🔍 AST-Based Security Analysis Report\n").unwrap();
    writeln!(out, "## 📊 Executive Summary\n").unwrap();
    writeln!(out, "- **Files Analyzed**: {}", analyzed_files).unwrap();
    writeln!(out, "- **Files Failed**: {}", failed_files).unwrap();
    writeln!(out, "- **Total Findings**: {}", findings.len()).unwrap();

    // Group findings by severity
    let mut severity_counts = HashMap::new();
    for finding in findings {
        *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
    }

    writeln!(out, "\n### Findings by Severity\n").unwrap();
    for severity in &[
        SecuritySeverity::Critical,
        SecuritySeverity::High,
        SecuritySeverity::Medium,
        SecuritySeverity::Low,
        SecuritySeverity::Info,
    ] {
        let count = severity_counts.get(severity).copied().unwrap_or(0);
        writeln!(out, "- **{:?}**: {}", severity, count).unwrap();
    }

    if !summary_only && !findings.is_empty() {
        writeln!(out, "\n## 🚨 Detailed Findings\n").unwrap();
        for (i, finding) in findings.iter().enumerate() {
            writeln!(out, "### {}. {}\n", i + 1, finding.title).unwrap();
            writeln!(out, "- **Severity**: {:?}", finding.severity).unwrap();
            writeln!(out, "- **Confidence**: {:.1}%", finding.confidence * 100.0).unwrap();
            writeln!(
                out,
                "- **CWE**: {}",
                finding.cwe_id.as_deref().unwrap_or("N/A")
            )
            .unwrap();
            writeln!(
                out,
                "- **Location**: `{}:{}`",
                finding.file_path, finding.line_number
            )
            .unwrap();
            writeln!(out, "- **Description**: {}", finding.description).unwrap();

            if !finding.code_snippet.is_empty() {
                writeln!(out, "- **Code**:\n```rust\n{}\n```", finding.code_snippet).unwrap();
            }

            writeln!(out, "- **Fix**: {}\n", finding.remediation).unwrap();
        }
    }

    out
}

/// Generate SARIF report for findings
fn generate_sarif_report(findings: &[SecurityFinding], root_path: &PathBuf) -> CliResult<String> {
    use serde_json::json;

    let rules: Vec<serde_json::Value> = findings
        .iter()
        .enumerate()
        .map(|(i, finding)| {
            json!({
                "id": format!("RULE_{}", i),
                "name": finding.title.clone(),
                "shortDescription": {
                    "text": finding.description.clone()
                },
                "fullDescription": {
                    "text": finding.description.clone()
                },
                "defaultConfiguration": {
                    "level": match finding.severity {
                        SecuritySeverity::Critical | SecuritySeverity::High => "error",
                        SecuritySeverity::Medium => "warning",
                        SecuritySeverity::Low | SecuritySeverity::Info => "note",
                    }
                },
                "properties": {
                    "tags": ["security"],
                    "precision": format!("{:.1}", finding.confidence * 100.0),
                    "cwe": finding.cwe_id
                }
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .enumerate()
        .map(|(i, finding)| {
            let relative_path = finding
                .file_path
                .strip_prefix(&root_path.to_string_lossy().as_ref())
                .unwrap_or(&finding.file_path)
                .to_string();

            json!({
                "ruleId": format!("RULE_{}", i),
                "ruleIndex": i,
                "level": match finding.severity {
                    SecuritySeverity::Critical | SecuritySeverity::High => "error",
                    SecuritySeverity::Medium => "warning",
                    SecuritySeverity::Low | SecuritySeverity::Info => "note",
                },
                "message": {
                    "text": finding.description.clone()
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": relative_path
                        },
                        "region": {
                            "startLine": finding.line_number,
                            "startColumn": finding.column_start,
                            "endColumn": finding.column_end
                        }
                    }
                }],
                "properties": {
                    "remediation": finding.remediation.clone(),
                    "confidence": finding.confidence
                }
            })
        })
        .collect();

    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rust_tree_sitter",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/yourusername/rust_tree_sitter",
                    "rules": rules
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "toolExecutionNotifications": []
            }]
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

/// Print security analysis summary
fn print_security_summary(
    findings: &[SecurityFinding],
    analyzed_files: usize,
    failed_files: usize,
) {
    let total_findings = findings.len();

    if total_findings == 0 {
        println!(
            "\n{}",
            "✅ No security issues found! Your code appears to be secure."
                .bright_green()
                .bold()
        );
        return;
    }

    // Calculate severity distribution
    let critical = findings
        .iter()
        .filter(|f| matches!(f.severity, SecuritySeverity::Critical))
        .count();
    let high = findings
        .iter()
        .filter(|f| matches!(f.severity, SecuritySeverity::High))
        .count();
    let medium = findings
        .iter()
        .filter(|f| matches!(f.severity, SecuritySeverity::Medium))
        .count();

    println!("\n{}", "📈 ANALYSIS SUMMARY".bright_yellow().bold());
    println!("Files Analyzed: {}", analyzed_files);
    println!("Files Failed: {}", failed_files);
    println!("Total Findings: {}", total_findings);

    if critical > 0 {
        println!(
            "Critical Issues: {} {}",
            critical.to_string().bright_red().bold(),
            "(Address immediately!)".bright_red()
        );
    }

    if high > 0 {
        println!(
            "High Severity: {} {}",
            high.to_string().red().bold(),
            "(Address soon)".red()
        );
    }

    if medium > 0 {
        println!(
            "Medium Severity: {} {}",
            medium.to_string().yellow().bold(),
            "(Address when possible)".yellow()
        );
    }

    // Average confidence
    let avg_confidence = if !findings.is_empty() {
        findings.iter().map(|f| f.confidence).sum::<f64>() / findings.len() as f64
    } else {
        0.0
    };

    println!("Average Confidence: {:.1}%", avg_confidence * 100.0);

    if failed_files > 0 {
        println!(
            "\n{}",
            format!("⚠️  {} files failed to analyze", failed_files)
                .bright_yellow()
                .bold()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_ast_security_command_validation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let result = execute(&path, "table", "low", None, false, None, false, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ast_security_command_invalid_severity() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let result = execute(
            &path,
            "table",
            "invalid_severity",
            None,
            false,
            None,
            false,
            false,
        )
        .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CliError::InvalidArgs(_)));
    }

    #[tokio::test]
    async fn test_ast_security_command_invalid_language() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let result = execute(
            &path,
            "table",
            "low",
            None,
            false,
            Some("invalid_language"),
            false,
            false,
        )
        .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CliError::InvalidArgs(_)));
    }
}
