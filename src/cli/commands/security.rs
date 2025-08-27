//! Security command implementation
//! 
//! Provides comprehensive security vulnerability scanning with configurable output formats.

use std::path::PathBuf;
use colored::*;
use crate::{CodebaseAnalyzer, SecurityScanner};
use crate::cli::error::{CliError, CliResult, validate_path, validate_format};
use crate::cli::utils::{create_progress_bar, create_analysis_config, parse_severity, severity_meets_threshold, validate_output_path, print_success};
use crate::cli::output::OutputFormat;

/// Execute the security command
pub fn execute(
    path: &PathBuf,
    format: &str,
    min_severity: &str,
    output: Option<&PathBuf>,
    summary_only: bool,
    compliance: bool,
    depth: &str,
    // Whether to enable heavy security scanning during initial parsing
    enable_security: bool,
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
    let config = create_analysis_config(1024, 20, depth, false, None, None, None, enable_security)?;
    let mut analyzer = CodebaseAnalyzer::with_config(config)
        .map_err(|e| CliError::Security(e.to_string()))?;
    
    // Run analysis first to get file content
    pb.set_message("Analyzing codebase...");
    let analysis_result = analyzer.analyze_directory(path)
        .map_err(|e| CliError::Security(e.to_string()))?;
    
    // Run security analysis
    pb.set_message("Scanning for vulnerabilities...");
    let security_scanner = SecurityScanner::new()
        .map_err(|e| CliError::Security(e.to_string()))?;
    let security_result = security_scanner.analyze(&analysis_result)
        .map_err(|e| CliError::Security(e.to_string()))?;
    
    pb.finish_with_message("Security scan complete!");
    
    // Filter vulnerabilities by severity
    let filtered_vulnerabilities: Vec<_> = security_result.vulnerabilities
        .iter()
        .filter(|vuln| severity_meets_threshold(&severity_threshold, &vuln.severity))
        .collect();
    
    // Display results based on format
    let output_format = OutputFormat::from_str(format)
        .map_err(|e| CliError::UnsupportedFormat(e))?;
    
    match output_format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&security_result)?;
            if let Some(output_path) = output {
                std::fs::write(output_path, &json)?;
                print_success(&format!("Security report saved to {}", output_path.display()));
            } else {
                println!("{}", json);
            }
        }
        OutputFormat::Markdown => {
            print_security_markdown(&security_result, summary_only, compliance, &filtered_vulnerabilities);
            if let Some(output_path) = output {
                let markdown = render_security_markdown(&security_result, summary_only, compliance, &filtered_vulnerabilities);
                std::fs::write(output_path, markdown)?;
                print_success(&format!("Security report saved to {}", output_path.display()));
            }
        }
        OutputFormat::Table | _ => {
            print_security_table(&security_result, summary_only, compliance, &filtered_vulnerabilities);
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&security_result)?;
                std::fs::write(output_path, json)?;
                print_success(&format!("Security report saved to {}", output_path.display()));
            }
        }
    }
    
    Ok(())
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
    println!("Security Score: {}/100",
        if security_result.security_score >= 80 {
            security_result.security_score.to_string().bright_green()
        } else if security_result.security_score >= 60 {
            security_result.security_score.to_string().bright_yellow()
        } else {
            security_result.security_score.to_string().bright_red()
        }
    );
    println!("Total Vulnerabilities: {}",
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
            println!("\n{} {}",
                format!("{}.", i + 1).bright_cyan(),
                vuln.title.bright_white().bold()
            );
            println!("   Severity: {:?} | Confidence: {:?}",
                format!("{:?}", vuln.severity).bright_red(),
                format!("{:?}", vuln.confidence).bright_yellow()
            );
            println!("   Location: {}:{}",
                vuln.location.file.display().to_string().bright_blue(),
                vuln.location.start_line.to_string().bright_green()
            );
            println!("   Description: {}", vuln.description.bright_white());
            println!("   Fix: {}", vuln.remediation.summary.bright_green());
        }
    }

    if compliance {
        println!("\n{}", "📋 COMPLIANCE STATUS".bright_yellow().bold());
        println!("OWASP Score: {}/100", security_result.compliance.owasp_score);
        println!("Overall Status: {:?}", security_result.compliance.overall_status);
    }

    if !security_result.recommendations.is_empty() {
        println!("\n{}", "💡 RECOMMENDATIONS".bright_yellow().bold());
        for (i, rec) in security_result.recommendations.iter().enumerate() {
            println!("{}. {} (Priority: {:?})",
                format!("{}", i + 1).bright_cyan(),
                rec.recommendation.bright_white(),
                format!("{:?}", rec.priority).bright_yellow()
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
    println!("- **Security Score**: {}/100", security_result.security_score);
    println!("- **Total Vulnerabilities**: {}", filtered_vulnerabilities.len());

    println!("\n### Vulnerabilities by Severity\n");
    for (severity, count) in &security_result.vulnerabilities_by_severity {
        println!("- **{:?}**: {}", severity, count);
    }

    if !summary_only && !filtered_vulnerabilities.is_empty() {
        println!("\n## 🚨 Detailed Findings\n");
        for (i, vuln) in filtered_vulnerabilities.iter().enumerate() {
            println!("### {}. {}\n", i + 1, vuln.title);
            println!("- **Severity**: {:?}", vuln.severity);
            println!("- **Location**: `{}:{}`", vuln.location.file.display(), vuln.location.start_line);
            println!("- **Description**: {}", vuln.description);
            println!("- **Fix**: {}\n", vuln.remediation.summary);
        }
    }

    if compliance {
        println!("## 📋 Compliance Status\n");
        println!("- **OWASP Score**: {}/100", security_result.compliance.owasp_score);
        println!("- **Overall Status**: {:?}\n", security_result.compliance.overall_status);
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
    writeln!(out, "- **Security Score**: {}/100", security_result.security_score).unwrap();
    writeln!(out, "- **Total Vulnerabilities**: {}", filtered_vulnerabilities.len()).unwrap();

    writeln!(out, "\n### Vulnerabilities by Severity\n").unwrap();
    for (severity, count) in &security_result.vulnerabilities_by_severity {
        writeln!(out, "- **{:?}**: {}", severity, count).unwrap();
    }

    if !summary_only && !filtered_vulnerabilities.is_empty() {
        writeln!(out, "\n## 🚨 Detailed Findings\n").unwrap();
        for (i, vuln) in filtered_vulnerabilities.iter().enumerate() {
            writeln!(out, "### {}. {}\n", i + 1, vuln.title).unwrap();
            writeln!(out, "- **Severity**: {:?}", vuln.severity).unwrap();
            writeln!(out, "- **Location**: `{}:{}`", vuln.location.file.display(), vuln.location.start_line).unwrap();
            writeln!(out, "- **Description**: {}", vuln.description).unwrap();
            writeln!(out, "- **Fix**: {}\n", vuln.remediation.summary).unwrap();
        }
    }

    if compliance {
        writeln!(out, "## 📋 Compliance Status\n").unwrap();
        writeln!(out, "- **OWASP Score**: {}/100", security_result.compliance.owasp_score).unwrap();
        writeln!(out, "- **Overall Status**: {:?}\n", security_result.compliance.overall_status).unwrap();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_security_command_validation() {
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
        );
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_security_command_invalid_severity() {
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
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CliError::InvalidArgs(_)));
    }
}
