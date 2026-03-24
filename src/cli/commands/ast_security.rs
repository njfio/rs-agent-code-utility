//! AST-based security analysis command implementation
//!
//! Provides intelligent security vulnerability scanning using AST parsing
//! and semantic analysis to reduce false positives and improve accuracy.
#![allow(
    clippy::ptr_arg,
    clippy::too_many_arguments,
    clippy::wildcard_in_or_patterns
)]

use crate::cli::error::{validate_format, validate_path, CliError, CliResult};
use crate::cli::output::OutputFormat;
use crate::cli::utils::{
    ast_severity_meets_threshold, create_progress_bar, parse_ast_severity, print_success,
    validate_output_path,
};
use crate::languages::Language;
use crate::parser::Parser;
use crate::security::ast_analyzer::{AstSecurityAnalyzer, SecurityFinding, SecuritySeverity};
use colored::*;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
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
    min_confidence: f64,
    fail_on: Option<&str>,
    baseline: Option<&PathBuf>,
    update_baseline: bool,
    max_file_kb: usize,
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
    let files_to_analyze = discover_files(
        path,
        language_filter,
        include_tests,
        include_examples,
        max_file_kb,
    )?;

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
    let mut inline_suppressed_findings = Vec::new();
    let mut analyzed_files = 0;
    let mut failed_files = 0;

    for (file_path, language) in &files_to_analyze {
        pb.set_message(format!("Analyzing {}...", file_path.display()));

        match analyzer.analyze_file(file_path, *language).await {
            Ok(mut findings) => {
                // Filter by severity and confidence
                findings.retain(|f| ast_severity_meets_threshold(&severity_threshold, &f.severity));
                if min_confidence > 0.0 {
                    findings.retain(|f| f.confidence >= min_confidence);
                }

                let inline_suppressions = match load_inline_suppressions(file_path, *language) {
                    Ok(suppressions) => suppressions,
                    Err(err) => {
                        warn!(
                            "Failed to parse inline suppressions for {}: {}",
                            file_path.display(),
                            err
                        );
                        HashMap::new()
                    }
                };

                let (mut retained_findings, mut suppressed_findings) =
                    partition_findings_by_inline_suppression(findings, &inline_suppressions);

                all_findings.append(&mut retained_findings);
                inline_suppressed_findings.append(&mut suppressed_findings);
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
    inline_suppressed_findings.sort_by(|a, b| match b.finding.severity.cmp(&a.finding.severity) {
        std::cmp::Ordering::Equal => a.finding.file_path.cmp(&b.finding.file_path),
        other => other,
    });

    // Baseline suppression (capture baseline set for SARIF)
    let mut baseline_set: Option<HashSet<String>> = None;
    if let Some(baseline_path) = baseline {
        let base = load_baseline_ast(baseline_path)?;
        baseline_set = Some(base.clone());
        all_findings.retain(|f| !base.contains(&fingerprint_ast(f)));
        if update_baseline {
            let current: HashSet<String> = all_findings.iter().map(fingerprint_ast).collect();
            save_baseline_ast(baseline_path, &current)?;
            baseline_set = Some(current); // reflect updated baseline if needed
        }
    }

    // Display results based on format
    let output_format = OutputFormat::from_str(format).map_err(CliError::UnsupportedFormat)?;

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
            let sarif = generate_sarif_report(
                &all_findings,
                &inline_suppressed_findings,
                path,
                baseline_set.as_ref(),
            )?;
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
                )?;
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

    // CI gating: fail if findings at or above threshold
    if let Some(fail_on_str) = fail_on {
        let fail_threshold = parse_ast_severity(fail_on_str)?;
        let offending = all_findings
            .iter()
            .any(|f| ast_severity_meets_threshold(&fail_threshold, &f.severity));
        if offending {
            return Err(CliError::Security(format!(
                "Failing due to findings at or above '{}'",
                fail_on_str
            )));
        }
    }

    Ok(())
}

fn fingerprint_ast(f: &crate::security::ast_analyzer::SecurityFinding) -> String {
    format!(
        "{}:{}:{}:{:?}",
        f.file_path, f.line_number, f.title, f.severity
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InlineSuppression {
    target_line: usize,
    rule_id: Option<String>,
    raw_comment: String,
}

#[derive(Debug, Clone)]
struct SuppressedFinding {
    finding: SecurityFinding,
    suppression: InlineSuppression,
}

fn load_baseline_ast(path: &PathBuf) -> CliResult<HashSet<String>> {
    use std::fs;
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let content = fs::read_to_string(path).map_err(CliError::Io)?;
    let list: Vec<String> = serde_json::from_str(&content).map_err(CliError::Json)?;
    Ok(list.into_iter().collect())
}

fn save_baseline_ast(path: &PathBuf, entries: &HashSet<String>) -> CliResult<()> {
    use std::fs;
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(CliError::Io)?;
        }
    }
    let mut v: Vec<String> = entries.iter().cloned().collect();
    v.sort();
    let data = serde_json::to_string_pretty(&v).map_err(CliError::Json)?;
    fs::write(path, data).map_err(CliError::Io)?;
    Ok(())
}

fn load_inline_suppressions(
    path: &Path,
    language: Language,
) -> CliResult<HashMap<usize, Vec<InlineSuppression>>> {
    let source = std::fs::read_to_string(path).map_err(CliError::Io)?;
    parse_inline_suppressions(&source, language)
}

fn parse_inline_suppressions(
    source: &str,
    language: Language,
) -> CliResult<HashMap<usize, Vec<InlineSuppression>>> {
    let parser = Parser::new(language)
        .map_err(|err| CliError::Security(format!("Failed to create parser: {}", err)))?;
    let tree = parser.parse(source, None).map_err(|err| {
        CliError::Security(format!("Failed to parse source for suppressions: {}", err))
    })?;

    let mut suppressions = HashMap::new();
    let mut comments = Vec::new();
    collect_comment_nodes(tree.root_node(), &mut comments);

    for comment in comments {
        let comment_text = comment
            .text()
            .map_err(|err| CliError::Security(format!("Failed to read comment text: {}", err)))?;
        if let Some(suppression) =
            parse_inline_suppression_comment(comment_text, comment.start_position().row)
        {
            suppressions
                .entry(suppression.target_line)
                .or_insert_with(Vec::new)
                .push(suppression);
        }
    }

    Ok(suppressions)
}

fn collect_comment_nodes<'a>(
    node: crate::tree::Node<'a>,
    comments: &mut Vec<crate::tree::Node<'a>>,
) {
    if node.kind().contains("comment") {
        comments.push(node);
    }

    for child in node.children() {
        collect_comment_nodes(child, comments);
    }
}

fn parse_inline_suppression_comment(
    comment_text: &str,
    comment_row: usize,
) -> Option<InlineSuppression> {
    let trimmed = comment_text.trim();
    let rest = trimmed
        .strip_prefix("//")
        .or_else(|| trimmed.strip_prefix('#'))?
        .trim_start();

    let remainder = rest.strip_prefix("rts-ignore")?.trim();
    let rule_id = if remainder.is_empty() {
        None
    } else if remainder.starts_with('[') {
        let closing = remainder.find(']')?;
        let rule = normalize_rule_id(&remainder[1..closing]);
        if rule.is_empty() {
            return None;
        }
        Some(rule)
    } else {
        return None;
    };

    Some(InlineSuppression {
        target_line: comment_row + 1,
        rule_id,
        raw_comment: trimmed.to_string(),
    })
}

fn partition_findings_by_inline_suppression(
    findings: Vec<SecurityFinding>,
    suppressions: &HashMap<usize, Vec<InlineSuppression>>,
) -> (Vec<SecurityFinding>, Vec<SuppressedFinding>) {
    if suppressions.is_empty() {
        return (findings, Vec::new());
    }

    let mut retained = Vec::new();
    let mut suppressed = Vec::new();

    for finding in findings {
        if let Some(applied_suppression) = find_matching_inline_suppression(&finding, suppressions)
        {
            suppressed.push(SuppressedFinding {
                finding,
                suppression: applied_suppression,
            });
        } else {
            retained.push(finding);
        }
    }

    (retained, suppressed)
}

fn find_matching_inline_suppression(
    finding: &SecurityFinding,
    suppressions: &HashMap<usize, Vec<InlineSuppression>>,
) -> Option<InlineSuppression> {
    let candidates = suppressions.get(&finding.line_number)?;

    candidates
        .iter()
        .find(|suppression| {
            suppression
                .rule_id
                .as_deref()
                .is_some_and(|rule_id| finding_matches_rule_id(finding, rule_id))
        })
        .cloned()
        .or_else(|| {
            candidates
                .iter()
                .find(|suppression| suppression.rule_id.is_none())
                .cloned()
        })
}

fn finding_matches_rule_id(finding: &SecurityFinding, rule_id: &str) -> bool {
    finding_rule_aliases(finding).contains(rule_id)
}

fn finding_rule_aliases(finding: &SecurityFinding) -> HashSet<String> {
    let mut aliases = HashSet::new();
    aliases.insert(finding_rule_id(finding));

    let title_rule = normalize_rule_id(&finding.title);
    if !title_rule.is_empty() {
        aliases.insert(title_rule);
    }

    let type_rule = normalize_rule_id(&finding.finding_type.to_string());
    if !type_rule.is_empty() {
        aliases.insert(type_rule);
    }

    if let Some(cwe_id) = finding.cwe_id.as_deref() {
        aliases.insert(cwe_id.to_ascii_lowercase());
    }

    aliases
}

fn finding_rule_id(finding: &SecurityFinding) -> String {
    if let Some(cwe_id) = finding.cwe_id.as_deref() {
        if let Some(mapped_rule_id) = cwe_rule_id(cwe_id) {
            return mapped_rule_id.to_string();
        }
    }

    let title = finding.title.to_ascii_lowercase();
    if title.contains("sql injection") {
        return "sql-injection".to_string();
    }
    if title.contains("command injection") {
        return "command-injection".to_string();
    }
    if title.contains("cross-site scripting") || title.contains("xss") {
        return "cross-site-scripting".to_string();
    }
    if title.contains("code injection") {
        return "code-injection".to_string();
    }
    if title.contains("path traversal") {
        return "path-traversal".to_string();
    }
    if title.contains("deserialization") {
        return "deserialization-attack".to_string();
    }
    if title.contains("hardcoded secret") {
        return "hardcoded-secret".to_string();
    }
    if title.contains("unsafe block") {
        return "unsafe-block-usage".to_string();
    }
    if title.contains("weak cryptographic") {
        return "weak-crypto".to_string();
    }

    let normalized_type = normalize_rule_id(&finding.finding_type.to_string());
    if normalized_type.is_empty() {
        "security-finding".to_string()
    } else {
        normalized_type
    }
}

fn cwe_rule_id(cwe_id: &str) -> Option<&'static str> {
    match cwe_id {
        "CWE-22" => Some("path-traversal"),
        "CWE-78" => Some("command-injection"),
        "CWE-79" => Some("cross-site-scripting"),
        "CWE-89" => Some("sql-injection"),
        "CWE-94" => Some("code-injection"),
        "CWE-327" => Some("weak-crypto"),
        "CWE-502" => Some("deserialization-attack"),
        "CWE-798" => Some("hardcoded-secret"),
        _ => None,
    }
}

fn normalize_rule_id(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut last_was_separator = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator && !normalized.is_empty() {
            normalized.push('-');
            last_was_separator = true;
        }
    }

    normalized.trim_matches('-').to_string()
}

/// Discover files to analyze based on criteria
fn discover_files(
    path: &PathBuf,
    language_filter: Option<Language>,
    include_tests: bool,
    include_examples: bool,
    max_file_kb: usize,
) -> CliResult<Vec<(PathBuf, Language)>> {
    let mut files = Vec::new();

    fn is_hidden_or_ignored(entry: &walkdir::DirEntry) -> bool {
        entry
            .file_name()
            .to_str()
            .is_some_and(|s| s.starts_with('.'))
            || entry.path().components().any(|c| {
                c.as_os_str().to_str().is_some_and(|s| {
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

        // Skip large files by size budget
        if let Ok(md) = entry.metadata() {
            if md.len() > (max_file_kb as u64) * 1024 {
                warn!(
                    "Skipping large file {} (>{} KB)",
                    entry.path().display(),
                    max_file_kb
                );
                continue;
            }
        }

        if let Some(language) = crate::detect_language_from_path(&entry.path().to_string_lossy()) {
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
pub fn render_ast_security_markdown(
    findings: &[SecurityFinding],
    summary_only: bool,
    analyzed_files: usize,
    failed_files: usize,
) -> CliResult<String> {
    use std::fmt::Write;
    let mut out = String::new();

    writeln!(out, "# 🔍 AST-Based Security Analysis Report\n")?;
    writeln!(out, "## 📊 Executive Summary\n")?;
    writeln!(out, "- **Files Analyzed**: {}", analyzed_files)?;
    writeln!(out, "- **Files Failed**: {}", failed_files)?;
    writeln!(out, "- **Total Findings**: {}", findings.len())?;

    // Group findings by severity
    let mut severity_counts = HashMap::new();
    for finding in findings {
        *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
    }

    writeln!(out, "\n### Findings by Severity\n")?;
    for severity in &[
        SecuritySeverity::Critical,
        SecuritySeverity::High,
        SecuritySeverity::Medium,
        SecuritySeverity::Low,
        SecuritySeverity::Info,
    ] {
        let count = severity_counts.get(severity).copied().unwrap_or(0);
        writeln!(out, "- **{:?}**: {}", severity, count)?;
    }

    if !summary_only && !findings.is_empty() {
        writeln!(out, "\n## 🚨 Detailed Findings\n")?;
        for (i, finding) in findings.iter().enumerate() {
            writeln!(out, "### {}. {}\n", i + 1, finding.title)?;
            writeln!(out, "- **Severity**: {:?}", finding.severity)?;
            writeln!(out, "- **Confidence**: {:.1}%", finding.confidence * 100.0)?;
            writeln!(
                out,
                "- **CWE**: {}",
                finding.cwe_id.as_deref().unwrap_or("N/A")
            )?;
            writeln!(
                out,
                "- **Location**: `{}:{}`",
                finding.file_path, finding.line_number
            )?;
            writeln!(out, "- **Description**: {}", finding.description)?;

            if !finding.code_snippet.is_empty() {
                writeln!(out, "- **Code**:\n```rust\n{}\n```", finding.code_snippet)?;
            }

            writeln!(out, "- **Fix**: {}\n", finding.remediation)?;
        }
    }

    Ok(out)
}

/// Generate SARIF report for findings
fn generate_sarif_report(
    findings: &[SecurityFinding],
    inline_suppressed_findings: &[SuppressedFinding],
    root_path: &PathBuf,
    baseline: Option<&HashSet<String>>,
) -> CliResult<String> {
    use serde_json::json;

    let sarif_findings: Vec<_> = findings
        .iter()
        .map(|finding| (finding, None))
        .chain(
            inline_suppressed_findings
                .iter()
                .map(|suppressed| (&suppressed.finding, Some(&suppressed.suppression))),
        )
        .collect();

    let mut rule_indices = HashMap::new();
    let mut rules = Vec::new();
    for (finding, _) in &sarif_findings {
        let rule_id = finding_rule_id(finding);
        if rule_indices.contains_key(&rule_id) {
            continue;
        }

        let rule_index = rules.len();
        rule_indices.insert(rule_id.clone(), rule_index);
        rules.push(json!({
            "id": rule_id,
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
        }));
    }

    let results: Vec<serde_json::Value> = sarif_findings
        .iter()
        .map(|(finding, inline_suppression)| {
            let rule_id = finding_rule_id(finding);
            let rule_index = rule_indices.get(&rule_id).copied().ok_or_else(|| {
                CliError::Internal(format!("Missing SARIF rule index for {}", rule_id))
            })?;
            let fp = fingerprint_ast(finding);
            let is_baselined =
                inline_suppression.is_none() && baseline.map(|b| b.contains(&fp)).unwrap_or(false);
            let relative_path = Path::new(&finding.file_path)
                .strip_prefix(root_path)
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_else(|_| finding.file_path.clone());

            let mut result = json!({
                "ruleId": rule_id,
                "ruleIndex": rule_index,
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
                            "startLine": finding.line_number.max(1),
                            "startColumn": finding.column_start.max(1),
                            "endColumn": finding.column_end.max(finding.column_start.max(1))
                        }
                    }
                }],
                "properties": {
                    "remediation": finding.remediation.clone(),
                    "confidence": finding.confidence,
                    "fingerprint": fp
                }
            });

            if let Some(result_object) = result.as_object_mut() {
                if let Some(suppression) = inline_suppression {
                    result_object.insert(
                        "suppressions".to_string(),
                        json!([{
                            "kind": "inSource",
                            "justification": suppression.raw_comment,
                        }]),
                    );
                } else {
                    result_object.insert(
                        "baselineState".to_string(),
                        json!(if is_baselined { "unchanged" } else { "new" }),
                    );
                }
            }

            Ok(result)
        })
        .collect::<CliResult<Vec<_>>>()?;

    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rust_tree_sitter",
                    "version": env!("CARGO_PKG_VERSION"),
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::security::ast_analyzer::SecurityFindingType;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_ast_security_command_validation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let result = execute(
            &path, "table", "low", None, false, None, false, false, 0.0, None, None, false, 1024,
        )
        .await;
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
            0.0,
            None,
            None,
            false,
            1024,
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
            0.0,
            None,
            None,
            false,
            1024,
        )
        .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CliError::InvalidArgs(_)));
    }

    #[test]
    fn test_parse_inline_suppression_supports_double_slash_comments() {
        let suppressions = parse_inline_suppressions(
            "// rts-ignore[sql-injection]\nlet query = format!(\"SELECT {}\", user_input);\n",
            Language::Rust,
        )
        .unwrap();

        let parsed = suppressions.get(&1).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].rule_id.as_deref(), Some("sql-injection"));
    }

    #[test]
    fn test_parse_inline_suppression_supports_hash_comments() {
        let suppressions = parse_inline_suppressions(
            "# rts-ignore\nquery = f\"SELECT * FROM users WHERE id = {user_id}\"\n",
            Language::Python,
        )
        .unwrap();

        let parsed = suppressions.get(&1).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].rule_id, None);
    }

    #[test]
    fn test_rule_specific_inline_suppression_only_matches_target_rule() {
        let suppressions = parse_inline_suppressions(
            "// rts-ignore[sql-injection]\nlet query = format!(\"SELECT {}\", user_input);\n",
            Language::Rust,
        )
        .unwrap();

        let sql_injection = test_security_finding(1, "Potential SQL Injection", Some("CWE-89"));
        let command_injection =
            test_security_finding(1, "Potential Command Injection", Some("CWE-78"));

        let (retained, suppressed) = partition_findings_by_inline_suppression(
            vec![sql_injection, command_injection],
            &suppressions,
        );

        assert_eq!(retained.len(), 1);
        assert_eq!(suppressed.len(), 1);
        assert_eq!(
            suppressed[0].suppression.rule_id.as_deref(),
            Some("sql-injection")
        );
        assert_eq!(retained[0].cwe_id.as_deref(), Some("CWE-78"));
    }

    #[test]
    fn test_all_inline_suppression_matches_any_rule_on_next_line_only() {
        let suppressions = parse_inline_suppressions(
            "# rts-ignore\n\nquery = f\"SELECT * FROM users WHERE id = {user_id}\"\n",
            Language::Python,
        )
        .unwrap();

        let suppressed_finding =
            test_security_finding(1, "Potential SQL Injection", Some("CWE-89"));
        let unsuppressed_finding =
            test_security_finding(2, "Potential Command Injection", Some("CWE-78"));

        let (retained, suppressed) = partition_findings_by_inline_suppression(
            vec![suppressed_finding, unsuppressed_finding],
            &suppressions,
        );

        assert_eq!(suppressed.len(), 1);
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].cwe_id.as_deref(), Some("CWE-78"));
    }

    #[test]
    fn test_sarif_report_includes_inline_suppressions() {
        let root = PathBuf::from("/tmp/project");
        let finding = test_security_finding(1, "Potential SQL Injection", Some("CWE-89"));
        let report = generate_sarif_report(
            &[],
            &[SuppressedFinding {
                finding,
                suppression: InlineSuppression {
                    target_line: 1,
                    rule_id: Some("sql-injection".to_string()),
                    raw_comment: "// rts-ignore[sql-injection]".to_string(),
                },
            }],
            &root,
            None,
        )
        .unwrap();

        let sarif: serde_json::Value = serde_json::from_str(&report).unwrap();
        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "sql-injection");
        assert_eq!(result["suppressions"][0]["kind"], "inSource");
        assert_eq!(
            result["suppressions"][0]["justification"],
            "// rts-ignore[sql-injection]"
        );
    }

    #[test]
    fn test_inline_suppression_takes_precedence_over_baseline_state() {
        let finding = test_security_finding(1, "Potential SQL Injection", Some("CWE-89"));
        let fingerprint = fingerprint_ast(&finding);
        let baseline = HashSet::from([fingerprint]);

        let report = generate_sarif_report(
            &[],
            &[SuppressedFinding {
                finding,
                suppression: InlineSuppression {
                    target_line: 1,
                    rule_id: Some("sql-injection".to_string()),
                    raw_comment: "// rts-ignore[sql-injection]".to_string(),
                },
            }],
            &PathBuf::from("/tmp/project"),
            Some(&baseline),
        )
        .unwrap();

        let sarif: serde_json::Value = serde_json::from_str(&report).unwrap();
        let result = &sarif["runs"][0]["results"][0];
        assert!(result.get("baselineState").is_none());
        assert_eq!(result["suppressions"][0]["kind"], "inSource");
    }

    fn test_security_finding(
        line_number: usize,
        title: &str,
        cwe_id: Option<&str>,
    ) -> SecurityFinding {
        SecurityFinding {
            id: "test-finding".to_string(),
            finding_type: SecurityFindingType::Injection,
            severity: SecuritySeverity::High,
            title: title.to_string(),
            description: title.to_string(),
            file_path: "/tmp/project/src/lib.rs".to_string(),
            line_number,
            column_start: 1,
            column_end: 12,
            code_snippet: "dangerous_call(user_input)".to_string(),
            cwe_id: cwe_id.map(str::to_string),
            remediation: "Fix it".to_string(),
            confidence: 0.9,
            context: Default::default(),
        }
    }
}
