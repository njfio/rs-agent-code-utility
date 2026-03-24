//! Security command implementation
//!
//! Provides comprehensive security vulnerability scanning with configurable output formats.
#![allow(clippy::too_many_arguments, clippy::wildcard_in_or_patterns)]

#[cfg(feature = "net")]
use crate::ai::AIServiceBuilder;
use crate::cli::error::{validate_format, validate_path, CliError, CliResult};
use crate::cli::output::OutputFormat;
use crate::cli::sarif::{
    help_uri as sarif_help_uri, partial_fingerprints, rule_id as sarif_rule_id,
    security_severity as sarif_security_severity, vulnerability_fingerprint, SARIF_SCHEMA_URL,
};
use crate::cli::utils::{
    create_analysis_config, create_progress_bar, parse_severity, print_success,
    severity_meets_threshold, validate_output_path,
};
use crate::security::deterministic_filter::{filter_vulnerabilities, FilterMode};
#[cfg(feature = "net")]
use crate::security::{AstSecurityAnalyzer, HeuristicFindingFilter};
use crate::{CodebaseAnalyzer, SecurityScanner};
use colored::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
#[cfg(feature = "net")]
use std::sync::Arc;

/// Execute the security command
pub async fn execute(
    path: &PathBuf,
    format: &str,
    min_severity: &str,
    output: Option<&PathBuf>,
    summary_only: bool,
    compliance: bool,
    diagnostics: bool,
    depth: &str,
    // Whether to enable heavy security scanning during initial parsing
    enable_security: bool,
    include_tests: bool,
    include_examples: bool,
    include_non_code: bool,
    min_confidence: &str,
    fail_on: Option<&str>,
    no_ai_filter: bool,
    filter_mode: &str,
    baseline: Option<&PathBuf>,
    update_baseline: bool,
    max_file_kb: usize,
) -> CliResult<()> {
    // Validate inputs
    validate_path(path)?;
    validate_format(
        format,
        &["table", "json", "markdown", "sarif", "codeclimate"],
    )?;
    let severity_threshold = parse_severity(min_severity)?;

    if let Some(output_path) = output {
        validate_output_path(output_path)?;
    }

    // Create progress bar
    let pb = create_progress_bar("Running security scan...");

    // Configure analyzer
    let mut config =
        create_analysis_config(1024, 20, depth, false, None, None, None, enable_security)?;

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
        max_file_kb,
    );

    // Run security analysis
    pb.set_message("Scanning for vulnerabilities...");

    // Create AI-powered security scanner with false positive filtering
    pb.set_message("Initializing AI security scanner...");

    // Initialize security scanner, optionally disabling AI filtering
    let security_scanner = if no_ai_filter {
        SecurityScanner::new().map_err(|e| CliError::Security(e.to_string()))?
    } else {
        #[cfg(feature = "net")]
        {
            let det_mode = FilterMode::from_str(filter_mode);
            let ai_service = Arc::new(
                AIServiceBuilder::new()
                    .with_mock_providers(true)
                    .build()
                    .await
                    .map_err(|e| {
                        CliError::Security(format!("Failed to initialize AI service: {}", e))
                    })?,
            );
            let heuristic_filter = Arc::new(HeuristicFindingFilter::with_mode(det_mode));
            let ast_analyzer = Arc::new(AstSecurityAnalyzer::new().map_err(|e| {
                CliError::Security(format!("Failed to create AST analyzer: {}", e))
            })?);
            // Adjust AI config based on filter mode
            let ai_min_conf = match det_mode {
                FilterMode::Strict => 0.8,
                FilterMode::Balanced => 0.6,
                FilterMode::Permissive => 0.4,
            };
            SecurityScanner::with_ai_filtering(
                ai_service,
                heuristic_filter,
                ast_analyzer,
                ai_min_conf,
                det_mode,
            )
            .await
            .map_err(|e| {
                CliError::Security(format!("Failed to create AI security scanner: {}", e))
            })?
        }
        #[cfg(not(feature = "net"))]
        {
            // AI filtering requires the 'net' feature; fall back to basic scanner
            SecurityScanner::new().map_err(|e| CliError::Security(e.to_string()))?
        }
    };

    pb.set_message("Running AI-powered security analysis...");
    let security_result = security_scanner
        .analyze(&filtered_analysis_result)
        .map_err(|e| CliError::Security(e.to_string()))?;

    pb.finish_with_message("Security scan complete!");

    // Deterministic filtering (strict|balanced|permissive)
    let det_mode = FilterMode::from_str(filter_mode);
    let det_filtered = filter_vulnerabilities(&security_result.vulnerabilities, det_mode);

    // Filter vulnerabilities by severity and confidence
    let confidence_threshold = crate::cli::utils::parse_confidence_level(min_confidence)?;
    let mut filtered_vulnerabilities: Vec<_> = det_filtered
        .iter()
        .filter(|vuln| severity_meets_threshold(&severity_threshold, &vuln.severity))
        .filter(|vuln| {
            crate::cli::utils::confidence_meets_threshold(&confidence_threshold, &vuln.confidence)
        })
        .copied()
        .collect();

    // Baseline suppression
    let mut baseline_set: Option<HashSet<String>> = None;
    if let Some(baseline_path) = baseline {
        let base = load_baseline_vuln(baseline_path)?;
        baseline_set = Some(base.clone());
        filtered_vulnerabilities.retain(|v| !base.contains(&fingerprint_vuln(v)));
        if update_baseline {
            let current: HashSet<String> =
                det_filtered.iter().map(|v| fingerprint_vuln(v)).collect();
            save_baseline_vuln(baseline_path, &current)?;
            baseline_set = Some(current);
        }
    }

    // Display results based on format
    let output_format = OutputFormat::from_str(format).map_err(CliError::UnsupportedFormat)?;

    match output_format {
        OutputFormat::Json => {
            use serde_json::json;

            #[derive(serde::Serialize)]
            struct FilteredJsonReport {
                security_score: u8,
                total_vulnerabilities: usize,
                vulnerabilities_by_severity:
                    std::collections::BTreeMap<crate::SecuritySeverity, usize>,
                vulnerabilities: Vec<serde_json::Value>,
                compliance: crate::advanced_security::ComplianceAssessment,
                // Optional diagnostics to compare filtered vs raw
                raw_total_vulnerabilities: usize,
                raw_vulnerabilities_by_severity:
                    std::collections::BTreeMap<crate::SecuritySeverity, usize>,
            }

            let mut filtered_findings: Vec<serde_json::Value> = filtered_vulnerabilities
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<_, _>>()?;

            filtered_findings.extend(
                security_result
                    .secrets
                    .iter()
                    .filter(|secret| {
                        crate::cli::utils::confidence_meets_threshold(
                            &confidence_threshold,
                            &secret.confidence,
                        )
                    })
                    .map(|secret| {
                        json!({
                            "finding_type": "secret",
                            "title": format!("Hardcoded {:?} detected", secret.secret_type),
                            "description": secret.remediation,
                            "severity": crate::SecuritySeverity::Critical,
                            "confidence": secret.confidence,
                            "location": secret.location,
                            "masked_value": secret.masked_value,
                            "secret_type": secret.secret_type,
                        })
                    }),
            );

            filtered_findings.extend(
                security_result
                    .input_validation_issues
                    .iter()
                    .filter(|issue| severity_meets_threshold(&severity_threshold, &issue.severity))
                    .map(|issue| {
                        json!({
                            "finding_type": "input_validation",
                            "title": format!("{:?}", issue.issue_type),
                            "description": issue.description,
                            "severity": issue.severity,
                            "confidence": serde_json::Value::Null,
                            "location": issue.location,
                            "remediation": issue.remediation,
                        })
                    }),
            );

            filtered_findings.extend(
                security_result
                    .injection_vulnerabilities
                    .iter()
                    .filter(|issue| severity_meets_threshold(&severity_threshold, &issue.severity))
                    .map(|issue| {
                        json!({
                            "finding_type": "injection",
                            "title": format!("{:?}", issue.injection_type),
                            "description": issue.pattern,
                            "severity": issue.severity,
                            "confidence": serde_json::Value::Null,
                            "location": issue.location,
                            "remediation": issue.remediation,
                        })
                    }),
            );

            filtered_findings.extend(
                security_result
                    .best_practice_violations
                    .iter()
                    .filter(|issue| severity_meets_threshold(&severity_threshold, &issue.severity))
                    .map(|issue| {
                        json!({
                            "finding_type": "best_practice",
                            "title": format!("{:?}", issue.category),
                            "description": issue.description,
                            "severity": issue.severity,
                            "confidence": serde_json::Value::Null,
                            "location": issue.location,
                            "recommendation": issue.recommendation,
                        })
                    }),
            );

            // Build severity counts from the flattened filtered list
            let mut sev_counts: std::collections::BTreeMap<crate::SecuritySeverity, usize> =
                Default::default();
            for vuln in &filtered_vulnerabilities {
                *sev_counts.entry(vuln.severity.clone()).or_insert(0) += 1;
            }
            for secret in &security_result.secrets {
                if crate::cli::utils::confidence_meets_threshold(
                    &confidence_threshold,
                    &secret.confidence,
                ) {
                    *sev_counts
                        .entry(crate::SecuritySeverity::Critical)
                        .or_insert(0) += 1;
                }
            }
            for issue in &security_result.input_validation_issues {
                if severity_meets_threshold(&severity_threshold, &issue.severity) {
                    *sev_counts.entry(issue.severity.clone()).or_insert(0) += 1;
                }
            }
            for issue in &security_result.injection_vulnerabilities {
                if severity_meets_threshold(&severity_threshold, &issue.severity) {
                    *sev_counts.entry(issue.severity.clone()).or_insert(0) += 1;
                }
            }
            for issue in &security_result.best_practice_violations {
                if severity_meets_threshold(&severity_threshold, &issue.severity) {
                    *sev_counts.entry(issue.severity.clone()).or_insert(0) += 1;
                }
            }

            // Convert raw severity counts to BTreeMap for stable ordering across all finding buckets
            let mut raw_counts: std::collections::BTreeMap<crate::SecuritySeverity, usize> =
                Default::default();
            for vuln in &security_result.vulnerabilities {
                *raw_counts.entry(vuln.severity.clone()).or_insert(0) += 1;
            }
            for _ in &security_result.secrets {
                *raw_counts
                    .entry(crate::SecuritySeverity::Critical)
                    .or_insert(0) += 1;
            }
            for issue in &security_result.input_validation_issues {
                *raw_counts.entry(issue.severity.clone()).or_insert(0) += 1;
            }
            for issue in &security_result.injection_vulnerabilities {
                *raw_counts.entry(issue.severity.clone()).or_insert(0) += 1;
            }
            for issue in &security_result.best_practice_violations {
                *raw_counts.entry(issue.severity.clone()).or_insert(0) += 1;
            }

            let report = FilteredJsonReport {
                security_score: security_result.security_score,
                total_vulnerabilities: filtered_findings.len(),
                vulnerabilities_by_severity: sev_counts,
                vulnerabilities: filtered_findings,
                compliance: security_result.compliance.clone(),
                raw_total_vulnerabilities: security_result.total_vulnerabilities,
                raw_vulnerabilities_by_severity: raw_counts,
            };

            let json = serde_json::to_string_pretty(&report)?;
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
                let mut markdown = render_security_markdown(
                    &security_result,
                    summary_only,
                    compliance,
                    &filtered_vulnerabilities,
                )?;
                if diagnostics {
                    use std::fmt::Write as _;
                    let mut raw_counts: std::collections::BTreeMap<crate::SecuritySeverity, usize> =
                        Default::default();
                    for (k, v) in &security_result.vulnerabilities_by_severity {
                        raw_counts.insert(k.clone(), *v);
                    }
                    let _ = writeln!(&mut markdown, "\n## 🧪 Diagnostics\n");
                    let _ = writeln!(
                        &mut markdown,
                        "- Raw Total Vulnerabilities: {}",
                        security_result.total_vulnerabilities
                    );
                    let _ = writeln!(&mut markdown, "- Raw by Severity:");
                    for sev in [
                        crate::SecuritySeverity::Critical,
                        crate::SecuritySeverity::High,
                        crate::SecuritySeverity::Medium,
                        crate::SecuritySeverity::Low,
                        crate::SecuritySeverity::Info,
                    ] {
                        let c = raw_counts.get(&sev).cloned().unwrap_or(0);
                        let _ = writeln!(&mut markdown, "  - {:?}: {}", sev, c);
                    }
                }
                std::fs::write(output_path, markdown)?;
                print_success(&format!(
                    "Security report saved to {}",
                    output_path.display()
                ));
            }
            if diagnostics && output.is_none() {
                // Print diagnostics to stdout after the main report
                let mut raw_counts: std::collections::BTreeMap<crate::SecuritySeverity, usize> =
                    Default::default();
                for (k, v) in &security_result.vulnerabilities_by_severity {
                    raw_counts.insert(k.clone(), *v);
                }
                println!("\n## 🧪 Diagnostics\n");
                println!(
                    "- Raw Total Vulnerabilities: {}",
                    security_result.total_vulnerabilities
                );
                println!("- Raw by Severity:");
                for sev in [
                    crate::SecuritySeverity::Critical,
                    crate::SecuritySeverity::High,
                    crate::SecuritySeverity::Medium,
                    crate::SecuritySeverity::Low,
                    crate::SecuritySeverity::Info,
                ] {
                    let c = raw_counts.get(&sev).cloned().unwrap_or(0);
                    println!("  - {:?}: {}", sev, c);
                }
            }
        }
        OutputFormat::Sarif => {
            let sarif = generate_security_sarif_report(
                &filtered_vulnerabilities,
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
        OutputFormat::CodeClimate => {
            let codeclimate =
                generate_security_codeclimate_report(&filtered_vulnerabilities, path)?;
            if let Some(output_path) = output {
                std::fs::write(output_path, &codeclimate)?;
                print_success(&format!(
                    "Code Climate security report saved to {}",
                    output_path.display()
                ));
            } else {
                println!("{}", codeclimate);
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

    // CI gating: fail if findings at or above threshold exist
    if let Some(fail_on_str) = fail_on {
        let fail_threshold = parse_severity(fail_on_str)?;
        let offending = filtered_vulnerabilities
            .iter()
            .any(|v| severity_meets_threshold(&fail_threshold, &v.severity));
        if offending {
            return Err(CliError::Security(format!(
                "Failing due to findings at or above '{}'",
                fail_on_str
            )));
        }
    }

    Ok(())
}

fn generate_security_sarif_report(
    filtered_vulns: &[&crate::SecurityVulnerability],
    root_path: &PathBuf,
    baseline: Option<&HashSet<String>>,
) -> CliResult<String> {
    use serde_json::json;

    let mut rule_indices = HashMap::new();
    let mut rules = Vec::new();

    for vuln in filtered_vulns {
        let rule_id = sarif_rule_id(vuln.cwe_id.as_deref(), &vuln.owasp_category);
        if rule_indices.contains_key(&rule_id) {
            continue;
        }

        let rule_index = rules.len();
        rule_indices.insert(rule_id.clone(), rule_index);
        rules.push(json!({
            "id": rule_id,
            "name": vuln.title,
            "shortDescription": {"text": vuln.description},
            "fullDescription": {"text": vuln.description},
            "helpUri": sarif_help_uri(vuln.cwe_id.as_deref(), &vuln.owasp_category),
            "defaultConfiguration": {
                "level": match vuln.severity {
                    crate::SecuritySeverity::Critical | crate::SecuritySeverity::High => "error",
                    crate::SecuritySeverity::Medium => "warning",
                    crate::SecuritySeverity::Low | crate::SecuritySeverity::Info => "note",
                }
            },
            "properties": {
                "tags": ["security"],
                "cwe": vuln.cwe_id,
                "owasp": format!("{:?}", vuln.owasp_category),
            }
        }));
    }

    let results: Vec<serde_json::Value> = filtered_vulns
        .iter()
        .map(|v| {
            let rule_id = sarif_rule_id(v.cwe_id.as_deref(), &v.owasp_category);
            let rule_index = rule_indices.get(&rule_id).copied().ok_or_else(|| {
                CliError::Internal(format!("Missing SARIF rule index for {}", rule_id))
            })?;
            let relative_path = v
                .location
                .file
                .strip_prefix(root_path)
                .unwrap_or(&v.location.file)
                .to_string_lossy()
                .to_string();
            let baseline_fp = fingerprint_vuln(v);
            let is_baselined = baseline.map(|b| b.contains(&baseline_fp)).unwrap_or(false);
            let fingerprint = vulnerability_fingerprint(
                &relative_path,
                v.location.start_line,
                v.location.column,
                &rule_id,
                &v.title,
            );
            Ok(json!({
                "ruleId": rule_id,
                "ruleIndex": rule_index,
                "level": match v.severity {
                    crate::SecuritySeverity::Critical | crate::SecuritySeverity::High => "error",
                    crate::SecuritySeverity::Medium => "warning",
                    crate::SecuritySeverity::Low | crate::SecuritySeverity::Info => "note",
                },
                "message": {"text": v.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": relative_path},
                        "region": {
                            "startLine": v.location.start_line,
                            "endLine": v.location.end_line,
                            "startColumn": v.location.column.max(1),
                        }
                    }
                }],
                "baselineState": if is_baselined { "unchanged" } else { "new" },
                "partialFingerprints": partial_fingerprints(&fingerprint),
                "properties": {
                    "remediation": v.remediation.summary,
                    "confidence": match v.confidence {
                        crate::advanced_security::ConfidenceLevel::Low => "low",
                        crate::advanced_security::ConfidenceLevel::Medium => "medium",
                        crate::advanced_security::ConfidenceLevel::High => "high",
                    },
                    "security-severity": sarif_security_severity(v.impact.overall_score, &v.severity),
                    "cwe": v.cwe_id,
                    "owasp": format!("{:?}", v.owasp_category),
                }
            }))
        })
        .collect::<CliResult<Vec<_>>>()?;

    let sarif = json!({
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "rust-tree-sitter security",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": option_env!("CARGO_PKG_REPOSITORY").unwrap_or("https://github.com/"),
                "rules": rules
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": true
            }]
        }]
    });
    serde_json::to_string_pretty(&sarif).map_err(CliError::Json)
}

fn generate_security_codeclimate_report(
    filtered_vulns: &[&crate::SecurityVulnerability],
    root_path: &PathBuf,
) -> CliResult<String> {
    use serde_json::json;

    let issues: Vec<_> = filtered_vulns
        .iter()
        .map(|v| {
            let relative_path = v
                .location
                .file
                .strip_prefix(root_path)
                .unwrap_or(&v.location.file)
                .to_string_lossy()
                .to_string();
            let rule_id = sarif_rule_id(v.cwe_id.as_deref(), &v.owasp_category);
            let fingerprint = vulnerability_fingerprint(
                &relative_path,
                v.location.start_line,
                v.location.column,
                &rule_id,
                &v.title,
            );

            json!({
                "type": "issue",
                "check_name": rule_id,
                "description": format!("{}: {}", v.title, v.description),
                "categories": ["Security"],
                "severity": match v.severity {
                    crate::SecuritySeverity::Critical => "critical",
                    crate::SecuritySeverity::High | crate::SecuritySeverity::Medium => "major",
                    crate::SecuritySeverity::Low => "minor",
                    crate::SecuritySeverity::Info => "info",
                },
                "fingerprint": fingerprint,
                "location": {
                    "path": relative_path,
                    "lines": {
                        "begin": v.location.start_line,
                        "end": v.location.end_line,
                    }
                },
                "content": {
                    "body": v.remediation.summary,
                }
            })
        })
        .collect();

    serde_json::to_string_pretty(&issues).map_err(CliError::Json)
}

fn fingerprint_vuln(v: &crate::SecurityVulnerability) -> String {
    format!(
        "{}:{}:{}:{:?}",
        v.location.file.display(),
        v.location.start_line,
        v.title,
        v.severity
    )
}

fn load_baseline_vuln(path: &PathBuf) -> CliResult<HashSet<String>> {
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let content = fs::read_to_string(path).map_err(CliError::Io)?;
    let list: Vec<String> = serde_json::from_str(&content).map_err(CliError::Json)?;
    Ok(list.into_iter().collect())
}

fn save_baseline_vuln(path: &PathBuf, entries: &HashSet<String>) -> CliResult<()> {
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

fn filter_analysis_result(
    mut result: crate::AnalysisResult,
    include_tests: bool,
    include_examples: bool,
    include_non_code: bool,
    max_file_kb: usize,
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
        if !include_tests
            && (path_str.contains("/tests/")
                || fname.starts_with("test_")
                || fname.ends_with("_test.rs")
                || path_str.contains("/spec/")
                || path_str.contains("/specs/"))
        {
            continue;
        }
        // Examples/demo filtering
        if !include_examples
            && (path_str.contains("/examples/")
                || path_str.contains("/example/")
                || path_str.contains("/demo/")
                || path_str.contains("/demos/"))
        {
            continue;
        }
        // Size filtering (skip very large files)
        if f.size / 1024 > max_file_kb {
            continue;
        }
        // Non-code filtering
        if !include_non_code {
            if path_str.contains("/docs/") || ext == "md" || ext == "markdown" {
                continue;
            }
            // Exclude common binary/media assets to avoid noise
            let non_code_exts = [
                "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp", "ico", "pdf", "zip", "gz",
                "tgz", "tar", "xz", "7z", "rar",
            ];
            if non_code_exts.iter().any(|e| *e == ext) {
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

    // Show vulnerabilities by severity (derived from filtered list)
    println!("\n{}", "🚨 BY SEVERITY".bright_yellow().bold());
    let mut sev_counts: std::collections::BTreeMap<crate::SecuritySeverity, usize> =
        Default::default();
    for v in filtered_vulnerabilities {
        *sev_counts.entry(v.severity.clone()).or_insert(0) += 1;
    }
    for sev in [
        crate::SecuritySeverity::Critical,
        crate::SecuritySeverity::High,
        crate::SecuritySeverity::Medium,
        crate::SecuritySeverity::Low,
        crate::SecuritySeverity::Info,
    ] {
        let count = *sev_counts.get(&sev).unwrap_or(&0);
        let color = match sev {
            crate::SecuritySeverity::Critical => "bright_red",
            crate::SecuritySeverity::High => "red",
            crate::SecuritySeverity::Medium => "yellow",
            crate::SecuritySeverity::Low => "blue",
            crate::SecuritySeverity::Info => "bright_black",
        };
        println!("  {sev:?}: {}", count.to_string().color(color));
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
            println!("   Severity: {} | Confidence: {}", sev, conf);
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
            "Overall Status: {:?}",
            security_result.compliance.overall_status
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
    let mut sev_counts: std::collections::BTreeMap<crate::SecuritySeverity, usize> =
        Default::default();
    for v in filtered_vulnerabilities {
        *sev_counts.entry(v.severity.clone()).or_insert(0) += 1;
    }
    for sev in &[
        crate::SecuritySeverity::Critical,
        crate::SecuritySeverity::High,
        crate::SecuritySeverity::Medium,
        crate::SecuritySeverity::Low,
        crate::SecuritySeverity::Info,
    ] {
        let count = *sev_counts.get(sev).unwrap_or(&0);
        println!("- **{:?}**: {}", sev, count);
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

pub fn render_security_markdown(
    security_result: &crate::SecurityScanResult,
    summary_only: bool,
    compliance: bool,
    filtered_vulnerabilities: &[&crate::SecurityVulnerability],
) -> CliResult<String> {
    use std::fmt::Write;
    let mut out = String::new();
    writeln!(out, "# 🔍 Security Scan Report\n")?;

    writeln!(out, "## 📊 Executive Summary\n")?;
    writeln!(
        out,
        "- **Security Score**: {}/100",
        security_result.security_score
    )?;
    writeln!(
        out,
        "- **Total Vulnerabilities**: {}",
        filtered_vulnerabilities.len()
    )?;

    writeln!(out, "\n### Vulnerabilities by Severity\n")?;
    let mut sev_counts: std::collections::BTreeMap<crate::SecuritySeverity, usize> =
        Default::default();
    for v in filtered_vulnerabilities {
        *sev_counts.entry(v.severity.clone()).or_insert(0) += 1;
    }
    for sev in [
        crate::SecuritySeverity::Critical,
        crate::SecuritySeverity::High,
        crate::SecuritySeverity::Medium,
        crate::SecuritySeverity::Low,
        crate::SecuritySeverity::Info,
    ] {
        let count = *sev_counts.get(&sev).unwrap_or(&0);
        writeln!(out, "- **{:?}**: {}", sev, count)?;
    }

    if !summary_only && !filtered_vulnerabilities.is_empty() {
        writeln!(out, "\n## 🚨 Detailed Findings\n")?;
        for (i, vuln) in filtered_vulnerabilities.iter().enumerate() {
            writeln!(out, "### {}. {}\n", i + 1, vuln.title)?;
            writeln!(out, "- **Severity**: {:?}", vuln.severity)?;
            writeln!(
                out,
                "- **Location**: `{}:{}`",
                vuln.location.file.display(),
                vuln.location.start_line
            )?;
            writeln!(out, "- **Description**: {}", vuln.description)?;
            writeln!(out, "- **Fix**: {}\n", vuln.remediation.summary)?;
        }
    }

    if compliance {
        writeln!(out, "## 📋 Compliance Status\n")?;
        writeln!(
            out,
            "- **OWASP Score**: {}/100",
            security_result.compliance.owasp_score
        )?;
        writeln!(
            out,
            "- **Overall Status**: {:?}\n",
            security_result.compliance.overall_status
        )?;
    }

    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_security_command_validation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let result = execute(
            &path, "table", "low", None, false, // summary_only
            false, // compliance
            false, // diagnostics
            "full", false,      // enable_security
            false,      // include_tests
            false,      // include_examples
            false,      // include_non_code
            "low",      // min_confidence
            None,       // fail_on
            false,      // no_ai_filter
            "balanced", // filter_mode
            None,       // baseline
            false,      // update_baseline
            1024,
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
            false, // summary_only
            false, // compliance
            false, // diagnostics
            "full",
            false,      // enable_security
            false,      // include_tests
            false,      // include_examples
            false,      // include_non_code
            "low",      // min_confidence
            None,       // fail_on
            false,      // no_ai_filter
            "balanced", // filter_mode
            None,       // baseline
            false,      // update_baseline
            1024,
        )
        .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CliError::InvalidArgs(_)));
    }
}
