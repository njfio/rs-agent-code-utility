#![cfg(feature = "cli")]

use rust_tree_sitter::advanced_security::{
    CodeExample, ConfidenceLevel, ImpactLevel, OwaspCategory, RemediationEffort,
    RemediationGuidance, SecurityImpact, SecuritySeverity, SecurityVulnerability,
    VulnerabilityLocation,
};
use rust_tree_sitter::{AnalysisConfig, AnalysisResult, FileInfo};

fn sample_analysis_result() -> AnalysisResult {
    let mut res = AnalysisResult::new();
    res.root_path = std::path::PathBuf::from("/tmp/project");
    res.config = AnalysisConfig::default();

    let vuln = SecurityVulnerability {
        id: "TEST-1".to_string(),
        title: "Command Injection".to_string(),
        description: "Untrusted input flows into shell command".to_string(),
        severity: SecuritySeverity::High,
        owasp_category: OwaspCategory::Injection,
        cwe_id: Some("CWE-78".to_string()),
        location: VulnerabilityLocation {
            file: std::path::PathBuf::from("src/main.rs"),
            function: Some("run_cmd".to_string()),
            start_line: 10,
            end_line: 12,
            column: 4,
        },
        code_snippet: "std::process::Command::new(user_input)".to_string(),
        impact: SecurityImpact {
            confidentiality: ImpactLevel::High,
            integrity: ImpactLevel::High,
            availability: ImpactLevel::Medium,
            overall_score: 8.5,
        },
        remediation: RemediationGuidance {
            summary: "Validate and sanitize input".to_string(),
            steps: vec!["Use allowlist".to_string()],
            code_examples: vec![CodeExample {
                description: "Use execve with fixed path".to_string(),
                vulnerable_code: "Command::new(user)".to_string(),
                secure_code: "Command::new(\"/usr/bin/ls\")".to_string(),
                language: "Rust".to_string(),
            }],
            references: vec![],
            effort: RemediationEffort::Medium,
        },
        confidence: ConfidenceLevel::High,
    };

    let file = FileInfo {
        path: std::path::PathBuf::from("src/main.rs"),
        language: "Rust".to_string(),
        size: 100,
        lines: 50,
        parsed_successfully: true,
        parse_errors: vec![],
        symbols: vec![],
        security_vulnerabilities: vec![vuln],
    };

    res.files.push(file);
    res.total_files = 1;
    res.parsed_files = 1;
    res.total_lines = 50;
    res
}

#[test]
fn test_to_sarif_basic_shape() {
    let analysis = sample_analysis_result();
    let sarif = rust_tree_sitter::cli::sarif::to_sarif(&analysis);

    // Minimal shape and metadata
    assert_eq!(sarif.schema, rust_tree_sitter::cli::sarif::SARIF_SCHEMA_URL);
    assert_eq!(sarif.version, "2.1.0");
    assert_eq!(sarif.runs.len(), 1);

    let run = &sarif.runs[0];
    assert_eq!(run.tool.driver.name, "rust-tree-sitter");
    assert_eq!(run.tool.driver.rules.len(), 1);

    // One vulnerability -> one result
    assert_eq!(run.results.len(), 1);
    let r = &run.results[0];
    assert!(r.rule_id.contains("CWE-78") || r.rule_id.contains("Injection"));
    assert_eq!(r.level, Some("error")); // High -> error
    assert!(r.message.text.contains("Untrusted input"));
    assert!(r
        .partial_fingerprints
        .contains_key("primaryLocationLineHash"));
    assert_eq!(
        r.properties
            .as_ref()
            .map(|properties| properties.security_severity.as_str()),
        Some("8.5")
    );
    assert_eq!(
        r.properties
            .as_ref()
            .map(|properties| properties.confidence.as_str()),
        Some("high")
    );
    assert!(r.locations[0]
        .physical_location
        .artifact_location
        .uri
        .ends_with("src/main.rs"));
}

#[test]
fn test_to_codeclimate_basic_shape() {
    let analysis = sample_analysis_result();
    let issues = rust_tree_sitter::cli::sarif::to_codeclimate(&analysis);

    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].issue_type, "issue");
    assert_eq!(issues[0].check_name, "CWE-78");
    assert_eq!(issues[0].categories, vec!["Security".to_string()]);
    assert_eq!(issues[0].severity, "major");
    assert_eq!(issues[0].location.path, "src/main.rs");
}
