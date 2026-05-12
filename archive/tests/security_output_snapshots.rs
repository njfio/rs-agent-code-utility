// snapshot tests for markdown renderers

#[test]
fn security_markdown_snapshot_is_stable_for_empty() {
    // Minimal empty result snapshot to stabilize header and sections
    let result = rust_tree_sitter::SecurityScanResult {
        security_score: 100,
        total_vulnerabilities: 0,
        vulnerabilities_by_severity: std::collections::HashMap::new(),
        owasp_categories: std::collections::HashMap::new(),
        vulnerabilities: vec![],
        secrets: vec![],
        input_validation_issues: vec![],
        injection_vulnerabilities: vec![],
        best_practice_violations: vec![],
        recommendations: vec![],
        compliance: rust_tree_sitter::advanced_security::ComplianceAssessment {
            owasp_score: 100,
            cwe_coverage: std::collections::HashMap::new(),
            standards_compliance: std::collections::HashMap::new(),
            overall_status: rust_tree_sitter::advanced_security::ComplianceStatus::Compliant,
        },
    };

    let md = render_security_markdown_wrapper(&result, true, false, &[]);
    assert!(md.contains("# 🔍 Security Scan Report"));
    assert!(md.contains("## 📊 Executive Summary"));
}

fn render_security_markdown_wrapper(
    res: &rust_tree_sitter::SecurityScanResult,
    summary_only: bool,
    compliance: bool,
    filtered: &[&rust_tree_sitter::SecurityVulnerability],
) -> String {
    // Call the internal render to snapshot markdown
    rust_tree_sitter::cli::commands::security::render_security_markdown(res, summary_only, compliance, filtered)
}

#[test]
fn ast_security_markdown_snapshot_is_stable_for_empty() {
    let findings: Vec<rust_tree_sitter::security::ast_analyzer::SecurityFinding> = vec![];
    let md = render_ast_security_markdown_wrapper(&findings, true, 0, 0);
    assert!(md.contains("# 🔍 AST-Based Security Analysis Report"));
    assert!(md.contains("## 📊 Executive Summary"));
}

fn render_ast_security_markdown_wrapper(
    findings: &[rust_tree_sitter::security::ast_analyzer::SecurityFinding],
    summary_only: bool,
    analyzed: usize,
    failed: usize,
) -> String {
    rust_tree_sitter::cli::commands::ast_security::render_ast_security_markdown(findings, summary_only, analyzed, failed)
}
