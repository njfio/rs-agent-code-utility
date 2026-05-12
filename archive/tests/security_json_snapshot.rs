#[test]
fn security_json_snapshot_basic_fields() {
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
    let json = serde_json::to_string_pretty(&result).unwrap();
    assert!(json.contains("security_score"));
    assert!(json.contains("total_vulnerabilities"));
}

