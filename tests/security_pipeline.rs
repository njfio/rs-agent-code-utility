use rust_tree_sitter::security::{SecurityFindingType, SecurityPipelineConfig};
use rust_tree_sitter::{ConfidenceSource, Language, SecurityPipeline};
use tempfile::TempDir;

#[test]
fn test_security_pipeline_hides_heuristic_findings_by_default() {
    let pipeline = SecurityPipeline::new().unwrap();
    let source = r#"
        fn delete_user(user_id: &str) {
            let _id = user_id;
        }
    "#;

    let findings = pipeline
        .analyze_with_path(source, std::path::Path::new("src/admin.rs"), Language::Rust)
        .unwrap();

    assert!(
        findings.is_empty(),
        "heuristic-only findings should be hidden below the default 0.5 threshold"
    );
}

#[test]
fn test_security_pipeline_can_include_lower_confidence_heuristics() {
    let pipeline = SecurityPipeline::with_config(SecurityPipelineConfig {
        min_confidence: 0.4,
        ..SecurityPipelineConfig::default()
    })
    .unwrap();
    let source = r#"
        fn delete_user(user_id: &str) {
            let _id = user_id;
        }
    "#;

    let findings = pipeline
        .analyze_with_path(source, std::path::Path::new("src/admin.rs"), Language::Rust)
        .unwrap();

    assert!(
        findings.iter().any(|finding| {
            finding.finding_type == SecurityFindingType::BrokenAccessControl
                && finding.confidence_source == ConfidenceSource::Heuristic
        }),
        "lowering the threshold should surface the heuristic broken-access-control finding"
    );
    assert!(findings.iter().all(|finding| finding.confidence >= 0.4));
}

#[test]
fn test_security_pipeline_keeps_ast_backed_findings_at_or_above_default_threshold() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("admin.rs");
    let source = r#"
        fn delete_user(user_id: &str) {
            let _id = user_id;
        }
    "#;

    std::fs::write(&file_path, source).unwrap();

    let pipeline = SecurityPipeline::with_config(SecurityPipelineConfig {
        min_confidence: 0.4,
        ..SecurityPipelineConfig::default()
    })
    .unwrap();
    let findings = pipeline.analyze_file(&file_path, Language::Rust).unwrap();

    assert!(
        findings.iter().any(|finding| {
            finding.finding_type == SecurityFindingType::BrokenAccessControl
                && finding.confidence_source == ConfidenceSource::Heuristic
        }),
        "the file-based pipeline path should surface the same heuristic finding as the in-memory path"
    );
    assert!(findings.iter().all(|finding| finding.confidence >= 0.4));
}
