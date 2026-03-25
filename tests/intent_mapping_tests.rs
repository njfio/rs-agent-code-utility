use rust_tree_sitter::{
    AnalysisConfig, AnalysisResult, FileInfo, ImplementationStatus, ImplementationType,
    IntentMappingSystem, MappingConfig, Priority, Requirement, RequirementStatus, RequirementType,
    Symbol,
};
use std::collections::HashMap;
use std::path::PathBuf;

fn sample_requirement() -> Requirement {
    Requirement {
        id: "REQ-LOGIN".to_string(),
        requirement_type: RequirementType::Functional,
        description: "login auth".to_string(),
        priority: Priority::High,
        acceptance_criteria: vec!["users can login".to_string()],
        stakeholders: vec!["security".to_string()],
        tags: vec!["auth".to_string(), "login".to_string()],
        status: RequirementStatus::Approved,
    }
}

fn sample_analysis() -> AnalysisResult {
    let mut languages = HashMap::new();
    languages.insert("Rust".to_string(), 1);

    AnalysisResult {
        root_path: PathBuf::from("."),
        total_files: 1,
        parsed_files: 1,
        error_files: 0,
        total_lines: 12,
        languages,
        files: vec![FileInfo {
            path: PathBuf::from("src/auth.rs"),
            language: "Rust".to_string(),
            size: 128,
            lines: 12,
            parsed_successfully: true,
            parse_errors: Vec::new(),
            symbols: vec![Symbol {
                name: "login".to_string(),
                kind: "function".to_string(),
                start_line: 1,
                end_line: 3,
                start_column: 0,
                end_column: 5,
                visibility: "public".to_string(),
                documentation: Some("Authenticate a user".to_string()),
            }],
            security_vulnerabilities: Vec::new(),
        }],
        config: AnalysisConfig::default(),
    }
}

#[test]
fn test_intent_mapping_system_baseline_public_api() {
    let config = MappingConfig {
        confidence_threshold: 0.5,
        enable_nlp: true,
        enable_semantic_analysis: false,
        max_mapping_distance: 0.9,
        auto_validation_threshold: 0.95,
    };
    let system = IntentMappingSystem::with_config(config);

    assert!(system.requirements().is_empty());
    assert!(system.implementations().is_empty());
    assert!(system.mappings().is_empty());
    assert_eq!(system.config().confidence_threshold, 0.5);
    assert!(!system.has_embeddings());
}

#[test]
fn test_extract_implementations_from_analysis_result() -> rust_tree_sitter::Result<()> {
    let mut system = IntentMappingSystem::new();
    let analysis = sample_analysis();

    system.extract_implementations(&analysis)?;

    assert_eq!(system.implementations().len(), 1);
    assert_eq!(
        system.implementations()[0].implementation_type,
        ImplementationType::Module
    );
    assert_eq!(
        system.implementations()[0].status,
        ImplementationStatus::Complete
    );
    assert_eq!(system.implementations()[0].code_elements.len(), 1);
    assert_eq!(system.implementations()[0].code_elements[0].name, "login");

    Ok(())
}

#[test]
fn test_generate_mappings_and_traceability_without_ml() -> rust_tree_sitter::Result<()> {
    let mut system = IntentMappingSystem::with_config(MappingConfig {
        confidence_threshold: 0.5,
        enable_nlp: true,
        enable_semantic_analysis: false,
        max_mapping_distance: 0.9,
        auto_validation_threshold: 0.95,
    });
    let analysis = sample_analysis();
    let requirement = sample_requirement();

    system.add_requirement(requirement.clone());
    let mappings = system.generate_mappings(&analysis)?;
    let traceability = system.build_traceability_matrix()?;
    let report = system.get_traceability_report();

    assert!(mappings
        .iter()
        .any(|mapping| mapping.requirement_id == requirement.id));
    assert!(mappings
        .iter()
        .any(|mapping| mapping.implementation_id == "impl_src/auth.rs"));
    assert!(traceability.forward_trace.contains_key(&requirement.id));
    assert_eq!(traceability.coverage_metrics.requirement_coverage, 1.0);
    assert!(report.orphaned_requirements.is_empty());
    assert!(report.orphaned_implementations.is_empty());

    Ok(())
}
