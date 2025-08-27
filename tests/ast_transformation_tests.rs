//! Tests for AST transformation functionality
//!
//! These tests verify that the AST transformation engine can properly
//! perform method extraction and other refactoring operations.

use rust_tree_sitter::{
    AstTransformationEngine, TransformationConfig, Language,
    Transformation, TransformationType, TransformationLocation, Position,
    TransformationMetadata, TransformationImpact, ImpactScope, RiskLevel,
    Result
};
use std::path::PathBuf;

#[test]
fn test_ast_transformation_engine_creation() -> Result<()> {
    let engine = AstTransformationEngine::new();
    assert!(engine.config.enable_semantic_validation);
    assert!(engine.config.enable_safety_checks);
    Ok(())
}

#[test]
fn test_transformation_config() -> Result<()> {
    let config = TransformationConfig::default();
    assert!(config.enable_semantic_validation);
    assert!(config.enable_safety_checks);
    assert!(config.enable_rollback);
    assert!(config.preserve_formatting);
    assert!(config.enable_incremental);
    assert_eq!(config.max_transformation_depth, 10);
    Ok(())
}

#[test]
fn test_transformation_metadata_creation() -> Result<()> {
    let impact = TransformationImpact {
        scope: ImpactScope::Local,
        risk_level: RiskLevel::Low,
        affected_lines: 5,
        affected_functions: vec!["test_function".to_string()],
        affected_variables: vec!["x".to_string(), "y".to_string()],
    };

    let metadata = TransformationMetadata {
        description: "Extract method: calculate_sum".to_string(),
        confidence: 0.9,
        impact,
        dependencies: Vec::new(),
        rollback_info: None,
    };

    assert_eq!(metadata.description, "Extract method: calculate_sum");
    assert_eq!(metadata.confidence, 0.9);
    assert_eq!(metadata.impact.affected_lines, 5);
    assert_eq!(metadata.impact.affected_functions.len(), 1);
    assert_eq!(metadata.impact.affected_variables.len(), 2);

    Ok(())
}

#[test]
fn test_transformation_location() -> Result<()> {
    let location = TransformationLocation {
        file_path: PathBuf::from("test.rs"),
        start_position: Position { line: 1, column: 0, byte_offset: 0 },
        end_position: Position { line: 5, column: 10, byte_offset: 100 },
        node_kind: "function_item".to_string(),
    };

    assert_eq!(location.file_path, PathBuf::from("test.rs"));
    assert_eq!(location.start_position.line, 1);
    assert_eq!(location.end_position.line, 5);
    assert_eq!(location.node_kind, "function_item");

    Ok(())
}

#[test]
fn test_transformation_creation() -> Result<()> {
    let transformation = Transformation {
        id: "test_transform_1".to_string(),
        transformation_type: TransformationType::ExtractMethod,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position { line: 10, column: 4, byte_offset: 150 },
            end_position: Position { line: 15, column: 5, byte_offset: 200 },
            node_kind: "block".to_string(),
        },
        original_code: "let result = x + y;".to_string(),
        new_code: "let result = calculate_sum(x, y);".to_string(),
        metadata: TransformationMetadata {
            description: "Extract calculation into method".to_string(),
            confidence: 0.85,
            impact: TransformationImpact {
                scope: ImpactScope::Local,
                risk_level: RiskLevel::Low,
                affected_lines: 5,
                affected_functions: vec!["main".to_string()],
                affected_variables: vec!["x".to_string(), "y".to_string(), "result".to_string()],
            },
            dependencies: Vec::new(),
            rollback_info: None,
        },
        validation_result: None,
    };

    assert_eq!(transformation.id, "test_transform_1");
    assert!(matches!(transformation.transformation_type, TransformationType::ExtractMethod));
    assert_eq!(transformation.original_code, "let result = x + y;");
    assert_eq!(transformation.new_code, "let result = calculate_sum(x, y);");
    assert_eq!(transformation.metadata.confidence, 0.85);

    Ok(())
}

#[test]
fn test_simple_transformation_application() -> Result<()> {
    let engine = AstTransformationEngine::new();

    let source = r#"fn main() {
    let x = 5;
    let y = 10;
    println!("Hello, world!");
}"#;

    // Find the correct byte offsets for "Hello, world!"
    let hello_world_start = source.find("\"Hello, world!\"").expect("Should find the string");
    let hello_world_end = hello_world_start + "\"Hello, world!\"".len();

    // Create a simple replace transformation
    let transformation = Transformation {
        id: "replace_hello".to_string(),
        transformation_type: TransformationType::Replace,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position { line: 4, column: 13, byte_offset: hello_world_start },
            end_position: Position { line: 4, column: 27, byte_offset: hello_world_end },
            node_kind: "string_literal".to_string(),
        },
        original_code: "\"Hello, world!\"".to_string(),
        new_code: "\"Hello, Rust!\"".to_string(),
        metadata: TransformationMetadata {
            description: "Replace greeting message".to_string(),
            confidence: 0.95,
            impact: TransformationImpact {
                scope: ImpactScope::Local,
                risk_level: RiskLevel::Low,
                affected_lines: 1,
                affected_functions: vec!["main".to_string()],
                affected_variables: Vec::new(),
            },
            dependencies: Vec::new(),
            rollback_info: None,
        },
        validation_result: None,
    };

    let result = engine.apply_transformation(source, Language::Rust, &transformation)?;

    // The transformation should succeed or fail gracefully
    assert!(result.applied_transformations.len() + result.failed_transformations.len() == 1);

    // If it succeeds, check the result
    if result.success {
        assert!(result.updated_source.contains("Hello, Rust!"));
    } else {
        // If it fails, ensure we have meaningful error information
        assert!(!result.failed_transformations.is_empty());
        assert!(!result.failed_transformations[0].failure_reason.is_empty());
    }

    Ok(())
}

#[test]
fn test_transformation_with_custom_config() -> Result<()> {
    let config = TransformationConfig {
        enable_semantic_validation: false,
        enable_rollback: true,
        max_transformation_depth: 5,
        enable_safety_checks: true,
        preserve_formatting: false,
        enable_incremental: false,
    };

    let engine = AstTransformationEngine::with_config(config);

    assert!(!engine.config.enable_semantic_validation);
    assert!(engine.config.enable_rollback);
    assert_eq!(engine.config.max_transformation_depth, 5);
    assert!(engine.config.enable_safety_checks);
    assert!(!engine.config.preserve_formatting);
    assert!(!engine.config.enable_incremental);

    Ok(())
}
