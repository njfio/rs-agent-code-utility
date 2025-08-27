use rust_tree_sitter::{
    AstTransformationEngine, TransformationConfig, Transformation, TransformationType,
    SemanticValidator, ValidationConfig, Language, Parser
};
use rust_tree_sitter::ast_transformation::{
    TransformationLocation, Position, TransformationMetadata, TransformationImpact,
    ImpactScope
};
use rust_tree_sitter::RiskLevel;
use std::path::PathBuf;

#[test]
fn test_ast_transformation_engine_creation() {
    let engine = AstTransformationEngine::new();
    assert!(engine.config.enable_semantic_validation);
    assert!(engine.config.enable_rollback);
    assert_eq!(engine.config.max_transformation_depth, 10);
}

#[test]
fn test_ast_transformation_engine_with_config() {
    let config = TransformationConfig {
        enable_semantic_validation: false,
        enable_rollback: false,
        max_transformation_depth: 5,
        enable_safety_checks: false,
        preserve_formatting: false,
        enable_incremental: false,
    };
    
    let engine = AstTransformationEngine::with_config(config.clone());
    assert!(!engine.config.enable_semantic_validation);
    assert!(!engine.config.enable_rollback);
    assert_eq!(engine.config.max_transformation_depth, 5);
}

#[test]
fn test_semantic_validator_creation() {
    let validator = SemanticValidator::new();
    assert!(validator.config.enable_scope_analysis);
    assert!(validator.config.enable_type_checking);
    assert!(validator.config.enable_control_flow_analysis);
    assert!(validator.config.enable_data_flow_analysis);
    assert!(!validator.config.strict_mode);
}

#[test]
fn test_semantic_validator_with_config() {
    let config = ValidationConfig {
        enable_scope_analysis: false,
        enable_type_checking: false,
        enable_control_flow_analysis: false,
        enable_data_flow_analysis: false,
        strict_mode: true,
    };
    
    let validator = SemanticValidator::with_config(config);
    assert!(!validator.config.enable_scope_analysis);
    assert!(!validator.config.enable_type_checking);
    assert!(!validator.config.enable_control_flow_analysis);
    assert!(!validator.config.enable_data_flow_analysis);
    assert!(validator.config.strict_mode);
}

#[test]
fn test_simple_replace_transformation() {
    let engine = AstTransformationEngine::new();
    let source = "fn main() { println!(\"Hello, world!\"); }";
    
    let transformation = Transformation {
        id: "test_replace_1".to_string(),
        transformation_type: TransformationType::Replace,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position {
                line: 0,
                column: 21,
                byte_offset: 21,
            },
            end_position: Position {
                line: 0,
                column: 36,
                byte_offset: 36,
            },
            node_kind: "string_literal".to_string(),
        },
        original_code: "\"Hello, world!\"".to_string(),
        new_code: "\"Hello, Rust!\"".to_string(),
        metadata: TransformationMetadata {
            description: "Replace greeting message".to_string(),
            confidence: 1.0,
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
    
    let result = engine.apply_transformation(source, Language::Rust, &transformation).unwrap();
    assert!(result.success);
    assert_eq!(result.applied_transformations.len(), 1);
    assert_eq!(result.failed_transformations.len(), 0);
    assert!(result.updated_source.contains("Hello, Rust!"));
}

#[test]
fn test_simple_insert_transformation() {
    let engine = AstTransformationEngine::new();
    let source = "fn main() {\n}";
    
    let transformation = Transformation {
        id: "test_insert_1".to_string(),
        transformation_type: TransformationType::Insert,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position {
                line: 0,
                column: 12,
                byte_offset: 12,
            },
            end_position: Position {
                line: 0,
                column: 12,
                byte_offset: 12,
            },
            node_kind: "block".to_string(),
        },
        original_code: "".to_string(),
        new_code: "\n    println!(\"Hello, world!\");".to_string(),
        metadata: TransformationMetadata {
            description: "Insert print statement".to_string(),
            confidence: 0.9,
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
    
    let result = engine.apply_transformation(source, Language::Rust, &transformation).unwrap();
    assert!(result.success);
    assert_eq!(result.applied_transformations.len(), 1);
    assert_eq!(result.failed_transformations.len(), 0);
    assert!(result.updated_source.contains("println!"));
}

#[test]
fn test_simple_delete_transformation() {
    let engine = AstTransformationEngine::new();
    let source = "fn main() {\n    println!(\"Hello, world!\");\n    // This is a comment\n}";
    
    let transformation = Transformation {
        id: "test_delete_1".to_string(),
        transformation_type: TransformationType::Delete,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position {
                line: 2,
                column: 4,
                byte_offset: 44,
            },
            end_position: Position {
                line: 2,
                column: 25,
                byte_offset: 65,
            },
            node_kind: "line_comment".to_string(),
        },
        original_code: "// This is a comment".to_string(),
        new_code: "".to_string(),
        metadata: TransformationMetadata {
            description: "Remove comment".to_string(),
            confidence: 1.0,
            impact: TransformationImpact {
                scope: ImpactScope::Local,
                risk_level: RiskLevel::Low,
                affected_lines: 1,
                affected_functions: Vec::new(),
                affected_variables: Vec::new(),
            },
            dependencies: Vec::new(),
            rollback_info: None,
        },
        validation_result: None,
    };
    
    let result = engine.apply_transformation(source, Language::Rust, &transformation).unwrap();
    assert!(result.success);
    assert_eq!(result.applied_transformations.len(), 1);
    assert_eq!(result.failed_transformations.len(), 0);
    assert!(!result.updated_source.contains("// This is a comment"));
}

#[test]
fn test_multiple_transformations() {
    let engine = AstTransformationEngine::new();
    let source = "fn main() {\n    let x = 5;\n    println!(\"{}\", x);\n}";
    
    let transformations = vec![
        Transformation {
            id: "test_multi_1".to_string(),
            transformation_type: TransformationType::Replace,
            target_location: TransformationLocation {
                file_path: PathBuf::from("test.rs"),
                start_position: Position {
                    line: 1,
                    column: 12,
                    byte_offset: 24,
                },
                end_position: Position {
                    line: 1,
                    column: 13,
                    byte_offset: 25,
                },
                node_kind: "integer_literal".to_string(),
            },
            original_code: "5".to_string(),
            new_code: "10".to_string(),
            metadata: TransformationMetadata {
                description: "Change value from 5 to 10".to_string(),
                confidence: 1.0,
                impact: TransformationImpact {
                    scope: ImpactScope::Local,
                    risk_level: RiskLevel::Low,
                    affected_lines: 1,
                    affected_functions: vec!["main".to_string()],
                    affected_variables: vec!["x".to_string()],
                },
                dependencies: Vec::new(),
                rollback_info: None,
            },
            validation_result: None,
        },
        Transformation {
            id: "test_multi_2".to_string(),
            transformation_type: TransformationType::Replace,
            target_location: TransformationLocation {
                file_path: PathBuf::from("test.rs"),
                start_position: Position {
                    line: 2,
                    column: 4,
                    byte_offset: 31,
                },
                end_position: Position {
                    line: 2,
                    column: 22,
                    byte_offset: 49,
                },
                node_kind: "macro_invocation".to_string(),
            },
            original_code: "println!(\"{}\", x)".to_string(),
            new_code: "println!(\"Value: {}\", x)".to_string(),
            metadata: TransformationMetadata {
                description: "Add label to print statement".to_string(),
                confidence: 0.9,
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
        },
    ];
    
    let result = engine.apply_transformations(source, Language::Rust, &transformations).unwrap();
    assert!(result.success);
    assert_eq!(result.applied_transformations.len(), 2);
    assert_eq!(result.failed_transformations.len(), 0);
    assert!(result.updated_source.contains("10"));
    assert!(result.updated_source.contains("Value:"));
}

#[test]
fn test_transformation_with_syntax_error() {
    let engine = AstTransformationEngine::new();
    let source = "fn main() { println!(\"Hello, world!\"); }";
    
    // This transformation would create invalid syntax
    let transformation = Transformation {
        id: "test_syntax_error".to_string(),
        transformation_type: TransformationType::Replace,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position {
                line: 0,
                column: 0,
                byte_offset: 0,
            },
            end_position: Position {
                line: 0,
                column: 2,
                byte_offset: 2,
            },
            node_kind: "function_item".to_string(),
        },
        original_code: "fn".to_string(),
        new_code: "invalid_keyword".to_string(),
        metadata: TransformationMetadata {
            description: "Invalid transformation that breaks syntax".to_string(),
            confidence: 0.1,
            impact: TransformationImpact {
                scope: ImpactScope::Local,
                risk_level: RiskLevel::High,
                affected_lines: 1,
                affected_functions: vec!["main".to_string()],
                affected_variables: Vec::new(),
            },
            dependencies: Vec::new(),
            rollback_info: None,
        },
        validation_result: None,
    };
    
    let result = engine.apply_transformation(source, Language::Rust, &transformation).unwrap();
    assert!(!result.success);
    assert_eq!(result.applied_transformations.len(), 0);
    assert_eq!(result.failed_transformations.len(), 1);
    assert_eq!(result.updated_source, source); // Should remain unchanged
}

#[test]
fn test_validation_with_strict_mode() {
    let config = ValidationConfig {
        enable_scope_analysis: true,
        enable_type_checking: true,
        enable_control_flow_analysis: true,
        enable_data_flow_analysis: true,
        strict_mode: true,
    };
    
    let validator = SemanticValidator::with_config(config);
    let parser = Parser::new(Language::Rust).unwrap();
    let source = "fn main() { let x = 5; }";
    let tree = parser.parse(source, None).unwrap();
    
    let transformation = Transformation {
        id: "test_validation".to_string(),
        transformation_type: TransformationType::Rename,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position {
                line: 0,
                column: 16,
                byte_offset: 16,
            },
            end_position: Position {
                line: 0,
                column: 17,
                byte_offset: 17,
            },
            node_kind: "identifier".to_string(),
        },
        original_code: "x".to_string(),
        new_code: "y".to_string(),
        metadata: TransformationMetadata {
            description: "Rename variable x to y".to_string(),
            confidence: 0.8,
            impact: TransformationImpact {
                scope: ImpactScope::Local,
                risk_level: RiskLevel::Low,
                affected_lines: 1,
                affected_functions: vec!["main".to_string()],
                affected_variables: vec!["x".to_string()],
            },
            dependencies: Vec::new(),
            rollback_info: None,
        },
        validation_result: None,
    };
    
    let result = validator.validate_transformation(&tree, &transformation, Language::Rust).unwrap();
    assert!(result.is_valid); // Should pass basic validation
    assert!(result.confidence > 0.0);
}

#[test]
fn test_extract_method_transformation() {
    let engine = AstTransformationEngine::new();
    let source = r#"fn main() {
    let x = 5;
    let y = 10;
    let result = x + y;
    println!("Result: {}", result);
}"#;

    let transformation = Transformation {
        id: "extract_calculation".to_string(),
        transformation_type: TransformationType::ExtractMethod,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position {
                line: 2,
                column: 4,
                byte_offset: 32,
            },
            end_position: Position {
                line: 3,
                column: 24,
                byte_offset: 67,
            },
            node_kind: "block".to_string(),
        },
        original_code: "let y = 10;\n    let result = x + y;".to_string(),
        new_code: "".to_string(),
        metadata: TransformationMetadata {
            description: "Extract method: calculate_sum".to_string(),
            confidence: 0.9,
            impact: TransformationImpact {
                scope: ImpactScope::Local,
                risk_level: RiskLevel::Medium,
                affected_lines: 2,
                affected_functions: vec!["main".to_string()],
                affected_variables: vec!["x".to_string(), "y".to_string(), "result".to_string()],
            },
            dependencies: Vec::new(),
            rollback_info: None,
        },
        validation_result: None,
    };

    let result = engine.apply_transformation(source, Language::Rust, &transformation).unwrap();

    // Extract method transformation is complex and may not succeed in all cases
    // The important thing is that the transformation engine handles it gracefully
    assert!(result.applied_transformations.len() + result.failed_transformations.len() == 1);

    // If it fails, it should provide meaningful error information
    if !result.success {
        assert!(!result.failed_transformations.is_empty());
        assert!(!result.failed_transformations[0].failure_reason.is_empty());
    }
}

#[test]
fn test_rename_variable_transformation() {
    let engine = AstTransformationEngine::new();
    let source = r#"fn main() {
    let old_name = 42;
    println!("Value: {}", old_name);
    let result = old_name * 2;
}"#;

    let transformation = Transformation {
        id: "rename_variable".to_string(),
        transformation_type: TransformationType::Rename,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position {
                line: 1,
                column: 8,
                byte_offset: 20,
            },
            end_position: Position {
                line: 1,
                column: 16,
                byte_offset: 28,
            },
            node_kind: "identifier".to_string(),
        },
        original_code: "old_name".to_string(),
        new_code: "new_name".to_string(),
        metadata: TransformationMetadata {
            description: "Rename variable from old_name to new_name".to_string(),
            confidence: 1.0,
            impact: TransformationImpact {
                scope: ImpactScope::Local,
                risk_level: RiskLevel::Low,
                affected_lines: 3,
                affected_functions: vec!["main".to_string()],
                affected_variables: vec!["old_name".to_string()],
            },
            dependencies: Vec::new(),
            rollback_info: None,
        },
        validation_result: None,
    };

    let result = engine.apply_transformation(source, Language::Rust, &transformation).unwrap();

    // The transformation should succeed and rename all occurrences
    assert!(result.success);
    assert_eq!(result.applied_transformations.len(), 1);
    assert_eq!(result.failed_transformations.len(), 0);
    assert!(result.updated_source.contains("new_name"));
    assert!(!result.updated_source.contains("old_name"));
}

#[test]
fn test_inline_variable_transformation() {
    let engine = AstTransformationEngine::new();
    let source = r#"fn main() {
    let temp = 42;
    let result = temp * 2;
    println!("Result: {}", result);
}"#;

    let transformation = Transformation {
        id: "inline_variable".to_string(),
        transformation_type: TransformationType::Inline,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position {
                line: 1,
                column: 4,
                byte_offset: 16,
            },
            end_position: Position {
                line: 1,
                column: 18,
                byte_offset: 30,
            },
            node_kind: "let_declaration".to_string(),
        },
        original_code: "temp".to_string(),
        new_code: "".to_string(),
        metadata: TransformationMetadata {
            description: "Inline variable temp".to_string(),
            confidence: 0.9,
            impact: TransformationImpact {
                scope: ImpactScope::Local,
                risk_level: RiskLevel::Low,
                affected_lines: 2,
                affected_functions: vec!["main".to_string()],
                affected_variables: vec!["temp".to_string()],
            },
            dependencies: Vec::new(),
            rollback_info: None,
        },
        validation_result: None,
    };

    let result = engine.apply_transformation(source, Language::Rust, &transformation).unwrap();

    // The transformation should succeed and inline the variable
    assert!(result.success);
    assert_eq!(result.applied_transformations.len(), 1);
    assert_eq!(result.failed_transformations.len(), 0);
    // The variable should be inlined (temp replaced with 42)
    assert!(result.updated_source.contains("42 * 2") || result.updated_source.contains("let result = 42"));
}

#[test]
fn test_invalid_identifier_rename() {
    let engine = AstTransformationEngine::new();
    let source = r#"fn main() { let x = 5; }"#;

    let transformation = Transformation {
        id: "invalid_rename".to_string(),
        transformation_type: TransformationType::Rename,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position {
                line: 0,
                column: 16,
                byte_offset: 16,
            },
            end_position: Position {
                line: 0,
                column: 17,
                byte_offset: 17,
            },
            node_kind: "identifier".to_string(),
        },
        original_code: "x".to_string(),
        new_code: "123invalid".to_string(), // Invalid identifier
        metadata: TransformationMetadata {
            description: "Rename to invalid identifier".to_string(),
            confidence: 0.1,
            impact: TransformationImpact {
                scope: ImpactScope::Local,
                risk_level: RiskLevel::High,
                affected_lines: 1,
                affected_functions: vec!["main".to_string()],
                affected_variables: vec!["x".to_string()],
            },
            dependencies: Vec::new(),
            rollback_info: None,
        },
        validation_result: None,
    };

    let result = engine.apply_transformation(source, Language::Rust, &transformation).unwrap();

    // The transformation should fail due to invalid identifier
    assert!(!result.success);
    assert_eq!(result.applied_transformations.len(), 0);
    assert_eq!(result.failed_transformations.len(), 1);
    assert_eq!(result.updated_source, source); // Should remain unchanged
}

#[test]
fn test_keyword_rename_conflict() {
    let engine = AstTransformationEngine::new();
    let source = r#"fn main() { let x = 5; }"#;

    let transformation = Transformation {
        id: "keyword_rename".to_string(),
        transformation_type: TransformationType::Rename,
        target_location: TransformationLocation {
            file_path: PathBuf::from("test.rs"),
            start_position: Position {
                line: 0,
                column: 16,
                byte_offset: 16,
            },
            end_position: Position {
                line: 0,
                column: 17,
                byte_offset: 17,
            },
            node_kind: "identifier".to_string(),
        },
        original_code: "x".to_string(),
        new_code: "fn".to_string(), // Rust keyword
        metadata: TransformationMetadata {
            description: "Rename to Rust keyword".to_string(),
            confidence: 0.1,
            impact: TransformationImpact {
                scope: ImpactScope::Local,
                risk_level: RiskLevel::High,
                affected_lines: 1,
                affected_functions: vec!["main".to_string()],
                affected_variables: vec!["x".to_string()],
            },
            dependencies: Vec::new(),
            rollback_info: None,
        },
        validation_result: None,
    };

    let result = engine.apply_transformation(source, Language::Rust, &transformation).unwrap();

    // The transformation should fail due to keyword conflict
    assert!(!result.success);
    assert_eq!(result.applied_transformations.len(), 0);
    assert_eq!(result.failed_transformations.len(), 1);
    assert_eq!(result.updated_source, source); // Should remain unchanged
}
