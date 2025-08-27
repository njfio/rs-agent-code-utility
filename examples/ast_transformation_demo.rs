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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 AST Transformation Engine Demo");
    println!("==================================\n");

    // Create transformation engine with default configuration
    let engine = AstTransformationEngine::new();
    println!("✅ Created AST transformation engine");

    // Example 1: Simple string replacement
    println!("\n📝 Example 1: Simple String Replacement");
    println!("----------------------------------------");
    
    let source1 = r#"fn main() {
    println!("Hello, world!");
    let x = 42;
}"#;
    
    println!("Original code:");
    println!("{}", source1);
    
    let transformation1 = Transformation {
        id: "replace_greeting".to_string(),
        transformation_type: TransformationType::Replace,
        target_location: TransformationLocation {
            file_path: PathBuf::from("example.rs"),
            start_position: Position {
                line: 1,
                column: 13,
                byte_offset: 25,
            },
            end_position: Position {
                line: 1,
                column: 28,
                byte_offset: 40,
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
    
    let result1 = engine.apply_transformation(source1, Language::Rust, &transformation1)?;
    
    if result1.success {
        println!("\n✅ Transformation successful!");
        println!("Updated code:");
        println!("{}", result1.updated_source);
        println!("Confidence: {:.1}%", result1.validation_summary.overall_confidence * 100.0);
    } else {
        println!("❌ Transformation failed");
        for failure in &result1.failed_transformations {
            println!("  Reason: {}", failure.failure_reason);
        }
    }

    // Example 2: Multiple transformations
    println!("\n📝 Example 2: Multiple Transformations");
    println!("--------------------------------------");
    
    let source2 = r#"fn calculate() {
    let a = 5;
    let b = 10;
    println!("Result: {}", a + b);
}"#;
    
    println!("Original code:");
    println!("{}", source2);
    
    let transformations = vec![
        Transformation {
            id: "change_value_a".to_string(),
            transformation_type: TransformationType::Replace,
            target_location: TransformationLocation {
                file_path: PathBuf::from("example.rs"),
                start_position: Position {
                    line: 1,
                    column: 12,
                    byte_offset: 28,
                },
                end_position: Position {
                    line: 1,
                    column: 13,
                    byte_offset: 29,
                },
                node_kind: "integer_literal".to_string(),
            },
            original_code: "5".to_string(),
            new_code: "15".to_string(),
            metadata: TransformationMetadata {
                description: "Change value of a from 5 to 15".to_string(),
                confidence: 1.0,
                impact: TransformationImpact {
                    scope: ImpactScope::Local,
                    risk_level: RiskLevel::Low,
                    affected_lines: 1,
                    affected_functions: vec!["calculate".to_string()],
                    affected_variables: vec!["a".to_string()],
                },
                dependencies: Vec::new(),
                rollback_info: None,
            },
            validation_result: None,
        },
        Transformation {
            id: "change_value_b".to_string(),
            transformation_type: TransformationType::Replace,
            target_location: TransformationLocation {
                file_path: PathBuf::from("example.rs"),
                start_position: Position {
                    line: 2,
                    column: 12,
                    byte_offset: 43,
                },
                end_position: Position {
                    line: 2,
                    column: 14,
                    byte_offset: 45,
                },
                node_kind: "integer_literal".to_string(),
            },
            original_code: "10".to_string(),
            new_code: "25".to_string(),
            metadata: TransformationMetadata {
                description: "Change value of b from 10 to 25".to_string(),
                confidence: 1.0,
                impact: TransformationImpact {
                    scope: ImpactScope::Local,
                    risk_level: RiskLevel::Low,
                    affected_lines: 1,
                    affected_functions: vec!["calculate".to_string()],
                    affected_variables: vec!["b".to_string()],
                },
                dependencies: Vec::new(),
                rollback_info: None,
            },
            validation_result: None,
        },
    ];
    
    let result2 = engine.apply_transformations(source2, Language::Rust, &transformations)?;
    
    if result2.success {
        println!("\n✅ All transformations successful!");
        println!("Updated code:");
        println!("{}", result2.updated_source);
        println!("Applied {} transformations", result2.applied_transformations.len());
        println!("Overall confidence: {:.1}%", result2.validation_summary.overall_confidence * 100.0);
    } else {
        println!("❌ Some transformations failed");
        println!("Applied {} transformations", result2.applied_transformations.len());
        println!("Failed {} transformations", result2.failed_transformations.len());
    }

    // Example 3: Semantic validation
    println!("\n📝 Example 3: Semantic Validation");
    println!("----------------------------------");
    
    let config = ValidationConfig {
        enable_scope_analysis: true,
        enable_type_checking: true,
        enable_control_flow_analysis: true,
        enable_data_flow_analysis: true,
        strict_mode: false,
    };
    
    let validator = SemanticValidator::with_config(config);
    let parser = Parser::new(Language::Rust)?;
    let source3 = "fn test() { let x = 42; println!(\"{}\", x); }";
    let tree = parser.parse(source3, None)?;
    
    println!("Source code: {}", source3);
    
    let transformation3 = Transformation {
        id: "rename_variable".to_string(),
        transformation_type: TransformationType::Rename,
        target_location: TransformationLocation {
            file_path: PathBuf::from("example.rs"),
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
        new_code: "value".to_string(),
        metadata: TransformationMetadata {
            description: "Rename variable x to value".to_string(),
            confidence: 0.9,
            impact: TransformationImpact {
                scope: ImpactScope::Local,
                risk_level: RiskLevel::Low,
                affected_lines: 1,
                affected_functions: vec!["test".to_string()],
                affected_variables: vec!["x".to_string()],
            },
            dependencies: Vec::new(),
            rollback_info: None,
        },
        validation_result: None,
    };
    
    let validation_result = validator.validate_transformation(&tree, &transformation3, Language::Rust)?;
    
    println!("\n🔍 Validation Results:");
    println!("  Valid: {}", validation_result.is_valid);
    println!("  Confidence: {:.1}%", validation_result.confidence * 100.0);
    println!("  Errors: {}", validation_result.errors.len());
    println!("  Warnings: {}", validation_result.warnings.len());
    
    if !validation_result.errors.is_empty() {
        println!("  Validation Errors:");
        for error in &validation_result.errors {
            println!("    - {}: {}", error.code, error.message);
        }
    }
    
    if !validation_result.warnings.is_empty() {
        println!("  Validation Warnings:");
        for warning in &validation_result.warnings {
            println!("    - {}: {}", warning.code, warning.message);
        }
    }

    // Example 4: Configuration options
    println!("\n📝 Example 4: Custom Configuration");
    println!("-----------------------------------");
    
    let custom_config = TransformationConfig {
        enable_semantic_validation: true,
        enable_rollback: true,
        max_transformation_depth: 5,
        enable_safety_checks: true,
        preserve_formatting: true,
        enable_incremental: false,
    };
    
    let _custom_engine = AstTransformationEngine::with_config(custom_config);
    
    println!("✅ Created custom transformation engine with:");
    println!("  - Semantic validation: enabled");
    println!("  - Rollback support: enabled");
    println!("  - Max transformation depth: 5");
    println!("  - Safety checks: enabled");
    println!("  - Preserve formatting: enabled");
    println!("  - Incremental mode: disabled");

    println!("\n🎉 AST Transformation Engine Demo Complete!");
    println!("The engine provides safe, validated code transformations with:");
    println!("  • Syntax validation to prevent broken code");
    println!("  • Semantic analysis for transformation safety");
    println!("  • Multiple transformation types (replace, insert, delete, etc.)");
    println!("  • Configurable validation and safety checks");
    println!("  • Language-specific transformation rules");
    println!("  • Rollback capabilities for failed transformations");

    Ok(())
}
