# AST Transformation Engine

The AST Transformation Engine provides safe, semantic-preserving code transformations for supported programming languages. It enables automated refactoring, code modifications, and structural changes while maintaining code correctness.

## Features

- **Safe Transformations**: Validates syntax and semantics before applying changes
- **Multiple Transformation Types**: Replace, insert, delete, rename, extract method, inline, move, reorder, wrap, unwrap
- **Language Support**: Rust, Python, JavaScript, TypeScript, Go, C, C++, Java
- **Semantic Validation**: Scope analysis, type checking, control flow analysis, data flow analysis
- **Rollback Capabilities**: Ability to undo transformations if they fail
- **Configurable Safety**: Adjustable validation levels and safety checks
- **Incremental Processing**: Support for large files with incremental transformations

## Core Components

### AstTransformationEngine

The main engine that orchestrates transformations:

```rust
use rust_tree_sitter::{AstTransformationEngine, TransformationConfig, Language};

// Create with default configuration
let engine = AstTransformationEngine::new();

// Create with custom configuration
let config = TransformationConfig {
    enable_semantic_validation: true,
    enable_rollback: true,
    max_transformation_depth: 10,
    enable_safety_checks: true,
    preserve_formatting: true,
    enable_incremental: true,
};
let engine = AstTransformationEngine::with_config(config);
```

### Transformation Types

The engine supports various transformation operations:

- **Replace**: Replace existing code with new code
- **Insert**: Insert new code at a specific location
- **Delete**: Remove code from a specific location
- **Rename**: Rename variables, functions, or other identifiers
- **ExtractMethod**: Extract code into a new method/function
- **Inline**: Inline variables or method calls
- **Move**: Move code between scopes or locations
- **Reorder**: Change the order of statements or declarations
- **Wrap**: Wrap code in new structures (blocks, conditionals, etc.)
- **Unwrap**: Remove wrapper structures

### Semantic Validation

The SemanticValidator ensures transformations are safe:

```rust
use rust_tree_sitter::{SemanticValidator, ValidationConfig};

let config = ValidationConfig {
    enable_scope_analysis: true,
    enable_type_checking: true,
    enable_control_flow_analysis: true,
    enable_data_flow_analysis: true,
    strict_mode: false,
};

let validator = SemanticValidator::with_config(config);
```

## Usage Examples

### Basic String Replacement

```rust
use rust_tree_sitter::{
    AstTransformationEngine, Transformation, TransformationType,
    Language, Parser
};
use rust_tree_sitter::ast_transformation::{
    TransformationLocation, Position, TransformationMetadata,
    TransformationImpact, ImpactScope, RiskLevel
};
use std::path::PathBuf;

let engine = AstTransformationEngine::new();
let source = r#"fn main() { println!("Hello, world!"); }"#;

let transformation = Transformation {
    id: "replace_greeting".to_string(),
    transformation_type: TransformationType::Replace,
    target_location: TransformationLocation {
        file_path: PathBuf::from("example.rs"),
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
            risk_level: RiskLevel::VeryLow,
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

if result.success {
    println!("Transformation successful!");
    println!("Updated code: {}", result.updated_source);
} else {
    println!("Transformation failed");
    for failure in &result.failed_transformations {
        println!("Reason: {}", failure.failure_reason);
    }
}
```

### Multiple Transformations

```rust
let transformations = vec![
    // First transformation
    Transformation { /* ... */ },
    // Second transformation
    Transformation { /* ... */ },
];

let result = engine.apply_transformations(source, Language::Rust, &transformations)?;

println!("Applied {} transformations", result.applied_transformations.len());
println!("Failed {} transformations", result.failed_transformations.len());
```

### Semantic Validation

```rust
let validator = SemanticValidator::new();
let parser = Parser::new(Language::Rust)?;
let tree = parser.parse(source, None)?;

let validation_result = validator.validate_transformation(
    &tree, 
    &transformation, 
    Language::Rust
)?;

if validation_result.is_valid {
    println!("Validation passed with confidence: {:.1}%", 
             validation_result.confidence * 100.0);
} else {
    println!("Validation failed:");
    for error in &validation_result.errors {
        println!("  - {}: {}", error.code, error.message);
    }
}
```

## Configuration Options

### TransformationConfig

- `enable_semantic_validation`: Enable semantic validation before applying transformations
- `enable_rollback`: Enable rollback capabilities for failed transformations
- `max_transformation_depth`: Maximum depth for complex transformation operations
- `enable_safety_checks`: Enable additional safety checks for critical transformations
- `preserve_formatting`: Attempt to preserve original code formatting when possible
- `enable_incremental`: Enable incremental transformation for large files

### ValidationConfig

- `enable_scope_analysis`: Enable scope analysis for variable and function visibility
- `enable_type_checking`: Enable type checking where applicable
- `enable_control_flow_analysis`: Enable control flow analysis for transformation safety
- `enable_data_flow_analysis`: Enable data flow analysis for dependency tracking
- `strict_mode`: Fail transformations on any validation warnings (not just errors)

## Language-Specific Features

### Rust
- Borrow checker validation
- Lifetime annotation preservation
- Unsafe block handling
- Macro invocation safety

### Python
- Indentation preservation
- Scope rule validation
- Import statement handling
- Global/nonlocal statement safety

### JavaScript/TypeScript
- Hoisting rule compliance
- Closure variable capture validation
- This binding preservation
- Module import/export handling

## Safety Features

1. **Syntax Validation**: All transformations are validated to ensure they don't break syntax
2. **Semantic Preservation**: Semantic analysis ensures transformations don't change program meaning
3. **Rollback Support**: Failed transformations can be rolled back to original state
4. **Impact Assessment**: Each transformation includes risk and impact analysis
5. **Dependency Tracking**: Transformations can declare dependencies on other transformations
6. **Language-Specific Rules**: Each language has specific validation rules and constraints

## Error Handling

The engine provides detailed error information for failed transformations:

```rust
if !result.success {
    for failure in &result.failed_transformations {
        println!("Failed transformation: {}", failure.transformation.id);
        println!("Reason: {}", failure.failure_reason);
        
        for error in &failure.error_details {
            println!("Error {}: {} at {}:{}", 
                     error.code, 
                     error.message,
                     error.location.start_position.line,
                     error.location.start_position.column);
        }
        
        if !failure.suggested_alternatives.is_empty() {
            println!("Suggested alternatives:");
            for alt in &failure.suggested_alternatives {
                println!("  - {}", alt);
            }
        }
    }
}
```

## Performance Considerations

- Use incremental mode for large files
- Batch related transformations together
- Enable validation caching for repeated operations
- Consider transformation depth limits for complex operations
- Use appropriate confidence thresholds for automated transformations

## Future Enhancements

The AST transformation engine is designed to be extensible. Future enhancements may include:

- Advanced refactoring operations (extract class, move method, etc.)
- Machine learning-based transformation suggestions
- Integration with language servers for real-time validation
- Support for additional programming languages
- Performance optimizations for large codebases
- Visual transformation preview and approval workflows
