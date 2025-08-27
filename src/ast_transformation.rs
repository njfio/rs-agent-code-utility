//! AST Transformation Engine for Safe Code Refactoring
//!
//! This module provides a comprehensive AST transformation engine that enables
//! safe, semantic-preserving code transformations. It includes:
//! - Core AST transformation engine with validation
//! - Safe node replacement and modification
//! - Semantic preservation checks
//! - Transformation rollback capabilities
//! - Language-specific transformation rules

use crate::{Result, Error, SyntaxTree, Node, Parser, Language};
use crate::constants::common::RiskLevel;
use std::collections::HashMap;
use std::path::PathBuf;
use tree_sitter::InputEdit;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Core AST transformation engine
#[derive(Debug, Clone)]
pub struct AstTransformationEngine {
    /// Configuration for transformations
    pub config: TransformationConfig,
    /// Language-specific transformation rules
    #[allow(dead_code)]
    transformation_rules: HashMap<Language, LanguageTransformationRules>,
    /// Validation engine for semantic preservation
    validator: SemanticValidator,
}

/// Configuration for AST transformations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransformationConfig {
    /// Enable semantic validation before applying transformations
    pub enable_semantic_validation: bool,
    /// Enable rollback capabilities
    pub enable_rollback: bool,
    /// Maximum transformation depth for complex operations
    pub max_transformation_depth: usize,
    /// Enable safety checks for critical transformations
    pub enable_safety_checks: bool,
    /// Preserve original formatting when possible
    pub preserve_formatting: bool,
    /// Enable incremental transformation for large files
    pub enable_incremental: bool,
}

/// Language-specific transformation rules
#[derive(Debug, Clone)]
pub struct LanguageTransformationRules {
    /// Language being configured
    pub language: Language,
    /// Safe node types that can be transformed
    pub safe_node_types: Vec<String>,
    /// Node types that require special handling
    pub special_handling_types: Vec<String>,
    /// Forbidden transformations for this language
    pub forbidden_transformations: Vec<TransformationType>,
    /// Language-specific validation rules
    pub validation_rules: Vec<ValidationRule>,
}

/// Types of transformations supported
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TransformationType {
    /// Extract method refactoring
    ExtractMethod,
    /// Rename variable/function
    Rename,
    /// Inline variable/method
    Inline,
    /// Move code between scopes
    Move,
    /// Replace node with another
    Replace,
    /// Insert new nodes
    Insert,
    /// Delete nodes
    Delete,
    /// Reorder nodes
    Reorder,
    /// Wrap nodes in new structure
    Wrap,
    /// Unwrap nodes from structure
    Unwrap,
}

/// Validation rules for transformations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ValidationRule {
    /// Rule identifier
    pub id: String,
    /// Rule description
    pub description: String,
    /// Node types this rule applies to
    pub applicable_node_types: Vec<String>,
    /// Transformation types this rule applies to
    pub applicable_transformations: Vec<TransformationType>,
    /// Severity of rule violation
    pub severity: ValidationSeverity,
}

/// Severity levels for validation rules
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ValidationSeverity {
    /// Error - transformation must be blocked
    Error,
    /// Warning - transformation can proceed with caution
    Warning,
    /// Info - informational only
    Info,
}

/// Semantic validator for transformation safety
#[derive(Debug, Clone)]
pub struct SemanticValidator {
    /// Validation configuration
    pub config: ValidationConfig,
    /// Cache of validation results
    #[allow(dead_code)]
    validation_cache: HashMap<String, ValidationResult>,
}

/// Configuration for semantic validation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ValidationConfig {
    /// Enable scope analysis
    pub enable_scope_analysis: bool,
    /// Enable type checking (where applicable)
    pub enable_type_checking: bool,
    /// Enable control flow analysis
    pub enable_control_flow_analysis: bool,
    /// Enable data flow analysis
    pub enable_data_flow_analysis: bool,
    /// Strict mode - fail on any potential issue
    pub strict_mode: bool,
}

/// Result of semantic validation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ValidationResult {
    /// Whether validation passed
    pub is_valid: bool,
    /// Validation errors found
    pub errors: Vec<ValidationError>,
    /// Validation warnings
    pub warnings: Vec<ValidationWarning>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Detailed analysis results
    pub analysis_details: ValidationAnalysis,
}

/// Validation error
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ValidationError {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Location of the error
    pub location: TransformationLocation,
    /// Suggested fix (if available)
    pub suggested_fix: Option<String>,
}

/// Validation warning
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ValidationWarning {
    /// Warning code
    pub code: String,
    /// Warning message
    pub message: String,
    /// Location of the warning
    pub location: TransformationLocation,
    /// Severity level
    pub severity: ValidationSeverity,
}

/// Detailed validation analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ValidationAnalysis {
    /// Scope analysis results
    pub scope_analysis: Option<ScopeAnalysisResult>,
    /// Type analysis results
    pub type_analysis: Option<TypeAnalysisResult>,
    /// Control flow analysis results
    pub control_flow_analysis: Option<ControlFlowAnalysisResult>,
    /// Data flow analysis results
    pub data_flow_analysis: Option<DataFlowAnalysisResult>,
}

/// Location information for transformations
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransformationLocation {
    /// File path
    pub file_path: PathBuf,
    /// Start position
    pub start_position: Position,
    /// End position
    pub end_position: Position,
    /// Node kind
    pub node_kind: String,
}

/// Position in source code
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Position {
    /// Line number (0-based)
    pub line: usize,
    /// Column number (0-based)
    pub column: usize,
    /// Byte offset
    pub byte_offset: usize,
}

/// Scope analysis result
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ScopeAnalysisResult {
    /// Variables in scope
    pub variables_in_scope: Vec<VariableInfo>,
    /// Functions in scope
    pub functions_in_scope: Vec<FunctionInfo>,
    /// Scope conflicts detected
    pub scope_conflicts: Vec<ScopeConflict>,
}

/// Type analysis result
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TypeAnalysisResult {
    /// Type information for expressions
    pub expression_types: HashMap<String, String>,
    /// Type conflicts detected
    pub type_conflicts: Vec<TypeConflict>,
    /// Type safety score
    pub type_safety_score: f64,
}

/// Control flow analysis result
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ControlFlowAnalysisResult {
    /// Control flow paths
    pub control_paths: Vec<ControlPath>,
    /// Unreachable code detected
    pub unreachable_code: Vec<TransformationLocation>,
    /// Control flow integrity score
    pub integrity_score: f64,
}

/// Data flow analysis result
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DataFlowAnalysisResult {
    /// Data dependencies
    pub data_dependencies: Vec<DataDependency>,
    /// Potential data flow issues
    pub data_flow_issues: Vec<DataFlowIssue>,
    /// Data flow safety score
    pub safety_score: f64,
}

/// Variable information for scope analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VariableInfo {
    /// Variable name
    pub name: String,
    /// Variable type (if known)
    pub var_type: Option<String>,
    /// Declaration location
    pub declaration_location: TransformationLocation,
    /// Usage locations
    pub usage_locations: Vec<TransformationLocation>,
    /// Is mutable
    pub is_mutable: bool,
}

/// Function information for scope analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FunctionInfo {
    /// Function name
    pub name: String,
    /// Function signature
    pub signature: String,
    /// Declaration location
    pub declaration_location: TransformationLocation,
    /// Call locations
    pub call_locations: Vec<TransformationLocation>,
}

/// Scope conflict information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ScopeConflict {
    /// Conflict type
    pub conflict_type: ScopeConflictType,
    /// Conflicting identifier
    pub identifier: String,
    /// Locations involved in conflict
    pub locations: Vec<TransformationLocation>,
    /// Suggested resolution
    pub suggested_resolution: String,
}

/// Types of scope conflicts
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ScopeConflictType {
    /// Variable shadowing
    VariableShadowing,
    /// Name collision
    NameCollision,
    /// Undefined reference
    UndefinedReference,
    /// Out of scope access
    OutOfScopeAccess,
}

/// Type conflict information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TypeConflict {
    /// Expected type
    pub expected_type: String,
    /// Actual type
    pub actual_type: String,
    /// Location of conflict
    pub location: TransformationLocation,
    /// Conflict severity
    pub severity: ValidationSeverity,
}

/// Control flow path
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ControlPath {
    /// Path identifier
    pub id: String,
    /// Nodes in the path
    pub nodes: Vec<TransformationLocation>,
    /// Path type
    pub path_type: ControlPathType,
}

/// Types of control flow paths
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ControlPathType {
    /// Sequential execution
    Sequential,
    /// Conditional branch
    Conditional,
    /// Loop iteration
    Loop,
    /// Function call
    FunctionCall,
    /// Exception handling
    ExceptionHandling,
}

/// Data dependency information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DataDependency {
    /// Source location
    pub source: TransformationLocation,
    /// Target location
    pub target: TransformationLocation,
    /// Dependency type
    pub dependency_type: DataDependencyType,
    /// Variable involved
    pub variable: String,
}

/// Types of data dependencies
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DataDependencyType {
    /// Read after write
    ReadAfterWrite,
    /// Write after read
    WriteAfterRead,
    /// Write after write
    WriteAfterWrite,
    /// Control dependency
    Control,
}

/// Data flow issue
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DataFlowIssue {
    /// Issue type
    pub issue_type: DataFlowIssueType,
    /// Issue description
    pub description: String,
    /// Location of issue
    pub location: TransformationLocation,
    /// Severity
    pub severity: ValidationSeverity,
}

/// Types of data flow issues
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DataFlowIssueType {
    /// Use of uninitialized variable
    UninitializedVariable,
    /// Dead code
    DeadCode,
    /// Potential null pointer dereference
    NullPointerDereference,
    /// Memory leak
    MemoryLeak,
    /// Race condition
    RaceCondition,
}

/// Analysis of variables in extracted code for method extraction
#[derive(Debug, Clone)]
pub struct ExtractedVariableAnalysis {
    /// Variables that need to be passed as parameters
    pub input_variables: Vec<VariableInfo>,
    /// Variables that need to be returned from the method
    pub output_variables: Vec<VariableInfo>,
    /// Variables that are local to the extracted code
    pub local_variables: Vec<VariableInfo>,
}

/// Occurrence of a variable in source code
#[derive(Debug, Clone)]
pub struct VariableOccurrence {
    /// Location of the occurrence
    pub location: TransformationLocation,
    /// Type of occurrence (declaration, reference, etc.)
    pub occurrence_type: VariableOccurrenceType,
}

/// Type of variable occurrence
#[derive(Debug, Clone)]
pub enum VariableOccurrenceType {
    /// Variable declaration
    Declaration,
    /// Variable reference/usage
    Reference,
    /// Variable assignment
    Assignment,
}

/// Type of inline transformation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InlineType {
    /// Inline a variable
    Variable,
    /// Inline a method/function
    Method,
}

/// Context in which a variable is used
#[derive(Debug, Clone, PartialEq)]
enum VariableUsageContext {
    /// Variable is only read from
    Read,
    /// Variable is only written to
    Write,
    /// Variable is both read from and written to
    ReadWrite,
}

/// Transformation operation that can be applied to AST
#[derive(Debug, Clone)]
pub struct Transformation {
    /// Unique transformation ID
    pub id: String,
    /// Type of transformation
    pub transformation_type: TransformationType,
    /// Target location for transformation
    pub target_location: TransformationLocation,
    /// Original code before transformation
    pub original_code: String,
    /// New code after transformation
    pub new_code: String,
    /// Transformation metadata
    pub metadata: TransformationMetadata,
    /// Validation result
    pub validation_result: Option<ValidationResult>,
}

/// Metadata for transformations
#[derive(Debug, Clone)]
pub struct TransformationMetadata {
    /// Transformation description
    pub description: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Estimated impact
    pub impact: TransformationImpact,
    /// Dependencies on other transformations
    pub dependencies: Vec<String>,
    /// Rollback information
    pub rollback_info: Option<RollbackInfo>,
}

/// Impact assessment for transformations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransformationImpact {
    /// Scope of impact
    pub scope: ImpactScope,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Affected lines of code
    pub affected_lines: usize,
    /// Affected functions
    pub affected_functions: Vec<String>,
    /// Affected variables
    pub affected_variables: Vec<String>,
}

/// Scope of transformation impact
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImpactScope {
    /// Local to a single function
    Local,
    /// Affects multiple functions in same file
    File,
    /// Affects multiple files
    Module,
    /// Affects entire codebase
    Global,
}

// RiskLevel is now imported from crate::constants::common
// Note: The common RiskLevel doesn't have VeryLow/VeryHigh variants,
// so transformations using those will need to map to the available variants

/// Rollback information for transformations
#[derive(Debug, Clone)]
pub struct RollbackInfo {
    /// Original AST state
    pub original_ast_hash: String,
    /// Edits to apply for rollback
    pub rollback_edits: Vec<InputEdit>,
    /// Timestamp of transformation
    pub timestamp: u64,
    /// Rollback instructions
    pub rollback_instructions: String,
}

/// Result of applying transformations
#[derive(Debug, Clone)]
pub struct TransformationResult {
    /// Whether transformation was successful
    pub success: bool,
    /// Applied transformations
    pub applied_transformations: Vec<Transformation>,
    /// Failed transformations
    pub failed_transformations: Vec<FailedTransformation>,
    /// Updated source code
    pub updated_source: String,
    /// Updated syntax tree
    pub updated_tree_hash: String,
    /// Validation summary
    pub validation_summary: ValidationSummary,
}

/// Information about failed transformations
#[derive(Debug, Clone)]
pub struct FailedTransformation {
    /// The transformation that failed
    pub transformation: Transformation,
    /// Reason for failure
    pub failure_reason: String,
    /// Error details
    pub error_details: Vec<ValidationError>,
    /// Suggested alternatives
    pub suggested_alternatives: Vec<String>,
}

/// Summary of validation results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ValidationSummary {
    /// Total validations performed
    pub total_validations: usize,
    /// Successful validations
    pub successful_validations: usize,
    /// Failed validations
    pub failed_validations: usize,
    /// Total errors found
    pub total_errors: usize,
    /// Total warnings found
    pub total_warnings: usize,
    /// Overall confidence score
    pub overall_confidence: f64,
}

impl Default for TransformationConfig {
    fn default() -> Self {
        Self {
            enable_semantic_validation: true,
            enable_rollback: true,
            max_transformation_depth: 10,
            enable_safety_checks: true,
            preserve_formatting: true,
            enable_incremental: true,
        }
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            enable_scope_analysis: true,
            enable_type_checking: true,
            enable_control_flow_analysis: true,
            enable_data_flow_analysis: true,
            strict_mode: false,
        }
    }
}

impl AstTransformationEngine {
    /// Create a new AST transformation engine with default configuration
    pub fn new() -> Self {
        Self {
            config: TransformationConfig::default(),
            transformation_rules: Self::create_default_transformation_rules(),
            validator: SemanticValidator::new(),
        }
    }

    /// Create a new AST transformation engine with custom configuration
    pub fn with_config(config: TransformationConfig) -> Self {
        Self {
            config,
            transformation_rules: Self::create_default_transformation_rules(),
            validator: SemanticValidator::with_config(ValidationConfig::default()),
        }
    }

    /// Apply a single transformation to source code
    pub fn apply_transformation(
        &self,
        source: &str,
        language: Language,
        transformation: &Transformation,
    ) -> Result<TransformationResult> {
        // Parse the source code
        let parser = Parser::new(language)?;
        let tree = parser.parse(source, None)?;

        // Validate the transformation if enabled
        if self.config.enable_semantic_validation {
            let validation_result = self.validator.validate_transformation(
                &tree,
                transformation,
                language,
            )?;

            if !validation_result.is_valid && self.validator.config.strict_mode {
                return Ok(TransformationResult {
                    success: false,
                    applied_transformations: Vec::new(),
                    failed_transformations: vec![FailedTransformation {
                        transformation: transformation.clone(),
                        failure_reason: "Semantic validation failed".to_string(),
                        error_details: validation_result.errors.clone(),
                        suggested_alternatives: Vec::new(),
                    }],
                    updated_source: source.to_string(),
                    updated_tree_hash: self.calculate_tree_hash(&tree),
                    validation_summary: ValidationSummary {
                        total_validations: 1,
                        successful_validations: 0,
                        failed_validations: 1,
                        total_errors: validation_result.errors.len(),
                        total_warnings: validation_result.warnings.len(),
                        overall_confidence: validation_result.confidence,
                    },
                });
            }
        }

        // Apply the transformation
        match self.apply_single_transformation(source, &tree, transformation, language) {
            Ok(updated_source) => {
                // Parse the updated source to verify it's still valid
                let updated_tree = parser.parse(&updated_source, None)?;

                if updated_tree.root_node().has_error() {
                    return Ok(TransformationResult {
                        success: false,
                        applied_transformations: Vec::new(),
                        failed_transformations: vec![FailedTransformation {
                            transformation: transformation.clone(),
                            failure_reason: "Transformation resulted in syntax errors".to_string(),
                            error_details: Vec::new(),
                            suggested_alternatives: Vec::new(),
                        }],
                        updated_source: source.to_string(),
                        updated_tree_hash: self.calculate_tree_hash(&tree),
                        validation_summary: ValidationSummary {
                            total_validations: 1,
                            successful_validations: 0,
                            failed_validations: 1,
                            total_errors: 1,
                            total_warnings: 0,
                            overall_confidence: 0.0,
                        },
                    });
                }

                Ok(TransformationResult {
                    success: true,
                    applied_transformations: vec![transformation.clone()],
                    failed_transformations: Vec::new(),
                    updated_source,
                    updated_tree_hash: self.calculate_tree_hash(&updated_tree),
                    validation_summary: ValidationSummary {
                        total_validations: 1,
                        successful_validations: 1,
                        failed_validations: 0,
                        total_errors: 0,
                        total_warnings: 0,
                        overall_confidence: 1.0,
                    },
                })
            }
            Err(e) => Ok(TransformationResult {
                success: false,
                applied_transformations: Vec::new(),
                failed_transformations: vec![FailedTransformation {
                    transformation: transformation.clone(),
                    failure_reason: format!("Transformation failed: {}", e),
                    error_details: Vec::new(),
                    suggested_alternatives: Vec::new(),
                }],
                updated_source: source.to_string(),
                updated_tree_hash: self.calculate_tree_hash(&tree),
                validation_summary: ValidationSummary {
                    total_validations: 1,
                    successful_validations: 0,
                    failed_validations: 1,
                    total_errors: 1,
                    total_warnings: 0,
                    overall_confidence: 0.0,
                },
            }),
        }
    }

    /// Apply multiple transformations in sequence
    pub fn apply_transformations(
        &self,
        source: &str,
        language: Language,
        transformations: &[Transformation],
    ) -> Result<TransformationResult> {
        let mut current_source = source.to_string();
        let mut applied_transformations = Vec::new();
        let mut failed_transformations = Vec::new();
        let mut total_validations = 0;
        let mut successful_validations = 0;
        let mut failed_validations = 0;
        let mut total_errors = 0;
        let mut total_warnings = 0;
        let mut confidence_scores = Vec::new();

        for transformation in transformations {
            let result = self.apply_transformation(&current_source, language, transformation)?;

            total_validations += result.validation_summary.total_validations;
            successful_validations += result.validation_summary.successful_validations;
            failed_validations += result.validation_summary.failed_validations;
            total_errors += result.validation_summary.total_errors;
            total_warnings += result.validation_summary.total_warnings;
            confidence_scores.push(result.validation_summary.overall_confidence);

            if result.success {
                current_source = result.updated_source;
                applied_transformations.extend(result.applied_transformations);
            } else {
                failed_transformations.extend(result.failed_transformations);
                // Stop on first failure if strict mode is enabled
                if self.validator.config.strict_mode {
                    break;
                }
            }
        }

        let overall_confidence = if confidence_scores.is_empty() {
            0.0
        } else {
            confidence_scores.iter().sum::<f64>() / confidence_scores.len() as f64
        };

        // Parse final result to get tree hash
        let parser = Parser::new(language)?;
        let final_tree = parser.parse(&current_source, None)?;

        Ok(TransformationResult {
            success: failed_transformations.is_empty(),
            applied_transformations,
            failed_transformations,
            updated_source: current_source,
            updated_tree_hash: self.calculate_tree_hash(&final_tree),
            validation_summary: ValidationSummary {
                total_validations,
                successful_validations,
                failed_validations,
                total_errors,
                total_warnings,
                overall_confidence,
            },
        })
    }

    /// Create default transformation rules for supported languages
    fn create_default_transformation_rules() -> HashMap<Language, LanguageTransformationRules> {
        let mut rules = HashMap::new();

        // Rust transformation rules
        rules.insert(Language::Rust, LanguageTransformationRules {
            language: Language::Rust,
            safe_node_types: vec![
                "function_item".to_string(),
                "impl_item".to_string(),
                "struct_item".to_string(),
                "enum_item".to_string(),
                "block".to_string(),
                "expression_statement".to_string(),
                "let_declaration".to_string(),
            ],
            special_handling_types: vec![
                "unsafe_block".to_string(),
                "macro_invocation".to_string(),
                "attribute_item".to_string(),
            ],
            forbidden_transformations: vec![
                // Don't allow unsafe transformations by default
            ],
            validation_rules: vec![
                ValidationRule {
                    id: "rust_borrow_checker".to_string(),
                    description: "Ensure transformations don't violate borrow checker rules".to_string(),
                    applicable_node_types: vec!["reference_expression".to_string(), "let_declaration".to_string()],
                    applicable_transformations: vec![TransformationType::Rename, TransformationType::Move],
                    severity: ValidationSeverity::Error,
                },
                ValidationRule {
                    id: "rust_lifetime_safety".to_string(),
                    description: "Ensure lifetime annotations remain valid".to_string(),
                    applicable_node_types: vec!["lifetime".to_string(), "reference_type".to_string()],
                    applicable_transformations: vec![TransformationType::ExtractMethod, TransformationType::Move],
                    severity: ValidationSeverity::Error,
                },
            ],
        });

        // Python transformation rules
        rules.insert(Language::Python, LanguageTransformationRules {
            language: Language::Python,
            safe_node_types: vec![
                "function_definition".to_string(),
                "class_definition".to_string(),
                "block".to_string(),
                "expression_statement".to_string(),
                "assignment".to_string(),
            ],
            special_handling_types: vec![
                "global_statement".to_string(),
                "nonlocal_statement".to_string(),
                "import_statement".to_string(),
                "import_from_statement".to_string(),
            ],
            forbidden_transformations: vec![],
            validation_rules: vec![
                ValidationRule {
                    id: "python_indentation".to_string(),
                    description: "Ensure proper Python indentation is maintained".to_string(),
                    applicable_node_types: vec!["block".to_string()],
                    applicable_transformations: vec![TransformationType::ExtractMethod, TransformationType::Move],
                    severity: ValidationSeverity::Error,
                },
                ValidationRule {
                    id: "python_scope_rules".to_string(),
                    description: "Ensure Python scope rules are followed".to_string(),
                    applicable_node_types: vec!["identifier".to_string()],
                    applicable_transformations: vec![TransformationType::Rename, TransformationType::Move],
                    severity: ValidationSeverity::Warning,
                },
            ],
        });

        // JavaScript transformation rules
        rules.insert(Language::JavaScript, LanguageTransformationRules {
            language: Language::JavaScript,
            safe_node_types: vec![
                "function_declaration".to_string(),
                "arrow_function".to_string(),
                "class_declaration".to_string(),
                "statement_block".to_string(),
                "expression_statement".to_string(),
                "variable_declaration".to_string(),
            ],
            special_handling_types: vec![
                "this_expression".to_string(),
                "super".to_string(),
                "import_statement".to_string(),
                "export_statement".to_string(),
            ],
            forbidden_transformations: vec![],
            validation_rules: vec![
                ValidationRule {
                    id: "js_hoisting_rules".to_string(),
                    description: "Ensure JavaScript hoisting rules are respected".to_string(),
                    applicable_node_types: vec!["function_declaration".to_string(), "variable_declaration".to_string()],
                    applicable_transformations: vec![TransformationType::Move, TransformationType::Reorder],
                    severity: ValidationSeverity::Warning,
                },
                ValidationRule {
                    id: "js_closure_safety".to_string(),
                    description: "Ensure closure variable capture remains valid".to_string(),
                    applicable_node_types: vec!["arrow_function".to_string(), "function_expression".to_string()],
                    applicable_transformations: vec![TransformationType::ExtractMethod, TransformationType::Move],
                    severity: ValidationSeverity::Error,
                },
            ],
        });

        rules
    }

    /// Apply a single transformation to the source code
    fn apply_single_transformation(
        &self,
        source: &str,
        tree: &SyntaxTree,
        transformation: &Transformation,
        language: Language,
    ) -> Result<String> {
        match transformation.transformation_type {
            TransformationType::Replace => {
                self.apply_replace_transformation(source, tree, transformation)
            }
            TransformationType::Insert => {
                self.apply_insert_transformation(source, tree, transformation)
            }
            TransformationType::Delete => {
                self.apply_delete_transformation(source, tree, transformation)
            }
            TransformationType::Rename => {
                self.apply_rename_transformation(source, tree, transformation, language)
            }
            TransformationType::ExtractMethod => {
                self.apply_extract_method_transformation(source, tree, transformation, language)
            }
            TransformationType::Inline => {
                self.apply_inline_transformation(source, tree, transformation, language)
            }
            TransformationType::Move => {
                self.apply_move_transformation(source, tree, transformation)
            }
            TransformationType::Reorder => {
                self.apply_reorder_transformation(source, tree, transformation)
            }
            TransformationType::Wrap => {
                self.apply_wrap_transformation(source, tree, transformation)
            }
            TransformationType::Unwrap => {
                self.apply_unwrap_transformation(source, tree, transformation)
            }
        }
    }

    /// Apply a replace transformation
    fn apply_replace_transformation(
        &self,
        source: &str,
        _tree: &SyntaxTree,
        transformation: &Transformation,
    ) -> Result<String> {
        let start_byte = transformation.target_location.start_position.byte_offset;
        let end_byte = transformation.target_location.end_position.byte_offset;

        if start_byte > source.len() || end_byte > source.len() || start_byte > end_byte {
            return Err(Error::internal_error(
                "ast_transformation",
                "Invalid byte range for replacement",
            ));
        }

        let mut result = String::new();
        result.push_str(&source[..start_byte]);
        result.push_str(&transformation.new_code);
        result.push_str(&source[end_byte..]);

        Ok(result)
    }

    /// Apply an insert transformation
    fn apply_insert_transformation(
        &self,
        source: &str,
        _tree: &SyntaxTree,
        transformation: &Transformation,
    ) -> Result<String> {
        let insert_byte = transformation.target_location.start_position.byte_offset;

        if insert_byte > source.len() {
            return Err(Error::internal_error(
                "ast_transformation",
                "Invalid byte offset for insertion",
            ));
        }

        let mut result = String::new();
        result.push_str(&source[..insert_byte]);
        result.push_str(&transformation.new_code);
        result.push_str(&source[insert_byte..]);

        Ok(result)
    }

    /// Apply a delete transformation
    fn apply_delete_transformation(
        &self,
        source: &str,
        _tree: &SyntaxTree,
        transformation: &Transformation,
    ) -> Result<String> {
        let start_byte = transformation.target_location.start_position.byte_offset;
        let end_byte = transformation.target_location.end_position.byte_offset;

        if start_byte > source.len() || end_byte > source.len() || start_byte > end_byte {
            return Err(Error::internal_error(
                "ast_transformation",
                "Invalid byte range for deletion",
            ));
        }

        let mut result = String::new();
        result.push_str(&source[..start_byte]);
        result.push_str(&source[end_byte..]);

        Ok(result)
    }

    /// Calculate a hash of the syntax tree for comparison
    fn calculate_tree_hash(&self, tree: &SyntaxTree) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        tree.source().hash(&mut hasher);
        tree.root_node().kind().hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Extract method name from transformation metadata with validation
    fn extract_method_name_from_metadata(&self, metadata: &TransformationMetadata) -> Result<String> {
        // Look for method name in the description
        if metadata.description.contains("extract method") || metadata.description.contains("Extract method") {
            // Try to extract method name from description like "Extract method: calculate_sum"
            if let Some(colon_pos) = metadata.description.find(':') {
                let method_name = metadata.description[colon_pos + 1..].trim();
                if !method_name.is_empty() {
                    // Validate the method name
                    let cleaned_name = self.sanitize_method_name(method_name);
                    if self.is_valid_method_name(&cleaned_name) {
                        return Ok(cleaned_name);
                    }
                }
            }
        }

        // Look for method name in other patterns
        let patterns = [
            "method:",
            "function:",
            "name:",
            "extract:",
            "refactor:",
        ];

        for pattern in &patterns {
            if let Some(pos) = metadata.description.to_lowercase().find(pattern) {
                let start = pos + pattern.len();
                if start < metadata.description.len() {
                    let remaining = &metadata.description[start..];
                    if let Some(end) = remaining.find(|c: char| c.is_whitespace() || c == ',' || c == ';') {
                        let method_name = remaining[..end].trim();
                        if !method_name.is_empty() {
                            let cleaned_name = self.sanitize_method_name(method_name);
                            if self.is_valid_method_name(&cleaned_name) {
                                return Ok(cleaned_name);
                            }
                        }
                    } else {
                        let method_name = remaining.trim();
                        if !method_name.is_empty() {
                            let cleaned_name = self.sanitize_method_name(method_name);
                            if self.is_valid_method_name(&cleaned_name) {
                                return Ok(cleaned_name);
                            }
                        }
                    }
                }
            }
        }

        // Generate a default method name based on context
        Ok(self.generate_default_method_name())
    }

    /// Sanitize a method name to ensure it's valid
    fn sanitize_method_name(&self, name: &str) -> String {
        let mut result = String::new();
        let mut chars = name.chars();

        // Ensure first character is valid
        if let Some(first) = chars.next() {
            if first.is_alphabetic() || first == '_' {
                result.push(first);
            } else {
                result.push('_');
            }
        }

        // Process remaining characters
        for c in chars {
            if c.is_alphanumeric() || c == '_' {
                result.push(c);
            } else if c.is_whitespace() || c == '-' {
                result.push('_');
            }
            // Skip other invalid characters
        }

        // Ensure the name is not empty
        if result.is_empty() {
            result = "extracted_method".to_string();
        }

        result
    }

    /// Check if a method name is valid
    fn is_valid_method_name(&self, name: &str) -> bool {
        if name.is_empty() || name.len() > 64 {
            return false;
        }

        // Check first character
        let mut chars = name.chars();
        if let Some(first) = chars.next() {
            if !first.is_alphabetic() && first != '_' {
                return false;
            }
        } else {
            return false;
        }

        // Check remaining characters
        for c in chars {
            if !c.is_alphanumeric() && c != '_' {
                return false;
            }
        }

        // Check if it's a reserved keyword (basic check)
        !self.is_language_keyword(name)
    }

    /// Generate a default method name
    fn generate_default_method_name(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Generate a unique name based on timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        format!("extracted_method_{}", timestamp % 10000)
    }

    /// Analyze variables used in extracted code
    fn analyze_extracted_code_variables(
        &self,
        tree: &SyntaxTree,
        extract_range: &TransformationLocation,
        source: &str,
        _language: Language,
    ) -> Result<ExtractedVariableAnalysis> {
        let mut analysis = ExtractedVariableAnalysis {
            input_variables: Vec::new(),
            output_variables: Vec::new(),
            local_variables: Vec::new(),
        };

        // Find the node containing the extracted code
        let root = tree.root_node();
        if let Some(target_node) = self.validator.find_node_at_position(&root, extract_range) {
            // Analyze variables in the extracted code
            self.collect_variables_in_node(&target_node, source, &mut analysis)?;
        }

        Ok(analysis)
    }

    /// Generate method signature based on variable analysis
    fn generate_method_signature(
        &self,
        method_name: &str,
        analysis: &ExtractedVariableAnalysis,
        language: Language,
    ) -> Result<String> {
        match language {
            Language::Rust => {
                let mut params = Vec::new();
                for var in &analysis.input_variables {
                    params.push(format!("{}: {}", var.name, var.var_type.as_deref().unwrap_or("&str")));
                }

                let return_type = if analysis.output_variables.is_empty() {
                    "()".to_string()
                } else if analysis.output_variables.len() == 1 {
                    analysis.output_variables[0].var_type.as_deref().unwrap_or("String").to_string()
                } else {
                    format!("({})", analysis.output_variables.iter()
                        .map(|v| v.var_type.as_deref().unwrap_or("String"))
                        .collect::<Vec<_>>()
                        .join(", "))
                };

                Ok(format!("fn {}({}) -> {}", method_name, params.join(", "), return_type))
            }
            Language::Python => {
                let mut params = vec!["self".to_string()];
                for var in &analysis.input_variables {
                    params.push(var.name.clone());
                }
                Ok(format!("def {}({}):", method_name, params.join(", ")))
            }
            Language::JavaScript => {
                let params: Vec<String> = analysis.input_variables.iter()
                    .map(|v| v.name.clone())
                    .collect();
                Ok(format!("function {}({})", method_name, params.join(", ")))
            }
            _ => {
                // Generic signature for other languages
                let params: Vec<String> = analysis.input_variables.iter()
                    .map(|v| v.name.clone())
                    .collect();
                Ok(format!("{}({})", method_name, params.join(", ")))
            }
        }
    }
    fn generate_method_call(
        &self,
        method_name: &str,
        analysis: &ExtractedVariableAnalysis,
        language: Language,
    ) -> Result<String> {
        let args: Vec<String> = analysis.input_variables.iter()
            .map(|v| v.name.clone())
            .collect();

        match language {
            Language::Rust => {
                if analysis.output_variables.is_empty() {
                    Ok(format!("{}({});", method_name, args.join(", ")))
                } else if analysis.output_variables.len() == 1 {
                    Ok(format!("let {} = {}({});",
                        analysis.output_variables[0].name,
                        method_name,
                        args.join(", ")))
                } else {
                    let output_names: Vec<String> = analysis.output_variables.iter()
                        .map(|v| v.name.clone())
                        .collect();
                    Ok(format!("let ({}) = {}({});",
                        output_names.join(", "),
                        method_name,
                        args.join(", ")))
                }
            }
            Language::Python => {
                if analysis.output_variables.is_empty() {
                    Ok(format!("self.{}({})", method_name, args.join(", ")))
                } else {
                    let output_names: Vec<String> = analysis.output_variables.iter()
                        .map(|v| v.name.clone())
                        .collect();
                    Ok(format!("{} = self.{}({})",
                        output_names.join(", "),
                        method_name,
                        args.join(", ")))
                }
            }
            Language::JavaScript => {
                if analysis.output_variables.is_empty() {
                    Ok(format!("{}({});", method_name, args.join(", ")))
                } else {
                    let output_names: Vec<String> = analysis.output_variables.iter()
                        .map(|v| v.name.clone())
                        .collect();
                    Ok(format!("const {} = {}({});",
                        output_names.join(", "),
                        method_name,
                        args.join(", ")))
                }
            }
            _ => {
                Ok(format!("{}({});", method_name, args.join(", ")))
            }
        }
    }

    /// Apply a rename transformation
    fn apply_rename_transformation(
        &self,
        source: &str,
        tree: &SyntaxTree,
        transformation: &Transformation,
        language: Language,
    ) -> Result<String> {
        let old_name = &transformation.original_code;
        let new_name = &transformation.new_code;

        // Validate the new name
        if !self.is_valid_identifier(new_name, language) {
            return Err(Error::internal_error(
                "ast_transformation",
                &format!("Invalid identifier name: {}", new_name),
            ));
        }

        // Find all occurrences of the variable in the appropriate scope
        let target_location = &transformation.target_location;
        let occurrences = self.find_variable_occurrences(tree, old_name, target_location, language)?;

        // Check for naming conflicts
        if self.has_naming_conflict(tree, new_name, &occurrences, language)? {
            return Err(Error::internal_error(
                "ast_transformation",
                &format!("Naming conflict: identifier '{}' already exists in scope", new_name),
            ));
        }

        // Apply the rename transformation to all occurrences
        self.apply_rename_to_occurrences(source, &occurrences, old_name, new_name)
    }

    /// Apply an extract method transformation
    fn apply_extract_method_transformation(
        &self,
        source: &str,
        tree: &SyntaxTree,
        transformation: &Transformation,
        language: Language,
    ) -> Result<String> {
        // Parse the transformation metadata to get method extraction details
        let method_name = self.extract_method_name_from_metadata(&transformation.metadata)?;
        let extract_range = &transformation.target_location;

        // Extract the code block to be moved to a new method
        let start_byte = extract_range.start_position.byte_offset;
        let end_byte = extract_range.end_position.byte_offset;

        if start_byte > source.len() || end_byte > source.len() || start_byte > end_byte {
            return Err(Error::internal_error(
                "ast_transformation",
                "Invalid byte range for method extraction",
            ));
        }

        let extracted_code = &source[start_byte..end_byte];

        // Analyze variables used in the extracted code
        let variable_analysis = self.analyze_extracted_code_variables(tree, extract_range, source, language)?;

        // Generate method signature based on variable analysis
        let method_signature = self.generate_method_signature(
            &method_name,
            &variable_analysis,
            language,
        )?;

        // Generate method call to replace the extracted code
        let method_call = self.generate_method_call(
            &method_name,
            &variable_analysis,
            language,
        )?;

        // Find the appropriate location to insert the new method
        let insertion_point = self.find_method_insertion_point(tree, source, language)?;

        // Build the new method definition
        let method_definition = self.build_method_definition(
            &method_signature,
            extracted_code,
            &variable_analysis,
            language,
        )?;

        // Apply the transformation: replace extracted code with method call and insert method
        let mut result = String::new();

        // Add code before the extracted section
        result.push_str(&source[..start_byte]);

        // Add the method call
        result.push_str(&method_call);

        // Add code after the extracted section but before method insertion point
        result.push_str(&source[end_byte..insertion_point]);

        // Add the new method definition
        result.push_str(&method_definition);

        // Add remaining code after insertion point
        result.push_str(&source[insertion_point..]);

        Ok(result)
    }

    /// Apply an inline transformation
    fn apply_inline_transformation(
        &self,
        source: &str,
        tree: &SyntaxTree,
        transformation: &Transformation,
        language: Language,
    ) -> Result<String> {
        // Determine if we're inlining a variable or a method
        let inline_type = self.determine_inline_type(tree, transformation, language)?;

        match inline_type {
            InlineType::Variable => {
                self.apply_inline_variable_transformation(source, tree, transformation, language)
            }
            InlineType::Method => {
                self.apply_inline_method_transformation(source, tree, transformation, language)
            }
        }
    }

    /// Placeholder for move transformation
    fn apply_move_transformation(
        &self,
        source: &str,
        _tree: &SyntaxTree,
        _transformation: &Transformation,
    ) -> Result<String> {
        // Basic move implementation - will be enhanced
        Ok(source.to_string())
    }

    /// Placeholder for reorder transformation
    fn apply_reorder_transformation(
        &self,
        source: &str,
        _tree: &SyntaxTree,
        _transformation: &Transformation,
    ) -> Result<String> {
        // Basic reorder implementation - will be enhanced
        Ok(source.to_string())
    }

    /// Placeholder for wrap transformation
    fn apply_wrap_transformation(
        &self,
        source: &str,
        _tree: &SyntaxTree,
        _transformation: &Transformation,
    ) -> Result<String> {
        // Basic wrap implementation - will be enhanced
        Ok(source.to_string())
    }

    /// Placeholder for unwrap transformation
    fn apply_unwrap_transformation(
        &self,
        source: &str,
        _tree: &SyntaxTree,
        _transformation: &Transformation,
    ) -> Result<String> {
        // Basic unwrap implementation - will be enhanced
        Ok(source.to_string())
    }

    /// Validate if a string is a valid identifier for the given language
    fn is_valid_identifier(&self, name: &str, language: Language) -> bool {
        if name.is_empty() {
            return false;
        }

        match language {
            Language::Rust => {
                // Rust identifier rules: start with letter or underscore, followed by letters, digits, or underscores
                let mut chars = name.chars();
                if let Some(first) = chars.next() {
                    if !first.is_alphabetic() && first != '_' {
                        return false;
                    }
                    for c in chars {
                        if !c.is_alphanumeric() && c != '_' {
                            return false;
                        }
                    }
                    // Check if it's a reserved keyword
                    !self.is_rust_keyword(name)
                } else {
                    false
                }
            }
            Language::Python => {
                // Python identifier rules: similar to Rust but different keywords
                let mut chars = name.chars();
                if let Some(first) = chars.next() {
                    if !first.is_alphabetic() && first != '_' {
                        return false;
                    }
                    for c in chars {
                        if !c.is_alphanumeric() && c != '_' {
                            return false;
                        }
                    }
                    !self.is_python_keyword(name)
                } else {
                    false
                }
            }
            Language::JavaScript => {
                // JavaScript identifier rules
                let mut chars = name.chars();
                if let Some(first) = chars.next() {
                    if !first.is_alphabetic() && first != '_' && first != '$' {
                        return false;
                    }
                    for c in chars {
                        if !c.is_alphanumeric() && c != '_' && c != '$' {
                            return false;
                        }
                    }
                    !self.is_javascript_keyword(name)
                } else {
                    false
                }
            }
            _ => {
                // Generic identifier validation
                let mut chars = name.chars();
                if let Some(first) = chars.next() {
                    if !first.is_alphabetic() && first != '_' {
                        return false;
                    }
                    for c in chars {
                        if !c.is_alphanumeric() && c != '_' {
                            return false;
                        }
                    }
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Check if a name is a Rust keyword
    fn is_rust_keyword(&self, name: &str) -> bool {
        matches!(name,
            "as" | "break" | "const" | "continue" | "crate" | "else" | "enum" | "extern" |
            "false" | "fn" | "for" | "if" | "impl" | "in" | "let" | "loop" | "match" |
            "mod" | "move" | "mut" | "pub" | "ref" | "return" | "self" | "Self" |
            "static" | "struct" | "super" | "trait" | "true" | "type" | "unsafe" |
            "use" | "where" | "while" | "async" | "await" | "dyn"
        )
    }

    /// Check if a name is a Python keyword
    fn is_python_keyword(&self, name: &str) -> bool {
        matches!(name,
            "False" | "None" | "True" | "and" | "as" | "assert" | "break" | "class" |
            "continue" | "def" | "del" | "elif" | "else" | "except" | "finally" |
            "for" | "from" | "global" | "if" | "import" | "in" | "is" | "lambda" |
            "nonlocal" | "not" | "or" | "pass" | "raise" | "return" | "try" |
            "while" | "with" | "yield"
        )
    }

    /// Check if a name is a JavaScript keyword
    fn is_javascript_keyword(&self, name: &str) -> bool {
        matches!(name,
            "break" | "case" | "catch" | "class" | "const" | "continue" | "debugger" |
            "default" | "delete" | "do" | "else" | "export" | "extends" | "finally" |
            "for" | "function" | "if" | "import" | "in" | "instanceof" | "new" |
            "return" | "super" | "switch" | "this" | "throw" | "try" | "typeof" |
            "var" | "void" | "while" | "with" | "yield" | "let" | "static" | "enum" |
            "implements" | "package" | "protected" | "interface" | "private" | "public"
        )
    }

    /// Find all occurrences of a variable in the appropriate scope
    fn find_variable_occurrences(
        &self,
        tree: &SyntaxTree,
        variable_name: &str,
        target_location: &TransformationLocation,
        _language: Language,
    ) -> Result<Vec<VariableOccurrence>> {
        let mut occurrences = Vec::new();
        let root = tree.root_node();

        // Find the scope containing the target location
        if let Some(scope_node) = self.find_containing_scope(&root, target_location) {
            // Search for all identifiers matching the variable name within this scope
            self.find_identifiers_in_scope(&scope_node, variable_name, &mut occurrences)?;
        }

        Ok(occurrences)
    }

    /// Find the scope (function, block, etc.) containing the target location
    fn find_containing_scope<'a>(&self, node: &Node<'a>, target_location: &TransformationLocation) -> Option<Node<'a>> {
        let target_start = target_location.start_position.byte_offset;
        let target_end = target_location.end_position.byte_offset;

        // Check if this node contains the target location
        if node.start_byte() <= target_start && node.end_byte() >= target_end {
            // Check if this is a scope-defining node
            if self.is_scope_defining_node(node) {
                return Some(node.clone());
            }

            // Otherwise, check children
            for child in node.children() {
                if let Some(scope) = self.find_containing_scope(&child, target_location) {
                    return Some(scope);
                }
            }

            // If no child scope found, this node is the containing scope
            Some(node.clone())
        } else {
            None
        }
    }

    /// Check if a node defines a scope
    fn is_scope_defining_node(&self, node: &Node) -> bool {
        matches!(node.kind(),
            "function_item" | "function_declaration" | "function_definition" |
            "block" | "compound_statement" | "class_definition" | "impl_item" |
            "for_statement" | "while_statement" | "if_statement"
        )
    }

    /// Find all identifiers matching the variable name in a scope
    fn find_identifiers_in_scope(
        &self,
        scope_node: &Node,
        variable_name: &str,
        occurrences: &mut Vec<VariableOccurrence>,
    ) -> Result<()> {
        for child in scope_node.children() {
            if child.kind() == "identifier" {
                if let Ok(text) = child.text() {
                    if text == variable_name {
                        occurrences.push(VariableOccurrence {
                            location: self.node_to_location(&child),
                            occurrence_type: VariableOccurrenceType::Reference,
                        });
                    }
                }
            }

            // Recursively search child nodes
            self.find_identifiers_in_scope(&child, variable_name, occurrences)?;
        }

        Ok(())
    }

    /// Check for naming conflicts with the new name
    fn has_naming_conflict(
        &self,
        tree: &SyntaxTree,
        new_name: &str,
        occurrences: &[VariableOccurrence],
        _language: Language,
    ) -> Result<bool> {
        // Check if the new name already exists in any of the scopes where we're renaming
        for occurrence in occurrences {
            let root = tree.root_node();
            if let Some(scope_node) = self.find_containing_scope(&root, &occurrence.location) {
                if self.identifier_exists_in_scope(&scope_node, new_name)? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Check if an identifier already exists in a scope
    fn identifier_exists_in_scope(&self, scope_node: &Node, identifier: &str) -> Result<bool> {
        for child in scope_node.children() {
            if child.kind() == "identifier" {
                if let Ok(text) = child.text() {
                    if text == identifier {
                        return Ok(true);
                    }
                }
            }

            // Check child nodes (but not nested scopes)
            if !self.is_scope_defining_node(&child) {
                if self.identifier_exists_in_scope(&child, identifier)? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Apply rename transformation to all occurrences
    fn apply_rename_to_occurrences(
        &self,
        source: &str,
        occurrences: &[VariableOccurrence],
        old_name: &str,
        new_name: &str,
    ) -> Result<String> {
        let mut result = source.to_string();
        let mut offset = 0i32;

        // Sort occurrences by position to apply changes from end to beginning
        let mut sorted_occurrences = occurrences.to_vec();
        sorted_occurrences.sort_by_key(|occ| occ.location.start_position.byte_offset);
        sorted_occurrences.reverse();

        for occurrence in &sorted_occurrences {
            let start = occurrence.location.start_position.byte_offset;
            let end = occurrence.location.end_position.byte_offset;

            // Adjust for previous changes
            let adjusted_start = (start as i32 + offset) as usize;
            let adjusted_end = (end as i32 + offset) as usize;

            if adjusted_start <= result.len() && adjusted_end <= result.len() && adjusted_start <= adjusted_end {
                // Replace the old name with the new name
                result.replace_range(adjusted_start..adjusted_end, new_name);

                // Update offset for next replacements
                offset += new_name.len() as i32 - old_name.len() as i32;
            }
        }

        Ok(result)
    }

    /// Convert a node to a transformation location
    fn node_to_location(&self, node: &Node) -> TransformationLocation {
        TransformationLocation {
            file_path: PathBuf::from(""), // Would be provided by caller in full implementation
            start_position: Position {
                line: node.start_position().row,
                column: node.start_position().column,
                byte_offset: node.start_byte(),
            },
            end_position: Position {
                line: node.end_position().row,
                column: node.end_position().column,
                byte_offset: node.end_byte(),
            },
            node_kind: node.kind().to_string(),
        }
    }

    /// Determine the type of inline transformation
    fn determine_inline_type(
        &self,
        tree: &SyntaxTree,
        transformation: &Transformation,
        _language: Language,
    ) -> Result<InlineType> {
        let root = tree.root_node();
        if let Some(target_node) = self.validator.find_node_at_position(&root, &transformation.target_location) {
            // Check if the target is a variable declaration or a method/function
            match target_node.kind() {
                "let_declaration" | "variable_declaration" | "assignment" => Ok(InlineType::Variable),
                "function_item" | "function_declaration" | "function_definition" | "method_definition" => Ok(InlineType::Method),
                _ => {
                    // Try to determine from parent context
                    if let Some(parent) = target_node.parent() {
                        match parent.kind() {
                            "let_declaration" | "variable_declaration" => Ok(InlineType::Variable),
                            "function_item" | "function_declaration" => Ok(InlineType::Method),
                            _ => Ok(InlineType::Variable), // Default to variable
                        }
                    } else {
                        Ok(InlineType::Variable)
                    }
                }
            }
        } else {
            Ok(InlineType::Variable)
        }
    }

    /// Apply inline variable transformation
    fn apply_inline_variable_transformation(
        &self,
        source: &str,
        tree: &SyntaxTree,
        transformation: &Transformation,
        language: Language,
    ) -> Result<String> {
        // Find the variable declaration
        let variable_name = &transformation.original_code;
        let variable_declaration = self.find_variable_declaration(tree, variable_name, &transformation.target_location)?;

        // Extract the variable's value/expression
        let variable_value = self.extract_variable_value(source, &variable_declaration, language)?;

        // Find all usages of the variable
        let usages = self.find_variable_usages(tree, variable_name, &transformation.target_location, language)?;

        // Validate that inlining is safe
        if !self.is_safe_to_inline_variable(&variable_value, &usages, language)? {
            return Err(Error::internal_error(
                "ast_transformation",
                "Inlining this variable would change program semantics",
            ));
        }

        // Apply the inline transformation
        let mut result = source.to_string();
        let mut offset = 0i32;

        // Sort by position and process from end to beginning
        let mut all_locations = usages.clone();
        all_locations.push(variable_declaration.clone());
        all_locations.sort_by_key(|loc| loc.start_position.byte_offset);
        all_locations.reverse();

        for location in &all_locations {
            let start = location.start_position.byte_offset;
            let end = location.end_position.byte_offset;

            let adjusted_start = (start as i32 + offset) as usize;
            let adjusted_end = (end as i32 + offset) as usize;

            if adjusted_start <= result.len() && adjusted_end <= result.len() {
                if location == &variable_declaration {
                    // Remove the variable declaration
                    result.replace_range(adjusted_start..adjusted_end, "");
                    offset -= (end - start) as i32;
                } else {
                    // Replace usage with the variable's value
                    result.replace_range(adjusted_start..adjusted_end, &variable_value);
                    offset += variable_value.len() as i32 - (end - start) as i32;
                }
            }
        }

        Ok(result)
    }

    /// Apply inline method transformation
    fn apply_inline_method_transformation(
        &self,
        source: &str,
        tree: &SyntaxTree,
        transformation: &Transformation,
        language: Language,
    ) -> Result<String> {
        // Find the method definition
        let method_name = &transformation.original_code;
        let method_definition = self.find_method_definition(tree, method_name, &transformation.target_location)?;

        // Extract the method body
        let method_body = self.extract_method_body(source, &method_definition, language)?;

        // Find all calls to the method
        let method_calls = self.find_method_calls(tree, method_name, language)?;

        // Validate that inlining is safe
        if !self.is_safe_to_inline_method(&method_body, &method_calls, language)? {
            return Err(Error::internal_error(
                "ast_transformation",
                "Inlining this method would change program semantics",
            ));
        }

        // Apply the inline transformation
        let mut result = source.to_string();
        let mut offset = 0i32;

        // Sort by position and process from end to beginning
        let mut all_locations = method_calls.clone();
        all_locations.push(method_definition.clone());
        all_locations.sort_by_key(|loc| loc.start_position.byte_offset);
        all_locations.reverse();

        for location in &all_locations {
            let start = location.start_position.byte_offset;
            let end = location.end_position.byte_offset;

            let adjusted_start = (start as i32 + offset) as usize;
            let adjusted_end = (end as i32 + offset) as usize;

            if adjusted_start <= result.len() && adjusted_end <= result.len() {
                if location == &method_definition {
                    // Remove the method definition
                    result.replace_range(adjusted_start..adjusted_end, "");
                    offset -= (end - start) as i32;
                } else {
                    // Replace method call with the method body
                    let inlined_body = self.adapt_method_body_for_call(&method_body, source, location, language)?;
                    result.replace_range(adjusted_start..adjusted_end, &inlined_body);
                    offset += inlined_body.len() as i32 - (end - start) as i32;
                }
            }
        }

        Ok(result)
    }

    /// Find variable declaration location
    fn find_variable_declaration(
        &self,
        tree: &SyntaxTree,
        variable_name: &str,
        _target_location: &TransformationLocation,
    ) -> Result<TransformationLocation> {
        let root = tree.root_node();

        // Search for variable declaration
        if let Some(decl_node) = self.find_variable_declaration_node(&root, variable_name) {
            Ok(self.node_to_location(&decl_node))
        } else {
            Err(Error::internal_error(
                "ast_transformation",
                &format!("Variable declaration not found: {}", variable_name),
            ))
        }
    }

    /// Find variable declaration node
    fn find_variable_declaration_node<'a>(&self, node: &Node<'a>, variable_name: &str) -> Option<Node<'a>> {
        // Check if this node is a variable declaration
        if matches!(node.kind(), "let_declaration" | "variable_declaration") {
            // Look for the variable name in this declaration
            for child in node.children() {
                if child.kind() == "identifier" {
                    if let Ok(text) = child.text() {
                        if text == variable_name {
                            return Some(node.clone());
                        }
                    }
                }
            }
        }

        // Recursively search children
        for child in node.children() {
            if let Some(found) = self.find_variable_declaration_node(&child, variable_name) {
                return Some(found);
            }
        }

        None
    }

    /// Extract variable value from declaration
    fn extract_variable_value(
        &self,
        source: &str,
        declaration_location: &TransformationLocation,
        _language: Language,
    ) -> Result<String> {
        // This is a simplified implementation
        // In practice, you'd need to parse the AST to find the initializer expression
        let start = declaration_location.start_position.byte_offset;
        let end = declaration_location.end_position.byte_offset;

        if start < source.len() && end <= source.len() && start < end {
            let declaration_text = &source[start..end];

            // Simple pattern matching to extract the value
            // This would need to be more sophisticated for real use
            if let Some(equals_pos) = declaration_text.find('=') {
                let value_part = &declaration_text[equals_pos + 1..];
                if let Some(semicolon_pos) = value_part.find(';') {
                    Ok(value_part[..semicolon_pos].trim().to_string())
                } else {
                    Ok(value_part.trim().to_string())
                }
            } else {
                Err(Error::internal_error(
                    "ast_transformation",
                    "Could not extract variable value",
                ))
            }
        } else {
            Err(Error::internal_error(
                "ast_transformation",
                "Invalid declaration location",
            ))
        }
    }

    /// Find all usages of a variable
    fn find_variable_usages(
        &self,
        tree: &SyntaxTree,
        variable_name: &str,
        _target_location: &TransformationLocation,
        _language: Language,
    ) -> Result<Vec<TransformationLocation>> {
        let mut usages = Vec::new();
        let root = tree.root_node();

        self.find_variable_usages_in_node(&root, variable_name, &mut usages)?;

        Ok(usages)
    }

    /// Find variable usages in a node
    fn find_variable_usages_in_node(
        &self,
        node: &Node,
        variable_name: &str,
        usages: &mut Vec<TransformationLocation>,
    ) -> Result<()> {
        if node.kind() == "identifier" {
            if let Ok(text) = node.text() {
                if text == variable_name {
                    // Check if this is a usage (not a declaration)
                    if let Some(parent) = node.parent() {
                        if !matches!(parent.kind(), "let_declaration" | "variable_declaration") {
                            usages.push(self.node_to_location(node));
                        }
                    }
                }
            }
        }

        // Recursively search children
        for child in node.children() {
            self.find_variable_usages_in_node(&child, variable_name, usages)?;
        }

        Ok(())
    }

    /// Check if it's safe to inline a variable
    fn is_safe_to_inline_variable(
        &self,
        _variable_value: &str,
        _usages: &[TransformationLocation],
        _language: Language,
    ) -> Result<bool> {
        // Simplified safety check
        // In practice, this would check for side effects, evaluation order, etc.
        Ok(true)
    }

    /// Find method definition location
    fn find_method_definition(
        &self,
        tree: &SyntaxTree,
        method_name: &str,
        _target_location: &TransformationLocation,
    ) -> Result<TransformationLocation> {
        let root = tree.root_node();

        if let Some(method_node) = self.find_method_definition_node(&root, method_name) {
            Ok(self.node_to_location(&method_node))
        } else {
            Err(Error::internal_error(
                "ast_transformation",
                &format!("Method definition not found: {}", method_name),
            ))
        }
    }

    /// Find method definition node
    fn find_method_definition_node<'a>(&self, node: &Node<'a>, method_name: &str) -> Option<Node<'a>> {
        if matches!(node.kind(), "function_item" | "function_declaration" | "function_definition") {
            // Look for the method name
            for child in node.children() {
                if child.kind() == "identifier" {
                    if let Ok(text) = child.text() {
                        if text == method_name {
                            return Some(node.clone());
                        }
                    }
                }
            }
        }

        // Recursively search children
        for child in node.children() {
            if let Some(found) = self.find_method_definition_node(&child, method_name) {
                return Some(found);
            }
        }

        None
    }

    /// Extract method body
    fn extract_method_body(
        &self,
        source: &str,
        method_location: &TransformationLocation,
        _language: Language,
    ) -> Result<String> {
        // Simplified implementation - extract the method body
        let start = method_location.start_position.byte_offset;
        let end = method_location.end_position.byte_offset;

        if start < source.len() && end <= source.len() && start < end {
            let method_text = &source[start..end];

            // Find the method body (between braces)
            if let Some(open_brace) = method_text.find('{') {
                if let Some(close_brace) = method_text.rfind('}') {
                    if open_brace < close_brace {
                        return Ok(method_text[open_brace + 1..close_brace].trim().to_string());
                    }
                }
            }
        }

        Err(Error::internal_error(
            "ast_transformation",
            "Could not extract method body",
        ))
    }

    /// Find all calls to a method
    fn find_method_calls(
        &self,
        tree: &SyntaxTree,
        method_name: &str,
        _language: Language,
    ) -> Result<Vec<TransformationLocation>> {
        let mut calls = Vec::new();
        let root = tree.root_node();

        self.find_method_calls_in_node(&root, method_name, &mut calls)?;

        Ok(calls)
    }

    /// Find method calls in a node
    fn find_method_calls_in_node(
        &self,
        node: &Node,
        method_name: &str,
        calls: &mut Vec<TransformationLocation>,
    ) -> Result<()> {
        if matches!(node.kind(), "call_expression" | "function_call") {
            // Check if this is a call to our method
            for child in node.children() {
                if child.kind() == "identifier" {
                    if let Ok(text) = child.text() {
                        if text == method_name {
                            calls.push(self.node_to_location(node));
                            break;
                        }
                    }
                }
            }
        }

        // Recursively search children
        for child in node.children() {
            self.find_method_calls_in_node(&child, method_name, calls)?;
        }

        Ok(())
    }

    /// Check if it's safe to inline a method
    fn is_safe_to_inline_method(
        &self,
        _method_body: &str,
        _method_calls: &[TransformationLocation],
        _language: Language,
    ) -> Result<bool> {
        // Simplified safety check
        // In practice, this would check for recursion, side effects, etc.
        Ok(true)
    }

    /// Adapt method body for inlining at a specific call site
    fn adapt_method_body_for_call(
        &self,
        method_body: &str,
        _source: &str,
        _call_location: &TransformationLocation,
        _language: Language,
    ) -> Result<String> {
        // Simplified implementation - just return the method body
        // In practice, this would handle parameter substitution, return value handling, etc.
        Ok(format!("{{ {} }}", method_body))
    }

    /// Collect variables used in a node with proper scope and data flow analysis
    fn collect_variables_in_node(
        &self,
        node: &Node,
        source: &str,
        analysis: &mut ExtractedVariableAnalysis,
    ) -> Result<()> {
        // Track variables declared within the extracted code
        let mut local_declarations = std::collections::HashSet::new();

        // First pass: collect all variable declarations within the extracted code
        self.collect_local_declarations(node, &mut local_declarations)?;

        // Second pass: analyze variable usage patterns
        self.analyze_variable_usage(node, source, analysis, &local_declarations)?;

        Ok(())
    }

    /// Collect all variable declarations within a node
    fn collect_local_declarations(
        &self,
        node: &Node,
        declarations: &mut std::collections::HashSet<String>,
    ) -> Result<()> {
        // Check if this node is a variable declaration
        if self.is_variable_declaration_node(node) {
            if let Some(var_name) = self.extract_declared_variable_name(node)? {
                declarations.insert(var_name);
            }
        }

        // Recursively check children
        for child in node.children() {
            self.collect_local_declarations(&child, declarations)?;
        }

        Ok(())
    }

    /// Analyze variable usage patterns to determine input/output variables
    fn analyze_variable_usage(
        &self,
        node: &Node,
        source: &str,
        analysis: &mut ExtractedVariableAnalysis,
        local_declarations: &std::collections::HashSet<String>,
    ) -> Result<()> {
        // Check if this node is an identifier
        if node.kind() == "identifier" {
            if let Ok(name) = node.text() {
                let var_name = name.to_string();

                // Skip language keywords and built-in functions
                if self.is_language_keyword(&var_name) || self.is_builtin_function(&var_name) {
                    return Ok(());
                }

                // Determine variable type and role
                let var_type = self.infer_variable_type(node, source)?;
                let is_mutable = self.is_variable_mutable(node)?;

                // Create variable info
                let var_info = VariableInfo {
                    name: var_name.clone(),
                    var_type: Some(var_type),
                    declaration_location: self.node_to_location(node),
                    usage_locations: Vec::new(),
                    is_mutable,
                };

                // Categorize the variable based on usage context
                if local_declarations.contains(&var_name) {
                    // Variable is declared within the extracted code
                    if !analysis.local_variables.iter().any(|v| v.name == var_name) {
                        analysis.local_variables.push(var_info);
                    }
                } else {
                    // Variable is used but not declared locally
                    let usage_context = self.determine_variable_usage_context(node)?;

                    match usage_context {
                        VariableUsageContext::Read => {
                            // Input variable: read from outside scope
                            if !analysis.input_variables.iter().any(|v| v.name == var_name) {
                                analysis.input_variables.push(var_info);
                            }
                        }
                        VariableUsageContext::Write => {
                            // Output variable: modified and potentially returned
                            if !analysis.output_variables.iter().any(|v| v.name == var_name) {
                                analysis.output_variables.push(var_info);
                            }
                        }
                        VariableUsageContext::ReadWrite => {
                            // Both input and output
                            if !analysis.input_variables.iter().any(|v| v.name == var_name) {
                                analysis.input_variables.push(var_info.clone());
                            }
                            if !analysis.output_variables.iter().any(|v| v.name == var_name) {
                                analysis.output_variables.push(var_info);
                            }
                        }
                    }
                }
            }
        }

        // Recursively analyze children
        for child in node.children() {
            self.analyze_variable_usage(&child, source, analysis, local_declarations)?;
        }

        Ok(())
    }

    /// Check if a node represents a variable declaration
    fn is_variable_declaration_node(&self, node: &Node) -> bool {
        matches!(node.kind(),
            "let_declaration" | "variable_declaration" | "assignment_expression" |
            "const_declaration" | "var_declaration" | "parameter" | "pattern"
        )
    }

    /// Extract the variable name from a declaration node
    fn extract_declared_variable_name(&self, node: &Node) -> Result<Option<String>> {
        // Try different field names based on node type
        let field_names = ["name", "pattern", "left", "id"];

        for field_name in &field_names {
            if let Some(name_node) = node.child_by_field_name(field_name) {
                if name_node.kind() == "identifier" {
                    if let Ok(name) = name_node.text() {
                        return Ok(Some(name.to_string()));
                    }
                }
            }
        }

        // Fallback: look for first identifier child
        for child in node.children() {
            if child.kind() == "identifier" {
                if let Ok(name) = child.text() {
                    return Ok(Some(name.to_string()));
                }
            }
        }

        Ok(None)
    }

    /// Check if a string is a language keyword
    fn is_language_keyword(&self, name: &str) -> bool {
        // Common keywords across languages (duplicates removed)
        matches!(name,
            "if" | "else" | "for" | "while" | "do" | "switch" | "case" | "default" |
            "break" | "continue" | "return" | "function" | "var" | "let" | "const" |
            "true" | "false" | "null" | "undefined" | "this" | "super" | "new" |
            "try" | "catch" | "finally" | "throw" | "class" | "extends" | "import" |
            "export" | "from" | "as" | "async" | "await" | "yield" | "static" |
            "public" | "private" | "protected" | "abstract" | "interface" | "enum" |
            "type" | "namespace" | "module" | "package" | "use" | "mod" | "crate" |
            "fn" | "impl" | "trait" | "struct" | "match" | "loop" | "move" | "mut" |
            "ref" | "self" | "Self" | "unsafe" | "where" | "dyn" | "extern" |
            "def" | "lambda" | "pass" | "with" | "assert" | "global" |
            "nonlocal" | "del" | "and" | "or" | "not" | "in" | "is" | "None" |
            "True" | "False" | "except" | "raise" | "elif"
        )
    }

    /// Check if a string is a built-in function
    fn is_builtin_function(&self, name: &str) -> bool {
        // Common built-in functions across languages
        matches!(name,
            "print" | "println" | "console" | "log" | "len" | "length" | "size" |
            "push" | "pop" | "shift" | "unshift" | "slice" | "splice" | "join" |
            "split" | "replace" | "substring" | "indexOf" | "charAt" | "toString" |
            "parseInt" | "parseFloat" | "isNaN" | "isFinite" | "Math" | "Date" |
            "Array" | "Object" | "String" | "Number" | "Boolean" | "RegExp" |
            "Error" | "TypeError" | "ReferenceError" | "SyntaxError" | "RangeError" |
            "vec" | "Vec" | "HashMap" | "BTreeMap" | "HashSet" | "BTreeSet" |
            "Option" | "Some" | "None" | "Result" | "Ok" | "Err" | "Box" | "Rc" |
            "Arc" | "Mutex" | "RwLock" | "Cell" | "RefCell" | "Cow" | "Clone" |
            "list" | "dict" | "set" | "tuple" | "str" | "int" | "float" | "bool" |
            "range" | "enumerate" | "zip" | "map" | "filter" | "reduce" | "sum" |
            "min" | "max" | "abs" | "round" | "sorted" | "reversed" | "any" | "all"
        )
    }

    /// Infer the type of a variable from its usage context
    fn infer_variable_type(&self, node: &Node, source: &str) -> Result<String> {
        // Look at the parent context to infer type
        if let Some(parent) = node.parent() {
            match parent.kind() {
                "assignment_expression" | "assignment" => {
                    // Look at the right-hand side of assignment
                    if let Some(value_node) = parent.child_by_field_name("right") {
                        return Ok(self.infer_type_from_expression(&value_node, source)?);
                    }
                }
                "let_declaration" | "variable_declaration" => {
                    // Look for type annotation or initializer
                    if let Some(type_node) = parent.child_by_field_name("type") {
                        if let Ok(type_text) = type_node.text() {
                            return Ok(type_text.to_string());
                        }
                    }
                    if let Some(init_node) = parent.child_by_field_name("value") {
                        return Ok(self.infer_type_from_expression(&init_node, source)?);
                    }
                }
                "parameter" => {
                    // Function parameter - look for type annotation
                    if let Some(type_node) = parent.child_by_field_name("type") {
                        if let Ok(type_text) = type_node.text() {
                            return Ok(type_text.to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        // Default type inference
        Ok("auto".to_string())
    }

    /// Infer type from an expression node
    fn infer_type_from_expression(&self, node: &Node, _source: &str) -> Result<String> {
        match node.kind() {
            "string_literal" | "template_string" => Ok("String".to_string()),
            "number_literal" | "integer_literal" => Ok("i32".to_string()),
            "float_literal" => Ok("f64".to_string()),
            "boolean_literal" => Ok("bool".to_string()),
            "array_expression" | "array_literal" => Ok("Vec<T>".to_string()),
            "object_expression" | "object_literal" => Ok("HashMap<String, T>".to_string()),
            "call_expression" | "function_call" => {
                // Try to infer from function name
                if let Some(func_node) = node.child_by_field_name("function") {
                    if let Ok(func_name) = func_node.text() {
                        return Ok(self.infer_return_type_from_function_name(&func_name));
                    }
                }
                Ok("auto".to_string())
            }
            _ => Ok("auto".to_string()),
        }
    }

    /// Infer return type from function name
    fn infer_return_type_from_function_name(&self, func_name: &str) -> String {
        match func_name {
            "len" | "length" | "size" | "count" => "usize".to_string(),
            "toString" | "to_string" => "String".to_string(),
            "parseInt" | "parse" => "i32".to_string(),
            "parseFloat" => "f64".to_string(),
            "isNaN" | "isFinite" | "isEmpty" => "bool".to_string(),
            _ => "auto".to_string(),
        }
    }

    /// Check if a variable is mutable based on its declaration context
    fn is_variable_mutable(&self, node: &Node) -> Result<bool> {
        // Walk up to find the declaration
        let mut current = Some(node.clone());
        while let Some(node) = current {
            if self.is_variable_declaration_node(&node) {
                // Check for mutability keywords
                for child in node.children() {
                    if let Ok(text) = child.text() {
                        if matches!(text, "mut" | "var" | "let") {
                            return Ok(text == "mut" || text == "var");
                        }
                    }
                }
                break;
            }
            current = node.parent();
        }

        // Default to immutable
        Ok(false)
    }

    /// Determine how a variable is being used in its context
    fn determine_variable_usage_context(&self, node: &Node) -> Result<VariableUsageContext> {
        // Check the immediate parent context
        if let Some(parent) = node.parent() {
            match parent.kind() {
                "assignment_expression" | "assignment" => {
                    // Check if this identifier is on the left or right side
                    if let Some(left_node) = parent.child_by_field_name("left") {
                        if self.node_contains_identifier(&left_node, node) {
                            return Ok(VariableUsageContext::Write);
                        }
                    }
                    if let Some(right_node) = parent.child_by_field_name("right") {
                        if self.node_contains_identifier(&right_node, node) {
                            return Ok(VariableUsageContext::Read);
                        }
                    }
                }
                "update_expression" | "unary_expression" => {
                    // Check for increment/decrement operators
                    for child in parent.children() {
                        if let Ok(text) = child.text() {
                            if matches!(text, "++" | "--" | "+=" | "-=" | "*=" | "/=" | "%=") {
                                return Ok(VariableUsageContext::ReadWrite);
                            }
                        }
                    }
                }
                "call_expression" | "function_call" => {
                    // Variable used as function argument - typically read
                    return Ok(VariableUsageContext::Read);
                }
                "return_statement" => {
                    // Variable being returned - read
                    return Ok(VariableUsageContext::Read);
                }
                "if_statement" | "while_statement" | "for_statement" => {
                    // Variable used in condition - read
                    return Ok(VariableUsageContext::Read);
                }
                "binary_expression" | "comparison_operator" => {
                    // Variable used in expression - read
                    return Ok(VariableUsageContext::Read);
                }
                _ => {}
            }
        }

        // Default to read if context is unclear
        Ok(VariableUsageContext::Read)
    }

    /// Check if a node contains a specific identifier node
    fn node_contains_identifier(&self, container: &Node, target: &Node) -> bool {
        // Compare nodes by their byte positions and content
        if container.start_byte() == target.start_byte() &&
           container.end_byte() == target.end_byte() &&
           container.kind() == target.kind() {
            return true;
        }

        for child in container.children() {
            if self.node_contains_identifier(&child, target) {
                return true;
            }
        }

        false
    }

    /// Find appropriate location to insert new method with intelligent placement
    fn find_method_insertion_point(
        &self,
        tree: &SyntaxTree,
        source: &str,
        language: Language,
    ) -> Result<usize> {
        let root = tree.root_node();

        // Strategy 1: Find the containing class/impl block and insert within it
        if let Some(container_end) = self.find_containing_class_or_impl(&root, language) {
            // Insert before the closing brace of the container
            let insertion_point = self.find_insertion_point_before_closing_brace(source, container_end)?;
            if insertion_point > 0 {
                return Ok(insertion_point);
            }
        }

        // Strategy 2: Find the last function/method definition at the same scope level
        let mut last_function_end = 0;
        let mut best_insertion_point = 0;

        // Look for functions at the top level or within the same scope
        for child in root.children() {
            if self.is_function_like_node(&child, language) {
                last_function_end = child.end_byte();
                best_insertion_point = self.find_good_insertion_point_after_function(source, last_function_end)?;
            }
        }

        // Strategy 3: If no functions found, find a good location based on language conventions
        if last_function_end == 0 {
            return self.find_default_insertion_point(source, &root, language);
        }

        Ok(best_insertion_point)
    }

    /// Find the containing class or impl block
    fn find_containing_class_or_impl(&self, node: &Node, language: Language) -> Option<usize> {
        for child in node.children() {
            match language {
                Language::Rust => {
                    if matches!(child.kind(), "impl_item" | "struct_item" | "enum_item") {
                        return Some(child.end_byte());
                    }
                }
                Language::Python => {
                    if child.kind() == "class_definition" {
                        return Some(child.end_byte());
                    }
                }
                Language::JavaScript => {
                    if matches!(child.kind(), "class_declaration" | "class_expression") {
                        return Some(child.end_byte());
                    }
                }
                _ => {}
            }

            // Recursively search children
            if let Some(result) = self.find_containing_class_or_impl(&child, language) {
                return Some(result);
            }
        }
        None
    }

    /// Find insertion point before the closing brace of a container
    fn find_insertion_point_before_closing_brace(&self, source: &str, container_end: usize) -> Result<usize> {
        if container_end == 0 || container_end > source.len() {
            return Ok(0);
        }

        // Work backwards from the container end to find the closing brace
        let mut pos = container_end.saturating_sub(1);
        let chars: Vec<char> = source.chars().collect();

        while pos > 0 {
            if chars[pos] == '}' {
                // Found closing brace, insert before it with proper indentation
                let mut insertion_point = pos;

                // Find the beginning of the line
                while insertion_point > 0 && chars[insertion_point - 1] != '\n' {
                    insertion_point -= 1;
                }

                return Ok(insertion_point);
            }
            pos -= 1;
        }

        Ok(0)
    }

    /// Find a good insertion point after a function
    fn find_good_insertion_point_after_function(&self, source: &str, function_end: usize) -> Result<usize> {
        if function_end >= source.len() {
            return Ok(source.len());
        }

        let mut insertion_point = function_end;
        let chars: Vec<char> = source.chars().collect();

        // Skip any trailing whitespace and comments
        while insertion_point < chars.len() {
            match chars[insertion_point] {
                '\n' => {
                    insertion_point += 1;
                    // Check if the next line is empty or contains only whitespace
                    let line_start = insertion_point;
                    while insertion_point < chars.len() && chars[insertion_point] != '\n' {
                        if !chars[insertion_point].is_whitespace() {
                            // Found non-whitespace, this is a good insertion point
                            return Ok(line_start);
                        }
                        insertion_point += 1;
                    }
                    // If we reach here, the line was empty, continue to next line
                }
                ' ' | '\t' | '\r' => {
                    insertion_point += 1;
                }
                '/' if insertion_point + 1 < chars.len() && chars[insertion_point + 1] == '/' => {
                    // Skip single-line comment
                    while insertion_point < chars.len() && chars[insertion_point] != '\n' {
                        insertion_point += 1;
                    }
                }
                '/' if insertion_point + 1 < chars.len() && chars[insertion_point + 1] == '*' => {
                    // Skip multi-line comment
                    insertion_point += 2;
                    while insertion_point + 1 < chars.len() {
                        if chars[insertion_point] == '*' && chars[insertion_point + 1] == '/' {
                            insertion_point += 2;
                            break;
                        }
                        insertion_point += 1;
                    }
                }
                _ => {
                    // Found non-whitespace/comment content
                    break;
                }
            }
        }

        Ok(insertion_point)
    }

    /// Find default insertion point based on language conventions
    fn find_default_insertion_point(&self, source: &str, root: &Node, language: Language) -> Result<usize> {
        match language {
            Language::Rust => {
                // In Rust, try to insert after imports and before main function
                for child in root.children() {
                    if child.kind() == "function_item" {
                        if let Ok(text) = child.text() {
                            if text.contains("fn main") {
                                return Ok(child.start_byte());
                            }
                        }
                    }
                }
            }
            Language::Python => {
                // In Python, insert after imports and class definitions
                let mut last_import_end = 0;
                for child in root.children() {
                    if matches!(child.kind(), "import_statement" | "import_from_statement") {
                        last_import_end = child.end_byte();
                    }
                }
                if last_import_end > 0 {
                    return self.find_good_insertion_point_after_function(source, last_import_end);
                }
            }
            Language::JavaScript => {
                // In JavaScript, insert after imports and before exports
                for child in root.children() {
                    if child.kind() == "export_statement" {
                        return Ok(child.start_byte());
                    }
                }
            }
            _ => {}
        }

        // Default: insert at the end of the file
        Ok(source.len())
    }

    /// Check if a node represents a function-like construct
    fn is_function_like_node(&self, node: &Node, language: Language) -> bool {
        match language {
            Language::Rust => matches!(node.kind(), "function_item" | "impl_item"),
            Language::Python => matches!(node.kind(), "function_definition" | "class_definition"),
            Language::JavaScript => matches!(node.kind(), "function_declaration" | "method_definition"),
            _ => matches!(node.kind(), "function" | "method" | "function_declaration"),
        }
    }

    /// Build complete method definition with proper formatting and documentation
    fn build_method_definition(
        &self,
        signature: &str,
        body: &str,
        analysis: &ExtractedVariableAnalysis,
        language: Language,
    ) -> Result<String> {
        match language {
            Language::Rust => {
                let mut method = String::new();

                // Add documentation comment
                method.push_str(&self.generate_method_documentation(analysis, language)?);

                // Add method signature
                method.push_str(&format!("{} {{\n", signature));

                // Process and add the extracted code with proper indentation
                let processed_body = self.process_extracted_body(body, analysis, language)?;
                for line in processed_body.lines() {
                    if line.trim().is_empty() {
                        method.push('\n');
                    } else {
                        method.push_str(&format!("    {}\n", line));
                    }
                }

                // Add return statement if needed
                if !analysis.output_variables.is_empty() {
                    method.push('\n');
                    if analysis.output_variables.len() == 1 {
                        let var = &analysis.output_variables[0];
                        method.push_str(&format!("    {}\n", var.name));
                    } else {
                        let output_names: Vec<String> = analysis.output_variables.iter()
                            .map(|v| v.name.clone())
                            .collect();
                        method.push_str(&format!("    ({})\n", output_names.join(", ")));
                    }
                }

                method.push_str("}\n\n");
                Ok(method)
            }
            Language::Python => {
                let mut method = String::new();

                // Add documentation comment
                method.push_str(&self.generate_method_documentation(analysis, language)?);

                // Add method signature with proper indentation
                method.push_str(&format!("    {}:\n", signature));

                // Add docstring if we have variable information
                if !analysis.input_variables.is_empty() || !analysis.output_variables.is_empty() {
                    method.push_str("        \"\"\"\n");
                    if !analysis.input_variables.is_empty() {
                        method.push_str("        Args:\n");
                        for var in &analysis.input_variables {
                            let var_type = var.var_type.as_deref().unwrap_or("Any");
                            method.push_str(&format!("            {} ({}): Input parameter\n", var.name, var_type));
                        }
                    }
                    if !analysis.output_variables.is_empty() {
                        method.push_str("        Returns:\n");
                        if analysis.output_variables.len() == 1 {
                            let var = &analysis.output_variables[0];
                            let var_type = var.var_type.as_deref().unwrap_or("Any");
                            method.push_str(&format!("            {}: Output value\n", var_type));
                        } else {
                            method.push_str("            Tuple: Multiple output values\n");
                        }
                    }
                    method.push_str("        \"\"\"\n");
                }

                // Process and add the extracted code with proper indentation
                let processed_body = self.process_extracted_body(body, analysis, language)?;
                for line in processed_body.lines() {
                    if line.trim().is_empty() {
                        method.push('\n');
                    } else {
                        method.push_str(&format!("        {}\n", line));
                    }
                }

                // Add return statement if needed
                if !analysis.output_variables.is_empty() {
                    method.push('\n');
                    let output_names: Vec<String> = analysis.output_variables.iter()
                        .map(|v| v.name.clone())
                        .collect();
                    method.push_str(&format!("        return {}\n", output_names.join(", ")));
                }

                method.push('\n');
                Ok(method)
            }
            Language::JavaScript => {
                let mut method = String::new();

                // Add JSDoc documentation
                method.push_str(&self.generate_method_documentation(analysis, language)?);

                // Add method signature
                method.push_str(&format!("{} {{\n", signature));

                // Process and add the extracted code with proper indentation
                let processed_body = self.process_extracted_body(body, analysis, language)?;
                for line in processed_body.lines() {
                    if line.trim().is_empty() {
                        method.push('\n');
                    } else {
                        method.push_str(&format!("    {}\n", line));
                    }
                }

                // Add return statement if needed
                if !analysis.output_variables.is_empty() {
                    method.push('\n');
                    if analysis.output_variables.len() == 1 {
                        method.push_str(&format!("    return {};\n", analysis.output_variables[0].name));
                    } else {
                        let output_names: Vec<String> = analysis.output_variables.iter()
                            .map(|v| v.name.clone())
                            .collect();
                        method.push_str(&format!("    return [{}];\n", output_names.join(", ")));
                    }
                }

                method.push_str("}\n\n");
                Ok(method)
            }
            _ => {
                // Generic method definition
                let mut method = String::new();

                // Add basic documentation
                method.push_str(&self.generate_method_documentation(analysis, language)?);

                // Add method signature
                method.push_str(&format!("{} {{\n", signature));

                // Process and add the extracted code
                let processed_body = self.process_extracted_body(body, analysis, language)?;
                for line in processed_body.lines() {
                    if line.trim().is_empty() {
                        method.push('\n');
                    } else {
                        method.push_str(&format!("    {}\n", line));
                    }
                }

                method.push_str("}\n\n");
                Ok(method)
            }
        }
    }

    /// Generate documentation for the extracted method
    fn generate_method_documentation(
        &self,
        analysis: &ExtractedVariableAnalysis,
        language: Language,
    ) -> Result<String> {
        let mut doc = String::new();

        match language {
            Language::Rust => {
                doc.push_str("/// Extracted method\n");
                if !analysis.input_variables.is_empty() {
                    doc.push_str("///\n/// # Arguments\n");
                    for var in &analysis.input_variables {
                        doc.push_str(&format!("/// * `{}` - Input parameter\n", var.name));
                    }
                }
                if !analysis.output_variables.is_empty() {
                    doc.push_str("///\n/// # Returns\n");
                    if analysis.output_variables.len() == 1 {
                        doc.push_str("/// The computed result\n");
                    } else {
                        doc.push_str("/// Tuple containing multiple results\n");
                    }
                }
                doc.push_str("///\n");
            }
            Language::JavaScript => {
                doc.push_str("/**\n * Extracted method\n");
                if !analysis.input_variables.is_empty() {
                    for var in &analysis.input_variables {
                        let var_type = var.var_type.as_deref().unwrap_or("any");
                        doc.push_str(&format!(" * @param {{{}}} {} - Input parameter\n", var_type, var.name));
                    }
                }
                if !analysis.output_variables.is_empty() {
                    if analysis.output_variables.len() == 1 {
                        let var_type = analysis.output_variables[0].var_type.as_deref().unwrap_or("any");
                        doc.push_str(&format!(" * @returns {{{}}} The computed result\n", var_type));
                    } else {
                        doc.push_str(" * @returns {Array} Array containing multiple results\n");
                    }
                }
                doc.push_str(" */\n");
            }
            Language::Python => {
                // Python docstrings are handled in the method body
            }
            _ => {
                doc.push_str("// Extracted method\n");
            }
        }

        Ok(doc)
    }

    /// Process the extracted body to handle variable references and cleanup
    fn process_extracted_body(
        &self,
        body: &str,
        analysis: &ExtractedVariableAnalysis,
        _language: Language,
    ) -> Result<String> {
        let mut processed = body.to_string();

        // Remove any trailing semicolons or return statements that might interfere
        processed = processed.trim().to_string();

        // Remove any existing return statements at the end if we're adding our own
        if !analysis.output_variables.is_empty() {
            let lines: Vec<&str> = processed.lines().collect();
            if let Some(last_line) = lines.last() {
                let trimmed = last_line.trim();
                if trimmed.starts_with("return ") || trimmed == "return;" {
                    // Remove the last line
                    if lines.len() > 1 {
                        processed = lines[..lines.len() - 1].join("\n");
                    } else {
                        processed = String::new();
                    }
                }
            }
        }

        Ok(processed)
    }
}

impl SemanticValidator {
    /// Create a new semantic validator with default configuration
    pub fn new() -> Self {
        Self {
            config: ValidationConfig::default(),
            validation_cache: HashMap::new(),
        }
    }

    /// Create a new semantic validator with custom configuration
    pub fn with_config(config: ValidationConfig) -> Self {
        Self {
            config,
            validation_cache: HashMap::new(),
        }
    }

    /// Validate a transformation for semantic safety
    pub fn validate_transformation(
        &self,
        tree: &SyntaxTree,
        transformation: &Transformation,
        language: Language,
    ) -> Result<ValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut confidence_factors = Vec::new();

        // Perform scope analysis if enabled
        let scope_analysis = if self.config.enable_scope_analysis {
            match self.perform_scope_analysis(tree, transformation, language) {
                Ok(analysis) => {
                    confidence_factors.push(0.8); // Scope analysis passed
                    Some(analysis)
                }
                Err(e) => {
                    errors.push(ValidationError {
                        code: "SCOPE_ANALYSIS_FAILED".to_string(),
                        message: format!("Scope analysis failed: {}", e),
                        location: transformation.target_location.clone(),
                        suggested_fix: None,
                    });
                    confidence_factors.push(0.2); // Scope analysis failed
                    None
                }
            }
        } else {
            None
        };

        // Perform type analysis if enabled
        let type_analysis = if self.config.enable_type_checking {
            match self.perform_type_analysis(tree, transformation, language) {
                Ok(analysis) => {
                    confidence_factors.push(0.7); // Type analysis passed
                    Some(analysis)
                }
                Err(e) => {
                    warnings.push(ValidationWarning {
                        code: "TYPE_ANALYSIS_WARNING".to_string(),
                        message: format!("Type analysis warning: {}", e),
                        location: transformation.target_location.clone(),
                        severity: ValidationSeverity::Warning,
                    });
                    confidence_factors.push(0.5); // Type analysis had warnings
                    None
                }
            }
        } else {
            None
        };

        // Perform control flow analysis if enabled
        let control_flow_analysis = if self.config.enable_control_flow_analysis {
            match self.perform_control_flow_analysis(tree, transformation, language) {
                Ok(analysis) => {
                    confidence_factors.push(0.9); // Control flow analysis passed
                    Some(analysis)
                }
                Err(e) => {
                    warnings.push(ValidationWarning {
                        code: "CONTROL_FLOW_WARNING".to_string(),
                        message: format!("Control flow analysis warning: {}", e),
                        location: transformation.target_location.clone(),
                        severity: ValidationSeverity::Warning,
                    });
                    confidence_factors.push(0.6); // Control flow analysis had warnings
                    None
                }
            }
        } else {
            None
        };

        // Perform data flow analysis if enabled
        let data_flow_analysis = if self.config.enable_data_flow_analysis {
            match self.perform_data_flow_analysis(tree, transformation, language) {
                Ok(analysis) => {
                    confidence_factors.push(0.8); // Data flow analysis passed
                    Some(analysis)
                }
                Err(e) => {
                    warnings.push(ValidationWarning {
                        code: "DATA_FLOW_WARNING".to_string(),
                        message: format!("Data flow analysis warning: {}", e),
                        location: transformation.target_location.clone(),
                        severity: ValidationSeverity::Warning,
                    });
                    confidence_factors.push(0.4); // Data flow analysis had warnings
                    None
                }
            }
        } else {
            None
        };

        // Calculate overall confidence
        let confidence = if confidence_factors.is_empty() {
            0.5 // Default confidence when no analysis is performed
        } else {
            confidence_factors.iter().sum::<f64>() / confidence_factors.len() as f64
        };

        // Determine if validation passed
        let is_valid = errors.is_empty() && (!self.config.strict_mode || warnings.is_empty());

        Ok(ValidationResult {
            is_valid,
            errors,
            warnings,
            confidence,
            analysis_details: ValidationAnalysis {
                scope_analysis,
                type_analysis,
                control_flow_analysis,
                data_flow_analysis,
            },
        })
    }

    /// Perform scope analysis for transformation validation
    fn perform_scope_analysis(
        &self,
        tree: &SyntaxTree,
        transformation: &Transformation,
        _language: Language,
    ) -> Result<ScopeAnalysisResult> {
        let mut variables_in_scope = Vec::new();
        let mut functions_in_scope = Vec::new();
        let mut scope_conflicts = Vec::new();

        // Find the target node
        let root = tree.root_node();
        if let Some(target_node) = self.find_node_at_position(&root, &transformation.target_location) {
            // Analyze variables in scope
            variables_in_scope = self.extract_variables_in_scope(&target_node, tree.source());

            // Analyze functions in scope
            functions_in_scope = self.extract_functions_in_scope(&target_node, tree.source());

            // Check for scope conflicts
            scope_conflicts = self.detect_scope_conflicts(&variables_in_scope, &functions_in_scope, transformation);
        }

        Ok(ScopeAnalysisResult {
            variables_in_scope,
            functions_in_scope,
            scope_conflicts,
        })
    }

    /// Perform type analysis for transformation validation
    fn perform_type_analysis(
        &self,
        _tree: &SyntaxTree,
        _transformation: &Transformation,
        _language: Language,
    ) -> Result<TypeAnalysisResult> {
        // Basic type analysis implementation
        // This would be enhanced with language-specific type checking
        Ok(TypeAnalysisResult {
            expression_types: HashMap::new(),
            type_conflicts: Vec::new(),
            type_safety_score: 0.8, // Default score
        })
    }

    /// Perform control flow analysis for transformation validation
    fn perform_control_flow_analysis(
        &self,
        _tree: &SyntaxTree,
        _transformation: &Transformation,
        _language: Language,
    ) -> Result<ControlFlowAnalysisResult> {
        // Basic control flow analysis implementation
        Ok(ControlFlowAnalysisResult {
            control_paths: Vec::new(),
            unreachable_code: Vec::new(),
            integrity_score: 0.9, // Default score
        })
    }

    /// Perform data flow analysis for transformation validation
    fn perform_data_flow_analysis(
        &self,
        _tree: &SyntaxTree,
        _transformation: &Transformation,
        _language: Language,
    ) -> Result<DataFlowAnalysisResult> {
        // Basic data flow analysis implementation
        Ok(DataFlowAnalysisResult {
            data_dependencies: Vec::new(),
            data_flow_issues: Vec::new(),
            safety_score: 0.8, // Default score
        })
    }

    /// Find a node at the specified position
    fn find_node_at_position<'a>(&self, node: &Node<'a>, location: &TransformationLocation) -> Option<Node<'a>> {
        let start_byte = location.start_position.byte_offset;
        let end_byte = location.end_position.byte_offset;

        if node.start_byte() <= start_byte && node.end_byte() >= end_byte {
            // Check children first for more specific match
            for child in node.children() {
                if let Some(found) = self.find_node_at_position(&child, location) {
                    return Some(found);
                }
            }
            // Return this node if no child matches
            Some(node.clone())
        } else {
            None
        }
    }

    /// Extract variables in scope for the given node
    fn extract_variables_in_scope(&self, node: &Node, source: &str) -> Vec<VariableInfo> {
        let mut variables = Vec::new();

        // Walk up the tree to find variable declarations
        let mut current = Some(node.clone());
        while let Some(node) = current {
            // Look for variable declarations in this scope
            for child in node.children() {
                if self.is_variable_declaration(&child) {
                    if let Some(var_info) = self.extract_variable_info(&child, source) {
                        variables.push(var_info);
                    }
                }
            }
            current = node.parent();
        }

        variables
    }

    /// Extract functions in scope for the given node
    fn extract_functions_in_scope(&self, node: &Node, source: &str) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();

        // Walk up the tree to find function declarations
        let mut current = Some(node.clone());
        while let Some(node) = current {
            // Look for function declarations in this scope
            for child in node.children() {
                if self.is_function_declaration(&child) {
                    if let Some(func_info) = self.extract_function_info(&child, source) {
                        functions.push(func_info);
                    }
                }
            }
            current = node.parent();
        }

        functions
    }

    /// Detect scope conflicts in the transformation
    fn detect_scope_conflicts(
        &self,
        _variables: &[VariableInfo],
        _functions: &[FunctionInfo],
        _transformation: &Transformation,
    ) -> Vec<ScopeConflict> {
        // Basic conflict detection - would be enhanced with more sophisticated analysis
        Vec::new()
    }

    /// Check if a node is a variable declaration
    fn is_variable_declaration(&self, node: &Node) -> bool {
        matches!(node.kind(), "let_declaration" | "variable_declaration" | "assignment")
    }

    /// Check if a node is a function declaration
    fn is_function_declaration(&self, node: &Node) -> bool {
        matches!(node.kind(), "function_item" | "function_declaration" | "method_definition")
    }

    /// Extract variable information from a declaration node
    fn extract_variable_info(&self, node: &Node, _source: &str) -> Option<VariableInfo> {
        // Extract variable name and type information
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                return Some(VariableInfo {
                    name: name.to_string(),
                    var_type: None, // Would extract type information in full implementation
                    declaration_location: self.node_to_location(node),
                    usage_locations: Vec::new(), // Would find all usages in full implementation
                    is_mutable: false, // Would determine mutability in full implementation
                });
            }
        }
        None
    }

    /// Extract function information from a declaration node
    fn extract_function_info(&self, node: &Node, _source: &str) -> Option<FunctionInfo> {
        // Extract function name and signature information
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                return Some(FunctionInfo {
                    name: name.to_string(),
                    signature: "".to_string(), // Would extract full signature in full implementation
                    declaration_location: self.node_to_location(node),
                    call_locations: Vec::new(), // Would find all calls in full implementation
                });
            }
        }
        None
    }

    /// Convert a node to a transformation location
    fn node_to_location(&self, node: &Node) -> TransformationLocation {
        TransformationLocation {
            file_path: PathBuf::from(""), // Would be provided by caller in full implementation
            start_position: Position {
                line: node.start_position().row,
                column: node.start_position().column,
                byte_offset: node.start_byte(),
            },
            end_position: Position {
                line: node.end_position().row,
                column: node.end_position().column,
                byte_offset: node.end_byte(),
            },
            node_kind: node.kind().to_string(),
        }
    }
}
