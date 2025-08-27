//! Semantic Context Tracking Module
//!
//! This module provides comprehensive semantic context tracking for static analysis
//! to significantly reduce false positives in security vulnerability detection.
//! 
//! The semantic context system builds rich contextual information about code including:
//! - Data flow analysis and taint tracking
//! - Control flow context and reachability
//! - Function call context and parameter flow
//! - Variable scope and lifetime tracking
//! - Type information and semantic relationships
//! - Security-relevant context (sanitization, validation, etc.)

use crate::error::Result;
use crate::tree::{SyntaxTree, Node};
use crate::languages::Language;
use crate::symbol_table::{SymbolTable, SymbolTableAnalyzer, SymbolId};
// Note: These modules will be implemented in future tasks
// use crate::control_flow::{ControlFlowGraph, CfgBuilder};
// use crate::taint_analysis::{TaintAnalyzer, TaintFlow, TaintSource, TaintSink};
use std::collections::{HashMap, HashSet};
use tree_sitter::Point;

// Serde support disabled for now due to Point type compatibility
// #[cfg(feature = "serde")]
// use serde::{Serialize, Deserialize};

// Placeholder types for modules to be implemented
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub nodes: Vec<String>, // Placeholder
}

#[derive(Debug, Clone)]
pub struct CfgBuilder;

impl CfgBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build_cfg(&self, _node: Node) -> Result<ControlFlowGraph> {
        Ok(ControlFlowGraph { nodes: Vec::new() })
    }
}

#[derive(Debug, Clone)]
pub struct TaintAnalyzer;

impl TaintAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_taint_flows(&mut self, _tree: &SyntaxTree) -> Result<TaintAnalysisResult> {
        Ok(TaintAnalysisResult { flows: Vec::new() })
    }
}

#[derive(Debug, Clone)]
pub struct TaintAnalysisResult {
    pub flows: Vec<TaintFlow>,
}

#[derive(Debug, Clone)]
pub struct TaintFlow {
    pub source: Point,
    pub sink: Point,
    pub path: Vec<Point>,
}

/// Comprehensive semantic context for code analysis
#[derive(Debug, Clone)]
pub struct SemanticContext {
    /// Symbol table with scope information
    pub symbol_table: SymbolTable,
    /// Control flow graph
    pub control_flow: ControlFlowGraph,
    /// Data flow analysis results
    pub data_flow: DataFlowAnalysis,
    /// Function call graph
    pub call_graph: CallGraph,
    /// Security-specific context
    pub security_context: SecuritySemanticContext,
    /// Type inference results
    pub type_context: TypeContext,
    /// Code patterns and idioms
    pub pattern_context: PatternContext,
}

/// Data flow analysis results
#[derive(Debug, Clone)]

pub struct DataFlowAnalysis {
    /// Variable definitions and their reaching definitions
    pub reaching_definitions: HashMap<Point, HashSet<DefinitionSite>>,
    /// Use-definition chains
    pub use_def_chains: HashMap<Point, Vec<DefinitionSite>>,
    /// Definition-use chains
    pub def_use_chains: HashMap<DefinitionSite, Vec<Point>>,
    /// Taint flows from sources to sinks
    pub taint_flows: Vec<TaintFlow>,
    /// Variable aliases and pointer analysis
    pub aliases: HashMap<SymbolId, HashSet<SymbolId>>,
    /// Constant propagation results
    pub constants: HashMap<Point, ConstantValue>,
}

/// Definition site information
#[derive(Debug, Clone, Hash, PartialEq, Eq)]

pub struct DefinitionSite {
    /// Symbol being defined
    pub symbol_id: SymbolId,
    /// Location of definition
    pub location: Point,
    /// Type of definition
    pub definition_type: DefinitionType,
    /// Value being assigned (if known)
    pub value: Option<String>,
}

/// Types of variable definitions
#[derive(Debug, Clone, Hash, PartialEq, Eq)]

pub enum DefinitionType {
    /// Variable declaration
    Declaration,
    /// Assignment
    Assignment,
    /// Parameter binding
    Parameter,
    /// Function return
    Return,
    /// Field assignment
    FieldAssignment,
}

/// Constant value information
#[derive(Debug, Clone)]

pub enum ConstantValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Null,
    Unknown,
}

/// Function call graph
#[derive(Debug, Clone)]

pub struct CallGraph {
    /// Function calls and their targets
    pub calls: HashMap<Point, Vec<FunctionCall>>,
    /// Function definitions
    pub functions: HashMap<String, FunctionDefinition>,
    /// Call chains and paths
    pub call_chains: Vec<CallChain>,
}

/// Function call information
#[derive(Debug, Clone)]

pub struct FunctionCall {
    /// Function being called
    pub function_name: String,
    /// Call site location
    pub call_site: Point,
    /// Arguments passed
    pub arguments: Vec<ArgumentInfo>,
    /// Return value usage
    pub return_usage: ReturnUsage,
}

/// Argument information
#[derive(Debug, Clone)]

pub struct ArgumentInfo {
    /// Argument position
    pub position: usize,
    /// Argument expression
    pub expression: String,
    /// Whether argument is tainted
    pub is_tainted: bool,
    /// Constant value if known
    pub constant_value: Option<ConstantValue>,
}

/// Return value usage
#[derive(Debug, Clone)]

pub enum ReturnUsage {
    /// Return value is used
    Used,
    /// Return value is ignored
    Ignored,
    /// Return value is checked for errors
    ErrorChecked,
    /// Return value is assigned to variable
    Assigned(String),
}

/// Function definition information
#[derive(Debug, Clone)]

pub struct FunctionDefinition {
    /// Function name
    pub name: String,
    /// Function location
    pub location: Point,
    /// Parameters
    pub parameters: Vec<ParameterInfo>,
    /// Return type
    pub return_type: Option<String>,
    /// Function attributes
    pub attributes: FunctionAttributes,
}

/// Parameter information
#[derive(Debug, Clone)]

pub struct ParameterInfo {
    /// Parameter name
    pub name: String,
    /// Parameter type
    pub param_type: Option<String>,
    /// Whether parameter is mutable
    pub is_mutable: bool,
    /// Default value
    pub default_value: Option<String>,
}

/// Function attributes
#[derive(Debug, Clone)]

pub struct FunctionAttributes {
    /// Whether function is pure (no side effects)
    pub is_pure: bool,
    /// Whether function performs I/O
    pub performs_io: bool,
    /// Whether function is security-sensitive
    pub is_security_sensitive: bool,
    /// Whether function sanitizes input
    pub sanitizes_input: bool,
    /// Whether function validates input
    pub validates_input: bool,
}

/// Call chain information
#[derive(Debug, Clone)]

pub struct CallChain {
    /// Chain of function calls
    pub chain: Vec<String>,
    /// Starting point
    pub start: Point,
    /// Ending point
    pub end: Point,
    /// Whether chain involves user input
    pub involves_user_input: bool,
    /// Whether chain involves output
    pub involves_output: bool,
}

/// Security-specific semantic context
#[derive(Debug, Clone)]

pub struct SecuritySemanticContext {
    /// Input validation points
    pub validation_points: Vec<ValidationPoint>,
    /// Sanitization points
    pub sanitization_points: Vec<SanitizationPoint>,
    /// Authentication checks
    pub auth_checks: Vec<AuthenticationCheck>,
    /// Authorization checks
    pub authz_checks: Vec<AuthorizationCheck>,
    /// Error handling patterns
    pub error_handling: Vec<ErrorHandlingPattern>,
    /// Security boundaries
    pub security_boundaries: Vec<SecurityBoundary>,
    /// Trust levels
    pub trust_levels: HashMap<Point, TrustLevel>,
}

/// Input validation point
#[derive(Debug, Clone)]

pub struct ValidationPoint {
    /// Location of validation
    pub location: Point,
    /// Type of validation
    pub validation_type: ValidationType,
    /// Variables being validated
    pub validated_variables: Vec<SymbolId>,
    /// Validation strength
    pub strength: ValidationStrength,
}

/// Types of input validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationType {
    /// Type checking
    TypeCheck,
    /// Range validation
    RangeCheck,
    /// Format validation (regex, etc.)
    FormatCheck,
    /// Length validation
    LengthCheck,
    /// Whitelist validation
    WhitelistCheck,
    /// Blacklist validation
    BlacklistCheck,
    /// Custom validation
    CustomValidation,
}

/// Validation strength levels
#[derive(Debug, Clone, PartialEq, PartialOrd)]

pub enum ValidationStrength {
    Weak,
    Moderate,
    Strong,
    Comprehensive,
}

/// Sanitization point
#[derive(Debug, Clone)]

pub struct SanitizationPoint {
    /// Location of sanitization
    pub location: Point,
    /// Type of sanitization
    pub sanitization_type: SanitizationType,
    /// Variables being sanitized
    pub sanitized_variables: Vec<SymbolId>,
    /// Sanitization effectiveness
    pub effectiveness: SanitizationEffectiveness,
}

/// Types of sanitization
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanitizationType {
    /// HTML escaping
    HtmlEscape,
    /// SQL escaping
    SqlEscape,
    /// Shell escaping
    ShellEscape,
    /// URL encoding
    UrlEncode,
    /// Input filtering
    InputFilter,
    /// Custom sanitization
    CustomSanitization,
}

/// Sanitization effectiveness levels
#[derive(Debug, Clone, PartialEq, PartialOrd)]

pub enum SanitizationEffectiveness {
    Ineffective,
    Partial,
    Effective,
    Comprehensive,
}

/// Authentication check
#[derive(Debug, Clone)]

pub struct AuthenticationCheck {
    /// Location of check
    pub location: Point,
    /// Type of authentication
    pub auth_type: AuthenticationType,
    /// Strength of authentication
    pub strength: AuthenticationStrength,
}

/// Types of authentication
#[derive(Debug, Clone)]

pub enum AuthenticationType {
    /// Session-based
    Session,
    /// Token-based
    Token,
    /// Certificate-based
    Certificate,
    /// Multi-factor
    MultiFactor,
    /// Custom authentication
    Custom,
}

/// Authentication strength levels
#[derive(Debug, Clone, PartialEq, PartialOrd)]

pub enum AuthenticationStrength {
    Weak,
    Moderate,
    Strong,
    VeryStrong,
}

/// Authorization check
#[derive(Debug, Clone)]

pub struct AuthorizationCheck {
    /// Location of check
    pub location: Point,
    /// Type of authorization
    pub authz_type: AuthorizationType,
    /// Resources being protected
    pub protected_resources: Vec<String>,
}

/// Types of authorization
#[derive(Debug, Clone)]

pub enum AuthorizationType {
    /// Role-based access control
    RoleBasedAccess,
    /// Attribute-based access control
    AttributeBasedAccess,
    /// Discretionary access control
    DiscretionaryAccess,
    /// Mandatory access control
    MandatoryAccess,
    /// Custom authorization
    Custom,
}

/// Error handling pattern
#[derive(Debug, Clone)]

pub struct ErrorHandlingPattern {
    /// Location of error handling
    pub location: Point,
    /// Type of error handling
    pub handling_type: ErrorHandlingType,
    /// Quality of error handling
    pub quality: ErrorHandlingQuality,
}

/// Types of error handling
#[derive(Debug, Clone)]

pub enum ErrorHandlingType {
    /// Try-catch blocks
    TryCatch,
    /// Result type handling
    ResultType,
    /// Option type handling
    OptionType,
    /// Error return codes
    ErrorCodes,
    /// Custom error handling
    Custom,
}

/// Error handling quality levels
#[derive(Debug, Clone, PartialEq, PartialOrd)]

pub enum ErrorHandlingQuality {
    Poor,
    Adequate,
    Good,
    Excellent,
}

/// Security boundary
#[derive(Debug, Clone)]

pub struct SecurityBoundary {
    /// Boundary location
    pub location: Point,
    /// Type of boundary
    pub boundary_type: SecurityBoundaryType,
    /// Trust level change
    pub trust_change: TrustLevelChange,
}

/// Types of security boundaries
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityBoundaryType {
    /// Network boundary
    Network,
    /// Process boundary
    Process,
    /// Module boundary
    Module,
    /// Function boundary
    Function,
    /// Trust boundary
    Trust,
}

/// Trust level change
#[derive(Debug, Clone)]

pub struct TrustLevelChange {
    /// Trust level before boundary
    pub from: TrustLevel,
    /// Trust level after boundary
    pub to: TrustLevel,
}

/// Trust levels
#[derive(Debug, Clone, PartialEq, PartialOrd)]

pub enum TrustLevel {
    Untrusted,
    LowTrust,
    ModerateTrust,
    HighTrust,
    FullyTrusted,
}

/// Type context information
#[derive(Debug, Clone)]

pub struct TypeContext {
    /// Type information for expressions
    pub expression_types: HashMap<Point, TypeInfo>,
    /// Type constraints
    pub type_constraints: Vec<TypeConstraint>,
    /// Generic type instantiations
    pub generic_instantiations: HashMap<Point, Vec<TypeInfo>>,
}

/// Type information
#[derive(Debug, Clone)]

pub struct TypeInfo {
    /// Type name
    pub type_name: String,
    /// Whether type is nullable
    pub is_nullable: bool,
    /// Whether type is mutable
    pub is_mutable: bool,
    /// Generic parameters
    pub generic_params: Vec<TypeInfo>,
}

/// Type constraint
#[derive(Debug, Clone)]

pub struct TypeConstraint {
    /// Location of constraint
    pub location: Point,
    /// Type being constrained
    pub constrained_type: TypeInfo,
    /// Constraint type
    pub constraint_type: ConstraintType,
}

/// Types of type constraints
#[derive(Debug, Clone)]

pub enum ConstraintType {
    /// Subtype constraint
    Subtype,
    /// Equality constraint
    Equality,
    /// Trait bound
    TraitBound,
    /// Lifetime constraint
    Lifetime,
}

/// Pattern context for code idioms
#[derive(Debug, Clone)]

pub struct PatternContext {
    /// Detected code patterns
    pub patterns: Vec<CodePattern>,
    /// Anti-patterns
    pub anti_patterns: Vec<AntiPattern>,
    /// Idioms and best practices
    pub idioms: Vec<CodeIdiom>,
}

/// Code pattern
#[derive(Debug, Clone)]

pub struct CodePattern {
    /// Pattern name
    pub name: String,
    /// Pattern location
    pub location: Point,
    /// Pattern type
    pub pattern_type: PatternType,
    /// Confidence level
    pub confidence: f64,
}

/// Types of code patterns
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternType {
    /// Security pattern
    Security,
    /// Design pattern
    Design,
    /// Performance pattern
    Performance,
    /// Error handling pattern
    ErrorHandling,
    /// Concurrency pattern
    Concurrency,
}

/// Anti-pattern
#[derive(Debug, Clone)]

pub struct AntiPattern {
    /// Anti-pattern name
    pub name: String,
    /// Location
    pub location: Point,
    /// Severity
    pub severity: AntiPatternSeverity,
    /// Suggested fix
    pub suggested_fix: String,
}

/// Anti-pattern severity levels
#[derive(Debug, Clone, PartialEq, PartialOrd)]

pub enum AntiPatternSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Code idiom
#[derive(Debug, Clone)]

pub struct CodeIdiom {
    /// Idiom name
    pub name: String,
    /// Location
    pub location: Point,
    /// Language-specific
    pub language: Language,
    /// Quality score
    pub quality_score: f64,
}

/// Semantic context analyzer
pub struct SemanticContextAnalyzer {
    /// Language being analyzed
    #[allow(dead_code)]
    language: Language,
    /// Symbol table analyzer
    symbol_analyzer: SymbolTableAnalyzer,
    /// Control flow graph builder
    cfg_builder: CfgBuilder,
    /// Taint analyzer
    taint_analyzer: TaintAnalyzer,
}

impl SemanticContextAnalyzer {
    /// Create a new semantic context analyzer
    pub fn new(language: Language) -> Result<Self> {
        Ok(Self {
            language,
            symbol_analyzer: SymbolTableAnalyzer::new(language),
            cfg_builder: CfgBuilder::new(),
            taint_analyzer: TaintAnalyzer::new(),
        })
    }

    /// Analyze a syntax tree and build comprehensive semantic context
    pub fn analyze(&mut self, tree: &SyntaxTree, content: &str) -> Result<SemanticContext> {
        // Phase 1: Build symbol table
        let symbol_analysis = self.symbol_analyzer.analyze(tree)?;
        let symbol_table = symbol_analysis.symbol_table;

        // Phase 2: Build control flow graph
        let control_flow = self.cfg_builder.build_cfg(tree.root_node())?;

        // Phase 3: Perform data flow analysis
        let data_flow = self.analyze_data_flow(tree, &symbol_table, &control_flow)?;

        // Phase 4: Build call graph
        let call_graph = self.build_call_graph(tree, content, &symbol_table)?;

        // Phase 5: Analyze security context
        let security_context = self.analyze_security_context(tree, content, &symbol_table, &data_flow)?;

        // Phase 6: Perform type analysis
        let type_context = self.analyze_types(tree, &symbol_table)?;

        // Phase 7: Detect patterns and idioms
        let pattern_context = self.analyze_patterns(tree, content, &symbol_table)?;

        Ok(SemanticContext {
            symbol_table,
            control_flow,
            data_flow,
            call_graph,
            security_context,
            type_context,
            pattern_context,
        })
    }

    /// Perform data flow analysis
    fn analyze_data_flow(
        &mut self,
        tree: &SyntaxTree,
        symbol_table: &SymbolTable,
        control_flow: &ControlFlowGraph,
    ) -> Result<DataFlowAnalysis> {
        let mut reaching_definitions = HashMap::new();
        let mut use_def_chains = HashMap::new();
        let mut def_use_chains = HashMap::new();
        let mut aliases = HashMap::new();
        let mut constants = HashMap::new();

        // Build reaching definitions
        self.compute_reaching_definitions(tree, symbol_table, control_flow, &mut reaching_definitions)?;

        // Build use-def chains
        self.compute_use_def_chains(tree, symbol_table, &reaching_definitions, &mut use_def_chains)?;

        // Build def-use chains
        self.compute_def_use_chains(&use_def_chains, &mut def_use_chains)?;

        // Perform alias analysis
        self.compute_aliases(tree, symbol_table, &mut aliases)?;

        // Perform constant propagation
        self.compute_constants(tree, symbol_table, control_flow, &mut constants)?;

        // Perform taint analysis
        let taint_flows = self.compute_taint_flows(tree, symbol_table)?;

        Ok(DataFlowAnalysis {
            reaching_definitions,
            use_def_chains,
            def_use_chains,
            taint_flows,
            aliases,
            constants,
        })
    }

    /// Compute reaching definitions
    fn compute_reaching_definitions(
        &self,
        tree: &SyntaxTree,
        symbol_table: &SymbolTable,
        _control_flow: &ControlFlowGraph,
        reaching_definitions: &mut HashMap<Point, HashSet<DefinitionSite>>,
    ) -> Result<()> {
        let root = tree.root_node();
        let mut definitions = HashMap::new();

        // Walk the tree to find all definitions
        self.collect_definitions(&root, symbol_table, &mut definitions)?;

        // For each program point, compute which definitions reach it
        self.propagate_definitions(&root, &definitions, reaching_definitions)?;

        Ok(())
    }

    /// Collect all variable definitions
    fn collect_definitions(
        &self,
        node: &Node,
        symbol_table: &SymbolTable,
        definitions: &mut HashMap<SymbolId, Vec<DefinitionSite>>,
    ) -> Result<()> {
        match node.kind() {
            "let_declaration" | "variable_declaration" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    if let Ok(_name) = pattern.text() {
                        // Find symbol in symbol table
                        if let Some(symbol_id) = self.find_symbol_at_location(symbol_table, node.start_position()) {
                            let def_site = DefinitionSite {
                                symbol_id,
                                location: node.start_position(),
                                definition_type: DefinitionType::Declaration,
                                value: node.child_by_field_name("value")
                                    .and_then(|v| v.text().ok())
                                    .map(|s| s.to_string()),
                            };
                            definitions.entry(symbol_id).or_insert_with(Vec::new).push(def_site);
                        }
                    }
                }
            }
            "assignment_expression" => {
                if let Some(left) = node.child_by_field_name("left") {
                    if let Ok(_name) = left.text() {
                        if let Some(symbol_id) = self.find_symbol_at_location(symbol_table, left.start_position()) {
                            let def_site = DefinitionSite {
                                symbol_id,
                                location: node.start_position(),
                                definition_type: DefinitionType::Assignment,
                                value: node.child_by_field_name("right")
                                    .and_then(|v| v.text().ok())
                                    .map(|s| s.to_string()),
                            };
                            definitions.entry(symbol_id).or_insert_with(Vec::new).push(def_site);
                        }
                    }
                }
            }
            "parameter" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    if let Ok(_name) = pattern.text() {
                        if let Some(symbol_id) = self.find_symbol_at_location(symbol_table, node.start_position()) {
                            let def_site = DefinitionSite {
                                symbol_id,
                                location: node.start_position(),
                                definition_type: DefinitionType::Parameter,
                                value: None,
                            };
                            definitions.entry(symbol_id).or_insert_with(Vec::new).push(def_site);
                        }
                    }
                }
            }
            _ => {}
        }

        // Recursively process children
        for child in node.children() {
            self.collect_definitions(&child, symbol_table, definitions)?;
        }

        Ok(())
    }

    /// Find symbol at a specific location
    fn find_symbol_at_location(&self, symbol_table: &SymbolTable, location: Point) -> Option<SymbolId> {
        // This is a simplified implementation - in practice, you'd need more sophisticated lookup
        for (&symbol_id, symbol_def) in &symbol_table.symbols {
            if symbol_def.definition_location == location {
                return Some(symbol_id);
            }
        }
        None
    }

    /// Propagate definitions to compute reaching definitions
    fn propagate_definitions(
        &self,
        node: &Node,
        definitions: &HashMap<SymbolId, Vec<DefinitionSite>>,
        reaching_definitions: &mut HashMap<Point, HashSet<DefinitionSite>>,
    ) -> Result<()> {
        // For each program point, determine which definitions reach it
        let mut current_definitions = HashSet::new();

        // Collect all definitions that reach this point
        for def_list in definitions.values() {
            for def_site in def_list {
                if def_site.location.row <= node.start_position().row {
                    current_definitions.insert(def_site.clone());
                }
            }
        }

        reaching_definitions.insert(node.start_position(), current_definitions);

        // Recursively process children
        for child in node.children() {
            self.propagate_definitions(&child, definitions, reaching_definitions)?;
        }

        Ok(())
    }

    /// Compute use-definition chains
    fn compute_use_def_chains(
        &self,
        tree: &SyntaxTree,
        symbol_table: &SymbolTable,
        reaching_definitions: &HashMap<Point, HashSet<DefinitionSite>>,
        use_def_chains: &mut HashMap<Point, Vec<DefinitionSite>>,
    ) -> Result<()> {
        let root = tree.root_node();
        self.collect_uses(&root, symbol_table, reaching_definitions, use_def_chains)?;
        Ok(())
    }

    /// Collect variable uses and link to definitions
    fn collect_uses(
        &self,
        node: &Node,
        symbol_table: &SymbolTable,
        reaching_definitions: &HashMap<Point, HashSet<DefinitionSite>>,
        use_def_chains: &mut HashMap<Point, Vec<DefinitionSite>>,
    ) -> Result<()> {
        if node.kind() == "identifier" {
            if let Ok(name) = node.text() {
                // Check if this is a variable use (not a definition)
                if !self.is_definition_site(node) {
                    if let Some(reaching_defs) = reaching_definitions.get(&node.start_position()) {
                        // Find definitions for this variable
                        let mut relevant_defs = Vec::new();
                        for def_site in reaching_defs {
                            if let Some(symbol_def) = symbol_table.symbols.get(&def_site.symbol_id) {
                                if symbol_def.name == name {
                                    relevant_defs.push(def_site.clone());
                                }
                            }
                        }
                        if !relevant_defs.is_empty() {
                            use_def_chains.insert(node.start_position(), relevant_defs);
                        }
                    }
                }
            }
        }

        // Recursively process children
        for child in node.children() {
            self.collect_uses(&child, symbol_table, reaching_definitions, use_def_chains)?;
        }

        Ok(())
    }

    /// Check if a node is a definition site
    fn is_definition_site(&self, node: &Node) -> bool {
        if let Some(parent) = node.parent() {
            match parent.kind() {
                "let_declaration" | "variable_declaration" => {
                    // Check if this identifier is the pattern being defined
                    if let Some(pattern) = parent.child_by_field_name("pattern") {
                        return pattern.start_position() == node.start_position();
                    }
                }
                "assignment_expression" => {
                    // Check if this identifier is on the left side
                    if let Some(left) = parent.child_by_field_name("left") {
                        return left.start_position() == node.start_position();
                    }
                }
                "parameter" => {
                    // Check if this identifier is the parameter name
                    if let Some(pattern) = parent.child_by_field_name("pattern") {
                        return pattern.start_position() == node.start_position();
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Compute definition-use chains
    fn compute_def_use_chains(
        &self,
        use_def_chains: &HashMap<Point, Vec<DefinitionSite>>,
        def_use_chains: &mut HashMap<DefinitionSite, Vec<Point>>,
    ) -> Result<()> {
        for (use_point, def_sites) in use_def_chains {
            for def_site in def_sites {
                def_use_chains.entry(def_site.clone()).or_insert_with(Vec::new).push(*use_point);
            }
        }
        Ok(())
    }

    /// Compute alias analysis
    fn compute_aliases(
        &self,
        tree: &SyntaxTree,
        symbol_table: &SymbolTable,
        aliases: &mut HashMap<SymbolId, HashSet<SymbolId>>,
    ) -> Result<()> {
        let root = tree.root_node();
        self.analyze_aliases(&root, symbol_table, aliases)?;
        Ok(())
    }

    /// Analyze pointer aliases and references
    fn analyze_aliases(
        &self,
        node: &Node,
        symbol_table: &SymbolTable,
        aliases: &mut HashMap<SymbolId, HashSet<SymbolId>>,
    ) -> Result<()> {
        match node.kind() {
            "assignment_expression" => {
                // Check for pointer assignments like a = &b or a = b
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right")
                ) {
                    if let (Ok(left_name), Ok(right_text)) = (left.text(), right.text()) {
                        // Simple alias detection for reference assignments
                        if right_text.starts_with('&') {
                            let right_name = &right_text[1..]; // Remove &
                            if let (Some(left_id), Some(right_id)) = (
                                self.find_symbol_by_name(symbol_table, &left_name),
                                self.find_symbol_by_name(symbol_table, right_name)
                            ) {
                                aliases.entry(left_id).or_insert_with(HashSet::new).insert(right_id);
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        // Recursively process children
        for child in node.children() {
            self.analyze_aliases(&child, symbol_table, aliases)?;
        }

        Ok(())
    }

    /// Find symbol by name (simplified lookup)
    fn find_symbol_by_name(&self, symbol_table: &SymbolTable, name: &str) -> Option<SymbolId> {
        for (&symbol_id, symbol_def) in &symbol_table.symbols {
            if symbol_def.name == name {
                return Some(symbol_id);
            }
        }
        None
    }

    /// Compute constant propagation
    fn compute_constants(
        &self,
        tree: &SyntaxTree,
        symbol_table: &SymbolTable,
        _control_flow: &ControlFlowGraph,
        constants: &mut HashMap<Point, ConstantValue>,
    ) -> Result<()> {
        let root = tree.root_node();
        self.propagate_constants(&root, symbol_table, constants)?;
        Ok(())
    }

    /// Propagate constant values
    fn propagate_constants(
        &self,
        node: &Node,
        _symbol_table: &SymbolTable,
        constants: &mut HashMap<Point, ConstantValue>,
    ) -> Result<()> {
        match node.kind() {
            "string_literal" | "string" => {
                if let Ok(text) = node.text() {
                    // Remove quotes
                    let value = text.trim_matches('"').trim_matches('\'');
                    constants.insert(node.start_position(), ConstantValue::String(value.to_string()));
                }
            }
            "integer_literal" | "number" => {
                if let Ok(text) = node.text() {
                    if let Ok(value) = text.parse::<i64>() {
                        constants.insert(node.start_position(), ConstantValue::Integer(value));
                    } else if let Ok(value) = text.parse::<f64>() {
                        constants.insert(node.start_position(), ConstantValue::Float(value));
                    }
                }
            }
            "true" => {
                constants.insert(node.start_position(), ConstantValue::Boolean(true));
            }
            "false" => {
                constants.insert(node.start_position(), ConstantValue::Boolean(false));
            }
            "null" | "nil" | "None" => {
                constants.insert(node.start_position(), ConstantValue::Null);
            }
            _ => {}
        }

        // Recursively process children
        for child in node.children() {
            self.propagate_constants(&child, _symbol_table, constants)?;
        }

        Ok(())
    }

    /// Compute taint flows
    fn compute_taint_flows(
        &mut self,
        tree: &SyntaxTree,
        _symbol_table: &SymbolTable,
    ) -> Result<Vec<TaintFlow>> {
        // Use the existing taint analyzer
        let taint_result = self.taint_analyzer.analyze_taint_flows(tree)?;
        Ok(taint_result.flows)
    }

    /// Build call graph
    fn build_call_graph(
        &self,
        tree: &SyntaxTree,
        content: &str,
        symbol_table: &SymbolTable,
    ) -> Result<CallGraph> {
        let mut calls = HashMap::new();
        let mut functions = HashMap::new();
        let mut call_chains = Vec::new();

        let root = tree.root_node();

        // Collect function definitions
        self.collect_function_definitions(&root, &mut functions)?;

        // Collect function calls
        self.collect_function_calls(&root, content, symbol_table, &mut calls)?;

        // Build call chains
        self.build_call_chains(&calls, &functions, &mut call_chains)?;

        Ok(CallGraph {
            calls,
            functions,
            call_chains,
        })
    }

    /// Collect function definitions
    fn collect_function_definitions(
        &self,
        node: &Node,
        functions: &mut HashMap<String, FunctionDefinition>,
    ) -> Result<()> {
        match node.kind() {
            "function_item" | "function_declaration" | "method_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.text() {
                        let mut parameters = Vec::new();

                        // Extract parameters
                        if let Some(params_node) = node.child_by_field_name("parameters") {
                            self.extract_parameters(&params_node, &mut parameters)?;
                        }

                        // Extract return type
                        let return_type = node.child_by_field_name("return_type")
                            .and_then(|rt| rt.text().ok())
                            .map(|s| s.to_string());

                        // Analyze function attributes
                        let attributes = self.analyze_function_attributes(node)?;

                        let function_def = FunctionDefinition {
                            name: name.to_string(),
                            location: node.start_position(),
                            parameters,
                            return_type,
                            attributes,
                        };

                        functions.insert(name.to_string(), function_def);
                    }
                }
            }
            _ => {}
        }

        // Recursively process children
        for child in node.children() {
            self.collect_function_definitions(&child, functions)?;
        }

        Ok(())
    }

    /// Extract function parameters
    fn extract_parameters(
        &self,
        params_node: &Node,
        parameters: &mut Vec<ParameterInfo>,
    ) -> Result<()> {
        for child in params_node.children() {
            if child.kind() == "parameter" {
                if let Some(pattern) = child.child_by_field_name("pattern") {
                    if let Ok(name) = pattern.text() {
                        let param_type = child.child_by_field_name("type")
                            .and_then(|t| t.text().ok())
                            .map(|s| s.to_string());

                        let default_value = child.child_by_field_name("default_value")
                            .and_then(|dv| dv.text().ok())
                            .map(|s| s.to_string());

                        let is_mutable = self.is_parameter_mutable(&child);

                        parameters.push(ParameterInfo {
                            name: name.to_string(),
                            param_type,
                            is_mutable,
                            default_value,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Check if parameter is mutable
    fn is_parameter_mutable(&self, param_node: &Node) -> bool {
        // Check for mut keyword in parameter
        for child in param_node.children() {
            if child.kind() == "mutable_pattern" {
                return true;
            }
        }
        false
    }

    /// Analyze function attributes
    fn analyze_function_attributes(&self, function_node: &Node) -> Result<FunctionAttributes> {
        let mut is_pure = true;
        let mut performs_io = false;
        let mut is_security_sensitive = false;
        let mut sanitizes_input = false;
        let mut validates_input = false;

        // Analyze function body for side effects
        if let Some(body) = function_node.child_by_field_name("body") {
            self.analyze_function_body(&body, &mut is_pure, &mut performs_io,
                                     &mut is_security_sensitive, &mut sanitizes_input,
                                     &mut validates_input)?;
        }

        Ok(FunctionAttributes {
            is_pure,
            performs_io,
            is_security_sensitive,
            sanitizes_input,
            validates_input,
        })
    }

    /// Analyze function body for attributes
    fn analyze_function_body(
        &self,
        body: &Node,
        is_pure: &mut bool,
        performs_io: &mut bool,
        is_security_sensitive: &mut bool,
        sanitizes_input: &mut bool,
        validates_input: &mut bool,
    ) -> Result<()> {
        for child in body.children() {
            match child.kind() {
                "call_expression" => {
                    if let Some(function) = child.child_by_field_name("function") {
                        if let Ok(func_name) = function.text() {
                            let func_name_lower = func_name.to_lowercase();

                            // Check for I/O operations
                            if self.is_io_function(&func_name_lower) {
                                *performs_io = true;
                                *is_pure = false;
                            }

                            // Check for security-sensitive functions
                            if self.is_security_sensitive_function(&func_name_lower) {
                                *is_security_sensitive = true;
                            }

                            // Check for sanitization functions
                            if self.is_sanitization_function(&func_name_lower) {
                                *sanitizes_input = true;
                            }

                            // Check for validation functions
                            if self.is_validation_function(&func_name_lower) {
                                *validates_input = true;
                            }
                        }
                    }
                }
                "assignment_expression" => {
                    // Assignments make function impure
                    *is_pure = false;
                }
                _ => {}
            }

            // Recursively analyze children
            self.analyze_function_body(&child, is_pure, performs_io,
                                     is_security_sensitive, sanitizes_input,
                                     validates_input)?;
        }

        Ok(())
    }

    /// Check if function performs I/O
    fn is_io_function(&self, func_name: &str) -> bool {
        let io_functions = [
            "print", "println", "printf", "read", "write", "open", "close",
            "file", "socket", "connect", "send", "recv", "fetch", "request"
        ];
        io_functions.iter().any(|&io_func| func_name.contains(io_func))
    }

    /// Check if function is security-sensitive
    fn is_security_sensitive_function(&self, func_name: &str) -> bool {
        let security_functions = [
            "auth", "login", "password", "token", "encrypt", "decrypt",
            "hash", "sign", "verify", "permission", "access", "admin"
        ];
        security_functions.iter().any(|&sec_func| func_name.contains(sec_func))
    }

    /// Check if function performs sanitization
    fn is_sanitization_function(&self, func_name: &str) -> bool {
        let sanitization_functions = [
            "escape", "sanitize", "clean", "filter", "encode", "strip"
        ];
        sanitization_functions.iter().any(|&san_func| func_name.contains(san_func))
    }

    /// Check if function performs validation
    fn is_validation_function(&self, func_name: &str) -> bool {
        let validation_functions = [
            "validate", "check", "verify", "assert", "ensure", "require"
        ];
        validation_functions.iter().any(|&val_func| func_name.contains(val_func))
    }

    /// Collect function calls
    fn collect_function_calls(
        &self,
        node: &Node,
        _content: &str,
        _symbol_table: &SymbolTable,
        calls: &mut HashMap<Point, Vec<FunctionCall>>,
    ) -> Result<()> {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                if let Ok(function_name) = function.text() {
                    let mut arguments = Vec::new();

                    // Extract arguments
                    if let Some(args_node) = node.child_by_field_name("arguments") {
                        self.extract_arguments(&args_node, &mut arguments)?;
                    }

                    let function_call = FunctionCall {
                        function_name: function_name.to_string(),
                        call_site: node.start_position(),
                        arguments,
                        return_usage: ReturnUsage::Used, // Simplified
                    };

                    calls.entry(node.start_position()).or_insert_with(Vec::new).push(function_call);
                }
            }
        }

        // Recursively process children
        for child in node.children() {
            self.collect_function_calls(&child, _content, _symbol_table, calls)?;
        }

        Ok(())
    }

    /// Extract function call arguments
    fn extract_arguments(&self, args_node: &Node, arguments: &mut Vec<ArgumentInfo>) -> Result<()> {
        let mut position = 0;
        for child in args_node.children() {
            if child.kind() != "," {
                if let Ok(expression) = child.text() {
                    arguments.push(ArgumentInfo {
                        position,
                        expression: expression.to_string(),
                        is_tainted: false, // Would be determined by taint analysis
                        constant_value: None, // Would be determined by constant propagation
                    });
                    position += 1;
                }
            }
        }
        Ok(())
    }

    /// Build call chains
    fn build_call_chains(
        &self,
        _calls: &HashMap<Point, Vec<FunctionCall>>,
        _functions: &HashMap<String, FunctionDefinition>,
        _call_chains: &mut Vec<CallChain>,
    ) -> Result<()> {
        // Placeholder implementation - would build actual call chains
        Ok(())
    }

    /// Analyze security context
    fn analyze_security_context(
        &self,
        tree: &SyntaxTree,
        _content: &str,
        _symbol_table: &SymbolTable,
        _data_flow: &DataFlowAnalysis,
    ) -> Result<SecuritySemanticContext> {
        let mut validation_points = Vec::new();
        let mut sanitization_points = Vec::new();
        let mut auth_checks = Vec::new();
        let mut authz_checks = Vec::new();
        let mut error_handling = Vec::new();
        let mut security_boundaries = Vec::new();
        let mut trust_levels = HashMap::new();

        let root = tree.root_node();
        self.analyze_security_patterns(&root, &mut validation_points, &mut sanitization_points,
                                     &mut auth_checks, &mut authz_checks, &mut error_handling,
                                     &mut security_boundaries, &mut trust_levels)?;

        Ok(SecuritySemanticContext {
            validation_points,
            sanitization_points,
            auth_checks,
            authz_checks,
            error_handling,
            security_boundaries,
            trust_levels,
        })
    }

    /// Analyze security patterns
    fn analyze_security_patterns(
        &self,
        node: &Node,
        validation_points: &mut Vec<ValidationPoint>,
        sanitization_points: &mut Vec<SanitizationPoint>,
        auth_checks: &mut Vec<AuthenticationCheck>,
        authz_checks: &mut Vec<AuthorizationCheck>,
        error_handling: &mut Vec<ErrorHandlingPattern>,
        security_boundaries: &mut Vec<SecurityBoundary>,
        trust_levels: &mut HashMap<Point, TrustLevel>,
    ) -> Result<()> {
        match node.kind() {
            "call_expression" => {
                if let Some(function) = node.child_by_field_name("function") {
                    if let Ok(func_name) = function.text() {
                        let func_name_lower = func_name.to_lowercase();

                        // Detect validation patterns
                        if self.is_validation_function(&func_name_lower) {
                            validation_points.push(ValidationPoint {
                                location: node.start_position(),
                                validation_type: ValidationType::CustomValidation,
                                validated_variables: Vec::new(), // Would be populated with actual analysis
                                strength: ValidationStrength::Moderate,
                            });
                        }

                        // Detect sanitization patterns
                        if self.is_sanitization_function(&func_name_lower) {
                            sanitization_points.push(SanitizationPoint {
                                location: node.start_position(),
                                sanitization_type: SanitizationType::CustomSanitization,
                                sanitized_variables: Vec::new(), // Would be populated with actual analysis
                                effectiveness: SanitizationEffectiveness::Effective,
                            });
                        }

                        // Detect authentication patterns
                        if func_name_lower.contains("auth") || func_name_lower.contains("login") {
                            auth_checks.push(AuthenticationCheck {
                                location: node.start_position(),
                                auth_type: AuthenticationType::Custom,
                                strength: AuthenticationStrength::Moderate,
                            });
                        }

                        // Set trust levels
                        if func_name_lower.contains("user_input") || func_name_lower.contains("request") {
                            trust_levels.insert(node.start_position(), TrustLevel::Untrusted);
                        }
                    }
                }
            }
            "try_expression" | "try_statement" => {
                error_handling.push(ErrorHandlingPattern {
                    location: node.start_position(),
                    handling_type: ErrorHandlingType::TryCatch,
                    quality: ErrorHandlingQuality::Good,
                });
            }
            _ => {}
        }

        // Recursively process children
        for child in node.children() {
            self.analyze_security_patterns(&child, validation_points, sanitization_points,
                                         auth_checks, authz_checks, error_handling,
                                         security_boundaries, trust_levels)?;
        }

        Ok(())
    }

    /// Analyze types
    fn analyze_types(&self, tree: &SyntaxTree, _symbol_table: &SymbolTable) -> Result<TypeContext> {
        let mut expression_types = HashMap::new();
        let mut type_constraints = Vec::new();
        let mut generic_instantiations = HashMap::new();

        let root = tree.root_node();
        self.infer_types(&root, &mut expression_types, &mut type_constraints, &mut generic_instantiations)?;

        Ok(TypeContext {
            expression_types,
            type_constraints,
            generic_instantiations,
        })
    }

    /// Infer types for expressions
    fn infer_types(
        &self,
        node: &Node,
        expression_types: &mut HashMap<Point, TypeInfo>,
        _type_constraints: &mut Vec<TypeConstraint>,
        _generic_instantiations: &mut HashMap<Point, Vec<TypeInfo>>,
    ) -> Result<()> {
        match node.kind() {
            "string_literal" | "string" => {
                expression_types.insert(node.start_position(), TypeInfo {
                    type_name: "String".to_string(),
                    is_nullable: false,
                    is_mutable: false,
                    generic_params: Vec::new(),
                });
            }
            "integer_literal" | "number" => {
                expression_types.insert(node.start_position(), TypeInfo {
                    type_name: "i32".to_string(), // Simplified
                    is_nullable: false,
                    is_mutable: false,
                    generic_params: Vec::new(),
                });
            }
            "true" | "false" => {
                expression_types.insert(node.start_position(), TypeInfo {
                    type_name: "bool".to_string(),
                    is_nullable: false,
                    is_mutable: false,
                    generic_params: Vec::new(),
                });
            }
            _ => {}
        }

        // Recursively process children
        for child in node.children() {
            self.infer_types(&child, expression_types, _type_constraints, _generic_instantiations)?;
        }

        Ok(())
    }

    /// Analyze patterns and idioms
    fn analyze_patterns(
        &self,
        tree: &SyntaxTree,
        _content: &str,
        _symbol_table: &SymbolTable,
    ) -> Result<PatternContext> {
        let mut patterns = Vec::new();
        let mut anti_patterns = Vec::new();
        let mut idioms = Vec::new();

        let root = tree.root_node();
        self.detect_patterns(&root, &mut patterns, &mut anti_patterns, &mut idioms)?;

        Ok(PatternContext {
            patterns,
            anti_patterns,
            idioms,
        })
    }

    /// Detect code patterns and anti-patterns
    fn detect_patterns(
        &self,
        node: &Node,
        patterns: &mut Vec<CodePattern>,
        anti_patterns: &mut Vec<AntiPattern>,
        idioms: &mut Vec<CodeIdiom>,
    ) -> Result<()> {
        match node.kind() {
            "if_expression" | "if_statement" => {
                // Check for security patterns
                if let Some(condition) = node.child_by_field_name("condition") {
                    if let Ok(condition_text) = condition.text() {
                        if condition_text.contains("auth") || condition_text.contains("permission") {
                            patterns.push(CodePattern {
                                name: "Security Check Pattern".to_string(),
                                location: node.start_position(),
                                pattern_type: PatternType::Security,
                                confidence: 0.8,
                            });
                        }
                    }
                }
            }
            "unwrap" => {
                // Detect unwrap anti-pattern
                anti_patterns.push(AntiPattern {
                    name: "Unwrap Anti-pattern".to_string(),
                    location: node.start_position(),
                    severity: AntiPatternSeverity::Medium,
                    suggested_fix: "Use proper error handling with match or if let".to_string(),
                });
            }
            _ => {}
        }

        // Recursively process children
        for child in node.children() {
            self.detect_patterns(&child, patterns, anti_patterns, idioms)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_semantic_context_analyzer_creation() -> Result<()> {
        let analyzer = SemanticContextAnalyzer::new(Language::Rust)?;
        assert_eq!(analyzer.language, Language::Rust);
        Ok(())
    }

    #[test]
    fn test_definition_site_creation() {
        let def_site = DefinitionSite {
            symbol_id: 0,
            location: Point { row: 1, column: 5 },
            definition_type: DefinitionType::Declaration,
            value: Some("42".to_string()),
        };

        assert_eq!(def_site.symbol_id, 0);
        assert_eq!(def_site.definition_type, DefinitionType::Declaration);
        assert_eq!(def_site.value, Some("42".to_string()));
    }

    #[test]
    fn test_constant_value_variants() {
        let string_val = ConstantValue::String("test".to_string());
        let int_val = ConstantValue::Integer(42);
        let float_val = ConstantValue::Float(3.14);
        let bool_val = ConstantValue::Boolean(true);
        let null_val = ConstantValue::Null;
        let unknown_val = ConstantValue::Unknown;

        match string_val {
            ConstantValue::String(s) => assert_eq!(s, "test"),
            _ => panic!("Expected string value"),
        }

        match int_val {
            ConstantValue::Integer(i) => assert_eq!(i, 42),
            _ => panic!("Expected integer value"),
        }

        match float_val {
            ConstantValue::Float(f) => assert!((f - 3.14).abs() < f64::EPSILON),
            _ => panic!("Expected float value"),
        }

        match bool_val {
            ConstantValue::Boolean(b) => assert!(b),
            _ => panic!("Expected boolean value"),
        }

        match null_val {
            ConstantValue::Null => {},
            _ => panic!("Expected null value"),
        }

        match unknown_val {
            ConstantValue::Unknown => {},
            _ => panic!("Expected unknown value"),
        }
    }

    #[test]
    fn test_function_call_creation() {
        let function_call = FunctionCall {
            function_name: "test_function".to_string(),
            call_site: Point { row: 5, column: 10 },
            arguments: vec![
                ArgumentInfo {
                    position: 0,
                    expression: "arg1".to_string(),
                    is_tainted: false,
                    constant_value: Some(ConstantValue::String("test".to_string())),
                }
            ],
            return_usage: ReturnUsage::Used,
        };

        assert_eq!(function_call.function_name, "test_function");
        assert_eq!(function_call.arguments.len(), 1);
        assert_eq!(function_call.arguments[0].position, 0);
        assert_eq!(function_call.arguments[0].expression, "arg1");
    }

    #[test]
    fn test_validation_point_creation() {
        let validation_point = ValidationPoint {
            location: Point { row: 10, column: 5 },
            validation_type: ValidationType::TypeCheck,
            validated_variables: vec![0, 1, 2],
            strength: ValidationStrength::Strong,
        };

        assert_eq!(validation_point.validation_type, ValidationType::TypeCheck);
        assert_eq!(validation_point.strength, ValidationStrength::Strong);
        assert_eq!(validation_point.validated_variables.len(), 3);
    }

    #[test]
    fn test_sanitization_point_creation() {
        let sanitization_point = SanitizationPoint {
            location: Point { row: 15, column: 8 },
            sanitization_type: SanitizationType::HtmlEscape,
            sanitized_variables: vec![5, 6],
            effectiveness: SanitizationEffectiveness::Comprehensive,
        };

        assert_eq!(sanitization_point.sanitization_type, SanitizationType::HtmlEscape);
        assert_eq!(sanitization_point.effectiveness, SanitizationEffectiveness::Comprehensive);
        assert_eq!(sanitization_point.sanitized_variables.len(), 2);
    }

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Untrusted < TrustLevel::LowTrust);
        assert!(TrustLevel::LowTrust < TrustLevel::ModerateTrust);
        assert!(TrustLevel::ModerateTrust < TrustLevel::HighTrust);
        assert!(TrustLevel::HighTrust < TrustLevel::FullyTrusted);
    }

    #[test]
    fn test_validation_strength_ordering() {
        assert!(ValidationStrength::Weak < ValidationStrength::Moderate);
        assert!(ValidationStrength::Moderate < ValidationStrength::Strong);
        assert!(ValidationStrength::Strong < ValidationStrength::Comprehensive);
    }

    #[test]
    fn test_sanitization_effectiveness_ordering() {
        assert!(SanitizationEffectiveness::Ineffective < SanitizationEffectiveness::Partial);
        assert!(SanitizationEffectiveness::Partial < SanitizationEffectiveness::Effective);
        assert!(SanitizationEffectiveness::Effective < SanitizationEffectiveness::Comprehensive);
    }

    #[test]
    fn test_authentication_strength_ordering() {
        assert!(AuthenticationStrength::Weak < AuthenticationStrength::Moderate);
        assert!(AuthenticationStrength::Moderate < AuthenticationStrength::Strong);
        assert!(AuthenticationStrength::Strong < AuthenticationStrength::VeryStrong);
    }

    #[test]
    fn test_error_handling_quality_ordering() {
        assert!(ErrorHandlingQuality::Poor < ErrorHandlingQuality::Adequate);
        assert!(ErrorHandlingQuality::Adequate < ErrorHandlingQuality::Good);
        assert!(ErrorHandlingQuality::Good < ErrorHandlingQuality::Excellent);
    }

    #[test]
    fn test_anti_pattern_severity_ordering() {
        assert!(AntiPatternSeverity::Low < AntiPatternSeverity::Medium);
        assert!(AntiPatternSeverity::Medium < AntiPatternSeverity::High);
        assert!(AntiPatternSeverity::High < AntiPatternSeverity::Critical);
    }

    #[test]
    fn test_type_info_creation() {
        let type_info = TypeInfo {
            type_name: "Vec<String>".to_string(),
            is_nullable: false,
            is_mutable: true,
            generic_params: vec![
                TypeInfo {
                    type_name: "String".to_string(),
                    is_nullable: false,
                    is_mutable: false,
                    generic_params: Vec::new(),
                }
            ],
        };

        assert_eq!(type_info.type_name, "Vec<String>");
        assert!(!type_info.is_nullable);
        assert!(type_info.is_mutable);
        assert_eq!(type_info.generic_params.len(), 1);
        assert_eq!(type_info.generic_params[0].type_name, "String");
    }

    #[test]
    fn test_code_pattern_creation() {
        let pattern = CodePattern {
            name: "Security Check Pattern".to_string(),
            location: Point { row: 20, column: 4 },
            pattern_type: PatternType::Security,
            confidence: 0.85,
        };

        assert_eq!(pattern.name, "Security Check Pattern");
        assert_eq!(pattern.pattern_type, PatternType::Security);
        assert!((pattern.confidence - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_anti_pattern_creation() {
        let anti_pattern = AntiPattern {
            name: "Unwrap Anti-pattern".to_string(),
            location: Point { row: 25, column: 12 },
            severity: AntiPatternSeverity::High,
            suggested_fix: "Use proper error handling".to_string(),
        };

        assert_eq!(anti_pattern.name, "Unwrap Anti-pattern");
        assert_eq!(anti_pattern.severity, AntiPatternSeverity::High);
        assert_eq!(anti_pattern.suggested_fix, "Use proper error handling");
    }

    #[test]
    fn test_security_boundary_creation() {
        let boundary = SecurityBoundary {
            location: Point { row: 30, column: 0 },
            boundary_type: SecurityBoundaryType::Network,
            trust_change: TrustLevelChange {
                from: TrustLevel::Untrusted,
                to: TrustLevel::LowTrust,
            },
        };

        assert_eq!(boundary.boundary_type, SecurityBoundaryType::Network);
        assert_eq!(boundary.trust_change.from, TrustLevel::Untrusted);
        assert_eq!(boundary.trust_change.to, TrustLevel::LowTrust);
    }

    #[test]
    fn test_data_flow_analysis_creation() {
        let data_flow = DataFlowAnalysis {
            reaching_definitions: HashMap::new(),
            use_def_chains: HashMap::new(),
            def_use_chains: HashMap::new(),
            taint_flows: Vec::new(),
            aliases: HashMap::new(),
            constants: HashMap::new(),
        };

        assert!(data_flow.reaching_definitions.is_empty());
        assert!(data_flow.use_def_chains.is_empty());
        assert!(data_flow.def_use_chains.is_empty());
        assert!(data_flow.taint_flows.is_empty());
        assert!(data_flow.aliases.is_empty());
        assert!(data_flow.constants.is_empty());
    }
}
