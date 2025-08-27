//! Symbol Table Analysis Module
//!
//! This module provides comprehensive symbol table analysis for scope-aware vulnerability detection.
//! It builds symbol tables with proper scope resolution, variable binding, and cross-reference tracking.

use crate::error::Result;
use crate::tree::{SyntaxTree, Node};
use crate::languages::Language;
use std::collections::{HashMap, HashSet};
use tree_sitter::Point;

/// Symbol table analyzer for scope-aware analysis
pub struct SymbolTableAnalyzer {
    language: Language,
    /// Global symbol table containing all scopes
    symbol_table: SymbolTable,
    /// Current scope stack for building the table
    scope_stack: Vec<ScopeId>,
    /// Next available scope ID
    next_scope_id: usize,
}

/// Unique identifier for a scope
pub type ScopeId = usize;

/// Unique identifier for a symbol
pub type SymbolId = usize;

/// Complete symbol table with scope hierarchy
#[derive(Debug, Clone)]
pub struct SymbolTable {
    /// All scopes in the program
    pub scopes: HashMap<ScopeId, Scope>,
    /// Root scope (global scope)
    pub root_scope: ScopeId,
    /// Symbol definitions by ID
    pub symbols: HashMap<SymbolId, SymbolDefinition>,
    /// Symbol references by location
    pub references: Vec<SymbolReference>,
    /// Next available symbol ID
    next_symbol_id: usize,
}

/// A scope in the program (function, block, class, etc.)
#[derive(Debug, Clone)]
pub struct Scope {
    /// Unique scope identifier
    pub id: ScopeId,
    /// Parent scope (None for root scope)
    pub parent: Option<ScopeId>,
    /// Child scopes
    pub children: Vec<ScopeId>,
    /// Scope type (function, block, class, etc.)
    pub scope_type: ScopeType,
    /// Scope name (function name, class name, etc.)
    pub name: Option<String>,
    /// Symbols defined in this scope
    pub symbols: HashMap<String, SymbolId>,
    /// Location where scope starts
    pub start_location: Point,
    /// Location where scope ends
    pub end_location: Point,
}

/// Type of scope
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScopeType {
    /// Global/module scope
    Global,
    /// Function scope
    Function,
    /// Class/struct scope
    Class,
    /// Block scope (if/while/for blocks)
    Block,
    /// Method scope
    Method,
    /// Namespace scope
    Namespace,
    /// Closure/lambda scope
    Closure,
}

/// Symbol definition information
#[derive(Debug, Clone)]
pub struct SymbolDefinition {
    /// Unique symbol identifier
    pub id: SymbolId,
    /// Symbol name
    pub name: String,
    /// Symbol type
    pub symbol_type: SymbolType,
    /// Data type if known
    pub data_type: Option<String>,
    /// Scope where symbol is defined
    pub scope_id: ScopeId,
    /// Location of definition
    pub definition_location: Point,
    /// Whether symbol is mutable
    pub is_mutable: bool,
    /// Whether symbol is exported/public
    pub is_public: bool,
    /// Whether symbol is a parameter
    pub is_parameter: bool,
    /// Initial value if available
    pub initial_value: Option<String>,
}

/// Type of symbol
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymbolType {
    /// Variable
    Variable,
    /// Function
    Function,
    /// Class/struct
    Class,
    /// Method
    Method,
    /// Parameter
    Parameter,
    /// Constant
    Constant,
    /// Type alias
    TypeAlias,
    /// Module/namespace
    Module,
    /// Field/property
    Field,
}

/// Symbol reference (usage)
#[derive(Debug, Clone)]
pub struct SymbolReference {
    /// Referenced symbol ID
    pub symbol_id: SymbolId,
    /// Location of reference
    pub location: Point,
    /// Type of reference
    pub reference_type: ReferenceType,
    /// Scope where reference occurs
    pub scope_id: ScopeId,
}

/// Type of symbol reference
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceType {
    /// Reading the symbol value
    Read,
    /// Writing to the symbol
    Write,
    /// Calling the symbol (for functions)
    Call,
    /// Taking address/reference
    AddressOf,
}

/// Symbol resolution result
#[derive(Debug, Clone)]
pub struct SymbolResolution {
    /// Resolved symbol ID
    pub symbol_id: SymbolId,
    /// Scope where symbol was found
    pub resolved_scope: ScopeId,
    /// Number of scope levels traversed
    pub scope_distance: usize,
}

/// Analysis result containing symbol table and cross-references
#[derive(Debug, Clone)]
pub struct SymbolAnalysisResult {
    /// Complete symbol table
    pub symbol_table: SymbolTable,
    /// Unresolved references (potential errors)
    pub unresolved_references: Vec<UnresolvedReference>,
    /// Variable shadowing warnings
    pub shadowing_warnings: Vec<ShadowingWarning>,
    /// Unused symbol warnings
    pub unused_symbols: Vec<SymbolId>,
    /// Cross-reference statistics
    pub statistics: SymbolStatistics,
}

/// Unresolved symbol reference
#[derive(Debug, Clone)]
pub struct UnresolvedReference {
    /// Symbol name that couldn't be resolved
    pub name: String,
    /// Location of unresolved reference
    pub location: Point,
    /// Scope where reference occurs
    pub scope_id: ScopeId,
}

/// Variable shadowing warning
#[derive(Debug, Clone)]
pub struct ShadowingWarning {
    /// Symbol being shadowed
    pub shadowed_symbol: SymbolId,
    /// Symbol doing the shadowing
    pub shadowing_symbol: SymbolId,
    /// Location of shadowing definition
    pub location: Point,
}

/// Symbol table statistics
#[derive(Debug, Clone)]
pub struct SymbolStatistics {
    /// Total number of scopes
    pub total_scopes: usize,
    /// Total number of symbols
    pub total_symbols: usize,
    /// Total number of references
    pub total_references: usize,
    /// Number of unresolved references
    pub unresolved_count: usize,
    /// Number of shadowing instances
    pub shadowing_count: usize,
    /// Symbols by type
    pub symbols_by_type: HashMap<SymbolType, usize>,
    /// Scopes by type
    pub scopes_by_type: HashMap<ScopeType, usize>,
}

impl SymbolTableAnalyzer {
    /// Create a new symbol table analyzer
    pub fn new(language: Language) -> Self {
        let mut symbol_table = SymbolTable {
            scopes: HashMap::new(),
            root_scope: 0,
            symbols: HashMap::new(),
            references: Vec::new(),
            next_symbol_id: 0,
        };

        // Create root scope
        let root_scope = Scope {
            id: 0,
            parent: None,
            children: Vec::new(),
            scope_type: ScopeType::Global,
            name: None,
            symbols: HashMap::new(),
            start_location: Point { row: 0, column: 0 },
            end_location: Point { row: usize::MAX, column: usize::MAX },
        };
        symbol_table.scopes.insert(0, root_scope);

        Self {
            language,
            symbol_table,
            scope_stack: vec![0], // Start with root scope
            next_scope_id: 1,
        }
    }

    /// Analyze a syntax tree and build symbol table
    pub fn analyze(&mut self, tree: &SyntaxTree) -> Result<SymbolAnalysisResult> {
        // Reset state for new analysis
        self.reset();

        // Phase 1: Build scope hierarchy and symbol definitions
        self.build_symbol_table(tree.root_node())?;

        // Phase 2: Resolve symbol references
        self.resolve_references(tree.root_node())?;

        // Phase 3: Analyze for warnings and statistics
        let unresolved_references = self.find_unresolved_references();
        let shadowing_warnings = self.find_shadowing_warnings();
        let unused_symbols = self.find_unused_symbols();
        let statistics = self.calculate_statistics();

        Ok(SymbolAnalysisResult {
            symbol_table: self.symbol_table.clone(),
            unresolved_references,
            shadowing_warnings,
            unused_symbols,
            statistics,
        })
    }

    /// Reset analyzer state for new analysis
    fn reset(&mut self) {
        self.symbol_table.scopes.clear();
        self.symbol_table.symbols.clear();
        self.symbol_table.references.clear();
        self.symbol_table.next_symbol_id = 0;
        self.scope_stack = vec![0];
        self.next_scope_id = 1;

        // Recreate root scope
        let root_scope = Scope {
            id: 0,
            parent: None,
            children: Vec::new(),
            scope_type: ScopeType::Global,
            name: None,
            symbols: HashMap::new(),
            start_location: Point { row: 0, column: 0 },
            end_location: Point { row: usize::MAX, column: usize::MAX },
        };
        self.symbol_table.scopes.insert(0, root_scope);
    }

    /// Build symbol table by traversing AST
    fn build_symbol_table(&mut self, node: Node) -> Result<()> {
        // Check if this node creates a new scope
        if self.creates_scope(node) {
            self.enter_scope(node)?;
        }

        // Check if this node defines a symbol
        if let Some(symbol_def) = self.extract_symbol_definition(node)? {
            self.add_symbol(symbol_def)?;
        }

        // Recursively process children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.build_symbol_table(cursor.node())?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        // Exit scope if we entered one
        if self.creates_scope(node) {
            self.exit_scope();
        }

        Ok(())
    }

    /// Check if a node creates a new scope
    fn creates_scope(&self, node: Node) -> bool {
        let node_kind = node.kind();
        match self.language {
            Language::Rust => matches!(node_kind,
                "function_item" | "impl_item" | "block" | "closure_expression" |
                "struct_item" | "enum_item" | "mod_item" | "if_expression" |
                "while_expression" | "for_expression" | "match_expression"
            ),
            Language::JavaScript | Language::TypeScript => matches!(node_kind,
                "function_declaration" | "arrow_function" | "method_definition" |
                "class_declaration" | "statement_block" | "if_statement" |
                "while_statement" | "for_statement" | "try_statement"
            ),
            Language::Python => matches!(node_kind,
                "function_definition" | "class_definition" | "if_statement" |
                "while_statement" | "for_statement" | "try_statement" |
                "with_statement" | "lambda"
            ),
            Language::C | Language::Cpp => matches!(node_kind,
                "function_definition" | "compound_statement" | "if_statement" |
                "while_statement" | "for_statement" | "switch_statement" |
                "struct_specifier" | "enum_specifier"
            ),
            Language::Go => matches!(node_kind,
                "function_declaration" | "method_declaration" | "block" |
                "if_statement" | "for_statement" | "switch_statement" |
                "type_switch_statement" | "select_statement"
            ),
        }
    }

    /// Enter a new scope
    fn enter_scope(&mut self, node: Node) -> Result<()> {
        let scope_type = self.determine_scope_type(node);
        let scope_name = self.extract_scope_name(node);
        let current_scope_id = *self.scope_stack.last().unwrap();
        let new_scope_id = self.next_scope_id;
        self.next_scope_id += 1;

        let new_scope = Scope {
            id: new_scope_id,
            parent: Some(current_scope_id),
            children: Vec::new(),
            scope_type,
            name: scope_name,
            symbols: HashMap::new(),
            start_location: node.start_position(),
            end_location: node.end_position(),
        };

        // Add to parent's children
        if let Some(parent_scope) = self.symbol_table.scopes.get_mut(&current_scope_id) {
            parent_scope.children.push(new_scope_id);
        }

        self.symbol_table.scopes.insert(new_scope_id, new_scope);
        self.scope_stack.push(new_scope_id);

        Ok(())
    }

    /// Exit current scope
    fn exit_scope(&mut self) {
        if self.scope_stack.len() > 1 {
            self.scope_stack.pop();
        }
    }

    /// Determine scope type from AST node
    fn determine_scope_type(&self, node: Node) -> ScopeType {
        let node_kind = node.kind();
        match self.language {
            Language::Rust => match node_kind {
                "function_item" => ScopeType::Function,
                "impl_item" => ScopeType::Class,
                "struct_item" | "enum_item" => ScopeType::Class,
                "mod_item" => ScopeType::Namespace,
                "closure_expression" => ScopeType::Closure,
                _ => ScopeType::Block,
            },
            Language::JavaScript | Language::TypeScript => match node_kind {
                "function_declaration" => ScopeType::Function,
                "arrow_function" => ScopeType::Closure,
                "method_definition" => ScopeType::Method,
                "class_declaration" => ScopeType::Class,
                _ => ScopeType::Block,
            },
            Language::Python => match node_kind {
                "function_definition" => ScopeType::Function,
                "class_definition" => ScopeType::Class,
                "lambda" => ScopeType::Closure,
                _ => ScopeType::Block,
            },
            Language::C | Language::Cpp => match node_kind {
                "function_definition" => ScopeType::Function,
                "struct_specifier" | "enum_specifier" => ScopeType::Class,
                _ => ScopeType::Block,
            },
            Language::Go => match node_kind {
                "function_declaration" => ScopeType::Function,
                "method_declaration" => ScopeType::Method,
                _ => ScopeType::Block,
            },
        }
    }

    /// Extract scope name from AST node
    fn extract_scope_name(&self, node: Node) -> Option<String> {
        if let Some(name_node) = node.child_by_field_name("name") {
            name_node.text().ok().map(|s| s.to_string())
        } else {
            None
        }
    }

    /// Extract symbol definition from AST node
    fn extract_symbol_definition(&self, node: Node) -> Result<Option<SymbolDefinition>> {
        let _node_kind = node.kind();

        match self.language {
            Language::Rust => self.extract_rust_symbol_definition(node),
            Language::JavaScript | Language::TypeScript => self.extract_js_symbol_definition(node),
            Language::Python => self.extract_python_symbol_definition(node),
            Language::C | Language::Cpp => self.extract_c_symbol_definition(node),
            Language::Go => self.extract_go_symbol_definition(node),
        }
    }

    /// Extract Rust symbol definitions
    fn extract_rust_symbol_definition(&self, node: Node) -> Result<Option<SymbolDefinition>> {
        let node_kind = node.kind();
        let current_scope = *self.scope_stack.last().unwrap();

        match node_kind {
            "function_item" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.text() {
                        let is_public = self.is_rust_item_public(node);
                        return Ok(Some(SymbolDefinition {
                            id: self.symbol_table.next_symbol_id,
                            name: name.to_string(),
                            symbol_type: SymbolType::Function,
                            data_type: self.extract_rust_function_type(node),
                            scope_id: current_scope,
                            definition_location: node.start_position(),
                            is_mutable: false,
                            is_public,
                            is_parameter: false,
                            initial_value: None,
                        }));
                    }
                }
            },
            "let_declaration" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    if pattern.kind() == "identifier" {
                        if let Ok(name) = pattern.text() {
                            let is_mutable = self.is_rust_let_mutable(node);
                            let data_type = self.extract_rust_variable_type(node);
                            let initial_value = self.extract_rust_initial_value(node);

                            return Ok(Some(SymbolDefinition {
                                id: self.symbol_table.next_symbol_id,
                                name: name.to_string(),
                                symbol_type: SymbolType::Variable,
                                data_type,
                                scope_id: current_scope,
                                definition_location: node.start_position(),
                                is_mutable,
                                is_public: false,
                                is_parameter: false,
                                initial_value,
                            }));
                        }
                    }
                }
            },
            "parameter" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    if pattern.kind() == "identifier" {
                        if let Ok(name) = pattern.text() {
                            let data_type = self.extract_rust_parameter_type(node);

                            return Ok(Some(SymbolDefinition {
                                id: self.symbol_table.next_symbol_id,
                                name: name.to_string(),
                                symbol_type: SymbolType::Parameter,
                                data_type,
                                scope_id: current_scope,
                                definition_location: node.start_position(),
                                is_mutable: false,
                                is_public: false,
                                is_parameter: true,
                                initial_value: None,
                            }));
                        }
                    }
                }
            },
            "struct_item" | "enum_item" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.text() {
                        let is_public = self.is_rust_item_public(node);
                        return Ok(Some(SymbolDefinition {
                            id: self.symbol_table.next_symbol_id,
                            name: name.to_string(),
                            symbol_type: SymbolType::Class,
                            data_type: Some(node_kind.to_string()),
                            scope_id: current_scope,
                            definition_location: node.start_position(),
                            is_mutable: false,
                            is_public,
                            is_parameter: false,
                            initial_value: None,
                        }));
                    }
                }
            },
            _ => {}
        }

        Ok(None)
    }

    /// Add symbol to current scope
    fn add_symbol(&mut self, mut symbol_def: SymbolDefinition) -> Result<()> {
        let symbol_id = self.symbol_table.next_symbol_id;
        symbol_def.id = symbol_id;
        self.symbol_table.next_symbol_id += 1;

        let scope_id = symbol_def.scope_id;
        let symbol_name = symbol_def.name.clone();

        // Add to symbols table
        self.symbol_table.symbols.insert(symbol_id, symbol_def);

        // Add to scope's symbol map
        if let Some(scope) = self.symbol_table.scopes.get_mut(&scope_id) {
            scope.symbols.insert(symbol_name, symbol_id);
        }

        Ok(())
    }

    /// Resolve symbol references in AST
    fn resolve_references(&mut self, node: Node) -> Result<()> {
        // Check if this node is a symbol reference
        if self.is_symbol_reference(node) {
            if let Some(reference) = self.extract_symbol_reference(node)? {
                self.symbol_table.references.push(reference);
            }
        }

        // Recursively process children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.resolve_references(cursor.node())?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Check if node is a symbol reference
    fn is_symbol_reference(&self, node: Node) -> bool {
        let node_kind = node.kind();
        match self.language {
            Language::Rust => matches!(node_kind, "identifier" | "field_identifier"),
            Language::JavaScript | Language::TypeScript => matches!(node_kind, "identifier"),
            Language::Python => matches!(node_kind, "identifier"),
            Language::C | Language::Cpp => matches!(node_kind, "identifier"),
            Language::Go => matches!(node_kind, "identifier"),
        }
    }

    /// Extract symbol reference from AST node
    fn extract_symbol_reference(&self, node: Node) -> Result<Option<SymbolReference>> {
        if let Ok(name) = node.text() {
            let current_scope = *self.scope_stack.last().unwrap();

            // Try to resolve the symbol
            if let Some(resolution) = self.resolve_symbol(name, current_scope) {
                let reference_type = self.determine_reference_type(node);

                return Ok(Some(SymbolReference {
                    symbol_id: resolution.symbol_id,
                    location: node.start_position(),
                    reference_type,
                    scope_id: current_scope,
                }));
            }
        }

        Ok(None)
    }

    /// Resolve symbol by name starting from given scope
    fn resolve_symbol(&self, name: &str, scope_id: ScopeId) -> Option<SymbolResolution> {
        let mut current_scope_id = scope_id;
        let mut distance = 0;

        loop {
            if let Some(scope) = self.symbol_table.scopes.get(&current_scope_id) {
                // Check if symbol is defined in current scope
                if let Some(&symbol_id) = scope.symbols.get(name) {
                    return Some(SymbolResolution {
                        symbol_id,
                        resolved_scope: current_scope_id,
                        scope_distance: distance,
                    });
                }

                // Move to parent scope
                if let Some(parent_id) = scope.parent {
                    current_scope_id = parent_id;
                    distance += 1;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        None
    }

    /// Determine reference type from context
    fn determine_reference_type(&self, node: Node) -> ReferenceType {
        // Check parent node to determine context
        if let Some(parent) = node.parent() {
            let parent_kind = parent.kind();
            match self.language {
                Language::Rust => match parent_kind {
                    "assignment_expression" => {
                        // Check if this identifier is on the left side (write) or right side (read)
                        if let Some(left) = parent.child_by_field_name("left") {
                            if left.start_position() == node.start_position() && left.end_position() == node.end_position() {
                                return ReferenceType::Write;
                            }
                        }
                        ReferenceType::Read
                    },
                    "call_expression" => {
                        if let Some(function) = parent.child_by_field_name("function") {
                            if function.start_position() == node.start_position() && function.end_position() == node.end_position() {
                                return ReferenceType::Call;
                            }
                        }
                        ReferenceType::Read
                    },
                    "reference_expression" => ReferenceType::AddressOf,
                    _ => ReferenceType::Read,
                },
                _ => ReferenceType::Read, // Simplified for other languages
            }
        } else {
            ReferenceType::Read
        }
    }

    /// Helper methods for Rust-specific analysis
    fn is_rust_item_public(&self, node: Node) -> bool {
        // Check for 'pub' visibility modifier
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if cursor.node().kind() == "visibility_modifier" {
                    return true;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        false
    }

    fn is_rust_let_mutable(&self, node: Node) -> bool {
        // Check for 'mut' keyword in let declaration
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if cursor.node().kind() == "mutable_pattern" {
                    return true;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        false
    }

    fn extract_rust_function_type(&self, node: Node) -> Option<String> {
        // Extract function signature
        if let Some(params) = node.child_by_field_name("parameters") {
            if let Some(return_type) = node.child_by_field_name("return_type") {
                if let (Ok(params_text), Ok(return_text)) = (params.text(), return_type.text()) {
                    return Some(format!("fn{} {}", params_text, return_text));
                }
            } else if let Ok(params_text) = params.text() {
                return Some(format!("fn{}", params_text));
            }
        }
        None
    }

    fn extract_rust_variable_type(&self, node: Node) -> Option<String> {
        // Extract type annotation from let declaration
        if let Some(type_node) = node.child_by_field_name("type") {
            type_node.text().ok().map(|s| s.to_string())
        } else {
            None
        }
    }

    fn extract_rust_parameter_type(&self, node: Node) -> Option<String> {
        // Extract parameter type
        if let Some(type_node) = node.child_by_field_name("type") {
            type_node.text().ok().map(|s| s.to_string())
        } else {
            None
        }
    }

    fn extract_rust_initial_value(&self, node: Node) -> Option<String> {
        // Extract initial value from let declaration
        if let Some(value_node) = node.child_by_field_name("value") {
            value_node.text().ok().map(|s| s.to_string())
        } else {
            None
        }
    }

    /// Placeholder methods for other languages (to be implemented)
    fn extract_js_symbol_definition(&self, _node: Node) -> Result<Option<SymbolDefinition>> {
        // TODO: Implement JavaScript symbol extraction
        Ok(None)
    }

    fn extract_python_symbol_definition(&self, _node: Node) -> Result<Option<SymbolDefinition>> {
        // TODO: Implement Python symbol extraction
        Ok(None)
    }

    fn extract_c_symbol_definition(&self, _node: Node) -> Result<Option<SymbolDefinition>> {
        // TODO: Implement C/C++ symbol extraction
        Ok(None)
    }

    fn extract_go_symbol_definition(&self, _node: Node) -> Result<Option<SymbolDefinition>> {
        // TODO: Implement Go symbol extraction
        Ok(None)
    }

    /// Find unresolved symbol references
    fn find_unresolved_references(&self) -> Vec<UnresolvedReference> {
        // This would require tracking attempted resolutions during the reference phase
        // For now, return empty vector as a placeholder
        Vec::new()
    }

    /// Find variable shadowing warnings
    fn find_shadowing_warnings(&self) -> Vec<ShadowingWarning> {
        let mut warnings = Vec::new();

        for scope in self.symbol_table.scopes.values() {
            for (symbol_name, &symbol_id) in &scope.symbols {
                // Check if this symbol shadows a symbol in parent scopes
                if let Some(parent_id) = scope.parent {
                    if let Some(shadowed_resolution) = self.resolve_symbol(symbol_name, parent_id) {
                        if let Some(symbol_def) = self.symbol_table.symbols.get(&symbol_id) {
                            warnings.push(ShadowingWarning {
                                shadowed_symbol: shadowed_resolution.symbol_id,
                                shadowing_symbol: symbol_id,
                                location: symbol_def.definition_location,
                            });
                        }
                    }
                }
            }
        }

        warnings
    }

    /// Find unused symbols
    fn find_unused_symbols(&self) -> Vec<SymbolId> {
        let mut used_symbols = HashSet::new();

        // Mark all referenced symbols as used
        for reference in &self.symbol_table.references {
            used_symbols.insert(reference.symbol_id);
        }

        // Find symbols that are defined but never referenced
        let mut unused = Vec::new();
        for (&symbol_id, symbol_def) in &self.symbol_table.symbols {
            // Skip parameters and public symbols (they might be used externally)
            if !symbol_def.is_parameter && !symbol_def.is_public && !used_symbols.contains(&symbol_id) {
                unused.push(symbol_id);
            }
        }

        unused
    }

    /// Calculate symbol table statistics
    fn calculate_statistics(&self) -> SymbolStatistics {
        let mut symbols_by_type = HashMap::new();
        let mut scopes_by_type = HashMap::new();

        // Count symbols by type
        for symbol in self.symbol_table.symbols.values() {
            *symbols_by_type.entry(symbol.symbol_type.clone()).or_insert(0) += 1;
        }

        // Count scopes by type
        for scope in self.symbol_table.scopes.values() {
            *scopes_by_type.entry(scope.scope_type.clone()).or_insert(0) += 1;
        }

        SymbolStatistics {
            total_scopes: self.symbol_table.scopes.len(),
            total_symbols: self.symbol_table.symbols.len(),
            total_references: self.symbol_table.references.len(),
            unresolved_count: 0, // Would be calculated during resolution phase
            shadowing_count: self.find_shadowing_warnings().len(),
            symbols_by_type,
            scopes_by_type,
        }
    }
}

impl SymbolTable {
    /// Get symbol definition by ID
    pub fn get_symbol(&self, symbol_id: SymbolId) -> Option<&SymbolDefinition> {
        self.symbols.get(&symbol_id)
    }

    /// Get scope by ID
    pub fn get_scope(&self, scope_id: ScopeId) -> Option<&Scope> {
        self.scopes.get(&scope_id)
    }

    /// Find all symbols in a scope
    pub fn get_symbols_in_scope(&self, scope_id: ScopeId) -> Vec<&SymbolDefinition> {
        if let Some(scope) = self.scopes.get(&scope_id) {
            scope.symbols.values()
                .filter_map(|&symbol_id| self.symbols.get(&symbol_id))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Find all references to a symbol
    pub fn get_symbol_references(&self, symbol_id: SymbolId) -> Vec<&SymbolReference> {
        self.references.iter()
            .filter(|reference| reference.symbol_id == symbol_id)
            .collect()
    }

    /// Check if a symbol is accessible from a given scope
    pub fn is_symbol_accessible(&self, symbol_id: SymbolId, from_scope: ScopeId) -> bool {
        if let Some(symbol) = self.symbols.get(&symbol_id) {
            // Check if symbol's scope is in the scope chain of from_scope
            let mut current_scope = from_scope;
            loop {
                if current_scope == symbol.scope_id {
                    return true;
                }

                if let Some(scope) = self.scopes.get(&current_scope) {
                    if let Some(parent) = scope.parent {
                        current_scope = parent;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        false
    }

    /// Get scope chain from a given scope to root
    pub fn get_scope_chain(&self, scope_id: ScopeId) -> Vec<ScopeId> {
        let mut chain = Vec::new();
        let mut current_scope = scope_id;

        loop {
            chain.push(current_scope);
            if let Some(scope) = self.scopes.get(&current_scope) {
                if let Some(parent) = scope.parent {
                    current_scope = parent;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        chain
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_symbol_table_analyzer_creation() {
        let analyzer = SymbolTableAnalyzer::new(Language::Rust);
        assert_eq!(analyzer.language, Language::Rust);
        assert_eq!(analyzer.symbol_table.scopes.len(), 1); // Root scope
        assert_eq!(analyzer.scope_stack.len(), 1);
        assert_eq!(analyzer.next_scope_id, 1);
    }

    #[test]
    fn test_scope_creation_and_hierarchy() {
        let analyzer = SymbolTableAnalyzer::new(Language::Rust);

        // Test scope types
        assert_eq!(analyzer.symbol_table.scopes[&0].scope_type, ScopeType::Global);
        assert_eq!(analyzer.symbol_table.scopes[&0].parent, None);
        assert!(analyzer.symbol_table.scopes[&0].children.is_empty());
    }

    #[test]
    fn test_symbol_definition_creation() {
        let symbol_def = SymbolDefinition {
            id: 0,
            name: "test_var".to_string(),
            symbol_type: SymbolType::Variable,
            data_type: Some("i32".to_string()),
            scope_id: 0,
            definition_location: Point { row: 1, column: 5 },
            is_mutable: true,
            is_public: false,
            is_parameter: false,
            initial_value: Some("42".to_string()),
        };

        assert_eq!(symbol_def.name, "test_var");
        assert_eq!(symbol_def.symbol_type, SymbolType::Variable);
        assert_eq!(symbol_def.data_type, Some("i32".to_string()));
        assert!(symbol_def.is_mutable);
        assert!(!symbol_def.is_public);
        assert!(!symbol_def.is_parameter);
    }

    #[test]
    fn test_symbol_reference_creation() {
        let reference = SymbolReference {
            symbol_id: 0,
            location: Point { row: 5, column: 10 },
            reference_type: ReferenceType::Read,
            scope_id: 1,
        };

        assert_eq!(reference.symbol_id, 0);
        assert_eq!(reference.reference_type, ReferenceType::Read);
        assert_eq!(reference.scope_id, 1);
    }

    #[test]
    fn test_scope_type_variants() {
        assert_eq!(ScopeType::Global, ScopeType::Global);
        assert_ne!(ScopeType::Function, ScopeType::Class);

        let scope_types = vec![
            ScopeType::Global,
            ScopeType::Function,
            ScopeType::Class,
            ScopeType::Block,
            ScopeType::Method,
            ScopeType::Namespace,
            ScopeType::Closure,
        ];

        assert_eq!(scope_types.len(), 7);
    }

    #[test]
    fn test_symbol_type_variants() {
        assert_eq!(SymbolType::Variable, SymbolType::Variable);
        assert_ne!(SymbolType::Function, SymbolType::Class);

        let symbol_types = vec![
            SymbolType::Variable,
            SymbolType::Function,
            SymbolType::Class,
            SymbolType::Method,
            SymbolType::Parameter,
            SymbolType::Constant,
            SymbolType::TypeAlias,
            SymbolType::Module,
            SymbolType::Field,
        ];

        assert_eq!(symbol_types.len(), 9);
    }

    #[test]
    fn test_reference_type_variants() {
        assert_eq!(ReferenceType::Read, ReferenceType::Read);
        assert_ne!(ReferenceType::Write, ReferenceType::Call);

        let reference_types = vec![
            ReferenceType::Read,
            ReferenceType::Write,
            ReferenceType::Call,
            ReferenceType::AddressOf,
        ];

        assert_eq!(reference_types.len(), 4);
    }

    #[test]
    fn test_symbol_table_basic_operations() {
        let mut symbol_table = SymbolTable {
            scopes: HashMap::new(),
            root_scope: 0,
            symbols: HashMap::new(),
            references: Vec::new(),
            next_symbol_id: 0,
        };

        // Add root scope
        let root_scope = Scope {
            id: 0,
            parent: None,
            children: Vec::new(),
            scope_type: ScopeType::Global,
            name: None,
            symbols: HashMap::new(),
            start_location: Point { row: 0, column: 0 },
            end_location: Point { row: usize::MAX, column: usize::MAX },
        };
        symbol_table.scopes.insert(0, root_scope);

        // Test basic operations
        assert_eq!(symbol_table.get_scope(0).unwrap().scope_type, ScopeType::Global);
        assert!(symbol_table.get_symbol(0).is_none());
        assert!(symbol_table.get_symbols_in_scope(0).is_empty());
        assert!(symbol_table.get_symbol_references(0).is_empty());
    }

    #[test]
    fn test_scope_chain_calculation() {
        let mut symbol_table = SymbolTable {
            scopes: HashMap::new(),
            root_scope: 0,
            symbols: HashMap::new(),
            references: Vec::new(),
            next_symbol_id: 0,
        };

        // Create scope hierarchy: 0 -> 1 -> 2
        let root_scope = Scope {
            id: 0,
            parent: None,
            children: vec![1],
            scope_type: ScopeType::Global,
            name: None,
            symbols: HashMap::new(),
            start_location: Point { row: 0, column: 0 },
            end_location: Point { row: usize::MAX, column: usize::MAX },
        };

        let function_scope = Scope {
            id: 1,
            parent: Some(0),
            children: vec![2],
            scope_type: ScopeType::Function,
            name: Some("test_function".to_string()),
            symbols: HashMap::new(),
            start_location: Point { row: 1, column: 0 },
            end_location: Point { row: 10, column: 0 },
        };

        let block_scope = Scope {
            id: 2,
            parent: Some(1),
            children: Vec::new(),
            scope_type: ScopeType::Block,
            name: None,
            symbols: HashMap::new(),
            start_location: Point { row: 5, column: 4 },
            end_location: Point { row: 8, column: 4 },
        };

        symbol_table.scopes.insert(0, root_scope);
        symbol_table.scopes.insert(1, function_scope);
        symbol_table.scopes.insert(2, block_scope);

        let chain = symbol_table.get_scope_chain(2);
        assert_eq!(chain, vec![2, 1, 0]);
    }
}
