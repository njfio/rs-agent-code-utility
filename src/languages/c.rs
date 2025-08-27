//! C language support for tree-sitter
//!
//! This module provides C-specific utilities for parsing and analyzing
//! C source code using tree-sitter.

use crate::error::Result;
use crate::query::Query;
use crate::tree::{Node, SyntaxTree};

/// C-specific syntax utilities
pub struct CSyntax;

impl CSyntax {
    /// Check if a node represents a function definition
    pub fn is_function_definition(node: &Node) -> bool {
        node.kind() == "function_definition"
    }

    /// Check if a node represents a function declaration
    pub fn is_function_declaration(node: &Node) -> bool {
        node.kind() == "declaration" && Self::has_function_declarator(node)
    }

    /// Check if a declaration has a function declarator
    fn has_function_declarator(node: &Node) -> bool {
        for child in node.children() {
            if child.kind() == "function_declarator" {
                return true;
            }
        }
        false
    }

    /// Check if a node represents a struct declaration
    pub fn is_struct_declaration(node: &Node) -> bool {
        if node.kind() != "struct_specifier" {
            return false;
        }

        // Check if this struct has a field declaration list (body)
        // This distinguishes between struct definitions and struct references
        for child in node.children() {
            if child.kind() == "field_declaration_list" {
                return true;
            }
        }

        false
    }

    /// Check if a node represents a union declaration
    pub fn is_union_declaration(node: &Node) -> bool {
        node.kind() == "union_specifier"
    }

    /// Check if a node represents an enum declaration
    pub fn is_enum_declaration(node: &Node) -> bool {
        node.kind() == "enum_specifier"
    }

    /// Check if a node represents a typedef declaration
    pub fn is_typedef_declaration(node: &Node) -> bool {
        // In C tree-sitter grammar, typedefs are represented as "type_definition" nodes
        if node.kind() == "type_definition" {
            // Check if it starts with "typedef"
            for child in node.children() {
                if child.kind() == "typedef" {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a node represents a macro definition
    pub fn is_macro_definition(node: &Node) -> bool {
        node.kind() == "preproc_def"
    }

    /// Check if a node represents an include directive
    pub fn is_include_directive(node: &Node) -> bool {
        node.kind() == "preproc_include"
    }

    /// Extract function name from a function definition or declaration
    pub fn function_name(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_function_definition(node) && !Self::is_function_declaration(node) {
            return None;
        }

        // Look for function_declarator
        for child in node.children() {
            if child.kind() == "function_declarator" {
                // Get the identifier from the declarator
                for decl_child in child.children() {
                    if decl_child.kind() == "identifier" {
                        return decl_child.text().ok().map(|s| s.to_string());
                    }
                }
            }
        }

        None
    }

    /// Extract struct name from a struct declaration
    pub fn struct_name(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_struct_declaration(node) {
            return None;
        }

        for child in node.children() {
            if child.kind() == "type_identifier" {
                return child.text().ok().map(|s| s.to_string());
            }
        }

        None
    }

    /// Extract union name from a union declaration
    pub fn union_name(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_union_declaration(node) {
            return None;
        }

        for child in node.children() {
            if child.kind() == "type_identifier" {
                return child.text().ok().map(|s| s.to_string());
            }
        }

        None
    }

    /// Extract enum name from an enum declaration
    pub fn enum_name(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_enum_declaration(node) {
            return None;
        }

        for child in node.children() {
            if child.kind() == "type_identifier" {
                return child.text().ok().map(|s| s.to_string());
            }
        }

        None
    }

    /// Extract typedef name from a typedef declaration
    pub fn typedef_name(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_typedef_declaration(node) {
            return None;
        }

        // For type_definition nodes, the typedef name can be:
        // 1. A direct type_identifier (e.g., typedef int Integer;)
        // 2. Inside a pointer_declarator (e.g., typedef char* String;)
        let mut typedef_name = None;

        for child in node.children() {
            if child.kind() == "type_identifier" {
                if let Ok(text) = child.text() {
                    typedef_name = Some(text.to_string());
                }
            } else if child.kind() == "pointer_declarator" {
                // Look for type_identifier inside pointer_declarator
                for pointer_child in child.children() {
                    if pointer_child.kind() == "type_identifier" {
                        if let Ok(text) = pointer_child.text() {
                            typedef_name = Some(text.to_string());
                        }
                    }
                }
            }
        }

        typedef_name
    }

    /// Extract macro name from a macro definition
    pub fn macro_name(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_macro_definition(node) {
            return None;
        }

        for child in node.children() {
            if child.kind() == "identifier" {
                return child.text().ok().map(|s| s.to_string());
            }
        }

        None
    }

    /// Extract macro name from a function-like macro definition
    pub fn function_macro_name(node: &Node, _source: &str) -> Option<String> {
        if node.kind() != "preproc_function_def" {
            return None;
        }

        for child in node.children() {
            if child.kind() == "identifier" {
                return child.text().ok().map(|s| s.to_string());
            }
        }

        None
    }

    /// Get function parameters
    pub fn function_parameters(node: &Node, _source: &str) -> Vec<String> {
        if !Self::is_function_definition(node) && !Self::is_function_declaration(node) {
            return Vec::new();
        }

        let mut parameters = Vec::new();

        // Find the parameter list
        for child in node.children() {
            if child.kind() == "function_declarator" {
                for decl_child in child.children() {
                    if decl_child.kind() == "parameter_list" {
                        for param in decl_child.children() {
                            if param.kind() == "parameter_declaration" {
                                // Look for identifier in the parameter, which might be nested
                                if let Some(param_name) = Self::extract_parameter_name(&param) {
                                    parameters.push(param_name);
                                }
                            }
                        }
                    }
                }
            }
        }

        parameters
    }

    /// Helper function to extract parameter name from parameter_declaration
    fn extract_parameter_name(param_node: &Node) -> Option<String> {
        // Look for identifier directly in parameter_declaration
        for child in param_node.children() {
            if child.kind() == "identifier" {
                if let Ok(param_name) = child.text() {
                    return Some(param_name.to_string());
                }
            }
            // Look for identifier in pointer_declarator
            else if child.kind() == "pointer_declarator" {
                for pointer_child in child.children() {
                    if pointer_child.kind() == "identifier" {
                        if let Ok(param_name) = pointer_child.text() {
                            return Some(param_name.to_string());
                        }
                    }
                }
            }
            // Look for identifier in array_declarator
            else if child.kind() == "array_declarator" {
                for array_child in child.children() {
                    if array_child.kind() == "identifier" {
                        if let Ok(param_name) = array_child.text() {
                            return Some(param_name.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Get function return type
    pub fn function_return_type(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_function_definition(node) && !Self::is_function_declaration(node) {
            return None;
        }

        // Look for type specifiers before the function declarator
        let mut type_parts = Vec::new();
        
        for child in node.children() {
            match child.kind() {
                "primitive_type" | "type_identifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
                    if let Ok(type_text) = child.text() {
                        type_parts.push(type_text.to_string());
                    }
                }
                "storage_class_specifier" => {
                    if let Ok(storage_text) = child.text() {
                        if storage_text != "typedef" {
                            type_parts.push(storage_text.to_string());
                        }
                    }
                }
                "function_declarator" => break, // Stop when we reach the declarator
                _ => {}
            }
        }

        if type_parts.is_empty() {
            None
        } else {
            Some(type_parts.join(" "))
        }
    }

    /// Check if a function is static
    pub fn is_static_function(node: &Node) -> bool {
        if !Self::is_function_definition(node) && !Self::is_function_declaration(node) {
            return false;
        }

        for child in node.children() {
            if child.kind() == "storage_class_specifier" {
                if let Ok(text) = child.text() {
                    return text == "static";
                }
            }
        }
        false
    }

    /// Check if a function is inline
    pub fn is_inline_function(node: &Node) -> bool {
        if !Self::is_function_definition(node) && !Self::is_function_declaration(node) {
            return false;
        }

        for child in node.children() {
            if child.kind() == "storage_class_specifier" {
                if let Ok(text) = child.text() {
                    return text == "inline";
                }
            }
        }
        false
    }

    /// Get struct fields
    pub fn struct_fields(node: &Node, _source: &str) -> Vec<(String, String)> {
        if !Self::is_struct_declaration(node) {
            return Vec::new();
        }

        let mut fields = Vec::new();

        // Find the field declaration list
        for child in node.children() {
            if child.kind() == "field_declaration_list" {
                for field in child.children() {
                    if field.kind() == "field_declaration" {
                        let mut field_type = String::new();
                        let mut field_name = String::new();

                        for field_part in field.children() {
                            match field_part.kind() {
                                "primitive_type" | "type_identifier" => {
                                    if let Ok(type_text) = field_part.text() {
                                        field_type = type_text.to_string();
                                    }
                                }
                                "field_identifier" => {
                                    if let Ok(name_text) = field_part.text() {
                                        field_name = name_text.to_string();
                                    }
                                }
                                "array_declarator" => {
                                    // For array fields like "char name[50]", extract the identifier
                                    for array_child in field_part.children() {
                                        if array_child.kind() == "field_identifier" {
                                            if let Ok(name_text) = array_child.text() {
                                                field_name = name_text.to_string();
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }

                        if !field_type.is_empty() && !field_name.is_empty() {
                            fields.push((field_name, field_type));
                        }
                    }
                }
            }
        }

        fields
    }

    /// Get all function definitions in a syntax tree with start and end positions
    pub fn find_functions(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut functions = Vec::new();
        let function_nodes = tree.find_nodes_by_kind("function_definition");

        for func_node in function_nodes {
            if let Some(name) = Self::function_name(&func_node, source) {
                let ts_node = func_node.inner();
                functions.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        functions
    }

    /// Get all struct definitions in a syntax tree with start and end positions
    pub fn find_structs(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut structs = Vec::new();
        let struct_nodes = tree.find_nodes_by_kind("struct_specifier");

        for struct_node in struct_nodes {
            if let Some(name) = Self::struct_name(&struct_node, source) {
                let ts_node = struct_node.inner();
                structs.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        structs
    }



    /// Get all enum definitions in a syntax tree with start and end positions
    pub fn find_enums(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut enums = Vec::new();
        let enum_nodes = tree.find_nodes_by_kind("enum_specifier");

        for enum_node in enum_nodes {
            if let Some(name) = Self::enum_name(&enum_node, source) {
                let ts_node = enum_node.inner();
                enums.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        enums
    }

    /// Get all typedef definitions in a syntax tree with start and end positions
    pub fn find_typedefs(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut typedefs = Vec::new();
        let type_definition_nodes = tree.find_nodes_by_kind("type_definition");

        for type_def_node in type_definition_nodes {
            if Self::is_typedef_declaration(&type_def_node) {
                if let Some(name) = Self::typedef_name(&type_def_node, source) {
                    let ts_node = type_def_node.inner();
                    typedefs.push((name, ts_node.start_position(), ts_node.end_position()));
                }
            }
        }

        typedefs
    }

    /// Get all macro definitions in a syntax tree with start and end positions
    pub fn find_macros(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut macros = Vec::new();

        // Find simple macro definitions (#define NAME value)
        let simple_macro_nodes = tree.find_nodes_by_kind("preproc_def");
        for macro_node in simple_macro_nodes {
            if let Some(name) = Self::macro_name(&macro_node, source) {
                let ts_node = macro_node.inner();
                macros.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        // Find function-like macro definitions (#define NAME(args) body)
        let function_macro_nodes = tree.find_nodes_by_kind("preproc_function_def");
        for macro_node in function_macro_nodes {
            if let Some(name) = Self::function_macro_name(&macro_node, source) {
                let ts_node = macro_node.inner();
                macros.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        macros
    }

    /// Get all include directives in a syntax tree
    pub fn find_includes(tree: &SyntaxTree, _source: &str) -> Vec<String> {
        let mut includes = Vec::new();
        let include_nodes = tree.find_nodes_by_kind("preproc_include");

        for include_node in include_nodes {
            if let Ok(include_text) = include_node.text() {
                includes.push(include_text.to_string());
            }
        }

        includes
    }

    /// Create a query to find all function definitions
    pub fn functions_query() -> Result<Query> {
        let query_str = r#"
            (function_definition
                declarator: (function_declarator
                    declarator: (identifier) @name
                )
            ) @function
        "#;
        Query::new(crate::Language::C, query_str)
    }

    /// Create a query to find all struct definitions
    pub fn structs_query() -> Result<Query> {
        let query_str = r#"
            (struct_specifier
                name: (type_identifier) @name
            ) @struct
        "#;
        Query::new(crate::Language::C, query_str)
    }

    /// Create a query to find all union definitions
    pub fn unions_query() -> Result<Query> {
        let query_str = r#"
            (union_specifier
                name: (type_identifier) @name
            ) @union
        "#;
        Query::new(crate::Language::C, query_str)
    }

    /// Create a query to find all enum definitions
    pub fn enums_query() -> Result<Query> {
        let query_str = r#"
            (enum_specifier
                name: (type_identifier) @name
            ) @enum
        "#;
        Query::new(crate::Language::C, query_str)
    }

    /// Create a query to find all typedef definitions
    pub fn typedefs_query() -> Result<Query> {
        let query_str = r#"
            (declaration
                "typedef"
                type: (_)
                declarator: (type_identifier) @name
            ) @typedef
        "#;
        Query::new(crate::Language::C, query_str)
    }

    /// Create a query to find all macro definitions
    pub fn macros_query() -> Result<Query> {
        let query_str = r#"
            (preproc_def
                name: (identifier) @name
            ) @macro
        "#;
        Query::new(crate::Language::C, query_str)
    }

    /// Analyze C code complexity
    pub fn analyze_complexity(tree: &SyntaxTree) -> u32 {
        let mut complexity = 1; // Base complexity

        // Count decision points
        complexity += tree.find_nodes_by_kind("if_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("while_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("for_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("do_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("switch_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("case_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("conditional_expression").len() as u32;

        // Add C-specific complexity
        complexity += tree.find_nodes_by_kind("goto_statement").len() as u32;

        complexity
    }

    /// Detect C-specific features and patterns
    pub fn detect_c_features(tree: &SyntaxTree) -> Vec<String> {
        let mut features = Vec::new();

        // Check for pointer usage
        if !tree.find_nodes_by_kind("pointer_declarator").is_empty() {
            features.push("Pointers".to_string());
        }

        // Check for function pointers
        if !tree.find_nodes_by_kind("function_declarator").is_empty() {
            let function_declarators = tree.find_nodes_by_kind("function_declarator");
            for decl in function_declarators {
                if decl.parent().map_or(false, |p| p.kind() == "pointer_declarator") {
                    features.push("Function Pointers".to_string());
                    break;
                }
            }
        }

        // Check for structs
        if !tree.find_nodes_by_kind("struct_specifier").is_empty() {
            features.push("Structures".to_string());
        }

        // Check for unions
        if !tree.find_nodes_by_kind("union_specifier").is_empty() {
            features.push("Unions".to_string());
        }

        // Check for enums
        if !tree.find_nodes_by_kind("enum_specifier").is_empty() {
            features.push("Enumerations".to_string());
        }

        // Check for typedefs
        let type_definitions = tree.find_nodes_by_kind("type_definition");
        for type_def in type_definitions {
            if Self::is_typedef_declaration(&type_def) {
                features.push("Typedefs".to_string());
                break;
            }
        }

        // Check for preprocessor usage
        if !tree.find_nodes_by_kind("preproc_def").is_empty() {
            features.push("Macros".to_string());
        }

        if !tree.find_nodes_by_kind("preproc_include").is_empty() {
            features.push("Header Includes".to_string());
        }

        if !tree.find_nodes_by_kind("preproc_ifdef").is_empty()
            || !tree.find_nodes_by_kind("preproc_if").is_empty() {
            features.push("Conditional Compilation".to_string());
        }

        // Check for dynamic memory allocation
        // This would require more sophisticated analysis of function calls

        features
    }

    /// Check for potential memory management issues
    pub fn check_memory_patterns(tree: &SyntaxTree, _source: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Look for malloc/free patterns
        let call_expressions = tree.find_nodes_by_kind("call_expression");
        let mut malloc_calls = 0;
        let mut free_calls = 0;

        for call in call_expressions {
            if let Some(function_node) = call.child_by_field_name("function") {
                if let Ok(func_name) = function_node.text() {
                    match func_name {
                        "malloc" | "calloc" | "realloc" => malloc_calls += 1,
                        "free" => free_calls += 1,
                        _ => {}
                    }
                }
            }
        }

        if malloc_calls > 0 && free_calls == 0 {
            issues.push("Memory allocated but no free() calls found".to_string());
        } else if malloc_calls != free_calls {
            issues.push(format!("Potential memory leak: {} allocations, {} free calls", malloc_calls, free_calls));
        }

        // Check for array bounds (basic check)
        let array_accesses = tree.find_nodes_by_kind("subscript_expression");
        if !array_accesses.is_empty() {
            issues.push("Array access detected - verify bounds checking".to_string());
        }

        issues
    }

    /// Get function call graph (simplified)
    pub fn get_function_calls(tree: &SyntaxTree, source: &str) -> Vec<(String, Vec<String>)> {
        let mut call_graph = Vec::new();
        let function_nodes = tree.find_nodes_by_kind("function_definition");

        for func_node in function_nodes {
            if let Some(func_name) = Self::function_name(&func_node, source) {
                let mut called_functions = Vec::new();

                // Find all call expressions within this function
                Self::collect_function_calls(&func_node, &mut called_functions);

                call_graph.push((func_name, called_functions));
            }
        }

        call_graph
    }

    /// Helper function to collect function calls recursively
    fn collect_function_calls(node: &Node, calls: &mut Vec<String>) {
        for child in node.children() {
            if child.kind() == "call_expression" {
                if let Some(function_node) = child.child_by_field_name("function") {
                    if let Ok(func_name) = function_node.text() {
                        calls.push(func_name.to_string());
                    }
                }
            } else {
                // Recursively check children
                Self::collect_function_calls(&child, calls);
            }
        }
    }

    /// Find function pointer declarations in a syntax tree
    pub fn find_function_pointers(tree: &SyntaxTree, _source: &str) -> Vec<(String, String, tree_sitter::Point, tree_sitter::Point)> {
        let mut function_pointers = Vec::new();

        // Look for function pointer typedefs
        let typedef_nodes = tree.find_nodes_by_kind("type_definition");
        for typedef_node in typedef_nodes {
            // Check if this typedef contains a function_declarator (function pointer)
            let mut cursor = typedef_node.walk();
            if cursor.goto_first_child() {
                loop {
                    let node = cursor.node();
                    if node.kind() == "function_declarator" {
                        // This is a function pointer typedef
                        // Extract the name from the parenthesized_declarator
                        let mut func_cursor = node.walk();
                        if func_cursor.goto_first_child() {
                            loop {
                                let func_node = func_cursor.node();
                                if func_node.kind() == "parenthesized_declarator" {
                                    // Look for the pointer_declarator inside
                                    let mut ptr_cursor = func_node.walk();
                                    if ptr_cursor.goto_first_child() {
                                        loop {
                                            let ptr_node = ptr_cursor.node();
                                            if ptr_node.kind() == "pointer_declarator" {
                                                // Find the type_identifier (the name)
                                                let mut name_cursor = ptr_node.walk();
                                                if name_cursor.goto_first_child() {
                                                    loop {
                                                        let name_node = name_cursor.node();
                                                        if name_node.kind() == "type_identifier" {
                                                            if let Ok(name) = name_node.text() {
                                                                if let Ok(signature) = typedef_node.text() {
                                                                    let ts_node = typedef_node.inner();
                                                                    function_pointers.push((
                                                                        name.to_string(),
                                                                        signature.trim().to_string(),
                                                                        ts_node.start_position(),
                                                                        ts_node.end_position()
                                                                    ));
                                                                }
                                                            }
                                                            break;
                                                        }
                                                        if !name_cursor.goto_next_sibling() {
                                                            break;
                                                        }
                                                    }
                                                }
                                                break;
                                            }
                                            if !ptr_cursor.goto_next_sibling() {
                                                break;
                                            }
                                        }
                                    }
                                    break;
                                }
                                if !func_cursor.goto_next_sibling() {
                                    break;
                                }
                            }
                        }
                        break;
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        function_pointers
    }

    /// Find union declarations in a syntax tree
    pub fn find_unions(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut unions = Vec::new();
        let union_nodes = tree.find_nodes_by_kind("union_specifier");

        for union_node in union_nodes {
            if let Some(name) = Self::union_name(&union_node, source) {
                let ts_node = union_node.inner();
                unions.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        unions
    }

    /// Find bit field declarations in structs
    pub fn find_bit_fields(tree: &SyntaxTree, source: &str) -> Vec<(String, String, u32, tree_sitter::Point, tree_sitter::Point)> {
        let mut bit_fields = Vec::new();
        let struct_nodes = tree.find_nodes_by_kind("struct_specifier");

        for struct_node in struct_nodes {
            if let Some(struct_name) = Self::struct_name(&struct_node, source) {
                // Look for field declarations with bitfield_clause
                let mut cursor = struct_node.walk();
                if cursor.goto_first_child() {
                    loop {
                        let node = cursor.node();
                        if node.kind() == "field_declaration_list" {
                            // Look inside the field declaration list
                            let mut field_cursor = node.walk();
                            if field_cursor.goto_first_child() {
                                loop {
                                    let field_node = field_cursor.node();
                                    if field_node.kind() == "field_declaration" {
                                        // Look for field_identifier and bitfield_clause
                                        let mut decl_cursor = field_node.walk();
                                        let mut field_name = String::new();
                                        let mut bit_count = 0u32;
                                        let mut has_bitfield = false;

                                        if decl_cursor.goto_first_child() {
                                            loop {
                                                let decl_child = decl_cursor.node();
                                                if decl_child.kind() == "field_identifier" {
                                                    if let Ok(name) = decl_child.text() {
                                                        field_name = name.to_string();
                                                    }
                                                } else if decl_child.kind() == "bitfield_clause" {
                                                    has_bitfield = true;
                                                    // Look for the number_literal inside bitfield_clause
                                                    let mut bit_cursor = decl_child.walk();
                                                    if bit_cursor.goto_first_child() {
                                                        loop {
                                                            let bit_child = bit_cursor.node();
                                                            if bit_child.kind() == "number_literal" {
                                                                if let Ok(bits_text) = bit_child.text() {
                                                                    if let Ok(bits) = bits_text.parse::<u32>() {
                                                                        bit_count = bits;
                                                                    }
                                                                }
                                                                break;
                                                            }
                                                            if !bit_cursor.goto_next_sibling() {
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                                if !decl_cursor.goto_next_sibling() {
                                                    break;
                                                }
                                            }
                                        }

                                        if has_bitfield && !field_name.is_empty() {
                                            let ts_node = field_node.inner();
                                            bit_fields.push((
                                                struct_name.clone(),
                                                field_name,
                                                bit_count,
                                                ts_node.start_position(),
                                                ts_node.end_position()
                                            ));
                                        }
                                    }
                                    if !field_cursor.goto_next_sibling() {
                                        break;
                                    }
                                }
                            }
                            break;
                        }
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
        }

        bit_fields
    }

    /// Find preprocessor macros in a syntax tree
    pub fn find_preprocessor_macros(tree: &SyntaxTree, source: &str) -> Vec<(String, String, tree_sitter::Point, tree_sitter::Point)> {
        let mut macros = Vec::new();

        // Find #define directives
        let preproc_nodes = tree.find_nodes_by_kind("preproc_def");
        for macro_node in preproc_nodes {
            if let Some(name) = Self::macro_name(&macro_node, source) {
                let ts_node = macro_node.inner();
                if let Ok(macro_text) = macro_node.text() {
                    macros.push((
                        name,
                        macro_text.trim().to_string(),
                        ts_node.start_position(),
                        ts_node.end_position()
                    ));
                }
            }
        }

        // Find function-like macros
        let func_macro_nodes = tree.find_nodes_by_kind("preproc_function_def");
        for macro_node in func_macro_nodes {
            if let Some(name) = Self::function_macro_name(&macro_node, source) {
                let ts_node = macro_node.inner();
                if let Ok(macro_text) = macro_node.text() {
                    macros.push((
                        name,
                        macro_text.trim().to_string(),
                        ts_node.start_position(),
                        ts_node.end_position()
                    ));
                }
            }
        }

        macros
    }

    /// Find static functions in a syntax tree
    pub fn find_static_functions(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut static_functions = Vec::new();
        let function_nodes = tree.find_nodes_by_kind("function_definition");

        for func_node in function_nodes {
            // Check if function has static storage class specifier
            let mut cursor = func_node.walk();
            let mut is_static = false;

            if cursor.goto_first_child() {
                loop {
                    let node = cursor.node();
                    if node.kind() == "storage_class_specifier" {
                        if let Ok(specifier_text) = node.text() {
                            if specifier_text == "static" {
                                is_static = true;
                                break;
                            }
                        }
                    }

                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }

            if is_static {
                if let Some(name) = Self::function_name(&func_node, source) {
                    let ts_node = func_node.inner();
                    static_functions.push((name, ts_node.start_position(), ts_node.end_position()));
                }
            }
        }

        static_functions
    }

    /// Find inline functions in a syntax tree
    pub fn find_inline_functions(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut inline_functions = Vec::new();
        let function_nodes = tree.find_nodes_by_kind("function_definition");

        for func_node in function_nodes {
            // Check if function has inline specifier
            let mut cursor = func_node.walk();
            let mut is_inline = false;

            if cursor.goto_first_child() {
                loop {
                    let node = cursor.node();
                    if node.kind() == "storage_class_specifier" || node.kind() == "type_qualifier" {
                        if let Ok(specifier_text) = node.text() {
                            if specifier_text == "inline" {
                                is_inline = true;
                                break;
                            }
                        }
                    }

                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }

            if is_inline {
                if let Some(name) = Self::function_name(&func_node, source) {
                    let ts_node = func_node.inner();
                    inline_functions.push((name, ts_node.start_position(), ts_node.end_position()));
                }
            }
        }

        inline_functions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;

    #[test]
    fn test_c_function_detection() {
        let source = r#"
int main(int argc, char *argv[]) {
    return 0;
}

static void helper_function(void) {
    // helper code
}

inline int calculate(int a, int b) {
    return a + b;
}
        "#;

        let parser = Parser::new(crate::Language::C).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let functions = CSyntax::find_functions(&tree, source);
        assert_eq!(functions.len(), 3);

        let function_names: Vec<&str> = functions.iter().map(|(name, _, _)| name.as_str()).collect();
        assert!(function_names.contains(&"main"));
        assert!(function_names.contains(&"helper_function"));
        assert!(function_names.contains(&"calculate"));
    }

    #[test]
    fn test_c_struct_detection() {
        let source = r#"
struct Point {
    int x;
    int y;
};

struct Rectangle {
    struct Point top_left;
    struct Point bottom_right;
};

typedef struct {
    char name[50];
    int age;
} Person;
        "#;

        let parser = Parser::new(crate::Language::C).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let structs = CSyntax::find_structs(&tree, source);
        assert_eq!(structs.len(), 2); // Named structs only

        let struct_names: Vec<&str> = structs.iter().map(|(name, _, _)| name.as_str()).collect();
        assert!(struct_names.contains(&"Point"));
        assert!(struct_names.contains(&"Rectangle"));
    }

    #[test]
    fn test_c_typedef_detection() {
        let source = r#"
typedef int Integer;
typedef char* String;
typedef struct Point Point_t;

typedef struct {
    int value;
} Anonymous;
        "#;

        let parser = Parser::new(crate::Language::C).unwrap();
        let tree = parser.parse(source, None).unwrap();



        let typedefs = CSyntax::find_typedefs(&tree, source);
        assert!(typedefs.len() >= 3); // At least Integer, String, Point_t

        let typedef_names: Vec<&str> = typedefs.iter().map(|(name, _, _)| name.as_str()).collect();
        assert!(typedef_names.contains(&"Integer"));
        assert!(typedef_names.contains(&"String"));
        assert!(typedef_names.contains(&"Point_t"));
    }

    #[test]
    fn test_c_enum_detection() {
        let source = r#"
enum Color {
    RED,
    GREEN,
    BLUE
};

enum Status {
    SUCCESS = 0,
    ERROR = -1
};
        "#;

        let parser = Parser::new(crate::Language::C).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let enums = CSyntax::find_enums(&tree, source);
        assert_eq!(enums.len(), 2);

        let enum_names: Vec<&str> = enums.iter().map(|(name, _, _)| name.as_str()).collect();
        assert!(enum_names.contains(&"Color"));
        assert!(enum_names.contains(&"Status"));
    }

    #[test]
    fn test_c_macro_detection() {
        let source = r#"
#define MAX_SIZE 100
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define DEBUG_PRINT(x) printf("Debug: %s\n", x)
        "#;

        let parser = Parser::new(crate::Language::C).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let macros = CSyntax::find_macros(&tree, source);

        assert_eq!(macros.len(), 3);

        let macro_names: Vec<&str> = macros.iter().map(|(name, _, _)| name.as_str()).collect();
        assert!(macro_names.contains(&"MAX_SIZE"));
        assert!(macro_names.contains(&"MIN"));
        assert!(macro_names.contains(&"DEBUG_PRINT"));
    }



    #[test]
    fn test_function_parameters() {
        let source = r#"
int process_data(int count, char *buffer, size_t size) {
    return count;
}
        "#;

        let parser = Parser::new(crate::Language::C).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let function_nodes = tree.find_nodes_by_kind("function_definition");
        assert!(!function_nodes.is_empty());

        let params = CSyntax::function_parameters(&function_nodes[0], source);
        assert_eq!(params.len(), 3);
        assert!(params.contains(&"count".to_string()));
        assert!(params.contains(&"buffer".to_string()));
        assert!(params.contains(&"size".to_string()));
    }

    #[test]
    fn test_function_return_type() {
        let source = r#"
static int calculate(int a, int b) {
    return a + b;
}

void* allocate_memory(size_t size) {
    return malloc(size);
}
        "#;

        let parser = Parser::new(crate::Language::C).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let function_nodes = tree.find_nodes_by_kind("function_definition");
        assert_eq!(function_nodes.len(), 2);

        let return_type1 = CSyntax::function_return_type(&function_nodes[0], source);
        assert!(return_type1.is_some());
        assert!(return_type1.unwrap().contains("int"));

        let return_type2 = CSyntax::function_return_type(&function_nodes[1], source);
        assert!(return_type2.is_some());
        assert!(return_type2.unwrap().contains("void"));
    }

    #[test]
    fn test_struct_fields() {
        let source = r#"
struct Person {
    char name[50];
    int age;
    float height;
};
        "#;

        let parser = Parser::new(crate::Language::C).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let struct_nodes = tree.find_nodes_by_kind("struct_specifier");
        assert!(!struct_nodes.is_empty());

        let fields = CSyntax::struct_fields(&struct_nodes[0], source);
        assert_eq!(fields.len(), 3);

        let field_names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
        assert!(field_names.contains(&"name"));
        assert!(field_names.contains(&"age"));
        assert!(field_names.contains(&"height"));
    }

    #[test]
    fn test_c_features_detection() {
        let source = r#"
#include <stdio.h>
#define MAX 100

struct Point {
    int x, y;
};

union Data {
    int i;
    float f;
};

enum Color { RED, GREEN, BLUE };

typedef int* IntPtr;

int main() {
    int *ptr = malloc(sizeof(int));
    struct Point p = {0, 0};
    free(ptr);
    return 0;
}
        "#;

        let parser = Parser::new(crate::Language::C).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let features = CSyntax::detect_c_features(&tree);
        assert!(features.contains(&"Pointers".to_string()));
        assert!(features.contains(&"Structures".to_string()));
        assert!(features.contains(&"Unions".to_string()));
        assert!(features.contains(&"Enumerations".to_string()));
        assert!(features.contains(&"Typedefs".to_string()));
        assert!(features.contains(&"Macros".to_string()));
        assert!(features.contains(&"Header Includes".to_string()));
    }

    #[test]
    fn test_memory_pattern_analysis() {
        let source = r#"
int main() {
    int *ptr1 = malloc(sizeof(int));
    int *ptr2 = calloc(10, sizeof(int));

    // Missing free for ptr1
    free(ptr2);

    int arr[10];
    arr[15] = 5; // Potential bounds issue

    return 0;
}
        "#;

        let parser = Parser::new(crate::Language::C).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let issues = CSyntax::check_memory_patterns(&tree, source);
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|issue| issue.contains("allocations") && issue.contains("free calls")));
        assert!(issues.iter().any(|issue| issue.contains("Array access")));
    }
}
