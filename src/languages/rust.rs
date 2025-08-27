//! Rust language specific functionality

use crate::error::Result;
use crate::query::Query;
use crate::tree::SyntaxTree;
use tree_sitter::Node;

/// Rust-specific syntax tree utilities
pub struct RustSyntax;

impl RustSyntax {
    /// Check if a node is a function definition
    pub fn is_function(node: &Node) -> bool {
        node.kind() == "function_item"
    }

    /// Check if a node is a struct definition
    pub fn is_struct(node: &Node) -> bool {
        node.kind() == "struct_item"
    }

    /// Check if a node is an enum definition
    pub fn is_enum(node: &Node) -> bool {
        node.kind() == "enum_item"
    }

    /// Check if a node is an impl block
    pub fn is_impl(node: &Node) -> bool {
        node.kind() == "impl_item"
    }

    /// Check if a node is a trait definition
    pub fn is_trait(node: &Node) -> bool {
        node.kind() == "trait_item"
    }

    /// Check if a node is a module definition
    pub fn is_module(node: &Node) -> bool {
        node.kind() == "mod_item"
    }

    /// Check if a node is a use statement
    pub fn is_use_statement(node: &Node) -> bool {
        node.kind() == "use_declaration"
    }

    /// Extract function name from a function node
    pub fn function_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_function(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string())
    }

    /// Extract struct name from a struct node
    pub fn struct_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_struct(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string())
    }

    /// Extract enum name from an enum node
    pub fn enum_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_enum(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string())
    }

    /// Extract trait name from a trait node
    pub fn trait_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_trait(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string())
    }

    /// Extract module name from a module node
    pub fn module_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_module(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string())
    }

    /// Get all function definitions in a syntax tree with start and end positions
    pub fn find_functions(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut functions = Vec::new();
        let function_nodes = tree.find_nodes_by_kind("function_item");

        for func_node in function_nodes {
            let ts_node = func_node.inner();
            if let Some(name) = Self::function_name(&ts_node, source) {
                functions.push((name, func_node.start_position(), func_node.end_position()));
            }
        }

        functions
    }

    /// Get all struct definitions in a syntax tree with start and end positions
    pub fn find_structs(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut structs = Vec::new();
        let struct_nodes = tree.find_nodes_by_kind("struct_item");

        for struct_node in struct_nodes {
            let ts_node = struct_node.inner();
            if let Some(name) = Self::struct_name(&ts_node, source) {
                structs.push((name, struct_node.start_position(), struct_node.end_position()));
            }
        }

        structs
    }

    /// Create a query to find all public functions
    pub fn public_functions_query() -> Result<Query> {
        let query_str = r#"
            (function_item
                (visibility_modifier) @visibility
                name: (identifier) @name
            ) @function
        "#;
        Query::new(crate::Language::Rust, query_str)
    }

    /// Create a query to find all struct definitions
    pub fn structs_query() -> Result<Query> {
        let query_str = r#"
            (struct_item
                name: (type_identifier) @name
            ) @struct
        "#;
        Query::new(crate::Language::Rust, query_str)
    }

    /// Create a query to find all impl blocks
    pub fn impl_blocks_query() -> Result<Query> {
        let query_str = r#"
            (impl_item
                type: (type_identifier) @type
            ) @impl
        "#;
        Query::new(crate::Language::Rust, query_str)
    }



    /// Check if a function is public
    pub fn is_public_function(name: &str, content: &str) -> bool {
        // Look for the function definition and check for pub keyword
        for line in content.lines() {
            if line.contains(&format!("fn {}", name)) {
                return line.trim_start().starts_with("pub ");
            }
        }
        false
    }

    /// Check if a struct is public
    pub fn is_public_struct(name: &str, content: &str) -> bool {
        // Look for the struct definition and check for pub keyword
        for line in content.lines() {
            if line.contains(&format!("struct {}", name)) {
                return line.trim_start().starts_with("pub ");
            }
        }
        false
    }

    /// Extract documentation comment for a symbol
    pub fn extract_doc_comment(name: &str, content: &str) -> Option<String> {
        let lines: Vec<&str> = content.lines().collect();

        // Find the line with the symbol definition
        for (i, line) in lines.iter().enumerate() {
            if line.contains(&format!("fn {}", name)) || line.contains(&format!("struct {}", name)) {
                // Look backwards for doc comments
                let mut doc_lines = Vec::new();
                let mut j = i;

                while j > 0 {
                    j -= 1;
                    let prev_line = lines[j].trim();

                    if prev_line.starts_with("///") {
                        doc_lines.insert(0, prev_line.trim_start_matches("///").trim());
                    } else if prev_line.is_empty() {
                        continue;
                    } else {
                        break;
                    }
                }

                if !doc_lines.is_empty() {
                    return Some(doc_lines.join(" "));
                }
                break;
            }
        }

        None
    }

    /// Find trait definitions in a syntax tree
    pub fn find_traits(tree: &SyntaxTree, source: &str) -> Vec<(String, Vec<String>, tree_sitter::Point, tree_sitter::Point)> {
        let mut traits = Vec::new();
        let trait_nodes = tree.find_nodes_by_kind("trait_item");

        for trait_node in trait_nodes {
            let ts_node = trait_node.inner();
            if let Some(name) = Self::trait_name(&ts_node, source) {
                let mut methods = Vec::new();

                // Extract trait methods from declaration_list
                if let Some(decl_list) = ts_node.child_by_field_name("body") {
                    let mut cursor = decl_list.walk();
                    if cursor.goto_first_child() {
                        loop {
                            let node = cursor.node();
                            if node.kind() == "function_signature_item" {
                                // For function signatures, get the name directly
                                if let Some(name_node) = node.child_by_field_name("name") {
                                    if let Ok(method_name) = name_node.utf8_text(source.as_bytes()) {
                                        methods.push(method_name.to_string());
                                    }
                                }
                            } else if node.kind() == "function_item" {
                                if let Some(method_name) = Self::function_name(&node, source) {
                                    methods.push(method_name);
                                }
                            }

                            if !cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }

                traits.push((name, methods, trait_node.start_position(), trait_node.end_position()));
            }
        }

        traits
    }

    /// Find impl blocks in a syntax tree
    pub fn find_impl_blocks(tree: &SyntaxTree, source: &str) -> Vec<(String, Option<String>, Vec<String>, tree_sitter::Point, tree_sitter::Point)> {
        let mut impl_blocks = Vec::new();
        let impl_nodes = tree.find_nodes_by_kind("impl_item");

        for impl_node in impl_nodes {
            let ts_node = impl_node.inner();
            let mut type_name = None;
            let mut trait_name = None;
            let mut methods = Vec::new();

            // Extract type being implemented
            if let Some(type_node) = ts_node.child_by_field_name("type") {
                if let Ok(type_text) = type_node.utf8_text(source.as_bytes()) {
                    // Extract just the base type name (e.g., "Array" from "Array<T, N>")
                    let base_type = if let Some(angle_pos) = type_text.find('<') {
                        type_text[..angle_pos].trim()
                    } else {
                        type_text.trim()
                    };
                    type_name = Some(base_type.to_string());
                }
            }

            // Check if it's a trait implementation
            if let Some(trait_node) = ts_node.child_by_field_name("trait") {
                if let Ok(trait_text) = trait_node.utf8_text(source.as_bytes()) {
                    // Extract just the trait name (e.g., "Display" from "std::fmt::Display")
                    let base_trait = if let Some(colon_pos) = trait_text.rfind("::") {
                        &trait_text[colon_pos + 2..]
                    } else {
                        trait_text.trim()
                    };
                    trait_name = Some(base_trait.to_string());
                }
            }

            // Extract methods from the impl block's declaration_list
            if let Some(decl_list) = ts_node.child_by_field_name("body") {
                let mut cursor = decl_list.walk();
                if cursor.goto_first_child() {
                    loop {
                        let node = cursor.node();
                        if node.kind() == "function_item" {
                            if let Some(method_name) = Self::function_name(&node, source) {
                                methods.push(method_name);
                            }
                        }

                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }

            if let Some(type_name) = type_name {
                impl_blocks.push((
                    type_name,
                    trait_name,
                    methods,
                    impl_node.start_position(),
                    impl_node.end_position()
                ));
            }
        }

        impl_blocks
    }

    /// Find macro definitions in a syntax tree
    pub fn find_macros(tree: &SyntaxTree, source: &str) -> Vec<(String, String, tree_sitter::Point, tree_sitter::Point)> {
        let mut macros = Vec::new();

        // Find macro_rules! definitions
        let macro_nodes = tree.find_nodes_by_kind("macro_definition");
        for macro_node in macro_nodes {
            let ts_node = macro_node.inner();
            if let Some(name_node) = ts_node.child_by_field_name("name") {
                if let Ok(macro_name) = name_node.utf8_text(source.as_bytes()) {
                    if let Ok(macro_text) = ts_node.utf8_text(source.as_bytes()) {
                        macros.push((
                            macro_name.to_string(),
                            macro_text.to_string(),
                            macro_node.start_position(),
                            macro_node.end_position()
                        ));
                    }
                }
            }
        }

        // Find declarative macros (macro_rules!)
        let declarative_macro_nodes = tree.find_nodes_by_kind("macro_rule");
        for macro_node in declarative_macro_nodes {
            let ts_node = macro_node.inner();
            if let Ok(macro_text) = ts_node.utf8_text(source.as_bytes()) {
                // Extract macro name from macro_rules! name { ... }
                if let Some(start) = macro_text.find("macro_rules!") {
                    let after_macro_rules = &macro_text[start + 12..];
                    if let Some(name_end) = after_macro_rules.find('{') {
                        let macro_name = after_macro_rules[..name_end].trim();
                        macros.push((
                            macro_name.to_string(),
                            macro_text.to_string(),
                            macro_node.start_position(),
                            macro_node.end_position()
                        ));
                    }
                }
            }
        }

        macros
    }

    /// Find lifetime parameters in a syntax tree
    pub fn find_lifetimes(tree: &SyntaxTree, source: &str) -> Vec<(String, String, tree_sitter::Point, tree_sitter::Point)> {
        let mut lifetimes = Vec::new();

        // Find lifetime parameters in function signatures
        let function_nodes = tree.find_nodes_by_kind("function_item");
        for func_node in function_nodes {
            let ts_node = func_node.inner();
            if let Some(func_name) = Self::function_name(&ts_node, source) {
                // Look for lifetime parameters
                if let Some(params_node) = ts_node.child_by_field_name("type_parameters") {
                    let mut cursor = params_node.walk();
                    if cursor.goto_first_child() {
                        loop {
                            let node = cursor.node();
                            if node.kind() == "lifetime" {
                                if let Ok(lifetime_text) = node.utf8_text(source.as_bytes()) {
                                    lifetimes.push((
                                        func_name.clone(),
                                        lifetime_text.to_string(),
                                        func_node.start_position(),
                                        func_node.end_position()
                                    ));
                                }
                            }

                            if !cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
            }
        }

        lifetimes
    }

    /// Find associated types in trait definitions
    pub fn find_associated_types(tree: &SyntaxTree, source: &str) -> Vec<(String, String, tree_sitter::Point, tree_sitter::Point)> {
        let mut associated_types = Vec::new();
        let trait_nodes = tree.find_nodes_by_kind("trait_item");

        for trait_node in trait_nodes {
            let ts_node = trait_node.inner();
            if let Some(trait_name) = Self::trait_name(&ts_node, source) {
                // Look for associated type declarations in declaration_list
                if let Some(decl_list) = ts_node.child_by_field_name("body") {
                    let mut cursor = decl_list.walk();
                    if cursor.goto_first_child() {
                        loop {
                            let node = cursor.node();
                            if node.kind() == "associated_type" {
                                if let Some(type_name_node) = node.child_by_field_name("name") {
                                    if let Ok(type_name) = type_name_node.utf8_text(source.as_bytes()) {
                                        associated_types.push((
                                            trait_name.clone(),
                                            type_name.to_string(),
                                            trait_node.start_position(),
                                            trait_node.end_position()
                                        ));
                                    }
                                }
                            }

                            if !cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
            }
        }

        associated_types
    }

    /// Find const generics in type definitions
    pub fn find_const_generics(tree: &SyntaxTree, source: &str) -> Vec<(String, String, tree_sitter::Point, tree_sitter::Point)> {
        let mut const_generics = Vec::new();

        // Find const generics in struct definitions
        let struct_nodes = tree.find_nodes_by_kind("struct_item");
        for struct_node in struct_nodes {
            let ts_node = struct_node.inner();
            if let Some(struct_name) = Self::struct_name(&ts_node, source) {
                // Look for const generic parameters
                if let Some(params_node) = ts_node.child_by_field_name("type_parameters") {
                    let mut cursor = params_node.walk();
                    if cursor.goto_first_child() {
                        loop {
                            let node = cursor.node();
                            if node.kind() == "const_parameter" {
                                if let Ok(const_param_text) = node.utf8_text(source.as_bytes()) {
                                    const_generics.push((
                                        struct_name.clone(),
                                        const_param_text.to_string(),
                                        struct_node.start_position(),
                                        struct_node.end_position()
                                    ));
                                }
                            }

                            if !cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
            }
        }

        const_generics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;

    #[test]
    fn test_rust_syntax_detection() {
        let source = r#"
            fn main() {
                println!("Hello, world!");
            }
            
            struct Point {
                x: i32,
                y: i32,
            }
            
            enum Color {
                Red,
                Green,
                Blue,
            }
        "#;

        let parser = Parser::new(crate::Language::Rust).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        let mut found_function = false;
        let mut found_struct = false;
        let mut found_enum = false;

        let mut cursor = root.walk();
        if cursor.goto_first_child() {
            loop {
                let node = cursor.node();
                let ts_node = node.inner();
                if RustSyntax::is_function(&ts_node) {
                    found_function = true;
                    assert_eq!(RustSyntax::function_name(&ts_node, source), Some("main".to_string()));
                }
                if RustSyntax::is_struct(&ts_node) {
                    found_struct = true;
                    assert_eq!(RustSyntax::struct_name(&ts_node, source), Some("Point".to_string()));
                }
                if RustSyntax::is_enum(&ts_node) {
                    found_enum = true;
                    assert_eq!(RustSyntax::enum_name(&ts_node, source), Some("Color".to_string()));
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        assert!(found_function);
        assert!(found_struct);
        assert!(found_enum);
    }
}
