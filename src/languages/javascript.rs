//! JavaScript language support for tree-sitter
//!
//! This module provides JavaScript-specific utilities for parsing and analyzing
//! JavaScript source code using tree-sitter.

use crate::error::Result;
use crate::query::Query;
use crate::tree::{Node, SyntaxTree};


/// JavaScript-specific syntax utilities
pub struct JavaScriptSyntax;

impl JavaScriptSyntax {
    /// Check if a node represents a function declaration
    pub fn is_function_declaration(node: &Node) -> bool {
        node.kind() == "function_declaration"
    }

    /// Check if a node represents a function expression
    pub fn is_function_expression(node: &Node) -> bool {
        node.kind() == "function_expression"
    }

    /// Check if a node represents an arrow function
    pub fn is_arrow_function(node: &Node) -> bool {
        node.kind() == "arrow_function"
    }

    /// Check if a node represents any kind of function
    pub fn is_function(node: &Node) -> bool {
        Self::is_function_declaration(node)
            || Self::is_function_expression(node)
            || Self::is_arrow_function(node)
            || Self::is_generator_function_declaration(node)
            || Self::is_generator_function_expression(node)
    }

    /// Check if a node represents a generator function declaration
    pub fn is_generator_function_declaration(node: &Node) -> bool {
        node.kind() == "generator_function_declaration"
    }

    /// Check if a node represents a generator function expression
    pub fn is_generator_function_expression(node: &Node) -> bool {
        node.kind() == "generator_function"
    }

    /// Check if a node represents an async function
    pub fn is_async_function(node: &Node) -> bool {
        // Check if the function has an "async" modifier
        for child in node.children() {
            if child.kind() == "async" {
                return true;
            }
        }
        false
    }

    /// Check if a node represents a class declaration
    pub fn is_class_declaration(node: &Node) -> bool {
        node.kind() == "class_declaration"
    }

    /// Check if a node represents a class expression
    pub fn is_class_expression(node: &Node) -> bool {
        node.kind() == "class_expression"
    }

    /// Check if a node represents any kind of class
    pub fn is_class(node: &Node) -> bool {
        Self::is_class_declaration(node) || Self::is_class_expression(node)
    }

    /// Check if a node represents a method definition
    pub fn is_method_definition(node: &Node) -> bool {
        node.kind() == "method_definition"
    }

    /// Check if a node represents a variable declaration
    pub fn is_variable_declaration(node: &Node) -> bool {
        node.kind() == "variable_declaration"
    }

    /// Check if a node represents an import statement
    pub fn is_import_statement(node: &Node) -> bool {
        node.kind() == "import_statement"
    }

    /// Check if a node represents an export statement
    pub fn is_export_statement(node: &Node) -> bool {
        matches!(node.kind(), "export_statement" | "export_default_declaration")
    }

    /// Check if a node represents an object expression
    pub fn is_object_expression(node: &Node) -> bool {
        node.kind() == "object"
    }

    /// Extract function name from a function node
    pub fn function_name(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_function(node) {
            return None;
        }

        // Try to get name from identifier field
        if let Some(name_node) = node.child_by_field_name("name") {
            return name_node.text().ok().map(|s| s.to_string());
        }

        // For arrow functions assigned to variables, get the variable name
        if Self::is_arrow_function(node) {
            if let Some(parent) = node.parent() {
                if parent.kind() == "variable_declarator" {
                    if let Some(id_node) = parent.child_by_field_name("name") {
                        return id_node.text().ok().map(|s| s.to_string());
                    }
                }
            }
        }

        None
    }

    /// Extract class name from a class node
    pub fn class_name(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_class(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Extract method name from a method definition node
    pub fn method_name(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_method_definition(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Extract variable names from a variable declaration
    pub fn variable_names(node: &Node, _source: &str) -> Vec<String> {
        if !Self::is_variable_declaration(node) {
            return Vec::new();
        }

        let mut names = Vec::new();

        for child in node.children() {
            if child.kind() == "variable_declarator" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    if let Ok(name) = name_node.text() {
                        names.push(name.to_string());
                    }
                }
            }
        }

        names
    }



    /// Check if a function is a generator
    pub fn is_generator_function(node: &Node) -> bool {
        if !Self::is_function(node) {
            return false;
        }

        for child in node.children() {
            if child.kind() == "*" {
                return true;
            }
        }
        false
    }

    /// Get function parameters
    pub fn function_parameters(node: &Node, _source: &str) -> Vec<String> {
        if !Self::is_function(node) {
            return Vec::new();
        }

        let mut parameters = Vec::new();
        
        if let Some(params_node) = node.child_by_field_name("parameters") {
            for child in params_node.children() {
                if child.kind() == "identifier" {
                    if let Ok(param) = child.text() {
                        parameters.push(param.to_string());
                    }
                } else if child.kind() == "formal_parameters" {
                    // Handle nested formal parameters
                    for nested_child in child.children() {
                        if nested_child.kind() == "identifier" {
                            if let Ok(param) = nested_child.text() {
                                parameters.push(param.to_string());
                            }
                        }
                    }
                }
            }
        }

        parameters
    }

    /// Get all function definitions in a syntax tree with start and end positions
    pub fn find_functions(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut functions = Vec::new();

        // Find function declarations
        let function_nodes = tree.find_nodes_by_kind("function_declaration");
        for func_node in function_nodes {
            if let Some(name) = Self::function_name(&func_node, source) {
                let ts_node = func_node.inner();
                functions.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        // Find function expressions
        let expr_nodes = tree.find_nodes_by_kind("function_expression");
        for func_node in expr_nodes {
            if let Some(name) = Self::function_name(&func_node, source) {
                let ts_node = func_node.inner();
                functions.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        // Find arrow functions
        let arrow_nodes = tree.find_nodes_by_kind("arrow_function");
        for func_node in arrow_nodes {
            if let Some(name) = Self::function_name(&func_node, source) {
                let ts_node = func_node.inner();
                functions.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        functions
    }

    /// Get all class definitions in a syntax tree with start and end positions
    pub fn find_classes(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut classes = Vec::new();

        // Find class declarations
        let class_nodes = tree.find_nodes_by_kind("class_declaration");
        for class_node in class_nodes {
            if let Some(name) = Self::class_name(&class_node, source) {
                let ts_node = class_node.inner();
                classes.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        // Find class expressions
        let expr_nodes = tree.find_nodes_by_kind("class_expression");
        for class_node in expr_nodes {
            if let Some(name) = Self::class_name(&class_node, source) {
                let ts_node = class_node.inner();
                classes.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        classes
    }

    /// Get all import statements in a syntax tree
    pub fn find_imports(tree: &SyntaxTree, _source: &str) -> Vec<String> {
        let mut imports = Vec::new();
        let import_nodes = tree.find_nodes_by_kind("import_statement");
        
        for import_node in import_nodes {
            if let Ok(import_text) = import_node.text() {
                imports.push(import_text.to_string());
            }
        }

        imports
    }

    /// Get all export statements in a syntax tree
    pub fn find_exports(tree: &SyntaxTree, _source: &str) -> Vec<String> {
        let mut exports = Vec::new();

        let export_nodes = tree.find_nodes_by_kind("export_statement");
        for export_node in export_nodes {
            if let Ok(export_text) = export_node.text() {
                exports.push(export_text.to_string());
            }
        }

        let default_export_nodes = tree.find_nodes_by_kind("export_default_declaration");
        for export_node in default_export_nodes {
            if let Ok(export_text) = export_node.text() {
                exports.push(export_text.to_string());
            }
        }

        exports
    }

    /// Find generator functions in a syntax tree
    pub fn find_generators(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut generators = Vec::new();

        // Find generator function declarations
        let generator_nodes = tree.find_nodes_by_kind("generator_function_declaration");
        for gen_node in generator_nodes {
            if let Some(name) = Self::function_name(&gen_node, source) {
                let ts_node = gen_node.inner();
                generators.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        // Find generator function expressions
        let gen_expr_nodes = tree.find_nodes_by_kind("generator_function");
        for gen_node in gen_expr_nodes {
            if let Some(name) = Self::function_name(&gen_node, source) {
                let ts_node = gen_node.inner();
                generators.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        generators
    }

    /// Find async functions in a syntax tree
    pub fn find_async_functions(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut async_functions = Vec::new();

        // Find async function declarations
        let function_nodes = tree.find_nodes_by_kind("function_declaration");
        for func_node in function_nodes {
            if Self::is_async_function(&func_node) {
                if let Some(name) = Self::function_name(&func_node, source) {
                    let ts_node = func_node.inner();
                    async_functions.push((name, ts_node.start_position(), ts_node.end_position()));
                }
            }
        }

        // Find async function expressions
        let expr_nodes = tree.find_nodes_by_kind("function_expression");
        for func_node in expr_nodes {
            if Self::is_async_function(&func_node) {
                if let Some(name) = Self::function_name(&func_node, source) {
                    let ts_node = func_node.inner();
                    async_functions.push((name, ts_node.start_position(), ts_node.end_position()));
                }
            }
        }

        // Find async arrow functions
        let arrow_nodes = tree.find_nodes_by_kind("arrow_function");
        for func_node in arrow_nodes {
            if Self::is_async_function(&func_node) {
                let name = Self::function_name(&func_node, source)
                    .unwrap_or_else(|| "anonymous".to_string());
                let ts_node = func_node.inner();
                async_functions.push((name, ts_node.start_position(), ts_node.end_position()));
            }
        }

        async_functions
    }

    /// Find closures (arrow functions and function expressions) in a syntax tree
    pub fn find_closures(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut closures = Vec::new();

        // Find arrow functions
        let arrow_nodes = tree.find_nodes_by_kind("arrow_function");
        for arrow_node in arrow_nodes {
            let name = Self::function_name(&arrow_node, source)
                .unwrap_or_else(|| "anonymous".to_string());
            let ts_node = arrow_node.inner();
            closures.push((name, ts_node.start_position(), ts_node.end_position()));
        }

        // Find function expressions (anonymous functions)
        let expr_nodes = tree.find_nodes_by_kind("function_expression");
        for expr_node in expr_nodes {
            let name = Self::function_name(&expr_node, source)
                .unwrap_or_else(|| "anonymous".to_string());
            let ts_node = expr_node.inner();
            closures.push((name, ts_node.start_position(), ts_node.end_position()));
        }

        closures
    }

    /// Find destructuring patterns in a syntax tree
    pub fn find_destructuring_patterns(tree: &SyntaxTree, _source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut patterns = Vec::new();

        // Find array destructuring patterns
        let array_patterns = tree.find_nodes_by_kind("array_pattern");
        for pattern_node in array_patterns {
            let ts_node = pattern_node.inner();
            if let Ok(pattern_text) = pattern_node.text() {
                patterns.push((
                    format!("array_destructuring: {}", pattern_text.trim()),
                    ts_node.start_position(),
                    ts_node.end_position()
                ));
            }
        }

        // Find object destructuring patterns
        let object_patterns = tree.find_nodes_by_kind("object_pattern");
        for pattern_node in object_patterns {
            let ts_node = pattern_node.inner();
            if let Ok(pattern_text) = pattern_node.text() {
                patterns.push((
                    format!("object_destructuring: {}", pattern_text.trim()),
                    ts_node.start_position(),
                    ts_node.end_position()
                ));
            }
        }

        patterns
    }

    /// Find classes with private fields in a syntax tree
    pub fn find_classes_with_private_fields(tree: &SyntaxTree, source: &str) -> Vec<(String, Vec<String>, tree_sitter::Point, tree_sitter::Point)> {
        let mut classes_with_private = Vec::new();

        let class_nodes = tree.find_nodes_by_kind("class_declaration");
        for class_node in class_nodes {
            if let Some(class_name) = Self::class_name(&class_node, source) {
                let mut private_fields = Vec::new();

                // Look for private field definitions in the class body
                // Find the class_body node first
                for child in class_node.children() {
                    if child.kind() == "class_body" {
                        // Now look for field_definition nodes within the class body
                        for body_child in child.children() {
                            if body_child.kind() == "field_definition" {
                                // Look for private_property_identifier child nodes
                                for field_child in body_child.children() {
                                    if field_child.kind() == "private_property_identifier" {
                                        if let Ok(field_text) = field_child.text() {
                                            private_fields.push(field_text.to_string());
                                        }
                                    }
                                }
                            }
                        }
                        break; // Found the class body, no need to continue
                    }
                }

                if !private_fields.is_empty() {
                    let ts_node = class_node.inner();
                    classes_with_private.push((
                        class_name,
                        private_fields,
                        ts_node.start_position(),
                        ts_node.end_position()
                    ));
                }
            }
        }

        classes_with_private
    }

    /// Create a query to find all function declarations
    pub fn functions_query() -> Result<Query> {
        let query_str = r#"
            (function_declaration
                name: (identifier) @name
            ) @function

            (function_expression
                name: (identifier) @name
            ) @function

            (arrow_function) @function
        "#;
        Query::new(crate::Language::JavaScript, query_str)
    }

    /// Create a query to find all class definitions
    pub fn classes_query() -> Result<Query> {
        let query_str = r#"
            (class_declaration
                name: (identifier) @name
            ) @class

            (class_expression
                name: (identifier) @name
            ) @class
        "#;
        Query::new(crate::Language::JavaScript, query_str)
    }

    /// Create a query to find all method definitions
    pub fn methods_query() -> Result<Query> {
        let query_str = r#"
            (method_definition
                name: (property_identifier) @name
            ) @method
        "#;
        Query::new(crate::Language::JavaScript, query_str)
    }

    /// Create a query to find all variable declarations
    pub fn variables_query() -> Result<Query> {
        let query_str = r#"
            (variable_declaration
                (variable_declarator
                    name: (identifier) @name
                )
            ) @variable
        "#;
        Query::new(crate::Language::JavaScript, query_str)
    }

    /// Create a query to find all import statements
    pub fn imports_query() -> Result<Query> {
        let query_str = r#"
            (import_statement) @import
        "#;
        Query::new(crate::Language::JavaScript, query_str)
    }

    /// Create a query to find all export statements
    pub fn exports_query() -> Result<Query> {
        let query_str = r#"
            (export_statement) @export
            (export_default_declaration) @export
        "#;
        Query::new(crate::Language::JavaScript, query_str)
    }

    /// Create a query to find JSX elements
    pub fn jsx_elements_query() -> Result<Query> {
        let query_str = r#"
            (jsx_element
                open_tag: (jsx_opening_element
                    name: (identifier) @name
                )
            ) @jsx_element

            (jsx_self_closing_element
                name: (identifier) @name
            ) @jsx_element
        "#;
        Query::new(crate::Language::JavaScript, query_str)
    }

    /// Create a query to find async functions
    pub fn async_functions_query() -> Result<Query> {
        let query_str = r#"
            (function_declaration
                "async"
                name: (identifier) @name
            ) @async_function

            (function_expression
                "async"
                name: (identifier) @name
            ) @async_function

            (arrow_function
                "async"
            ) @async_function
        "#;
        Query::new(crate::Language::JavaScript, query_str)
    }

    /// Detect if code uses modern JavaScript features
    pub fn detect_modern_features(tree: &SyntaxTree) -> Vec<String> {
        let mut features = Vec::new();

        // Check for arrow functions
        if !tree.find_nodes_by_kind("arrow_function").is_empty() {
            features.push("Arrow Functions".to_string());
        }

        // Check for template literals
        if !tree.find_nodes_by_kind("template_string").is_empty() {
            features.push("Template Literals".to_string());
        }

        // Check for destructuring
        if !tree.find_nodes_by_kind("destructuring_pattern").is_empty() {
            features.push("Destructuring".to_string());
        }

        // Check for spread syntax
        if !tree.find_nodes_by_kind("spread_element").is_empty() {
            features.push("Spread Syntax".to_string());
        }

        // Check for async/await
        if !tree.find_nodes_by_kind("await_expression").is_empty() {
            features.push("Async/Await".to_string());
        }

        // Check for classes
        if !tree.find_nodes_by_kind("class_declaration").is_empty() {
            features.push("ES6 Classes".to_string());
        }

        // Check for modules
        if !tree.find_nodes_by_kind("import_statement").is_empty()
            || !tree.find_nodes_by_kind("export_statement").is_empty() {
            features.push("ES6 Modules".to_string());
        }

        features
    }

    /// Analyze code complexity for JavaScript
    pub fn analyze_complexity(tree: &SyntaxTree) -> u32 {
        let mut complexity = 1; // Base complexity

        // Count decision points
        complexity += tree.find_nodes_by_kind("if_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("while_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("for_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("for_in_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("switch_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("try_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("catch_clause").len() as u32;
        complexity += tree.find_nodes_by_kind("conditional_expression").len() as u32;

        complexity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;

    #[test]
    fn test_javascript_function_detection() {
        let source = r#"
            function regularFunction() {
                return "hello";
            }

            const arrowFunction = () => {
                return "world";
            };

            async function asyncFunction() {
                await something();
            }
        "#;

        let parser = Parser::new(crate::Language::JavaScript).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let functions = JavaScriptSyntax::find_functions(&tree, source);
        assert_eq!(functions.len(), 3);

        let function_names: Vec<&str> = functions.iter().map(|(name, _, _)| name.as_str()).collect();
        assert!(function_names.contains(&"regularFunction"));
        assert!(function_names.contains(&"arrowFunction"));
        assert!(function_names.contains(&"asyncFunction"));
    }

    #[test]
    fn test_javascript_class_detection() {
        let source = r#"
            class MyClass {
                constructor() {}

                method() {
                    return "test";
                }
            }

            const AnotherClass = class {
                anotherMethod() {}
            };
        "#;

        let parser = Parser::new(crate::Language::JavaScript).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let classes = JavaScriptSyntax::find_classes(&tree, source);
        assert_eq!(classes.len(), 1); // Only named classes are found
        assert_eq!(classes[0].0, "MyClass");
    }

    #[test]
    fn test_modern_features_detection() {
        let source = r#"
            const arrow = () => {};
            const template = `Hello ${name}`;
            const [a, b] = array;
            const obj = { ...other };

            async function test() {
                await promise;
            }
        "#;

        let parser = Parser::new(crate::Language::JavaScript).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let features = JavaScriptSyntax::detect_modern_features(&tree);
        assert!(features.contains(&"Arrow Functions".to_string()));
        assert!(features.contains(&"Template Literals".to_string()));
        assert!(features.contains(&"Async/Await".to_string()));
    }

    #[test]
    fn test_complexity_analysis() {
        let source = r#"
            function complexFunction(x) {
                if (x > 0) {
                    for (let i = 0; i < x; i++) {
                        if (i % 2 === 0) {
                            try {
                                doSomething();
                            } catch (e) {
                                handleError();
                            }
                        }
                    }
                } else {
                    while (x < 0) {
                        x++;
                    }
                }
                return x > 10 ? "high" : "low";
            }
        "#;

        let parser = Parser::new(crate::Language::JavaScript).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let complexity = JavaScriptSyntax::analyze_complexity(&tree);
        assert!(complexity > 5); // Should detect multiple decision points
    }
}
