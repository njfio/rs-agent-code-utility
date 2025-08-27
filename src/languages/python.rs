//! Python language support for tree-sitter
//!
//! This module provides Python-specific utilities for parsing and analyzing
//! Python source code using tree-sitter.

use crate::error::Result;
use crate::query::Query;
use crate::tree::{Node, SyntaxTree};
use tree_sitter::Point;

/// Python-specific syntax utilities
pub struct PythonSyntax;

impl PythonSyntax {
    /// Check if a node represents a function definition
    pub fn is_function_definition(node: &Node) -> bool {
        node.kind() == "function_definition"
    }

    /// Check if a node represents an async function definition
    pub fn is_async_function_definition(node: &Node) -> bool {
        if !Self::is_function_definition(node) {
            return false;
        }

        for child in node.children() {
            if child.kind() == "async" {
                return true;
            }
        }
        false
    }

    /// Check if a node represents a class definition
    pub fn is_class_definition(node: &Node) -> bool {
        node.kind() == "class_definition"
    }

    /// Check if a node represents a method definition (function inside a class)
    pub fn is_method_definition(node: &Node) -> bool {
        if !Self::is_function_definition(node) {
            return false;
        }

        // Check if the function is inside a class
        let mut current = node.parent();
        while let Some(parent) = current {
            if Self::is_class_definition(&parent) {
                return true;
            }
            current = parent.parent();
        }
        false
    }

    /// Check if a node represents a lambda expression
    pub fn is_lambda(node: &Node) -> bool {
        node.kind() == "lambda"
    }

    /// Check if a node represents an import statement
    pub fn is_import_statement(node: &Node) -> bool {
        matches!(node.kind(), "import_statement" | "import_from_statement")
    }

    /// Check if a node represents a decorator
    pub fn is_decorator(node: &Node) -> bool {
        node.kind() == "decorator"
    }

    /// Check if a node represents a global statement
    pub fn is_global_statement(node: &Node) -> bool {
        node.kind() == "global_statement"
    }

    /// Check if a node represents a nonlocal statement
    pub fn is_nonlocal_statement(node: &Node) -> bool {
        node.kind() == "nonlocal_statement"
    }

    /// Extract function name from a function definition node
    pub fn function_name(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_function_definition(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Extract class name from a class definition node
    pub fn class_name(node: &Node, _source: &str) -> Option<String> {
        if !Self::is_class_definition(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Get function parameters
    pub fn function_parameters(node: &Node, _source: &str) -> Vec<String> {
        if !Self::is_function_definition(node) {
            return Vec::new();
        }

        let mut parameters = Vec::new();
        
        if let Some(params_node) = node.child_by_field_name("parameters") {
            for child in params_node.children() {
                match child.kind() {
                    "identifier" => {
                        if let Ok(param) = child.text() {
                            parameters.push(param.to_string());
                        }
                    }
                    "default_parameter" => {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if let Ok(param) = name_node.text() {
                                parameters.push(param.to_string());
                            }
                        }
                    }
                    "typed_parameter" => {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if let Ok(param) = name_node.text() {
                                parameters.push(param.to_string());
                            }
                        }
                    }
                    "typed_default_parameter" => {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if let Ok(param) = name_node.text() {
                                parameters.push(param.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        parameters
    }

    /// Get class base classes (inheritance)
    pub fn class_bases(node: &Node, _source: &str) -> Vec<String> {
        if !Self::is_class_definition(node) {
            return Vec::new();
        }

        let mut bases = Vec::new();
        
        if let Some(superclasses_node) = node.child_by_field_name("superclasses") {
            for child in superclasses_node.children() {
                if child.kind() == "identifier" {
                    if let Ok(base) = child.text() {
                        bases.push(base.to_string());
                    }
                } else if child.kind() == "attribute" {
                    if let Ok(base) = child.text() {
                        bases.push(base.to_string());
                    }
                }
            }
        }

        bases
    }

    /// Get decorators applied to a function or class
    pub fn get_decorators(node: &Node, _source: &str) -> Vec<String> {
        let mut decorators = Vec::new();

        // Check if this function is inside a decorated_definition
        if let Some(parent) = node.parent() {
            if parent.kind() == "decorated_definition" {
                // Look for decorator children in the parent
                for child in parent.children() {
                    if Self::is_decorator(&child) {
                        if let Ok(decorator_text) = child.text() {
                            decorators.push(decorator_text.to_string());
                        }
                    }
                }
            }
        }

        // Also check direct children (in case structure is different)
        for child in node.children() {
            if Self::is_decorator(&child) {
                if let Ok(decorator_text) = child.text() {
                    decorators.push(decorator_text.to_string());
                }
            }
        }

        decorators
    }

    /// Check if a function is a special method (dunder method)
    pub fn is_special_method(node: &Node, source: &str) -> bool {
        if let Some(name) = Self::function_name(node, source) {
            return name.starts_with("__") && name.ends_with("__");
        }
        false
    }

    /// Check if a function is a property (has @property decorator)
    pub fn is_property(node: &Node, source: &str) -> bool {
        let decorators = Self::get_decorators(node, source);
        decorators.iter().any(|d| d.contains("@property"))
    }

    /// Check if a function is a static method
    pub fn is_static_method(node: &Node, source: &str) -> bool {
        let decorators = Self::get_decorators(node, source);
        decorators.iter().any(|d| d.contains("@staticmethod"))
    }

    /// Check if a function is a class method
    pub fn is_class_method(node: &Node, source: &str) -> bool {
        let decorators = Self::get_decorators(node, source);
        decorators.iter().any(|d| d.contains("@classmethod"))
    }

    /// Get docstring from a function or class
    pub fn get_docstring(node: &Node, _source: &str) -> Option<String> {
        if let Some(body_node) = node.child_by_field_name("body") {
            for child in body_node.children() {
                if child.kind() == "expression_statement" {
                    for expr_child in child.children() {
                        if expr_child.kind() == "string" {
                            if let Ok(docstring) = expr_child.text() {
                                // Remove quotes and clean up
                                let cleaned = docstring.trim_matches('"').trim_matches('\'');
                                return Some(cleaned.to_string());
                            }
                        }
                    }
                }
            }
        }
        None
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

    /// Get all class definitions in a syntax tree with start and end positions
    pub fn find_classes(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut classes = Vec::new();
        let class_nodes = tree.find_nodes_by_kind("class_definition");

        for class_node in class_nodes {
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

        let import_from_nodes = tree.find_nodes_by_kind("import_from_statement");
        for import_node in import_from_nodes {
            if let Ok(import_text) = import_node.text() {
                imports.push(import_text.to_string());
            }
        }

        imports
    }

    /// Get all global variables in a syntax tree
    pub fn find_global_variables(tree: &SyntaxTree, _source: &str) -> Vec<(String, tree_sitter::Point)> {
        let mut globals = Vec::new();

        // Find assignment statements at module level
        let assignment_nodes = tree.find_nodes_by_kind("assignment");
        for assign_node in assignment_nodes {
            // Check if it's at module level (not inside function/class)
            let mut is_global = true;
            let mut current = assign_node.parent();

            while let Some(parent) = current {
                if Self::is_function_definition(&parent) || Self::is_class_definition(&parent) {
                    is_global = false;
                    break;
                }
                current = parent.parent();
            }

            if is_global {
                if let Some(left_node) = assign_node.child_by_field_name("left") {
                    if left_node.kind() == "identifier" {
                        if let Ok(var_name) = left_node.text() {
                            globals.push((var_name.to_string(), assign_node.start_position()));
                        }
                    }
                }
            }
        }

        globals
    }

    /// Create a query to find all function definitions
    pub fn functions_query() -> Result<Query> {
        let query_str = r#"
            (function_definition
                name: (identifier) @name
            ) @function
        "#;
        Query::new(crate::Language::Python, query_str)
    }

    /// Create a query to find all class definitions
    pub fn classes_query() -> Result<Query> {
        let query_str = r#"
            (class_definition
                name: (identifier) @name
            ) @class
        "#;
        Query::new(crate::Language::Python, query_str)
    }

    /// Create a query to find all method definitions
    pub fn methods_query() -> Result<Query> {
        let query_str = r#"
            (class_definition
                body: (block
                    (function_definition
                        name: (identifier) @name
                    ) @method
                )
            )
        "#;
        Query::new(crate::Language::Python, query_str)
    }

    /// Create a query to find all import statements
    pub fn imports_query() -> Result<Query> {
        let query_str = r#"
            (import_statement) @import
            (import_from_statement) @import
        "#;
        Query::new(crate::Language::Python, query_str)
    }

    /// Create a query to find all decorators
    pub fn decorators_query() -> Result<Query> {
        let query_str = r#"
            (decorator) @decorator
        "#;
        Query::new(crate::Language::Python, query_str)
    }

    /// Create a query to find all async functions
    pub fn async_functions_query() -> Result<Query> {
        let query_str = r#"
            (function_definition
                "async"
                name: (identifier) @name
            ) @async_function
        "#;
        Query::new(crate::Language::Python, query_str)
    }

    /// Detect Python-specific features
    pub fn detect_python_features(tree: &SyntaxTree) -> Vec<String> {
        let mut features = Vec::new();

        // Check for async/await
        if !tree.find_nodes_by_kind("async").is_empty()
            || !tree.find_nodes_by_kind("await").is_empty() {
            features.push("Async/Await".to_string());
        }

        // Check for decorators
        if !tree.find_nodes_by_kind("decorator").is_empty() {
            features.push("Decorators".to_string());
        }

        // Check for list comprehensions
        if !tree.find_nodes_by_kind("list_comprehension").is_empty() {
            features.push("List Comprehensions".to_string());
        }

        // Check for dictionary comprehensions
        if !tree.find_nodes_by_kind("dictionary_comprehension").is_empty() {
            features.push("Dictionary Comprehensions".to_string());
        }

        // Check for set comprehensions
        if !tree.find_nodes_by_kind("set_comprehension").is_empty() {
            features.push("Set Comprehensions".to_string());
        }

        // Check for generator expressions
        if !tree.find_nodes_by_kind("generator_expression").is_empty() {
            features.push("Generator Expressions".to_string());
        }

        // Check for f-strings (try multiple possible node types)
        if !tree.find_nodes_by_kind("formatted_string").is_empty()
            || !tree.find_nodes_by_kind("f_string").is_empty()
            || !tree.find_nodes_by_kind("string").is_empty() && tree.root_node().text().unwrap_or("").contains("f\"") {
            features.push("F-strings".to_string());
        }

        // Check for type hints
        if !tree.find_nodes_by_kind("type").is_empty() {
            features.push("Type Hints".to_string());
        }

        // Check for context managers (with statements)
        if !tree.find_nodes_by_kind("with_statement").is_empty() {
            features.push("Context Managers".to_string());
        }

        // Check for lambda expressions
        if !tree.find_nodes_by_kind("lambda").is_empty() {
            features.push("Lambda Expressions".to_string());
        }

        features
    }

    /// Analyze Python code complexity
    pub fn analyze_complexity(tree: &SyntaxTree) -> u32 {
        let mut complexity = 1; // Base complexity

        // Count decision points
        complexity += tree.find_nodes_by_kind("if_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("while_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("for_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("try_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("except_clause").len() as u32;
        complexity += tree.find_nodes_by_kind("with_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("conditional_expression").len() as u32;

        // Add Python-specific complexity
        complexity += tree.find_nodes_by_kind("list_comprehension").len() as u32;
        complexity += tree.find_nodes_by_kind("dictionary_comprehension").len() as u32;
        complexity += tree.find_nodes_by_kind("set_comprehension").len() as u32;
        complexity += tree.find_nodes_by_kind("generator_expression").len() as u32;

        complexity
    }

    /// Check if code follows PEP 8 naming conventions
    pub fn check_naming_conventions(tree: &SyntaxTree, source: &str) -> Vec<String> {
        let mut violations = Vec::new();

        // Check function names (should be snake_case)
        let functions = Self::find_functions(tree, source);
        for (name, _, _) in functions {
            if !Self::is_snake_case(&name) && !Self::is_special_method_name(&name) {
                violations.push(format!("Function '{}' should use snake_case", name));
            }
        }

        // Check class names (should be PascalCase)
        let classes = Self::find_classes(tree, source);
        for (name, _, _) in classes {
            if !Self::is_pascal_case(&name) {
                violations.push(format!("Class '{}' should use PascalCase", name));
            }
        }

        violations
    }

    /// Check if a string is in snake_case
    fn is_snake_case(s: &str) -> bool {
        s.chars().all(|c| c.is_lowercase() || c.is_numeric() || c == '_')
            && !s.starts_with('_')
            && !s.ends_with('_')
            && !s.contains("__")
    }

    /// Check if a string is in PascalCase
    fn is_pascal_case(s: &str) -> bool {
        !s.is_empty()
            && s.chars().next().unwrap().is_uppercase()
            && s.chars().all(|c| c.is_alphanumeric())
            && !s.contains('_')
    }

    /// Check if a function name is a special method (dunder method)
    fn is_special_method_name(s: &str) -> bool {
        s.starts_with("__") && s.ends_with("__")
    }

    /// Get method resolution order for a class
    pub fn get_method_resolution_order(class_node: &Node, source: &str, _tree: &SyntaxTree) -> Vec<String> {
        let mut mro = Vec::new();

        if let Some(class_name) = Self::class_name(class_node, source) {
            mro.push(class_name.clone());

            // Add base classes
            let bases = Self::class_bases(class_node, source);
            for base in bases {
                mro.push(base);
            }
        }

        mro
    }

    /// Find all methods in a class
    pub fn find_class_methods(class_node: &Node, source: &str) -> Vec<(String, Point)> {
        let mut methods = Vec::new();

        if let Some(body_node) = class_node.child_by_field_name("body") {
            for child in body_node.children() {
                if Self::is_function_definition(&child) {
                    if let Some(name) = Self::function_name(&child, source) {
                        methods.push((name, child.start_position()));
                    }
                }
            }
        }

        methods
    }

    /// Check if a function has type hints
    pub fn has_type_hints(node: &Node) -> bool {
        if !Self::is_function_definition(node) {
            return false;
        }

        // Check parameters for type annotations
        if let Some(params_node) = node.child_by_field_name("parameters") {
            for child in params_node.children() {
                if child.kind() == "typed_parameter" || child.kind() == "typed_default_parameter" {
                    return true;
                }
            }
        }

        // Check return type annotation
        node.child_by_field_name("return_type").is_some()
    }

    /// Extract docstring for a symbol
    pub fn extract_docstring(name: &str, content: &str) -> Option<String> {
        let lines: Vec<&str> = content.lines().collect();

        // Find the line with the symbol definition
        for (i, line) in lines.iter().enumerate() {
            if line.contains(&format!("def {}", name)) || line.contains(&format!("class {}", name)) {
                // Look for docstring in the next few lines
                let mut j = i + 1;

                // Skip empty lines and find the opening of the function/class body
                while j < lines.len() {
                    let next_line = lines[j].trim();
                    if next_line.is_empty() {
                        j += 1;
                        continue;
                    }

                    // Check for docstring (triple quotes)
                    if next_line.starts_with("\"\"\"") || next_line.starts_with("'''") {
                        let quote_type = if next_line.starts_with("\"\"\"") { "\"\"\"" } else { "'''" };
                        let mut docstring = String::new();

                        // Single line docstring
                        if next_line.ends_with(quote_type) && next_line.len() > 6 {
                            let content = next_line.trim_start_matches(quote_type).trim_end_matches(quote_type);
                            return Some(content.trim().to_string());
                        }

                        // Multi-line docstring
                        let start_content = next_line.trim_start_matches(quote_type);
                        if !start_content.is_empty() {
                            docstring.push_str(start_content);
                        }

                        j += 1;
                        while j < lines.len() {
                            let doc_line = lines[j];
                            if doc_line.contains(quote_type) {
                                let end_content = doc_line.split(quote_type).next().unwrap_or("");
                                if !end_content.is_empty() {
                                    if !docstring.is_empty() {
                                        docstring.push(' ');
                                    }
                                    docstring.push_str(end_content.trim());
                                }
                                break;
                            } else {
                                if !docstring.is_empty() {
                                    docstring.push(' ');
                                }
                                docstring.push_str(doc_line.trim());
                            }
                            j += 1;
                        }

                        if !docstring.is_empty() {
                            return Some(docstring.trim().to_string());
                        }
                    }
                    break;
                }
                break;
            }
        }

        None
    }

    /// Find methods within classes
    pub fn find_methods(tree: &SyntaxTree, _content: &str) -> Vec<(String, String, tree_sitter::Point)> {
        let mut methods = Vec::new();

        // Find all class definitions
        let class_nodes = tree.find_nodes_by_kind("class_definition");
        for class_node in class_nodes {
            if let Some(class_name_node) = class_node.child_by_field_name("name") {
                if let Ok(class_name) = class_name_node.text() {
                    // Find function definitions within this class
                    let mut cursor = class_node.walk();
                    if cursor.goto_first_child() {
                        loop {
                            let node = cursor.node();
                            if node.kind() == "function_definition" {
                                if let Some(method_name_node) = node.child_by_field_name("name") {
                                    if let Ok(method_name) = method_name_node.text() {
                                        methods.push((
                                            class_name.to_string(),
                                            method_name.to_string(),
                                            node.start_position()
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

        methods
    }

    /// Find async functions in a syntax tree
    pub fn find_async_functions(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut async_functions = Vec::new();
        let function_nodes = tree.find_nodes_by_kind("function_definition");

        for func_node in function_nodes {
            // Check if function has 'async' keyword as a child node
            let mut cursor = func_node.walk();
            if cursor.goto_first_child() {
                loop {
                    let node = cursor.node();
                    if node.kind() == "async" {
                        if let Some(name) = Self::function_name(&func_node, source) {
                            let ts_node = func_node.inner();
                            async_functions.push((name, ts_node.start_position(), ts_node.end_position()));
                        }
                        break;
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        async_functions
    }

    /// Find context managers (with statements) in a syntax tree
    pub fn find_context_managers(tree: &SyntaxTree, _source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut context_managers = Vec::new();
        let with_nodes = tree.find_nodes_by_kind("with_statement");

        for with_node in with_nodes {
            let ts_node = with_node.inner();
            if let Ok(with_text) = with_node.text() {
                // Extract the context manager expression
                let context_expr = with_text.lines().next()
                    .unwrap_or("")
                    .trim_start_matches("with ")
                    .trim_end_matches(":")
                    .trim();

                context_managers.push((
                    format!("context_manager: {}", context_expr),
                    ts_node.start_position(),
                    ts_node.end_position()
                ));
            }
        }

        context_managers
    }

    /// Find classes with metaclasses in a syntax tree
    pub fn find_metaclasses(tree: &SyntaxTree, source: &str) -> Vec<(String, String, tree_sitter::Point, tree_sitter::Point)> {
        let mut metaclasses = Vec::new();
        let class_nodes = tree.find_nodes_by_kind("class_definition");

        for class_node in class_nodes {
            if let Some(class_name) = Self::class_name(&class_node, source) {
                // Check for metaclass in class arguments
                if let Some(args_node) = class_node.child_by_field_name("superclasses") {
                    if let Ok(args_text) = args_node.text() {
                        if args_text.contains("metaclass=") {
                            // Extract metaclass name
                            if let Some(metaclass_start) = args_text.find("metaclass=") {
                                let metaclass_part = &args_text[metaclass_start + 10..];
                                let metaclass_name = metaclass_part
                                    .split(&[',', ')', ' '][..])
                                    .next()
                                    .unwrap_or("")
                                    .trim();

                                let ts_node = class_node.inner();
                                metaclasses.push((
                                    class_name,
                                    metaclass_name.to_string(),
                                    ts_node.start_position(),
                                    ts_node.end_position()
                                ));
                            }
                        }
                    }
                }
            }
        }

        metaclasses
    }

    /// Find dataclasses in a syntax tree
    pub fn find_dataclasses(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut dataclasses = Vec::new();
        let class_nodes = tree.find_nodes_by_kind("class_definition");

        for class_node in class_nodes {
            // Check if class has @dataclass decorator
            let decorators = Self::get_decorators(&class_node, source);
            let has_dataclass = decorators.iter().any(|d|
                d.contains("@dataclass") || d.contains("@dataclasses.dataclass")
            );

            if has_dataclass {
                if let Some(class_name) = Self::class_name(&class_node, source) {
                    let ts_node = class_node.inner();
                    dataclasses.push((class_name, ts_node.start_position(), ts_node.end_position()));
                }
            }
        }

        dataclasses
    }

    /// Find functions with comprehensive type hints
    pub fn find_typed_functions(tree: &SyntaxTree, source: &str) -> Vec<(String, Vec<String>, Option<String>, tree_sitter::Point, tree_sitter::Point)> {
        let mut typed_functions = Vec::new();
        let function_nodes = tree.find_nodes_by_kind("function_definition");

        for func_node in function_nodes {
            if Self::has_type_hints(&func_node) {
                if let Some(name) = Self::function_name(&func_node, source) {
                    let mut param_types = Vec::new();
                    let mut return_type = None;

                    // Extract parameter types
                    if let Some(params_node) = func_node.child_by_field_name("parameters") {
                        for child in params_node.children() {
                            if child.kind() == "typed_parameter" || child.kind() == "typed_default_parameter" {
                                if let Some(type_node) = child.child_by_field_name("type") {
                                    if let Ok(type_text) = type_node.text() {
                                        param_types.push(type_text.to_string());
                                    }
                                }
                            }
                        }
                    }

                    // Extract return type
                    if let Some(return_node) = func_node.child_by_field_name("return_type") {
                        if let Ok(return_text) = return_node.text() {
                            return_type = Some(return_text.trim_start_matches("->").trim().to_string());
                        }
                    }

                    let ts_node = func_node.inner();
                    typed_functions.push((
                        name,
                        param_types,
                        return_type,
                        ts_node.start_position(),
                        ts_node.end_position()
                    ));
                }
            }
        }

        typed_functions
    }

    /// Find property decorators (like @property, @staticmethod, @classmethod)
    pub fn find_property_decorators(tree: &SyntaxTree, source: &str) -> Vec<(String, String, tree_sitter::Point, tree_sitter::Point)> {
        let mut property_decorators = Vec::new();
        let function_nodes = tree.find_nodes_by_kind("function_definition");

        for func_node in function_nodes {
            let decorators = Self::get_decorators(&func_node, source);
            let property_decorators_list = decorators.iter()
                .filter(|d| d.contains("@property") || d.contains("@staticmethod") || d.contains("@classmethod"))
                .collect::<Vec<_>>();

            if !property_decorators_list.is_empty() {
                if let Some(func_name) = Self::function_name(&func_node, source) {
                    for decorator in property_decorators_list {
                        let ts_node = func_node.inner();
                        property_decorators.push((
                            func_name.clone(),
                            decorator.clone(),
                            ts_node.start_position(),
                            ts_node.end_position()
                        ));
                    }
                }
            }
        }

        property_decorators
    }

    /// Find lambda functions in a syntax tree
    pub fn find_lambda_functions(tree: &SyntaxTree, _source: &str) -> Vec<(String, tree_sitter::Point, tree_sitter::Point)> {
        let mut lambdas = Vec::new();
        let lambda_nodes = tree.find_nodes_by_kind("lambda");

        for (index, lambda_node) in lambda_nodes.iter().enumerate() {
            let ts_node = lambda_node.inner();
            if let Ok(lambda_text) = lambda_node.text() {
                lambdas.push((
                    format!("lambda_{}: {}", index, lambda_text.trim()),
                    ts_node.start_position(),
                    ts_node.end_position()
                ));
            }
        }

        lambdas
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;

    #[test]
    fn test_python_function_detection() {
        let source = r#"
def regular_function():
    return "hello"

async def async_function():
    await something()

def function_with_params(a, b, c=None):
    return a + b
        "#;

        let parser = Parser::new(crate::Language::Python).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let functions = PythonSyntax::find_functions(&tree, source);
        assert_eq!(functions.len(), 3);

        let function_names: Vec<&str> = functions.iter().map(|(name, _, _)| name.as_str()).collect();
        assert!(function_names.contains(&"regular_function"));
        assert!(function_names.contains(&"async_function"));
        assert!(function_names.contains(&"function_with_params"));
    }

    #[test]
    fn test_python_class_detection() {
        let source = r#"
class MyClass:
    def __init__(self):
        self.value = 0

    def method(self):
        return self.value

class InheritedClass(MyClass):
    def another_method(self):
        pass
        "#;

        let parser = Parser::new(crate::Language::Python).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let classes = PythonSyntax::find_classes(&tree, source);
        assert_eq!(classes.len(), 2);

        let class_names: Vec<&str> = classes.iter().map(|(name, _, _)| name.as_str()).collect();
        assert!(class_names.contains(&"MyClass"));
        assert!(class_names.contains(&"InheritedClass"));
    }

    #[test]
    fn test_python_decorators() {
        let source = r#"
@property
def my_property(self):
    return self._value

@staticmethod
def static_method():
    return "static"

@classmethod
def class_method(cls):
    return cls()
        "#;

        let parser = Parser::new(crate::Language::Python).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let function_nodes = tree.find_nodes_by_kind("function_definition");
        assert_eq!(function_nodes.len(), 3);

        // Check decorators
        let decorators = PythonSyntax::get_decorators(&function_nodes[0], source);
        assert!(!decorators.is_empty());
        assert!(decorators[0].contains("@property"));
    }

    #[test]
    fn test_python_features_detection() {
        let source = r#"
async def async_func():
    await something()

@decorator
def decorated_func():
    pass

numbers = [x for x in range(10)]
squares = {x: x**2 for x in range(5)}
unique = {x for x in numbers}
gen = (x for x in range(3))

name = "world"
greeting = f"Hello, {name}!"

with open("file.txt") as f:
    content = f.read()

lambda_func = lambda x: x * 2
        "#;

        let parser = Parser::new(crate::Language::Python).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let features = PythonSyntax::detect_python_features(&tree);
        assert!(features.contains(&"Async/Await".to_string()));
        assert!(features.contains(&"Decorators".to_string()));
        assert!(features.contains(&"List Comprehensions".to_string()));
        assert!(features.contains(&"Dictionary Comprehensions".to_string()));
        assert!(features.contains(&"Set Comprehensions".to_string()));
        assert!(features.contains(&"Generator Expressions".to_string()));
        assert!(features.contains(&"F-strings".to_string()));
        assert!(features.contains(&"Context Managers".to_string()));
        assert!(features.contains(&"Lambda Expressions".to_string()));
    }

    #[test]
    fn test_function_parameters() {
        let source = r#"
def complex_function(a, b, c=None, *args, **kwargs):
    return a + b
        "#;

        let parser = Parser::new(crate::Language::Python).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let function_nodes = tree.find_nodes_by_kind("function_definition");
        assert!(!function_nodes.is_empty());

        let params = PythonSyntax::function_parameters(&function_nodes[0], source);
        assert!(params.len() >= 3); // At least a, b, c
        assert!(params.contains(&"a".to_string()));
        assert!(params.contains(&"b".to_string()));
        assert!(params.contains(&"c".to_string()));
    }

    #[test]
    fn test_class_inheritance() {
        let source = r#"
class Parent:
    pass

class Child(Parent):
    pass

class MultipleInheritance(Parent, object):
    pass
        "#;

        let parser = Parser::new(crate::Language::Python).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let class_nodes = tree.find_nodes_by_kind("class_definition");
        assert_eq!(class_nodes.len(), 3);

        // Check inheritance
        let child_bases = PythonSyntax::class_bases(&class_nodes[1], source);
        assert_eq!(child_bases.len(), 1);
        assert_eq!(child_bases[0], "Parent");

        let multiple_bases = PythonSyntax::class_bases(&class_nodes[2], source);
        assert_eq!(multiple_bases.len(), 2);
        assert!(multiple_bases.contains(&"Parent".to_string()));
        assert!(multiple_bases.contains(&"object".to_string()));
    }

    #[test]
    fn test_naming_conventions() {
        let source = r#"
def good_function_name():
    pass

def BadFunctionName():  # Should be snake_case
    pass

class GoodClassName:
    pass

class bad_class_name:  # Should be PascalCase
    pass
        "#;

        let parser = Parser::new(crate::Language::Python).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let violations = PythonSyntax::check_naming_conventions(&tree, source);
        assert_eq!(violations.len(), 2);
        assert!(violations.iter().any(|v| v.contains("BadFunctionName")));
        assert!(violations.iter().any(|v| v.contains("bad_class_name")));
    }

    #[test]
    fn test_special_methods() {
        let source = r#"
class MyClass:
    def __init__(self):
        pass

    def __str__(self):
        return "MyClass"

    def regular_method(self):
        pass
        "#;

        let parser = Parser::new(crate::Language::Python).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let class_nodes = tree.find_nodes_by_kind("class_definition");
        assert!(!class_nodes.is_empty());

        let methods = PythonSyntax::find_class_methods(&class_nodes[0], source);
        assert_eq!(methods.len(), 3);

        // Check for special methods
        let method_names: Vec<&str> = methods.iter().map(|(name, _)| name.as_str()).collect();
        assert!(method_names.contains(&"__init__"));
        assert!(method_names.contains(&"__str__"));
        assert!(method_names.contains(&"regular_method"));
    }
}
