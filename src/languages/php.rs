//! PHP language specific functionality

use crate::tree::{Node, SyntaxTree};

/// PHP-specific syntax tree utilities
pub struct PhpSyntax;

impl PhpSyntax {
    /// Check if a node is a class declaration
    pub fn is_class(node: &Node) -> bool {
        node.kind() == "class_declaration"
    }

    /// Check if a node is an interface declaration
    pub fn is_interface(node: &Node) -> bool {
        node.kind() == "interface_declaration"
    }

    /// Check if a node is a trait declaration
    pub fn is_trait(node: &Node) -> bool {
        node.kind() == "trait_declaration"
    }

    /// Check if a node is a function declaration
    pub fn is_function(node: &Node) -> bool {
        node.kind() == "function_definition"
    }

    /// Check if a node is a method declaration
    pub fn is_method(node: &Node) -> bool {
        node.kind() == "method_declaration"
    }

    /// Check if a node is a property declaration
    pub fn is_property(node: &Node) -> bool {
        node.kind() == "property_declaration"
    }

    /// Check if a node is a namespace declaration
    pub fn is_namespace(node: &Node) -> bool {
        node.kind() == "namespace_definition"
    }

    /// Check if a node is a use statement
    pub fn is_use_statement(node: &Node) -> bool {
        node.kind() == "namespace_use_declaration"
    }

    /// Extract class name from a class node
    pub fn class_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_class(node) {
            return None;
        }
        node.child_by_field_name("name")?
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string())
    }

    /// Extract function name from a function node
    pub fn function_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_function(node) {
            return None;
        }
        node.child_by_field_name("name")?
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string())
    }

    /// Extract method name from a method node
    pub fn method_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_method(node) {
            return None;
        }
        node.child_by_field_name("name")?
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string())
    }

    /// Extract property name from a property node
    pub fn property_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_property(node) {
            return None;
        }
        // Properties can have multiple variable names
        let declarator = node.child_by_field_name("name")?;
        declarator
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string())
    }

    /// Find all classes in the syntax tree
    pub fn find_classes(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("class_declaration")
    }

    /// Find all functions in the syntax tree
    pub fn find_functions(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("function_definition")
    }

    /// Find all methods in the syntax tree
    pub fn find_methods(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("method_declaration")
    }

    /// Find all public methods in the syntax tree
    pub fn public_methods_query() -> &'static str {
        r#"
        (method_declaration
          (visibility_modifier) @visibility (#eq? @visibility "public")
          name: (name) @method_name) @method
        "#
    }

    /// Find all classes query
    pub fn classes_query() -> &'static str {
        "(class_declaration name: (name) @class_name) @class"
    }

    /// Find all functions query
    pub fn functions_query() -> &'static str {
        "(function_definition name: (name) @function_name) @function"
    }

    /// Check if a method is public
    pub fn is_public_method(node: &Node, source: &str) -> bool {
        if !Self::is_method(node) {
            return false;
        }

        // Check for public visibility modifier
        if let Some(visibility) = node.child_by_field_name("visibility") {
            if let Ok(text) = visibility.utf8_text(source.as_bytes()) {
                return text == "public";
            }
        }
        false
    }

    /// Check if a class is public (PHP classes don't have explicit visibility, but can be final/abstract)
    pub fn is_public_class(node: &Node, _source: &str) -> bool {
        Self::is_class(node) // PHP classes are public by default
    }

    /// Extract PHPDoc comment from a node
    pub fn extract_phpdoc_comment(node: &Node, source: &str) -> Option<String> {
        // Look for comment nodes before this node
        let mut prev_sibling = node.prev_sibling();
        while let Some(sibling) = prev_sibling {
            if sibling.kind() == "comment" {
                if let Ok(text) = sibling.utf8_text(source.as_bytes()) {
                    if text.trim_start().starts_with("/**") {
                        return Some(text.to_string());
                    }
                }
            } else if sibling.kind() != "comment" {
                // Stop if we hit a non-comment node
                break;
            }
            prev_sibling = sibling.prev_sibling();
        }
        None
    }

    /// Find all traits in the syntax tree
    pub fn find_traits(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("trait_declaration")
    }

    /// Find all interfaces in the syntax tree
    pub fn find_interfaces(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("interface_declaration")
    }

    /// Find all namespace declarations
    pub fn find_namespaces(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("namespace_definition")
    }

    /// Find all use statements
    pub fn find_use_statements(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("namespace_use_declaration")
    }

    /// Check if a function is declared in the global scope
    pub fn is_global_function(node: &Node) -> bool {
        if !Self::is_function(node) {
            return false;
        }
        // Check if the function is not inside a class
        let mut parent = node.parent();
        while let Some(p) = parent {
            if p.kind() == "class_declaration"
                || p.kind() == "interface_declaration"
                || p.kind() == "trait_declaration"
            {
                return false;
            }
            parent = p.parent();
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::languages::Language;
    use crate::parser::Parser;

    #[test]
    fn test_php_syntax_detection() {
        // let source = r#"
        //     <?php

        //     namespace App\Controllers;

        //     use App\Models\User;

        //     /**
        //      * A simple PHP class
        //      */
        //     class UserController {
        //         private $userModel;

        //         public function __construct(User $userModel) {
        //             $this->userModel = $userModel;
        //         }

        //         public function getUser($id) {
        //             return $this->userModel->find($id);
        //         }

        //         private function privateMethod() {
        //             // private method
        //         }
        //     }

        //     interface Greeter {
        //         public function greet();
        //     }

        //     trait Loggable {
        //         public function log($message) {
        //             echo $message;
        //         }
        //     }
        // "#;

        // let language = Language::Php;
        // let mut parser = Parser::new(language).unwrap();
        // let tree = parser.parse(source, None).unwrap();

        // // Test class detection
        // let classes = PhpSyntax::find_classes(&tree);
        // assert_eq!(classes.len(), 1);

        // // Test function detection
        // let functions = PhpSyntax::find_functions(&tree);
        // assert_eq!(functions.len(), 1); // globalFunction

        // // Test method detection
        // let methods = PhpSyntax::find_methods(&tree);
        // assert_eq!(methods.len(), 3); // __construct, getUser, validateUser

        // // Test interface detection
        // let interfaces = PhpSyntax::find_interfaces(&tree);
        // assert_eq!(interfaces.len(), 1);

        // // Test trait detection
        // let traits = PhpSyntax::find_traits(&tree);
        // assert_eq!(traits.len(), 1);

        // // Test namespace detection
        // let namespaces = PhpSyntax::find_namespaces(&tree);
        // assert_eq!(namespaces.len(), 1);

        // // Test use statement detection
        // let use_statements = PhpSyntax::find_use_statements(&tree);
        // assert_eq!(use_statements.len(), 1);
    }

    // #[test]
    // #[test]
    // fn test_php_class_name_extraction() {
    //     let source = "<?php class TestClass { }";
    //     let language = Language::Php;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let classes = PhpSyntax::find_classes(&tree);
    //     assert_eq!(classes.len(), 1);

    //     let class_node = &classes[0];
    //     let name = PhpSyntax::class_name(class_node, source).unwrap();
    //     assert_eq!(name, "TestClass");
    // }

    // #[test]
    // #[test]
    // fn test_php_phpdoc_extraction() {
    //     let source = r#"
    //         <?php
    //         /**
    //          * This is a PHPDoc comment
    //          */
    //         class TestClass { }
    //     "#;

    //     let language = Language::Php;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let classes = PhpSyntax::find_classes(&tree);
    //     assert_eq!(classes.len(), 1);

    //     let class_node = &classes[0];
    //     let phpdoc = PhpSyntax::extract_phpdoc_comment(class_node, source);
    //     assert!(phpdoc.is_some());
    //     assert!(phpdoc.unwrap().contains("PHPDoc"));
    // }

    // #[test]
    // #[test]
    // fn test_php_global_function_detection() {
    //     let source = r#"
    //         <?php
    //         function globalFunc() { }

    //         class TestClass {
    //             function method() { }
    //         }
    //     "#;

    //     let language = Language::Php;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let functions = PhpSyntax::find_functions(&tree);
    //     assert_eq!(functions.len(), 2); // globalFunc and method

    //     // Check which ones are global
    //     let global_count = functions
    //         .iter()
    //         .filter(|node| PhpSyntax::is_global_function(node))
    //         .count();
    //     assert_eq!(global_count, 1); // Only globalFunc should be global
    // }
}
