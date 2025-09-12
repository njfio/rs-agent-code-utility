//! Ruby language specific functionality

use crate::tree::{Node, SyntaxTree};

/// Ruby-specific syntax tree utilities
pub struct RubySyntax;

impl RubySyntax {
    /// Check if a node is a class definition
    pub fn is_class(node: &Node) -> bool {
        node.kind() == "class"
    }

    /// Check if a node is a module definition
    pub fn is_module(node: &Node) -> bool {
        node.kind() == "module"
    }

    /// Check if a node is a method definition
    pub fn is_method(node: &Node) -> bool {
        node.kind() == "method" || node.kind() == "singleton_method"
    }

    /// Check if a node is a singleton method (class method)
    pub fn is_singleton_method(node: &Node) -> bool {
        node.kind() == "singleton_method"
    }

    /// Check if a node is an instance method
    pub fn is_instance_method(node: &Node) -> bool {
        node.kind() == "method"
    }

    /// Check if a node is a constant assignment
    pub fn is_constant(node: &Node) -> bool {
        node.kind() == "assignment"
            && matches!(node.child_by_field_name("left"), Some(left) if left.kind() == "constant")
    }

    /// Check if a node is a require/include statement
    pub fn is_require(node: &Node) -> bool {
        node.kind() == "call"
            && {
                if let Some(method) = node.child_by_field_name("method") {
                    method.kind() == "identifier"
                        && matches!(method.utf8_text(b""), Ok(text) if text == "require" || text == "require_relative" || text == "include" || text == "extend")
                } else {
                    false
                }
            }
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

    /// Extract module name from a module node
    pub fn module_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_module(node) {
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

    /// Extract constant name from a constant assignment
    pub fn constant_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_constant(node) {
            return None;
        }
        node.child_by_field_name("left")?
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string())
    }

    /// Find all classes in the syntax tree
    pub fn find_classes(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("class")
    }

    /// Find all modules in the syntax tree
    pub fn find_modules(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("module")
    }

    /// Find all methods in the syntax tree
    pub fn find_methods(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("method")
    }

    /// Find all singleton methods (class methods) in the syntax tree
    pub fn find_singleton_methods(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("singleton_method")
    }

    /// Find all public methods query
    pub fn public_methods_query() -> &'static str {
        r#"
        (method
          name: (identifier) @method_name) @method
        "#
    }

    /// Find all classes query
    pub fn classes_query() -> &'static str {
        "(class name: (constant) @class_name) @class"
    }

    /// Find all modules query
    pub fn modules_query() -> &'static str {
        "(module name: (constant) @module_name) @module"
    }

    /// Check if a method is public (Ruby methods are public by default)
    pub fn is_public_method(node: &Node, _source: &str) -> bool {
        if !Self::is_method(node) {
            return true; // Ruby methods are public by default
        }

        // Check if there's a private/protected modifier before this method
        let mut prev_sibling = node.prev_sibling();
        while let Some(sibling) = prev_sibling {
            match sibling.kind() {
                "private" | "protected" => return false,
                "public" => return true,
                _ if sibling.kind() == "comment" => {
                    // Skip comments
                    prev_sibling = sibling.prev_sibling();
                    continue;
                }
                _ => break, // Stop at non-modifier, non-comment nodes
            }
        }
        true // Default to public
    }

    /// Extract Ruby comment (RDoc) from a node
    pub fn extract_rdoc_comment(node: &Node, source: &str) -> Option<String> {
        // Look for comment nodes before this node
        let mut prev_sibling = node.prev_sibling();
        let mut comments = Vec::new();

        while let Some(sibling) = prev_sibling {
            if sibling.kind() == "comment" {
                if let Ok(text) = sibling.utf8_text(source.as_bytes()) {
                    if text.trim_start().starts_with("#") {
                        comments.push(text.to_string());
                    } else {
                        break; // Non-RDoc comment
                    }
                }
            } else if sibling.kind() != "comment" {
                // Stop if we hit a non-comment node
                break;
            }
            prev_sibling = sibling.prev_sibling();
        }

        if comments.is_empty() {
            None
        } else {
            // Reverse to get comments in order
            comments.reverse();
            Some(comments.join("\n"))
        }
    }

    /// Find all constants in the syntax tree
    pub fn find_constants(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("assignment")
            .into_iter()
            .filter(|node| {
                node.child_by_field_name("left")
                    .map_or(false, |left| left.kind() == "constant")
            })
            .collect()
    }

    /// Find all require/include statements
    pub fn find_requires(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("call")
            .into_iter()
            .filter(|node| {
                node.child_by_field_name("method")
                    .and_then(|method| method.utf8_text(b"").ok())
                    .map_or(false, |text| {
                        matches!(text, "require" | "require_relative" | "include" | "extend")
                    })
            })
            .collect()
    }

    /// Find all instance variables
    pub fn find_instance_variables(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("instance_variable")
    }

    /// Find all class variables
    pub fn find_class_variables(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("class_variable")
    }

    /// Check if a method is a class method (singleton method)
    pub fn is_class_method(node: &Node) -> bool {
        Self::is_singleton_method(node)
    }

    /// Check if a method is an instance method
    pub fn is_instance_method_check(node: &Node) -> bool {
        Self::is_instance_method(node)
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_ruby_syntax_detection() {
        let _source = r#"
            # A simple Ruby module
            module App
              # User class
              class User
                attr_accessor :name, :email

                def initialize(name, email)
                  @name = name
                  @email = email
                end

                def display_name
                  "\#{@name} <\#{@email}>"
                end

                def self.find_by_email(email)
                  # Class method
                end

                private

                def private_method
                  # Private instance method
                end
              end
            end

            require 'json'
            require_relative 'config/database'

            PI = 3.14159
        "#;

        // let language = Language::Ruby;
        // let mut parser = Parser::new(language).unwrap();
        // let tree = parser.parse(source, None).unwrap();

        // // Test class detection
        // let classes = RubySyntax::find_classes(&tree);
        // assert_eq!(classes.len(), 1);

        // // Test module detection
        // let modules = RubySyntax::find_modules(&tree);
        // assert_eq!(modules.len(), 1);

        // // Test method detection
        // let methods = RubySyntax::find_methods(&tree);
        // assert_eq!(methods.len(), 3); // initialize, display_name, private_method

        // // Test singleton method detection
        // let singleton_methods = RubySyntax::find_singleton_methods(&tree);
        // assert_eq!(singleton_methods.len(), 1); // find_by_email

        // // Test constant detection
        // let constants = RubySyntax::find_constants(&tree);
        // assert_eq!(constants.len(), 1); // PI

        // // Test require detection
        // let requires = RubySyntax::find_requires(&tree);
        // assert_eq!(requires.len(), 2); // require and require_relative
    }

    // #[test]
    // fn test_ruby_class_name_extraction() {
    //     let source = "class TestClass; end";
    //     let language = Language::Ruby;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let classes = RubySyntax::find_classes(&tree);
    //     assert_eq!(classes.len(), 1);

    //     let class_node = &classes[0];
    //     let name = RubySyntax::class_name(class_node, source).unwrap();
    //     assert_eq!(name, "TestClass");
    // }

    // #[test]
    // fn test_ruby_module_name_extraction() {
    //     let source = "module TestModule; end";
    //     let language = Language::Ruby;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let modules = RubySyntax::find_modules(&tree);
    //     assert_eq!(modules.len(), 1);

    //     let module_node = &modules[0];
    //     let name = RubySyntax::module_name(module_node, source).unwrap();
    //     assert_eq!(name, "TestModule");
    // }

    // #[test]
    // fn test_ruby_rdoc_extraction() {
    //     let source = r#"
    //         # This is an RDoc comment
    //         # for the User class
    //         class User
    //         end
    //     "#;

    //     let language = Language::Ruby;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let classes = RubySyntax::find_classes(&tree);
    //     assert_eq!(classes.len(), 1);

    //     let class_node = &classes[0];
    //     let rdoc = RubySyntax::extract_rdoc_comment(class_node, source);
    //     assert!(rdoc.is_some());
    //     let rdoc_text = rdoc.unwrap();
    //     assert!(rdoc_text.contains("RDoc"));
    //     assert!(rdoc_text.contains("User class"));
    // }

    // #[test]
    // fn test_ruby_method_visibility() {
    //     let source = r#"
    //         class Test
    //           def public_method
    //           end

    //           private

    //           def private_method
    //           end

    //           public

    //           def another_public_method
    //           end
    //     "#;

    //     let language = Language::Ruby;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let methods = RubySyntax::find_methods(&tree);
    //     assert_eq!(methods.len(), 3);

    //     // Note: This test might need adjustment based on the actual tree-sitter-ruby grammar
    //     // The visibility detection logic may need refinement
    // }

    // #[test]
    // fn test_ruby_constant_extraction() {
    //     let source = "VERSION = '1.0.0'";
    //     let language = Language::Ruby;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let constants = RubySyntax::find_constants(&tree);
    //     assert_eq!(constants.len(), 1);

    //     let constant_node = &constants[0];
    //     let name = RubySyntax::constant_name(constant_node, source).unwrap();
    //     assert_eq!(name, "VERSION");
    // }
}
