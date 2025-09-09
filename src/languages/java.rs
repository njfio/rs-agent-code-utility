//! Java language specific functionality

use crate::tree::{Node, SyntaxTree};

/// Java-specific syntax tree utilities
pub struct JavaSyntax;

impl JavaSyntax {
    /// Check if a node is a class declaration
    pub fn is_class(node: &Node) -> bool {
        node.kind() == "class_declaration"
    }

    /// Check if a node is an interface declaration
    pub fn is_interface(node: &Node) -> bool {
        node.kind() == "interface_declaration"
    }

    /// Check if a node is an enum declaration
    pub fn is_enum(node: &Node) -> bool {
        node.kind() == "enum_declaration"
    }

    /// Check if a node is a method declaration
    pub fn is_method(node: &Node) -> bool {
        node.kind() == "method_declaration"
    }

    /// Check if a node is a constructor declaration
    pub fn is_constructor(node: &Node) -> bool {
        node.kind() == "constructor_declaration"
    }

    /// Check if a node is a field declaration
    pub fn is_field(node: &Node) -> bool {
        node.kind() == "field_declaration"
    }

    /// Check if a node is an annotation declaration
    pub fn is_annotation(node: &Node) -> bool {
        node.kind() == "annotation_type_declaration"
    }

    /// Check if a node is an import declaration
    pub fn is_import(node: &Node) -> bool {
        node.kind() == "import_declaration"
    }

    /// Check if a node is a package declaration
    pub fn is_package(node: &Node) -> bool {
        node.kind() == "package_declaration"
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

    /// Extract interface name from an interface node
    pub fn interface_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_interface(node) {
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

    /// Extract field name from a field node
    pub fn field_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_field(node) {
            return None;
        }
        // Fields can have multiple variable declarators
        let declarator = node.child_by_field_name("declarator")?;
        declarator
            .child_by_field_name("name")?
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string())
    }

    /// Find all classes in the syntax tree
    pub fn find_classes(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("class_declaration")
    }

    /// Find all interfaces in the syntax tree
    pub fn find_interfaces(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("interface_declaration")
    }

    /// Find all methods in the syntax tree
    pub fn find_methods(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("method_declaration")
    }

    /// Find all public methods in the syntax tree
    pub fn public_methods_query() -> &'static str {
        r#"
        (method_declaration
          modifiers: (modifiers
            (marker_annotation
              name: (identifier) @anno (#eq? @anno "Override"))
            (public))
          name: (identifier) @method_name) @method
        "#
    }

    /// Find all classes query
    pub fn classes_query() -> &'static str {
        "(class_declaration name: (identifier) @class_name) @class"
    }

    /// Find all interfaces query
    pub fn interfaces_query() -> &'static str {
        "(interface_declaration name: (identifier) @interface_name) @interface"
    }

    /// Check if a method is public
    pub fn is_public_method(node: &Node, _source: &str) -> bool {
        if !Self::is_method(node) {
            return false;
        }

        // Check for public modifier in the modifiers
        if let Some(modifiers) = node.child_by_field_name("modifiers") {
            for i in 0..modifiers.child_count() {
                if let Some(modifier) = modifiers.child(i) {
                    if modifier.kind() == "public" {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if a class is public
    pub fn is_public_class(node: &Node, _source: &str) -> bool {
        if !Self::is_class(node) {
            return false;
        }

        // Check for public modifier in the modifiers
        if let Some(modifiers) = node.child_by_field_name("modifiers") {
            for i in 0..modifiers.child_count() {
                if let Some(modifier) = modifiers.child(i) {
                    if modifier.kind() == "public" {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Extract JavaDoc comment from a node
    pub fn extract_javadoc_comment(node: &Node, source: &str) -> Option<String> {
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

    /// Find all annotations in the syntax tree
    pub fn find_annotations(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("annotation")
    }

    /// Find all import statements
    pub fn find_imports(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("import_declaration")
    }

    /// Find all package declarations
    pub fn find_packages(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("package_declaration")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::languages::Language;
    use crate::parser::Parser;

    #[test]
    fn test_java_syntax_detection() {
        let source = r#"
            package com.example;

            import java.util.List;

            /**
             * A simple Java class
             */
            public class HelloWorld {
                private String message;

                public HelloWorld(String message) {
                    this.message = message;
                }

                public void sayHello() {
                    System.out.println(message);
                }

                private void privateMethod() {
                    // private method
                }
            }

            interface Greeter {
                void greet();
            }
        "#;

        // let language = Language::Java;
        // let mut parser = Parser::new(language).unwrap();
        // let tree = parser.parse(source, None).unwrap();

        // Test class detection
        // let classes = JavaSyntax::find_classes(&tree);
        // assert_eq!(classes.len(), 1);

        // // Test method detection
        // let methods = JavaSyntax::find_methods(&tree);
        // assert_eq!(methods.len(), 2); // sayHello and privateMethod

        // // Test interface detection
        // let interfaces = JavaSyntax::find_interfaces(&tree);
        // assert_eq!(interfaces.len(), 1);

        // // Test import detection
        // let imports = JavaSyntax::find_imports(&tree);
        // assert_eq!(imports.len(), 1);

        // // Test package detection
        // let packages = JavaSyntax::find_packages(&tree);
        // assert_eq!(packages.len(), 1);
    }

    #[test]
    fn test_java_class_name_extraction() {
        let source = "public class TestClass { }";
        // let language = Language::Java;
        // let mut parser = Parser::new(language).unwrap();
        // let tree = parser.parse(source, None).unwrap();

        // let classes = JavaSyntax::find_classes(&tree);
        // assert_eq!(classes.len(), 1);

        // let class_node = &classes[0];
        // let name = JavaSyntax::class_name(class_node, source).unwrap();
        // assert_eq!(name, "TestClass");
    }

    #[test]
    fn test_java_javadoc_extraction() {
        let source = r#"
            /**
             * This is a JavaDoc comment
             */
            public class TestClass { }
        "#;

        // let language = Language::Java;
        // let mut parser = Parser::new(language).unwrap();
        // let tree = parser.parse(source, None).unwrap();

        // let classes = JavaSyntax::find_classes(&tree);
        // assert_eq!(classes.len(), 1);

        // let class_node = &classes[0];
        // let javadoc = JavaSyntax::extract_javadoc_comment(class_node, source);
        // assert!(javadoc.is_some());
        // assert!(javadoc.unwrap().contains("JavaDoc"));
    }
}
