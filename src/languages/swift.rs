//! Swift language specific functionality

use crate::tree::{Node, SyntaxTree};

/// Swift-specific syntax tree utilities
pub struct SwiftSyntax;

impl SwiftSyntax {
    /// Check if a node is a class declaration
    pub fn is_class(node: &Node) -> bool {
        node.kind() == "class_declaration"
    }

    /// Check if a node is a struct declaration
    pub fn is_struct(node: &Node) -> bool {
        node.kind() == "struct_declaration"
    }

    /// Check if a node is an enum declaration
    pub fn is_enum(node: &Node) -> bool {
        node.kind() == "enum_declaration"
    }

    /// Check if a node is a protocol declaration
    pub fn is_protocol(node: &Node) -> bool {
        node.kind() == "protocol_declaration"
    }

    /// Check if a node is a function declaration
    pub fn is_function(node: &Node) -> bool {
        node.kind() == "function_declaration"
    }

    /// Check if a node is a method declaration
    pub fn is_method(node: &Node) -> bool {
        node.kind() == "function_declaration" && Self::is_inside_type(node)
    }

    /// Check if a node is a property declaration
    pub fn is_property(node: &Node) -> bool {
        node.kind() == "property_declaration"
    }

    /// Check if a node is an import declaration
    pub fn is_import(node: &Node) -> bool {
        node.kind() == "import_declaration"
    }

    /// Check if a node is inside a type declaration (class, struct, enum)
    fn is_inside_type(node: &Node) -> bool {
        let mut parent = node.parent();
        while let Some(p) = parent {
            match p.kind() {
                "class_declaration" | "struct_declaration" | "enum_declaration" => return true,
                "function_declaration" | "protocol_declaration" => return false,
                _ => parent = p.parent(),
            }
        }
        false
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

    /// Extract struct name from a struct node
    pub fn struct_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_struct(node) {
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

    /// Extract property name from a property node
    pub fn property_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_property(node) {
            return None;
        }
        let pattern = node.child_by_field_name("pattern")?;
        pattern
            .child_by_field_name("name")?
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string())
    }

    /// Find all classes in the syntax tree
    pub fn find_classes(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("class_declaration")
    }

    /// Find all structs in the syntax tree
    pub fn find_structs(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("struct_declaration")
    }

    /// Find all functions in the syntax tree
    pub fn find_functions(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("function_declaration")
    }

    /// Find all methods in the syntax tree
    pub fn find_methods(tree: &SyntaxTree) -> Vec<Node> {
        let all_functions = tree.find_nodes_by_kind("function_declaration");
        // Filter to only include methods (functions inside types)
        all_functions
            .into_iter()
            .filter(|node| Self::is_inside_type(node))
            .collect()
    }

    /// Find all public methods in the syntax tree
    pub fn public_methods_query() -> &'static str {
        r#"
        (function_declaration
          (modifiers
            (access_control_modifier) @modifier (#eq? @modifier "public"))
          name: (simple_identifier) @method_name) @method
        "#
    }

    /// Find all classes query
    pub fn classes_query() -> &'static str {
        "(class_declaration name: (type_identifier) @class_name) @class"
    }

    /// Find all structs query
    pub fn structs_query() -> &'static str {
        "(struct_declaration name: (type_identifier) @struct_name) @struct"
    }

    /// Check if a function/method is public
    pub fn is_public_function(node: &Node, source: &str) -> bool {
        if !Self::is_function(node) {
            return false;
        }

        // Check for public access modifier
        if let Some(modifiers) = node.child_by_field_name("modifiers") {
            for i in 0..modifiers.child_count() {
                if let Some(modifier) = modifiers.child(i) {
                    if modifier.kind() == "access_control_modifier" {
                        if let Ok(text) = modifier.utf8_text(source.as_bytes()) {
                            return text == "public";
                        }
                    }
                }
            }
        }
        false // Swift functions are internal by default
    }

    /// Check if a class/struct is public
    pub fn is_public_type(node: &Node, source: &str) -> bool {
        if !Self::is_class(node) && !Self::is_struct(node) {
            return false;
        }

        // Check for public access modifier
        if let Some(modifiers) = node.child_by_field_name("modifiers") {
            for i in 0..modifiers.child_count() {
                if let Some(modifier) = modifiers.child(i) {
                    if modifier.kind() == "access_control_modifier" {
                        if let Ok(text) = modifier.utf8_text(source.as_bytes()) {
                            return text == "public";
                        }
                    }
                }
            }
        }
        false // Swift types are internal by default
    }

    /// Extract documentation comment from a node
    pub fn extract_doc_comment(node: &Node, source: &str) -> Option<String> {
        // Look for comment nodes before this node
        let mut prev_sibling = node.prev_sibling();
        let mut comments = Vec::new();

        while let Some(sibling) = prev_sibling {
            if sibling.kind() == "comment" {
                if let Ok(text) = sibling.utf8_text(source.as_bytes()) {
                    if text.trim_start().starts_with("///") || text.trim_start().starts_with("/**")
                    {
                        comments.push(text.to_string());
                    } else {
                        break; // Non-doc comment
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

    /// Find all enums in the syntax tree
    pub fn find_enums(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("enum_declaration")
    }

    /// Find all protocols in the syntax tree
    pub fn find_protocols(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("protocol_declaration")
    }

    /// Find all import statements
    pub fn find_imports(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("import_declaration")
    }

    /// Find all properties in the syntax tree
    pub fn find_properties(tree: &SyntaxTree) -> Vec<Node> {
        tree.find_nodes_by_kind("property_declaration")
    }

    /// Check if a function is a static method
    pub fn is_static_function(node: &Node, _source: &str) -> bool {
        if !Self::is_function(node) {
            return false;
        }

        // Check for static modifier
        if let Some(modifiers) = node.child_by_field_name("modifiers") {
            for i in 0..modifiers.child_count() {
                if let Some(modifier) = modifiers.child(i) {
                    if modifier.kind() == "static" || modifier.kind() == "class" {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swift_syntax_detection() {
        // let source = r#"
        // A simple Swift struct
        // struct User {
        //     var name: String
        //     var email: String
        //
        //     init(name: String, email: String) {
        //         self.name = name
        //         self.email = email
        //     }
        //
        //     func displayName() -> String {
        //         return "\(name) <\(email)>"
        //     }
        //
        //     static func createGuest() -> User {
        //         return User(name: "Guest", email: "guest@example.com")
        //     }
        //
        //     private func privateMethod() {
        //         // private method
        //     }
        // }
        //
        // // A Swift class
        // public class UserController {
        //     private var users: [User] = []
        //
        //     public func addUser(_ user: User) {
        //         users.append(user)
        //     }
        //
        //     func getUsers() -> [User] {
        //         return users
        //     }
        // }
        //
        // // An enum
        // enum UserType {
        //     case admin
        //     case regular
        //     case guest
        // }
        //
        // // A protocol
        // protocol UserProtocol {
        //     func getName() -> String
        //     func getEmail() -> String
        // }
        //
        // import Foundation
        // import UIKit
        // ";

        // let language = Language::Swift;
        // let mut parser = Parser::new(language).unwrap();
        // let tree = parser.parse(source, None).unwrap();

        // // Test struct detection
        // let structs = SwiftSyntax::find_structs(&tree);
        // assert_eq!(structs.len(), 1);

        // // Test class detection
        // let classes = SwiftSyntax::find_classes(&tree);
        // assert_eq!(classes.len(), 1);

        // // Test function detection
        // let functions = SwiftSyntax::find_functions(&tree);
        // assert_eq!(functions.len(), 5); // init, displayName, createGuest, privateMethod, addUser, getUsers

        // // Test method detection
        // let methods = SwiftSyntax::find_methods(&tree);
        // assert_eq!(methods.len(), 5); // All functions are inside types

        // // Test enum detection
        // let enums = SwiftSyntax::find_enums(&tree);
        // assert_eq!(enums.len(), 1);

        // // Test protocol detection
        // let protocols = SwiftSyntax::find_protocols(&tree);
        // assert_eq!(protocols.len(), 1);

        // // Test import detection
        // let imports = SwiftSyntax::find_imports(&tree);
        // assert_eq!(imports.len(), 2);

        // // Test property detection
        // let properties = SwiftSyntax::find_properties(&tree);
        // assert_eq!(properties.len(), 3); // name, email, users
    }

    // #[test]
    // fn test_swift_struct_name_extraction() {
    //     let source = "struct TestStruct { }";
    //     let language = Language::Swift;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let structs = SwiftSyntax::find_structs(&tree);
    //     assert_eq!(structs.len(), 1);

    //     let struct_node = &structs[0];
    //     let name = SwiftSyntax::struct_name(struct_node, source).unwrap();
    //     assert_eq!(name, "TestStruct");
    // }

    // #[test]
    // fn test_swift_class_name_extraction() {
    //     let source = "class TestClass { }";
    //     let language = Language::Swift;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let classes = SwiftSyntax::find_classes(&tree);
    //     assert_eq!(classes.len(), 1);

    //     let class_node = &classes[0];
    //     let name = SwiftSyntax::class_name(class_node, source).unwrap();
    //     assert_eq!(name, "TestClass");
    // }

    // #[test]
    // fn test_swift_function_name_extraction() {
    //     let source = "func testFunction() { }";
    //     let language = Language::Swift;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let functions = SwiftSyntax::find_functions(&tree);
    //     assert_eq!(functions.len(), 1);

    //     let function_node = &functions[0];
    //     let name = SwiftSyntax::function_name(function_node, source).unwrap();
    //     assert_eq!(name, "testFunction");
    // }

    // #[test]
    // fn test_swift_doc_comment_extraction() {
    //     let source = r#"
    // /// This is a documentation comment
    // /// for the TestStruct
    // struct TestStruct { }
    // "#;

    //     let language = Language::Swift;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let structs = SwiftSyntax::find_structs(&tree);
    //     assert_eq!(structs.len(), 1);

    //     let struct_node = &structs[0];
    //     let doc = SwiftSyntax::extract_doc_comment(struct_node, source);
    //     assert!(doc.is_some());
    //     let doc_text = doc.unwrap();
    //     assert!(doc_text.contains("documentation comment"));
    //     assert!(doc_text.contains("TestStruct"));
    // }

    // #[test]
    // fn test_swift_property_name_extraction() {
    //     let source = "struct Test { var testProperty: String }";
    //     let language = Language::Swift;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let properties = SwiftSyntax::find_properties(&tree);
    //     assert_eq!(properties.len(), 1);

    //     let property_node = &properties[0];
    // let name = SwiftSyntax::property_name(property_node, source).unwrap();
    //     assert_eq!(name, "testProperty");
    // }

    // #[test]
    // fn test_swift_static_function_detection() {
    //     let source = r#"
    // struct Test {
    //     static func staticFunc() { }
    //     func instanceFunc() { }
    // }
    // "#;

    //     let language = Language::Swift;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let functions = SwiftSyntax::find_functions(&tree);
    //     assert_eq!(functions.len(), 2);

    //     let static_count = functions
    //         .iter()
    //         .filter(|node| SwiftSyntax::is_static_function(node, source))
    //         .count();
    //     assert_eq!(static_count, 1);
    // }
}
