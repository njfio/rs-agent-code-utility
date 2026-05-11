//! Kotlin language specific functionality

use crate::tree::{Node, SyntaxTree};

/// Kotlin-specific syntax tree utilities
pub struct KotlinSyntax;

impl KotlinSyntax {
    /// Check if a node is a class declaration
    pub fn is_class(node: &Node) -> bool {
        node.kind() == "class_declaration"
    }

    /// Check if a node is an interface declaration
    pub fn is_interface(node: &Node) -> bool {
        node.kind() == "interface_declaration"
    }

    /// Check if a node is an enum class declaration
    pub fn is_enum_class(node: &Node) -> bool {
        node.kind() == "enum_class_declaration"
    }

    /// Check if a node is an object declaration
    pub fn is_object(node: &Node) -> bool {
        node.kind() == "object_declaration"
    }

    /// Check if a node is a function declaration
    pub fn is_function(node: &Node) -> bool {
        node.kind() == "function_declaration"
    }

    /// Check if a node is a property declaration
    pub fn is_property(node: &Node) -> bool {
        node.kind() == "property_declaration"
    }

    /// Check if a node is a package declaration
    pub fn is_package(node: &Node) -> bool {
        node.kind() == "package_declaration"
    }

    /// Check if a node is an import declaration
    pub fn is_import(node: &Node) -> bool {
        node.kind() == "import_declaration"
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

    /// Extract property name from a property node
    pub fn property_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_property(node) {
            return None;
        }
        let variable = node.child_by_field_name("variable")?;
        variable
            .child_by_field_name("name")?
            .utf8_text(source.as_bytes())
            .ok()
            .map(|s| s.to_string())
    }

    /// Find all classes in the syntax tree
    pub fn find_classes(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("class_declaration")
    }

    /// Find all functions in the syntax tree
    pub fn find_functions(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("function_declaration")
    }

    /// Find all properties in the syntax tree
    pub fn find_properties(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("property_declaration")
    }

    /// Find all public functions in the syntax tree
    pub fn public_functions_query() -> &'static str {
        r#"
        (function_declaration
          (modifiers
            (visibility_modifier) @visibility (#eq? @visibility "public"))
          name: (simple_identifier) @function_name) @function
        "#
    }

    /// Find all classes query
    pub fn classes_query() -> &'static str {
        "(class_declaration name: (type_identifier) @class_name) @class"
    }

    /// Find all functions query
    pub fn functions_query() -> &'static str {
        "(function_declaration name: (simple_identifier) @function_name) @function"
    }

    /// Check if a function is public
    pub fn is_public_function(node: &Node, source: &str) -> bool {
        if !Self::is_function(node) {
            return false;
        }

        // Check for public visibility modifier
        if let Some(modifiers) = node.child_by_field_name("modifiers") {
            for i in 0..modifiers.child_count() {
                if let Some(modifier) = modifiers.child(i) {
                    if modifier.kind() == "visibility_modifier" {
                        if let Ok(text) = modifier.utf8_text(source.as_bytes()) {
                            return text == "public";
                        }
                    }
                }
            }
        }
        true // Kotlin functions are public by default
    }

    /// Check if a class is public
    pub fn is_public_class(node: &Node, source: &str) -> bool {
        if !Self::is_class(node) {
            return false;
        }

        // Check for public visibility modifier
        if let Some(modifiers) = node.child_by_field_name("modifiers") {
            for i in 0..modifiers.child_count() {
                if let Some(modifier) = modifiers.child(i) {
                    if modifier.kind() == "visibility_modifier" {
                        if let Ok(text) = modifier.utf8_text(source.as_bytes()) {
                            return text == "public";
                        }
                    }
                }
            }
        }
        true // Kotlin classes are public by default
    }

    /// Extract KDoc comment from a node
    pub fn extract_kdoc_comment(node: &Node, source: &str) -> Option<String> {
        // Look for comment nodes before this node
        let mut prev_sibling = node.prev_sibling();
        let mut comments = Vec::new();

        while let Some(sibling) = prev_sibling {
            if sibling.kind() == "comment" {
                if let Ok(text) = sibling.utf8_text(source.as_bytes()) {
                    if text.trim_start().starts_with("/**") {
                        comments.push(text.to_string());
                    } else {
                        break; // Non-KDoc comment
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

    /// Find all interfaces in the syntax tree
    pub fn find_interfaces(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("interface_declaration")
    }

    /// Find all enum classes in the syntax tree
    pub fn find_enum_classes(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("enum_class_declaration")
    }

    /// Find all objects in the syntax tree
    pub fn find_objects(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("object_declaration")
    }

    /// Find all package declarations
    pub fn find_packages(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("package_declaration")
    }

    /// Find all import statements
    pub fn find_imports(tree: &SyntaxTree) -> Vec<Node<'_>> {
        tree.find_nodes_by_kind("import_declaration")
    }

    /// Check if a function is a member function (inside a class/interface)
    pub fn is_member_function(node: &Node) -> bool {
        if !Self::is_function(node) {
            return false;
        }
        // Check if the function is inside a class, interface, or object
        let mut parent = node.parent();
        while let Some(p) = parent {
            match p.kind() {
                "class_declaration" | "interface_declaration" | "object_declaration" => {
                    return true
                }
                "function_declaration" => return false,
                _ => parent = p.parent(),
            }
        }
        false
    }

    /// Check if a function is a top-level function
    pub fn is_top_level_function(node: &Node) -> bool {
        Self::is_function(node) && !Self::is_member_function(node)
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    // #[test]
    // fn test_kotlin_syntax_detection() {
    //     let source = r#"
    // /**
    //  * A simple Kotlin data class
    //  */
    // data class User(
    //     val name: String,
    //     val email: String
    // ) {
    //     /**
    //      * Display name method
    //      */
    //     fun displayName(): String {
    //         return "$name <$email>"
    //     }

    //     companion object {
    //         fun createGuest(): User {
    //             return User("Guest", "guest@example.com")
    //         }
    //     }
    // }

    // /**
    //  * A Kotlin interface
    //  */
    // interface UserRepository {
    //     fun findById(id: Long): User?
    //     fun save(user: User): User
    // }

    // /**
    //  * An enum class
    //  */
    // enum class UserType {
    //     ADMIN, REGULAR, GUEST
    // }

    // /**
    //  * A singleton object
    //  */
    // object UserService {
    //     private val users = mutableListOf<User>()

    //     fun addUser(user: User) {
    //         users.add(user)
    //     }

    //     fun getUsers(): List<User> {
    //         return users.toList()
    //     }
    // }

    // // Top-level function
    // fun main() {
    //     println("Hello, Kotlin!")
    // }

    // // Package declaration
    // package com.example.user

    // // Import statements
    // import java.util.*
    // import kotlin.collections.List
    // ";

    //     let language = Language::Kotlin;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     // Test class detection
    //     let classes = KotlinSyntax::find_classes(&tree);
    //     assert_eq!(classes.len(), 1);

    //     // Test function detection
    //     let functions = KotlinSyntax::find_functions(&tree);
    //     assert_eq!(functions.len(), 5); // displayName, createGuest, findById, save, addUser, getUsers, main

    //     // Test interface detection
    //     let interfaces = KotlinSyntax::find_interfaces(&tree);
    //     assert_eq!(interfaces.len(), 1);

    //     // Test enum class detection
    //     let enum_classes = KotlinSyntax::find_enum_classes(&tree);
    //     assert_eq!(enum_classes.len(), 1);

    //     // Test object detection
    //     let objects = KotlinSyntax::find_objects(&tree);
    //     assert_eq!(objects.len(), 1);

    //     // Test package detection
    //     let packages = KotlinSyntax::find_packages(&tree);
    //     assert_eq!(packages.len(), 1);

    //     // Test import detection
    //     let imports = KotlinSyntax::find_imports(&tree);
    //     assert_eq!(imports.len(), 2);

    //     // Test property detection
    //     let properties = KotlinSyntax::find_properties(&tree);
    //     assert_eq!(properties.len(), 3); // name, email, users
    // }

    // #[test]
    // fn test_kotlin_class_name_extraction() {
    //     let source = "class TestClass { }";
    //     let language = Language::Kotlin;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let classes = KotlinSyntax::find_classes(&tree);
    //     assert_eq!(classes.len(), 1);

    //     let class_node = &classes[0];
    //     let name = KotlinSyntax::class_name(class_node, source).unwrap();
    //     assert_eq!(name, "TestClass");
    // }

    // #[test]
    // fn test_kotlin_function_name_extraction() {
    //     let source = "fun testFunction() { }";
    //     let language = Language::Kotlin;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let functions = KotlinSyntax::find_functions(&tree);
    //     assert_eq!(functions.len(), 1);

    //     let function_node = &functions[0];
    //     let name = KotlinSyntax::function_name(function_node, source).unwrap();
    //     assert_eq!(name, "testFunction");
    // }

    // #[test]
    // fn test_kotlin_kdoc_extraction() {
    //     let source = r#"
    // /**
    //  * This is a KDoc comment
    //  * for the TestClass
    //  */
    // class TestClass { }
    // "#;

    //     let language = Language::Kotlin;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let classes = KotlinSyntax::find_classes(&tree);
    //     assert_eq!(classes.len(), 1);

    //     let class_node = &classes[0];
    //     let kdoc = KotlinSyntax::extract_kdoc_comment(class_node, source);
    //     assert!(kdoc.is_some());
    //     let kdoc_text = kdoc.unwrap();
    //     assert!(kdoc_text.contains("KDoc"));
    //     assert!(kdoc_text.contains("TestClass"));
    // }

    // #[test]
    // fn test_kotlin_property_name_extraction() {
    //     let source = "class Test { val testProperty: String = \"\" }";
    //     let language = Language::Kotlin;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let properties = KotlinSyntax::find_properties(&tree);
    //     assert_eq!(properties.len(), 1);

    //     let property_node = &properties[0];
    //     let name = KotlinSyntax::property_name(property_node, source).unwrap();
    //     assert_eq!(name, "testProperty");
    // }

    // #[test]
    // fn test_kotlin_member_vs_top_level_function() {
    //     let source = r#"
    // class TestClass {
    //     fun memberFunction() { }
    // }

    // fun topLevelFunction() { }
    // "#;

    //     let language = Language::Kotlin;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let functions = KotlinSyntax::find_functions(&tree);
    //     assert_eq!(functions.len(), 2);

    //     let member_count = functions
    //         .iter()
    //         .filter(|node| KotlinSyntax::is_member_function(node))
    //         .count();
    //     assert_eq!(member_count, 1);

    //     let top_level_count = functions
    //         .iter()
    //         .filter(|node| KotlinSyntax::is_top_level_function(node))
    //         .count();
    //     assert_eq!(top_level_count, 1);
    // }

    // #[test]
    // fn test_kotlin_visibility_modifiers() {
    //     let source = r#"
    // class Test {
    //     fun publicFunction() { }  // public by default
    //     internal fun internalFunction() { }
    //     private fun privateFunction() { }
    // }
    // "#;

    //     let language = Language::Kotlin;
    //     let mut parser = Parser::new(language).unwrap();
    //     let tree = parser.parse(source, None).unwrap();

    //     let functions = KotlinSyntax::find_functions(&tree);
    //     assert_eq!(functions.len(), 3);

    //     // Note: This test may need adjustment based on the actual tree-sitter-kotlin grammar
    //     // The visibility detection logic may need refinement
    // }
}
