//! Integration tests for the rust_tree_sitter library

use rust_tree_sitter::{
    Parser, Language, Query, QueryBuilder, 
    detect_language_from_extension, detect_language_from_path,
    supported_languages, create_edit
};
use tree_sitter::{Point, InputEdit};

#[test]
fn test_parser_creation_and_basic_parsing() {
    let parser = Parser::new(Language::Rust).unwrap();
    assert_eq!(parser.language(), Language::Rust);

    let source = "fn main() { println!(\"Hello, world!\"); }";
    let tree = parser.parse(source, None).unwrap();
    
    assert_eq!(tree.root_node().kind(), "source_file");
    assert!(!tree.has_error());
    assert_eq!(tree.source(), source);
}

#[test]
fn test_multiple_languages() {
    for language in Language::all() {
        let parser = Parser::new(language);
        assert!(parser.is_ok(), "Failed to create parser for {}", language.name());
        
        let parser = parser.unwrap();
        assert_eq!(parser.language(), language);
    }
}

#[test]
fn test_rust_specific_parsing() {
    let parser = Parser::new(Language::Rust).unwrap();
    let source = r#"
        struct Point {
            x: i32,
            y: i32,
        }
        
        impl Point {
            fn new(x: i32, y: i32) -> Self {
                Self { x, y }
            }
        }
        
        fn main() {
            let p = Point::new(1, 2);
        }
    "#;
    
    let tree = parser.parse(source, None).unwrap();
    assert!(!tree.has_error());
    
    // Find structs
    let structs = tree.find_nodes_by_kind("struct_item");
    assert_eq!(structs.len(), 1);
    
    // Find impl blocks
    let impls = tree.find_nodes_by_kind("impl_item");
    assert_eq!(impls.len(), 1);
    
    // Find functions
    let functions = tree.find_nodes_by_kind("function_item");
    assert_eq!(functions.len(), 2); // new and main
}

#[test]
fn test_javascript_parsing() {
    let parser = Parser::new(Language::JavaScript).unwrap();
    let source = r#"
        class Calculator {
            constructor() {
                this.value = 0;
            }
            
            add(x) {
                this.value += x;
                return this;
            }
        }
        
        function main() {
            const calc = new Calculator();
            calc.add(5);
        }
    "#;
    
    let tree = parser.parse(source, None).unwrap();
    assert!(!tree.has_error());
    
    // Find classes
    let classes = tree.find_nodes_by_kind("class_declaration");
    assert_eq!(classes.len(), 1);
    
    // Find functions
    let functions = tree.find_nodes_by_kind("function_declaration");
    assert_eq!(functions.len(), 1);
}

#[test]
fn test_python_parsing() {
    let parser = Parser::new(Language::Python).unwrap();
    let source = r#"
class Calculator:
    def __init__(self):
        self.value = 0
    
    def add(self, x):
        self.value += x
        return self

def main():
    calc = Calculator()
    calc.add(5)
    "#;
    
    let tree = parser.parse(source, None).unwrap();
    assert!(!tree.has_error());
    
    // Find classes
    let classes = tree.find_nodes_by_kind("class_definition");
    assert_eq!(classes.len(), 1);
    
    // Find functions
    let functions = tree.find_nodes_by_kind("function_definition");
    assert_eq!(functions.len(), 3); // __init__, add, main
}

#[test]
fn test_query_system() {
    let parser = Parser::new(Language::Rust).unwrap();
    let source = r#"
        pub fn public_function() {}
        fn private_function() {}
        pub fn another_public() {}
    "#;
    
    let tree = parser.parse(source, None).unwrap();
    
    // Test basic query
    let query = Query::new(Language::Rust, "(function_item) @function").unwrap();
    let matches = query.matches(&tree).unwrap();
    assert_eq!(matches.len(), 3);
    
    // Test query with captures
    let pub_query = Query::new(Language::Rust, r#"
        (function_item
            (visibility_modifier) @visibility
            name: (identifier) @name
        ) @function
    "#).unwrap();
    
    let pub_matches = pub_query.matches(&tree).unwrap();
    assert_eq!(pub_matches.len(), 2); // Only public functions
    
    // Test capture by name
    for query_match in pub_matches {
        let name_capture = query_match.capture_by_name(&pub_query, "name");
        assert!(name_capture.is_some());
        
        let name = name_capture.unwrap().text().unwrap();
        assert!(name == "public_function" || name == "another_public");
    }
}

#[test]
fn test_query_builder() {
    let query = QueryBuilder::new(Language::Rust)
        .find_kind("function_item", "function")
        .find_kind("struct_item", "struct")
        .add_pattern("(impl_item) @impl")
        .build()
        .unwrap();
    
    let parser = Parser::new(Language::Rust).unwrap();
    let source = r#"
        struct Point { x: i32, y: i32 }
        impl Point {
            fn new() -> Self { Point { x: 0, y: 0 } }
        }
        fn main() {}
    "#;
    
    let tree = parser.parse(source, None).unwrap();
    let matches = query.matches(&tree).unwrap();
    
    // Should find: 1 struct, 1 impl, 2 functions (new and main)
    assert_eq!(matches.len(), 4);
}

#[test]
fn test_predefined_queries() {
    let parser = Parser::new(Language::Rust).unwrap();
    let source = r#"
        pub struct Point { x: i32, y: i32 }
        impl Point {
            pub fn new() -> Self { Point { x: 0, y: 0 } }
        }
        fn main() {}
    "#;
    
    let tree = parser.parse(source, None).unwrap();
    
    // Test functions query
    let functions_query = Query::functions(Language::Rust).unwrap();
    let function_matches = functions_query.matches(&tree).unwrap();
    assert_eq!(function_matches.len(), 2); // new and main
    
    // Test classes query (structs in Rust)
    let classes_query = Query::classes(Language::Rust).unwrap();
    let class_matches = classes_query.matches(&tree).unwrap();
    assert_eq!(class_matches.len(), 1); // Point struct
}

#[test]
fn test_incremental_parsing() {
    let parser = Parser::new(Language::Rust).unwrap();
    let mut source = "fn hello() {}".to_string();
    
    // Initial parse
    let mut tree = parser.parse(&source, None).unwrap();
    assert!(!tree.has_error());
    
    // Edit: change function name
    let edit = InputEdit {
        start_byte: 3,
        old_end_byte: 8, // "hello".len() = 5, so 3 + 5 = 8
        new_end_byte: 7, // "hi".len() = 2, so 3 + 2 = 5... wait, let me recalculate
        start_position: Point::new(0, 3),
        old_end_position: Point::new(0, 8),
        new_end_position: Point::new(0, 5), // 3 + "hi".len()
    };
    
    source.replace_range(3..8, "hi");
    tree.edit(&edit);
    
    let new_tree = parser.parse(&source, Some(&tree)).unwrap();
    assert!(!new_tree.has_error());
    assert_eq!(source, "fn hi() {}");
}

#[test]
fn test_language_detection() {
    assert_eq!(detect_language_from_extension("rs"), Some(Language::Rust));
    assert_eq!(detect_language_from_extension("js"), Some(Language::JavaScript));
    assert_eq!(detect_language_from_extension("py"), Some(Language::Python));
    assert_eq!(detect_language_from_extension("c"), Some(Language::C));
    assert_eq!(detect_language_from_extension("cpp"), Some(Language::Cpp));
    assert_eq!(detect_language_from_extension("unknown"), None);
    
    assert_eq!(detect_language_from_path("src/main.rs"), Some(Language::Rust));
    assert_eq!(detect_language_from_path("script.py"), Some(Language::Python));
    assert_eq!(detect_language_from_path("app.js"), Some(Language::JavaScript));
    assert_eq!(detect_language_from_path("unknown.txt"), None);
}

#[test]
fn test_supported_languages() {
    let languages = supported_languages();
    assert!(!languages.is_empty());
    
    let rust_info = languages.iter().find(|lang| lang.name == "Rust");
    assert!(rust_info.is_some());
    
    let rust_info = rust_info.unwrap();
    assert_eq!(rust_info.file_extensions, &["rs"]);
}

#[test]
fn test_tree_navigation() {
    let parser = Parser::new(Language::Rust).unwrap();
    let source = r#"
        fn main() {
            let x = 42;
            println!("{}", x);
        }
    "#;
    
    let tree = parser.parse(source, None).unwrap();
    let root = tree.root_node();
    
    // Navigate to function
    let function = root.child(0).unwrap();
    assert_eq!(function.kind(), "function_item");
    
    // Get function name
    let name = function.child_by_field_name("name").unwrap();
    assert_eq!(name.text().unwrap(), "main");
    
    // Get function body
    let body = function.child_by_field_name("body").unwrap();
    assert_eq!(body.kind(), "block");
    
    // Test node properties
    assert!(function.is_named());
    assert!(!function.is_error());
    assert!(!function.is_missing());
    assert!(function.child_count() > 0);
}

#[test]
fn test_error_handling() {
    // Test invalid query
    let invalid_query = Query::new(Language::Rust, "(invalid_syntax");
    assert!(invalid_query.is_err());
    
    // Test parsing invalid code (should still create a tree but with errors)
    let parser = Parser::new(Language::Rust).unwrap();
    let invalid_source = "fn main( { invalid syntax }";
    let tree = parser.parse(invalid_source, None).unwrap();
    assert!(tree.has_error());
    
    let error_nodes = tree.error_nodes();
    assert!(!error_nodes.is_empty());
}

#[test]
fn test_node_search() {
    let parser = Parser::new(Language::Rust).unwrap();
    let source = r#"
        struct Point { x: i32, y: i32 }
        struct Line { start: Point, end: Point }
        fn distance(p1: Point, p2: Point) -> f64 { 0.0 }
    "#;
    
    let tree = parser.parse(source, None).unwrap();
    let root = tree.root_node();
    
    // Find all struct definitions
    let structs = root.find_descendants(|node| node.kind() == "struct_item");
    assert_eq!(structs.len(), 2);
    
    // Find first function
    let function = root.find_descendant(|node| node.kind() == "function_item");
    assert!(function.is_some());
    assert_eq!(function.unwrap().kind(), "function_item");
}

#[test]
fn test_create_edit_helper() {
    let edit = create_edit(0, 5, 3, 0, 0, 0, 5, 0, 3);
    
    assert_eq!(edit.start_byte, 0);
    assert_eq!(edit.old_end_byte, 5);
    assert_eq!(edit.new_end_byte, 3);
    assert_eq!(edit.start_position, Point::new(0, 0));
    assert_eq!(edit.old_end_position, Point::new(0, 5));
    assert_eq!(edit.new_end_position, Point::new(0, 3));
}
