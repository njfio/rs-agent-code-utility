//! Basic usage example for the rust_tree_sitter library

use rust_tree_sitter::{Parser, Language, Query, QueryBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Rust Tree-sitter Library - Basic Usage Example ===\n");

    // Create a parser for Rust
    let parser = Parser::new(Language::Rust)?;
    println!("Created parser for {}", parser.language().name());

    // Sample Rust code to parse
    let source_code = r#"
        use std::collections::HashMap;

        /// A simple calculator struct
        pub struct Calculator {
            memory: f64,
            history: Vec<f64>,
        }

        impl Calculator {
            /// Create a new calculator
            pub fn new() -> Self {
                Self {
                    memory: 0.0,
                    history: Vec::new(),
                }
            }

            /// Add two numbers
            pub fn add(&mut self, a: f64, b: f64) -> f64 {
                let result = a + b;
                self.history.push(result);
                result
            }

            /// Get the calculation history
            pub fn get_history(&self) -> &[f64] {
                &self.history
            }
        }

        fn main() {
            let mut calc = Calculator::new();
            let result = calc.add(5.0, 3.0);
            println!("Result: {}", result);
        }
    "#;

    // Parse the source code
    println!("Parsing source code...");
    let tree = parser.parse(source_code, None)?;
    println!("✓ Parsing successful!");
    println!("Root node kind: {}", tree.root_node().kind());
    println!("Has errors: {}", tree.has_error());
    println!();

    // Basic tree navigation
    println!("=== Tree Navigation ===");
    let root = tree.root_node();
    println!("Root node has {} children", root.child_count());

    // Find all function definitions
    println!("\n=== Finding Functions ===");
    let functions = tree.find_nodes_by_kind("function_item");
    println!("Found {} function(s):", functions.len());
    
    for (i, func) in functions.iter().enumerate() {
        if let Some(name_node) = func.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                println!("  {}. Function: {}", i + 1, name);
                println!("     Position: {}:{} - {}:{}", 
                    func.start_position().row + 1, func.start_position().column,
                    func.end_position().row + 1, func.end_position().column);
            }
        }
    }

    // Find all struct definitions
    println!("\n=== Finding Structs ===");
    let structs = tree.find_nodes_by_kind("struct_item");
    println!("Found {} struct(s):", structs.len());
    
    for (i, struct_node) in structs.iter().enumerate() {
        if let Some(name_node) = struct_node.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                println!("  {}. Struct: {}", i + 1, name);
            }
        }
    }

    // Find all impl blocks
    println!("\n=== Finding Impl Blocks ===");
    let impls = tree.find_nodes_by_kind("impl_item");
    println!("Found {} impl block(s):", impls.len());
    
    for (i, impl_node) in impls.iter().enumerate() {
        if let Some(type_node) = impl_node.child_by_field_name("type") {
            if let Ok(type_name) = type_node.text() {
                println!("  {}. Impl for: {}", i + 1, type_name);
            }
        }
    }

    // Using queries for more sophisticated pattern matching
    println!("\n=== Using Queries ===");
    
    // Query for public functions
    let pub_func_query = Query::new(Language::Rust, r#"
        (function_item
            (visibility_modifier) @visibility
            name: (identifier) @name
        ) @function
    "#)?;
    
    let matches = pub_func_query.matches(&tree)?;
    println!("Found {} public function(s):", matches.len());
    
    for (i, query_match) in matches.iter().enumerate() {
        if let Some(name_capture) = query_match.capture_by_name(&pub_func_query, "name") {
            if let Ok(name) = name_capture.text() {
                println!("  {}. Public function: {}", i + 1, name);
            }
        }
    }

    // Using query builder
    println!("\n=== Using Query Builder ===");
    let builder_query = QueryBuilder::new(Language::Rust)
        .find_kind("use_declaration", "use")
        .find_kind("struct_item", "struct")
        .find_kind("impl_item", "impl")
        .build()?;
    
    let builder_matches = builder_query.matches(&tree)?;
    println!("Query builder found {} matches", builder_matches.len());

    // Language detection
    println!("\n=== Language Detection ===");
    let test_files = vec![
        "main.rs",
        "script.py", 
        "app.js",
        "program.c",
        "code.cpp",
        "unknown.txt"
    ];
    
    for file in test_files {
        match rust_tree_sitter::detect_language_from_path(file) {
            Some(lang) => println!("  {}: {} ({})", file, lang.name(), lang.version()),
            None => println!("  {}: Unknown language", file),
        }
    }

    // Show supported languages
    println!("\n=== Supported Languages ===");
    let languages = rust_tree_sitter::supported_languages();
    for lang_info in languages {
        println!("  {} v{} (extensions: {})", 
            lang_info.name, 
            lang_info.version,
            lang_info.file_extensions.join(", ")
        );
    }

    println!("\n=== Example completed successfully! ===");
    Ok(())
}
