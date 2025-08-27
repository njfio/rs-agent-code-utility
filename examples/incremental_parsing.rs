//! Incremental parsing example for the rust_tree_sitter library

use rust_tree_sitter::{Parser, Language, create_edit};
use tree_sitter::{Point, InputEdit};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Rust Tree-sitter Library - Incremental Parsing Example ===\n");

    // Create a parser for Rust
    let parser = Parser::new(Language::Rust)?;
    println!("Created parser for {}", parser.language().name());

    // Initial source code
    let mut source_code = r#"fn hello() {
    println!("Hello");
}"#.to_string();

    println!("Initial source code:");
    println!("{}", source_code);
    println!();

    // Parse the initial code
    let mut tree = parser.parse(&source_code, None)?;
    println!("✓ Initial parsing successful!");
    println!("Root node: {}", tree.root_node().kind());
    println!("Has errors: {}", tree.has_error());
    println!();

    // Show initial function
    let functions = tree.find_nodes_by_kind("function_item");
    if let Some(func) = functions.first() {
        if let Some(name_node) = func.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                println!("Initial function name: {}", name);
            }
        }
    }

    // === Edit 1: Change function name ===
    println!("\n=== Edit 1: Changing function name from 'hello' to 'greet' ===");
    
    // Find the position of "hello" in the source
    let hello_start = source_code.find("hello").unwrap();
    let hello_end = hello_start + "hello".len();
    
    // Create the edit
    let edit1 = InputEdit {
        start_byte: hello_start,
        old_end_byte: hello_end,
        new_end_byte: hello_start + "greet".len(),
        start_position: Point::new(0, hello_start),
        old_end_position: Point::new(0, hello_end),
        new_end_position: Point::new(0, hello_start + "greet".len()),
    };
    
    // Apply the edit to the source
    source_code.replace_range(hello_start..hello_end, "greet");
    
    // Apply the edit to the tree and reparse
    tree.edit(&edit1);
    let new_tree = parser.parse(&source_code, Some(&tree))?;
    tree = new_tree;
    
    println!("Modified source code:");
    println!("{}", source_code);
    println!("✓ Incremental parsing successful!");
    
    // Verify the change
    let functions = tree.find_nodes_by_kind("function_item");
    if let Some(func) = functions.first() {
        if let Some(name_node) = func.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                println!("New function name: {}", name);
            }
        }
    }

    // === Edit 2: Add a parameter ===
    println!("\n=== Edit 2: Adding a parameter to the function ===");
    
    // Find the position of "()" and replace with "(name: &str)"
    let params_start = source_code.find("()").unwrap();
    let params_end = params_start + "()".len();
    let new_params = "(name: &str)";
    
    let edit2 = InputEdit {
        start_byte: params_start,
        old_end_byte: params_end,
        new_end_byte: params_start + new_params.len(),
        start_position: Point::new(0, params_start),
        old_end_position: Point::new(0, params_end),
        new_end_position: Point::new(0, params_start + new_params.len()),
    };
    
    // Apply the edit
    source_code.replace_range(params_start..params_end, new_params);
    tree.edit(&edit2);
    let new_tree = parser.parse(&source_code, Some(&tree))?;
    tree = new_tree;
    
    println!("Modified source code:");
    println!("{}", source_code);
    println!("✓ Incremental parsing successful!");

    // === Edit 3: Modify the function body ===
    println!("\n=== Edit 3: Modifying the function body ===");
    
    // Replace the println! content
    let old_content = r#"println!("Hello");"#;
    let new_content = r#"println!("Hello, {}!", name);"#;
    
    let content_start = source_code.find(old_content).unwrap();
    let content_end = content_start + old_content.len();
    
    let edit3 = create_edit(
        content_start,
        content_end,
        content_start + new_content.len(),
        1, // row (0-indexed)
        4, // column for the start of println!
        1, // old end row
        4 + old_content.len(), // old end column
        1, // new end row
        4 + new_content.len(), // new end column
    );
    
    // Apply the edit
    source_code.replace_range(content_start..content_end, new_content);
    tree.edit(&edit3);
    let new_tree = parser.parse(&source_code, Some(&tree))?;
    tree = new_tree;
    
    println!("Final source code:");
    println!("{}", source_code);
    println!("✓ Incremental parsing successful!");
    println!("Has errors: {}", tree.has_error());

    // === Multiple edits at once ===
    println!("\n=== Multiple Edits: Adding documentation ===");
    
    let doc_comment = "/// Greets a person by name\n";
    let insert_pos = 0;
    
    let edit4 = InputEdit {
        start_byte: insert_pos,
        old_end_byte: insert_pos,
        new_end_byte: insert_pos + doc_comment.len(),
        start_position: Point::new(0, 0),
        old_end_position: Point::new(0, 0),
        new_end_position: Point::new(1, 0), // New line added
    };
    
    // Insert at the beginning
    source_code.insert_str(insert_pos, doc_comment);
    tree.edit(&edit4);
    let new_tree = parser.parse(&source_code, Some(&tree))?;
    tree = new_tree;
    
    println!("Final source code with documentation:");
    println!("{}", source_code);
    println!("✓ Final incremental parsing successful!");

    // === Performance comparison ===
    println!("\n=== Performance Comparison ===");
    
    // Time full parsing
    let start = std::time::Instant::now();
    let _full_parse = parser.parse(&source_code, None)?;
    let full_parse_time = start.elapsed();
    
    // Time incremental parsing (simulate a small edit)
    let small_edit = InputEdit {
        start_byte: 0,
        old_end_byte: 0,
        new_end_byte: 1,
        start_position: Point::new(0, 0),
        old_end_position: Point::new(0, 0),
        new_end_position: Point::new(0, 1),
    };
    
    let temp_source = " ".to_string() + &source_code;
    tree.edit(&small_edit);
    
    let start = std::time::Instant::now();
    let _incremental_parse = parser.parse(&temp_source, Some(&tree))?;
    let incremental_parse_time = start.elapsed();
    
    println!("Full parsing time: {:?}", full_parse_time);
    println!("Incremental parsing time: {:?}", incremental_parse_time);
    
    if incremental_parse_time < full_parse_time {
        println!("✓ Incremental parsing was faster!");
    } else {
        println!("ℹ Full parsing was faster (expected for small files)");
    }

    // === Show changed ranges ===
    println!("\n=== Changed Ranges Analysis ===");
    let original_tree = parser.parse("fn hello() {\n    println!(\"Hello\");\n}", None)?;
    let final_tree = parser.parse(&source_code, None)?;
    
    let changed_ranges = final_tree.changed_ranges(&original_tree);
    println!("Number of changed ranges: {}", changed_ranges.len());
    
    for (i, range) in changed_ranges.iter().enumerate() {
        println!("  Range {}: bytes {}..{}, lines {}:{} - {}:{}", 
            i + 1,
            range.start_byte, range.end_byte,
            range.start_point.row + 1, range.start_point.column,
            range.end_point.row + 1, range.end_point.column
        );
    }

    println!("\n=== Incremental parsing example completed successfully! ===");
    Ok(())
}
