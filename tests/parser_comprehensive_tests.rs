use rust_tree_sitter::{Parser, Language, ParseOptions};
use tempfile::TempDir;
use std::fs;

/// Test parser creation with custom options
#[test]
fn test_parser_with_options() -> Result<(), Box<dyn std::error::Error>> {
    let options = ParseOptions {
        max_bytes: Some(1000),
        timeout_millis: Some(2000),
        include_extras: false,
    };
    
    let parser = Parser::with_options(Language::Rust, options.clone())?;
    
    assert_eq!(parser.language(), Language::Rust);
    assert_eq!(parser.options().max_bytes, Some(1000));
    assert_eq!(parser.options().timeout_millis, Some(2000));
    assert_eq!(parser.options().include_extras, false);
    
    Ok(())
}

/// Test parser options getter and setter
#[test]
fn test_parser_options_management() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = Parser::new(Language::Rust)?;
    
    // Test default options
    let default_options = parser.options();
    assert_eq!(default_options.max_bytes, None);
    assert_eq!(default_options.timeout_millis, Some(5000));
    assert_eq!(default_options.include_extras, true);
    
    // Test setting new options
    let new_options = ParseOptions {
        max_bytes: Some(500),
        timeout_millis: Some(1000),
        include_extras: false,
    };
    
    parser.set_options(new_options.clone());
    
    let updated_options = parser.options();
    assert_eq!(updated_options.max_bytes, Some(500));
    assert_eq!(updated_options.timeout_millis, Some(1000));
    assert_eq!(updated_options.include_extras, false);
    
    Ok(())
}

/// Test parsing from bytes
#[test]
fn test_parse_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let parser = Parser::new(Language::Rust)?;
    let source_bytes = b"fn main() { println!(\"Hello, world!\"); }";
    
    let tree = parser.parse_bytes(source_bytes, None)?;
    
    assert!(!tree.has_error(), "Tree should not have parse errors");
    assert_eq!(tree.root_node().kind(), "source_file");
    
    Ok(())
}

/// Test parsing from file
#[test]
fn test_parse_file() -> Result<(), Box<dyn std::error::Error>> {
    let parser = Parser::new(Language::Rust)?;
    
    // Create a temporary file
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.rs");
    fs::write(&test_file, "fn main() { println!(\"Hello, world!\"); }")?;
    
    let tree = parser.parse_file(test_file.to_str().unwrap())?;
    
    assert!(!tree.has_error(), "Tree should not have parse errors");
    assert_eq!(tree.root_node().kind(), "source_file");
    
    Ok(())
}

/// Test incremental parsing
#[test]
fn test_parse_incremental() -> Result<(), Box<dyn std::error::Error>> {
    let parser = Parser::new(Language::Rust)?;
    
    // Parse initial source
    let initial_source = "fn main() { println!(\"Hello\"); }";
    let mut tree = parser.parse(initial_source, None)?;
    
    // Modify the source
    let new_source = "fn main() { println!(\"Hello, world!\"); }";
    
    // Create an edit that represents the change
    let edit = rust_tree_sitter::create_edit(
        20, // start_byte: position of "Hello"
        25, // old_end_byte: end of "Hello"
        32, // new_end_byte: end of "Hello, world!"
        0,  // start_row
        20, // start_column
        0,  // old_end_row
        25, // old_end_column
        0,  // new_end_row
        32, // new_end_column
    );
    
    // Apply incremental parsing
    let new_tree = parser.parse_incremental(new_source, &mut tree, &[edit])?;
    
    assert!(!new_tree.has_error(), "Incrementally parsed tree should not have errors");
    assert_eq!(new_tree.root_node().kind(), "source_file");
    
    Ok(())
}

/// Test parser reset functionality
#[test]
fn test_parser_reset() -> Result<(), Box<dyn std::error::Error>> {
    let parser = Parser::new(Language::Rust)?;
    
    // Parse some source to change parser state
    let _tree = parser.parse("fn main() {}", None)?;
    
    // Reset should not fail
    parser.reset()?;
    
    // Parser should still work after reset
    let tree = parser.parse("fn test() { return 42; }", None)?;
    assert!(!tree.has_error(), "Parser should work after reset");
    
    Ok(())
}

/// Test changing parser language
#[test]
fn test_set_language() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = Parser::new(Language::Rust)?;
    
    // Initial language should be Rust
    assert_eq!(parser.language(), Language::Rust);
    
    // Change to Python
    parser.set_language(Language::Python)?;
    assert_eq!(parser.language(), Language::Python);
    
    // Test parsing Python code
    let python_code = "def hello():\n    print('Hello, world!')";
    let tree = parser.parse(python_code, None)?;
    assert!(!tree.has_error(), "Should parse Python code correctly");
    
    // Change back to Rust
    parser.set_language(Language::Rust)?;
    assert_eq!(parser.language(), Language::Rust);
    
    Ok(())
}

/// Test parser cloning
#[test]
fn test_clone_parser() -> Result<(), Box<dyn std::error::Error>> {
    let original_options = ParseOptions {
        max_bytes: Some(1000),
        timeout_millis: Some(3000),
        include_extras: false,
    };
    
    let original_parser = Parser::with_options(Language::JavaScript, original_options)?;
    let cloned_parser = original_parser.clone_parser()?;
    
    // Cloned parser should have same language and options
    assert_eq!(cloned_parser.language(), Language::JavaScript);
    assert_eq!(cloned_parser.options().max_bytes, Some(1000));
    assert_eq!(cloned_parser.options().timeout_millis, Some(3000));
    assert_eq!(cloned_parser.options().include_extras, false);
    
    // Both parsers should work independently
    let js_code = "function hello() { console.log('Hello'); }";
    let tree1 = original_parser.parse(js_code, None)?;
    let tree2 = cloned_parser.parse(js_code, None)?;
    
    assert!(!tree1.has_error(), "Original parser should work");
    assert!(!tree2.has_error(), "Cloned parser should work");
    
    Ok(())
}

/// Test parsing with timeout
#[test]
fn test_parse_with_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let options = ParseOptions {
        max_bytes: None,
        timeout_millis: Some(1), // Very short timeout
        include_extras: true,
    };
    
    let parser = Parser::with_options(Language::Rust, options)?;
    
    // Simple code should parse even with short timeout
    let simple_code = "fn main() {}";
    let tree = parser.parse(simple_code, None)?;
    assert!(!tree.has_error(), "Simple code should parse with short timeout");
    
    Ok(())
}

/// Test parsing with byte limit
#[test]
fn test_parse_with_byte_limit() -> Result<(), Box<dyn std::error::Error>> {
    let options = ParseOptions {
        max_bytes: Some(50), // Limit to 50 bytes
        timeout_millis: Some(5000),
        include_extras: true,
    };
    
    let parser = Parser::with_options(Language::Rust, options)?;
    
    // Short code should parse fine
    let short_code = "fn main() {}"; // Less than 50 bytes
    let tree = parser.parse(short_code, None)?;
    assert!(!tree.has_error(), "Short code should parse with byte limit");
    
    Ok(())
}
