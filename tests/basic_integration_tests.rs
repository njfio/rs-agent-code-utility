//! Basic integration tests for core functionality
//! 
//! These tests verify that the main components work together correctly
//! with simple, realistic scenarios.

use rust_tree_sitter::{
    CodebaseAnalyzer, Parser, Language, ComplexityAnalyzer,
    Result
};
use tempfile::TempDir;
use std::fs;

/// Create a simple test project with basic Rust code
fn create_simple_test_project() -> Result<TempDir> {
    let temp_dir = TempDir::new().unwrap();
    let project_root = temp_dir.path();

    // Create src directory
    fs::create_dir_all(project_root.join("src"))?;

    // Create a simple main.rs
    fs::write(project_root.join("src/main.rs"), r#"
fn main() {
    println!("Hello, world!");
    let result = add_numbers(5, 3);
    println!("Result: {}", result);
}

fn add_numbers(a: i32, b: i32) -> i32 {
    a + b
}

fn complex_function(x: i32) -> i32 {
    if x > 0 {
        if x > 10 {
            x * 2
        } else {
            x + 1
        }
    } else {
        0
    }
}

struct Calculator {
    value: i32,
}

impl Calculator {
    fn new() -> Self {
        Self { value: 0 }
    }
    
    fn add(&mut self, n: i32) {
        self.value += n;
    }
    
    fn get_value(&self) -> i32 {
        self.value
    }
}
"#)?;

    // Create a simple lib.rs
    fs::write(project_root.join("src/lib.rs"), r#"
pub fn multiply(a: i32, b: i32) -> i32 {
    a * b
}

pub fn divide(a: i32, b: i32) -> Option<i32> {
    if b != 0 {
        Some(a / b)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiply() {
        assert_eq!(multiply(2, 3), 6);
    }

    #[test]
    fn test_divide() {
        assert_eq!(divide(6, 2), Some(3));
        assert_eq!(divide(5, 0), None);
    }
}
"#)?;

    Ok(temp_dir)
}

#[test]
fn test_basic_codebase_analysis() -> Result<()> {
    let temp_dir = create_simple_test_project()?;
    let project_path = temp_dir.path();

    // Create analyzer
    let mut analyzer = CodebaseAnalyzer::new()?;
    
    // Perform analysis
    let analysis_result = analyzer.analyze_directory(project_path)?;
    
    // Verify basic results
    assert!(!analysis_result.files.is_empty());
    assert!(analysis_result.total_files > 0);
    assert!(analysis_result.total_lines > 0);
    
    // Find Rust files
    let rust_files: Vec<_> = analysis_result.files.iter()
        .filter(|f| f.language == "Rust")
        .collect();
    assert!(!rust_files.is_empty());
    
    // Find main.rs
    let main_file = rust_files.iter()
        .find(|f| f.path.file_name().unwrap() == "main.rs")
        .expect("main.rs should be found");
    
    // Verify symbols were extracted
    assert!(!main_file.symbols.is_empty());
    
    // Check for specific symbols
    let main_function = main_file.symbols.iter()
        .find(|s| s.name == "main" && s.kind == "function");
    assert!(main_function.is_some());
    
    let add_numbers_function = main_file.symbols.iter()
        .find(|s| s.name == "add_numbers" && s.kind == "function");
    assert!(add_numbers_function.is_some());
    
    let calculator_struct = main_file.symbols.iter()
        .find(|s| s.name == "Calculator" && s.kind == "struct");
    assert!(calculator_struct.is_some());

    println!("✅ Basic codebase analysis completed successfully");
    println!("Files analyzed: {}", analysis_result.total_files);
    println!("Total lines: {}", analysis_result.total_lines);
    println!("Symbols found in main.rs: {}", main_file.symbols.len());
    
    Ok(())
}

#[test]
fn test_basic_complexity_analysis() -> Result<()> {
    let temp_dir = create_simple_test_project()?;
    let project_path = temp_dir.path();

    // Analyze codebase
    let mut analyzer = CodebaseAnalyzer::new()?;
    let analysis_result = analyzer.analyze_directory(project_path)?;

    // Find main.rs
    let main_file = analysis_result.files.iter()
        .find(|f| f.path.file_name().unwrap() == "main.rs")
        .expect("main.rs should be found");

    // Parse the file for complexity analysis
    let parser = Parser::new(Language::Rust)?;
    let full_path = project_path.join(&main_file.path);
    let content = std::fs::read_to_string(&full_path)?;
    let tree = parser.parse(&content, None)?;
    
    let complexity_analyzer = ComplexityAnalyzer::new("rust");
    let complexity_result = complexity_analyzer.analyze_complexity(&tree)?;
    
    // Verify complexity metrics are calculated
    assert!(complexity_result.cyclomatic_complexity > 0);
    assert!(complexity_result.npath_complexity > 0);
    assert!(complexity_result.halstead_volume > 0.0);
    assert!(complexity_result.lines_of_code > 0);
    
    println!("✅ Basic complexity analysis completed successfully");
    println!("McCabe Complexity: {}", complexity_result.cyclomatic_complexity);
    println!("Cognitive Complexity: {}", complexity_result.cognitive_complexity);
    println!("NPATH Complexity: {}", complexity_result.npath_complexity);
    println!("Halstead Volume: {:.2}", complexity_result.halstead_volume);
    println!("Lines of Code: {}", complexity_result.lines_of_code);
    
    Ok(())
}

#[test]
fn test_basic_parser_functionality() -> Result<()> {
    // Test basic parsing functionality
    let parser = Parser::new(Language::Rust)?;
    
    let source = r#"
    fn hello_world() {
        println!("Hello, world!");
    }
    "#;
    
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    
    // Verify basic tree structure
    assert_eq!(root.kind(), "source_file");
    assert!(root.child_count() > 0);
    
    // Find function node
    let mut cursor = root.walk();
    let mut found_function = false;
    
    if cursor.goto_first_child() {
        loop {
            if cursor.node().kind() == "function_item" {
                found_function = true;
                break;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    
    assert!(found_function, "Should find function_item node");
    
    println!("✅ Basic parser functionality verified");
    println!("Root node kind: {}", root.kind());
    println!("Root node children: {}", root.child_count());
    
    Ok(())
}

#[test]
fn test_multi_file_analysis() -> Result<()> {
    let temp_dir = create_simple_test_project()?;
    let project_path = temp_dir.path();

    // Create analyzer
    let mut analyzer = CodebaseAnalyzer::new()?;
    
    // Perform analysis
    let analysis_result = analyzer.analyze_directory(project_path)?;
    
    // Should find both main.rs and lib.rs
    let rust_files: Vec<_> = analysis_result.files.iter()
        .filter(|f| f.language == "Rust")
        .collect();
    
    assert!(rust_files.len() >= 2, "Should find at least 2 Rust files");
    
    // Verify both files have symbols
    for file in &rust_files {
        assert!(!file.symbols.is_empty(), "File {} should have symbols", file.path.display());
    }
    
    // Find lib.rs and verify its symbols
    let lib_file = rust_files.iter()
        .find(|f| f.path.file_name().unwrap() == "lib.rs")
        .expect("lib.rs should be found");
    
    let multiply_function = lib_file.symbols.iter()
        .find(|s| s.name == "multiply" && s.kind == "function");
    assert!(multiply_function.is_some());
    
    let divide_function = lib_file.symbols.iter()
        .find(|s| s.name == "divide" && s.kind == "function");
    assert!(divide_function.is_some());
    
    println!("✅ Multi-file analysis completed successfully");
    println!("Rust files found: {}", rust_files.len());
    for file in &rust_files {
        println!("  {}: {} symbols", file.path.file_name().unwrap().to_string_lossy(), file.symbols.len());
    }
    
    Ok(())
}

#[test]
fn test_error_handling() -> Result<()> {
    // Test that the analyzer handles non-existent directories gracefully
    let mut analyzer = CodebaseAnalyzer::new()?;
    let non_existent_path = std::path::Path::new("/non/existent/path");
    
    let result = analyzer.analyze_directory(non_existent_path);
    assert!(result.is_err(), "Should return error for non-existent path");
    
    println!("✅ Error handling verified");
    
    Ok(())
}
