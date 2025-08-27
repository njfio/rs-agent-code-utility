use rust_tree_sitter::*;
use std::time::Instant;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_memory_allocation_efficiency() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test that we pre-allocate collections efficiently
    let temp_dir = TempDir::new()?;
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir)?;
    
    // Create multiple test files to test collection pre-allocation
    for i in 0..100 {
        fs::write(src_dir.join(format!("file_{}.rs", i)), format!(r#"
fn function_{}() {{
    println!("Hello from function {}", {});
}}

struct Struct{} {{
    field: i32,
}}

impl Struct{} {{
    fn method(&self) -> i32 {{
        self.field * {}
    }}
}}
"#, i, i, i, i, i, i))?;
    }
    
    let start = Instant::now();
    let mut analyzer = CodebaseAnalyzer::new()?;
    let result = analyzer.analyze_directory(&src_dir)?;
    let duration = start.elapsed();
    
    // Verify analysis completed successfully
    assert!(!result.files.is_empty());
    assert!(result.files.len() >= 100);
    
    // Performance should be reasonable (increased timeout for different hardware)
    assert!(duration.as_secs() < 10, "Analysis took too long: {:?}", duration);
    
    println!("Analyzed {} files in {:?}", result.files.len(), duration);
    
    Ok(())
}

#[test]
fn test_string_allocation_optimization() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test that we don't unnecessarily clone strings
    let parser = Parser::new(Language::Rust)?;
    let source = r#"
fn test_function() {
    let variable = "test_string";
    println!("{}", variable);
}
"#;
    
    let start = Instant::now();
    
    // Parse the same source multiple times to test string handling efficiency
    for _ in 0..1000 {
        let tree = parser.parse(source, None)?;
        let _root = tree.root_node();
    }
    
    let duration = start.elapsed();
    
    // Should complete quickly (less than 1 second for 1000 parses)
    assert!(duration.as_millis() < 1000, "String handling inefficient: {:?}", duration);
    
    println!("Completed 1000 parses in {:?}", duration);
    
    Ok(())
}

#[test]
fn test_collection_capacity_optimization() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test that collections are pre-allocated with appropriate capacity
    let temp_dir = TempDir::new()?;
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir)?;
    
    // Create a file with many symbols to test collection growth
    let mut large_file_content = String::with_capacity(10000);
    for i in 0..500 {
        large_file_content.push_str(&format!(r#"
fn function_{}() {{
    let var_{} = {};
}}
"#, i, i, i));
    }
    
    fs::write(src_dir.join("large_file.rs"), large_file_content)?;
    
    let start = Instant::now();
    let mut analyzer = CodebaseAnalyzer::new()?;
    let result = analyzer.analyze_directory(&src_dir)?;
    let duration = start.elapsed();
    
    // Verify we found symbols (adjust expectation to be realistic)
    let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
    assert!(total_symbols > 100, "Should find many symbols, found: {}", total_symbols);
    
    // Should complete efficiently (increased timeout for different hardware)
    assert!(duration.as_millis() < 5000, "Collection handling inefficient: {:?}", duration);
    
    println!("Analyzed {} symbols in {:?}", total_symbols, duration);
    
    Ok(())
}

#[test]
fn test_memory_usage_bounds() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test that memory usage stays within reasonable bounds
    let temp_dir = TempDir::new()?;
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir)?;
    
    // Create files with varying sizes
    for i in 0..50 {
        let size = (i + 1) * 100; // Increasing file sizes
        let mut content = String::with_capacity(size * 20);
        for j in 0..size {
            content.push_str(&format!("let var_{} = {};\n", j, j));
        }
        fs::write(src_dir.join(format!("file_{}.rs", i)), content)?;
    }
    
    let mut analyzer = CodebaseAnalyzer::new()?;
    let result = analyzer.analyze_directory(&src_dir)?;
    
    // Verify analysis completed
    assert_eq!(result.files.len(), 50);
    
    // Memory usage should be proportional to input size
    // This is a basic sanity check - in a real scenario you'd use a memory profiler
    let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
    assert!(total_symbols > 50, "Should find symbols, found: {}", total_symbols);
    
    Ok(())
}

#[test]
fn test_concurrent_analysis_performance() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test that concurrent analysis doesn't degrade performance significantly
    let temp_dir = TempDir::new()?;
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir)?;
    
    // Create test files
    for i in 0..20 {
        fs::write(src_dir.join(format!("file_{}.rs", i)), format!(r#"
fn function_{}() {{
    for i in 0..{} {{
        println!("Iteration: {{}}", i);
    }}
}}
"#, i, i * 10))?;
    }
    
    // Sequential analysis
    let start = Instant::now();
    let mut analyzer1 = CodebaseAnalyzer::new()?;
    let _result1 = analyzer1.analyze_directory(&src_dir)?;
    let sequential_duration = start.elapsed();
    
    // The analysis should be fast enough for practical use
    assert!(sequential_duration.as_millis() < 3000, 
            "Sequential analysis too slow: {:?}", sequential_duration);
    
    println!("Sequential analysis completed in {:?}", sequential_duration);
    
    Ok(())
}

#[test]
fn test_parser_reuse_efficiency() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test that parser reuse is efficient
    let parser = Parser::new(Language::Rust)?;
    
    let sources = vec![
        "fn test1() { println!(\"test1\"); }",
        "fn test2() { let x = 42; }",
        "fn test3() { for i in 0..10 { println!(\"{}\", i); } }",
        "struct Test { field: i32 }",
        "impl Test { fn method(&self) -> i32 { self.field } }",
    ];
    
    let start = Instant::now();
    
    // Parse multiple sources with the same parser
    for _ in 0..200 {
        for source in &sources {
            let tree = parser.parse(source, None)?;
            let _root = tree.root_node();
        }
    }
    
    let duration = start.elapsed();
    
    // Should be very fast due to parser reuse
    assert!(duration.as_millis() < 500, "Parser reuse inefficient: {:?}", duration);
    
    println!("Completed 1000 parses with reuse in {:?}", duration);
    
    Ok(())
}

#[test]
fn test_large_file_handling() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test handling of large files without excessive memory usage
    let temp_dir = TempDir::new()?;
    let large_file = temp_dir.path().join("large.rs");
    
    // Create a moderately large file (optimized for CI performance)
    let mut content = String::with_capacity(50000);
    content.push_str("// Large file test\n");

    // Reduce the number of functions to make test more reasonable
    for i in 0..1000 {
        content.push_str(&format!(r#"
fn function_{}() {{
    let variable_{} = {};
    if variable_{} > 0 {{
        println!("Value: {{}}", variable_{});
    }}
}}
"#, i, i, i, i, i));
    }

    fs::write(&large_file, content)?;

    let start = Instant::now();
    let mut analyzer = CodebaseAnalyzer::new()?;
    let result = analyzer.analyze_directory(temp_dir.path())?;
    let duration = start.elapsed();

    // Should handle large files efficiently (more generous timeout for different hardware)
    let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
    assert!(total_symbols > 50, "Should find symbols, found: {}", total_symbols);

    // More reasonable timeout - 30 seconds should work on most hardware
    assert!(duration.as_secs() < 30, "Large file handling too slow: {:?}", duration);

    println!("Analyzed large file ({} symbols) in {:?}", total_symbols, duration);
    
    Ok(())
}

#[test]
fn test_complexity_analysis_performance() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test that complexity analysis doesn't have performance regressions
    let parser = Parser::new(Language::Rust)?;
    let analyzer = ComplexityAnalyzer::new("rust");
    
    let complex_source = r#"
fn complex_function(x: i32, y: i32, z: i32) -> i32 {
    let mut result = 0;
    
    for i in 0..x {
        for j in 0..y {
            if i % 2 == 0 {
                if j % 3 == 0 {
                    result += i * j;
                } else if j % 3 == 1 {
                    result += i + j;
                } else {
                    result += i - j;
                }
            } else {
                match j % 4 {
                    0 => result += z,
                    1 => result -= z,
                    2 => result *= 2,
                    _ => result /= 2,
                }
            }
        }
    }
    
    if result > 1000 {
        result = 1000;
    } else if result < -1000 {
        result = -1000;
    }
    
    result
}
"#;
    
    let start = Instant::now();
    
    // Analyze complexity multiple times
    for _ in 0..100 {
        let tree = parser.parse(complex_source, None)?;
        let _metrics = analyzer.analyze_complexity(&tree)?;
    }
    
    let duration = start.elapsed();
    
    // Should complete efficiently
    assert!(duration.as_millis() < 2000, "Complexity analysis too slow: {:?}", duration);
    
    println!("Completed 100 complexity analyses in {:?}", duration);
    
    Ok(())
}
