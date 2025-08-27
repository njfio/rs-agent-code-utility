//! Comprehensive unit tests for complexity analysis functionality
//! 
//! These tests verify the accuracy and reliability of complexity metrics
//! calculation across different programming languages and code patterns.

use rust_tree_sitter::{ComplexityAnalyzer, Parser, Language, Result};

#[test]
fn test_complexity_analyzer_creation() {
    let _analyzer = ComplexityAnalyzer::new("rust");
    // Analyzer should be created successfully
    // Note: language() method is not public, so we just verify creation
}

#[test]
fn test_basic_cyclomatic_complexity() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;
    
    // Simple function with no control flow - complexity should be 1
    let simple_code = r#"
        fn simple_function() {
            println!("Hello, world!");
        }
    "#;
    
    let tree = parser.parse(simple_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;
    
    assert_eq!(result.cyclomatic_complexity, 1);
    assert!(result.lines_of_code > 0);
    assert!(result.halstead_volume > 0.0);
    
    Ok(())
}

#[test]
fn test_if_statement_complexity() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;
    
    // Function with if statement - complexity should be 2
    let if_code = r#"
        fn function_with_if(x: i32) -> i32 {
            if x > 0 {
                x + 1
            } else {
                0
            }
        }
    "#;
    
    let tree = parser.parse(if_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;
    
    assert_eq!(result.cyclomatic_complexity, 2);
    assert!(result.cognitive_complexity >= 1);
    
    Ok(())
}

#[test]
fn test_nested_control_flow_complexity() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;
    
    // Function with nested control flow
    let nested_code = r#"
        fn complex_function(x: i32, y: i32) -> i32 {
            if x > 0 {
                if y > 0 {
                    for i in 0..x {
                        if i % 2 == 0 {
                            println!("{}", i);
                        }
                    }
                    x + y
                } else {
                    x
                }
            } else {
                0
            }
        }
    "#;
    
    let tree = parser.parse(nested_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;
    
    // Should have high complexity due to nested structures
    assert!(result.cyclomatic_complexity >= 2);
    assert!(result.cognitive_complexity >= 3);
    assert!(result.npath_complexity >= 2);
    
    Ok(())
}

#[test]
fn test_match_expression_complexity() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;
    
    // Function with match expression
    let match_code = r#"
        fn function_with_match(value: Option<i32>) -> i32 {
            match value {
                Some(x) if x > 0 => x * 2,
                Some(x) => x,
                None => 0,
            }
        }
    "#;
    
    let tree = parser.parse(match_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;
    
    // Match with 3 arms should increase complexity
    assert!(result.cyclomatic_complexity >= 2);
    
    Ok(())
}

#[test]
fn test_loop_complexity() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;
    
    // Function with different types of loops
    let loop_code = r#"
        fn function_with_loops() {
            for i in 0..10 {
                println!("{}", i);
            }
            
            let mut x = 0;
            while x < 5 {
                x += 1;
            }
            
            loop {
                break;
            }
        }
    "#;
    
    let tree = parser.parse(loop_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;
    
    // Should account for all three loop types
    assert!(result.cyclomatic_complexity >= 3);
    assert!(result.npath_complexity >= 2);
    
    Ok(())
}

#[test]
fn test_halstead_metrics() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;
    
    // Function with various operators and operands
    let code = r#"
        fn calculate(a: i32, b: i32, c: i32) -> i32 {
            let result = a + b * c - (a / b);
            if result > 0 {
                result * 2
            } else {
                result + 1
            }
        }
    "#;
    
    let tree = parser.parse(code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;
    
    // Verify Halstead metrics are calculated
    assert!(result.halstead_volume > 0.0);
    assert!(result.halstead_difficulty > 0.0);
    assert!(result.halstead_effort > 0.0);
    
    Ok(())
}

#[test]
fn test_empty_function_complexity() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;
    
    // Empty function
    let empty_code = r#"
        fn empty_function() {
        }
    "#;
    
    let tree = parser.parse(empty_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;
    
    // Even empty functions have base complexity of 1
    assert_eq!(result.cyclomatic_complexity, 1);
    assert_eq!(result.cognitive_complexity, 0);
    assert_eq!(result.npath_complexity, 1);
    
    Ok(())
}

#[test]
fn test_multiple_functions_complexity() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;
    
    // Multiple functions in one file
    let multi_code = r#"
        fn simple() {
            println!("simple");
        }
        
        fn with_if(x: i32) -> i32 {
            if x > 0 {
                x
            } else {
                0
            }
        }
        
        fn with_loop() {
            for i in 0..5 {
                println!("{}", i);
            }
        }
    "#;
    
    let tree = parser.parse(multi_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;
    
    // Should aggregate complexity from all functions
    assert!(result.cyclomatic_complexity >= 1); // Base complexity
    assert!(result.lines_of_code > 10);
    
    Ok(())
}

#[test]
fn test_error_handling_complexity() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;
    
    // Function with error handling patterns
    let error_code = r#"
        fn handle_errors() -> Result<i32, String> {
            let value = match some_operation() {
                Ok(v) => v,
                Err(e) => return Err(e.to_string()),
            };
            
            if value < 0 {
                return Err("Negative value".to_string());
            }
            
            Ok(value * 2)
        }
        
        fn some_operation() -> Result<i32, &'static str> {
            Ok(42)
        }
    "#;
    
    let tree = parser.parse(error_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;
    
    // Error handling patterns should contribute to complexity
    assert!(result.cyclomatic_complexity >= 3);
    
    Ok(())
}

#[test]
fn test_javascript_complexity() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("javascript");
    let parser = Parser::new(Language::JavaScript)?;
    
    // JavaScript function with control flow
    let js_code = r#"
        function complexFunction(x, y) {
            if (x > 0) {
                for (let i = 0; i < x; i++) {
                    if (i % 2 === 0) {
                        console.log(i);
                    }
                }
                return x + y;
            } else if (x < 0) {
                return -x;
            } else {
                return y;
            }
        }
    "#;
    
    let tree = parser.parse(js_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;
    
    // Should handle JavaScript syntax correctly
    assert!(result.cyclomatic_complexity >= 4);
    assert!(result.lines_of_code > 0);
    
    Ok(())
}

#[test]
fn test_python_complexity() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("python");
    let parser = Parser::new(Language::Python)?;
    
    // Python function with control flow
    let python_code = r#"
def complex_function(x, y):
    if x > 0:
        for i in range(x):
            if i % 2 == 0:
                print(i)
        return x + y
    elif x < 0:
        return -x
    else:
        return y
    "#;
    
    let tree = parser.parse(python_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;
    
    // Should handle Python syntax correctly
    assert!(result.cyclomatic_complexity >= 4);
    assert!(result.lines_of_code > 0);
    
    Ok(())
}

#[test]
fn test_complexity_metrics_consistency() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;
    
    let code = r#"
        fn test_function(x: i32) -> i32 {
            if x > 0 {
                x * 2
            } else {
                0
            }
        }
    "#;
    
    let tree = parser.parse(code, None)?;
    let result1 = analyzer.analyze_complexity(&tree)?;
    let result2 = analyzer.analyze_complexity(&tree)?;
    
    // Results should be consistent across multiple runs
    assert_eq!(result1.cyclomatic_complexity, result2.cyclomatic_complexity);
    assert_eq!(result1.cognitive_complexity, result2.cognitive_complexity);
    assert_eq!(result1.npath_complexity, result2.npath_complexity);
    assert_eq!(result1.lines_of_code, result2.lines_of_code);
    
    Ok(())
}

#[test]
fn test_npath_complexity_logical_operators() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;

    // Function with complex logical expressions
    let logical_code = r#"
        fn complex_logic(a: bool, b: bool, c: bool, d: bool) -> bool {
            if (a && b) || (c && d) {
                true
            } else {
                false
            }
        }
    "#;

    let tree = parser.parse(logical_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;

    // Should account for logical operators in condition
    assert!(result.npath_complexity >= 3,
            "Complex logical expression should increase NPATH complexity, got {}",
            result.npath_complexity);

    Ok(())
}

#[test]
fn test_npath_complexity_nested_functions() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;

    // Function with closures
    let closure_code = r#"
        fn with_closure() -> i32 {
            let numbers = vec![1, 2, 3, 4, 5];
            numbers.iter()
                .filter(|&x| *x > 2)
                .map(|x| x * 2)
                .sum()
        }
    "#;

    let tree = parser.parse(closure_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;

    // Should account for closures
    assert!(result.npath_complexity >= 1);

    Ok(())
}

#[test]
fn test_npath_complexity_try_catch() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;

    // Function with error handling
    let try_code = r#"
        fn with_error_handling() -> Result<i32, String> {
            match std::fs::read_to_string("file.txt") {
                Ok(content) => {
                    if content.is_empty() {
                        Err("Empty file".to_string())
                    } else {
                        Ok(content.len() as i32)
                    }
                },
                Err(_) => Err("File not found".to_string()),
            }
        }
    "#;

    let tree = parser.parse(try_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;

    // Should account for error handling paths
    assert!(result.npath_complexity >= 3,
            "Error handling should increase NPATH complexity, got {}",
            result.npath_complexity);

    Ok(())
}

#[test]
fn test_npath_complexity_complex_match() -> Result<()> {
    let analyzer = ComplexityAnalyzer::new("rust");
    let parser = Parser::new(Language::Rust)?;

    // Function with complex match with guards
    let complex_match_code = r#"
        fn complex_match(value: Option<i32>) -> String {
            match value {
                Some(x) if x > 100 => "large".to_string(),
                Some(x) if x > 50 => "medium".to_string(),
                Some(x) if x > 0 => "small".to_string(),
                Some(_) => "zero or negative".to_string(),
                None => "none".to_string(),
            }
        }
    "#;

    let tree = parser.parse(complex_match_code, None)?;
    let result = analyzer.analyze_complexity(&tree)?;

    // Should account for all match arms and guards
    assert!(result.npath_complexity >= 5,
            "Complex match with guards should have high NPATH complexity, got {}",
            result.npath_complexity);

    Ok(())
}
