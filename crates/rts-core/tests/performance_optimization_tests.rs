//! Performance optimization integration tests.
//!
//! Rewritten in PR-B (B4) to exercise `parse_content` / `Parser`
//! directly instead of the deleted
//! `CodebaseAnalyzer::analyze_directory` workspace-walker. The
//! daemon's writer hot path is `parse_content` — that's what these
//! tests should pin.

use rust_tree_sitter::{Language, Parser, parse_content};
use std::time::Instant;

#[test]
fn parse_content_handles_many_calls_efficiently()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Mirrors the pre-B4 `test_memory_allocation_efficiency` value:
    // running parse_content over many distinct sources stays fast.
    // Each call constructs a fresh `Parser`, so this also exercises
    // that fresh-parser construction isn't catastrophically slow.
    let start = Instant::now();

    for i in 0..100 {
        let source = format!(
            r#"
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
"#,
            i, i, i, i, i, i
        );
        let outcome = parse_content(&source, Language::Rust)?;
        assert!(!outcome.symbols.is_empty(), "expected symbols on iter {i}");
    }

    let duration = start.elapsed();
    assert!(
        duration.as_secs() < 10,
        "100 parse_content calls took too long: {:?}",
        duration
    );
    println!("Parsed 100 sources via parse_content in {:?}", duration);
    Ok(())
}

#[test]
fn parser_string_handling_efficient() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test that repeated `Parser::parse` on the same source is fast.
    let parser = Parser::new(Language::Rust)?;
    let source = r#"
fn test_function() {
    let variable = "test_string";
    println!("{}", variable);
}
"#;

    let start = Instant::now();

    for _ in 0..1000 {
        let tree = parser.parse(source, None)?;
        let _root = tree.root_node();
    }

    let duration = start.elapsed();
    assert!(
        duration.as_millis() < 1000,
        "String handling inefficient: {:?}",
        duration
    );
    println!("Completed 1000 parses in {:?}", duration);
    Ok(())
}

#[test]
fn parse_content_finds_many_symbols_in_one_pass()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Mirrors the pre-B4 `test_collection_capacity_optimization`
    // shape: exercise that a file dense with symbols extracts the
    // expected count efficiently.
    let mut source = String::with_capacity(10000);
    for i in 0..500 {
        source.push_str(&format!(
            "fn function_{}() {{ let var_{} = {}; }}\n",
            i, i, i
        ));
    }

    let start = Instant::now();
    let outcome = parse_content(&source, Language::Rust)?;
    let duration = start.elapsed();

    assert!(
        outcome.symbols.len() > 100,
        "Should find many symbols, found: {}",
        outcome.symbols.len()
    );
    assert!(
        duration.as_millis() < 5000,
        "Collection handling inefficient: {:?}",
        duration
    );
    println!(
        "Extracted {} symbols via parse_content in {:?}",
        outcome.symbols.len(),
        duration
    );
    Ok(())
}

#[test]
fn parser_reuse_efficient() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test that parser reuse is efficient.
    let parser = Parser::new(Language::Rust)?;

    let sources = vec![
        "fn test1() { println!(\"test1\"); }",
        "fn test2() { let x = 42; }",
        "fn test3() { for i in 0..10 { println!(\"{}\", i); } }",
        "struct Test { field: i32 }",
        "impl Test { fn method(&self) -> i32 { self.field } }",
    ];

    let start = Instant::now();

    for _ in 0..200 {
        for source in &sources {
            let tree = parser.parse(source, None)?;
            let _root = tree.root_node();
        }
    }

    let duration = start.elapsed();
    assert!(
        duration.as_millis() < 500,
        "Parser reuse inefficient: {:?}",
        duration
    );
    println!("Completed 1000 parses with reuse in {:?}", duration);
    Ok(())
}

#[test]
fn parse_content_handles_large_source() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Mirrors the pre-B4 `test_large_file_handling` value:
    // a single large source string parses + extracts symbols in
    // bounded time.
    let mut content = String::with_capacity(50000);
    content.push_str("// Large source test\n");

    for i in 0..1000 {
        content.push_str(&format!(
            r#"
fn function_{}() {{
    let variable_{} = {};
    if variable_{} > 0 {{
        println!("Value: {{}}", variable_{});
    }}
}}
"#,
            i, i, i, i, i
        ));
    }

    let start = Instant::now();
    let outcome = parse_content(&content, Language::Rust)?;
    let duration = start.elapsed();

    assert!(
        outcome.symbols.len() > 50,
        "Should find symbols, found: {}",
        outcome.symbols.len()
    );
    assert!(
        duration.as_secs() < 30,
        "Large source handling too slow: {:?}",
        duration
    );
    println!(
        "Parsed large source ({} symbols) in {:?}",
        outcome.symbols.len(),
        duration
    );
    Ok(())
}
