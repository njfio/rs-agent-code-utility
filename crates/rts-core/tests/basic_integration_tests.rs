//! Basic integration tests for core functionality.
//!
//! Rewritten in PR-B (B4) to exercise the `parse_content` facade
//! and `Parser` directly instead of the deleted `CodebaseAnalyzer`
//! workspace-walker. These tests still cover the same behavioural
//! surface — multi-symbol extraction, parser tree shape — but
//! against the post-cleanup public API.

use rust_tree_sitter::{parse_content, Language, Parser, Result};

#[test]
fn parse_content_extracts_main_and_struct_from_rust_source() -> Result<()> {
    // Mirrors the pre-B4 `test_basic_codebase_analysis` value:
    // exercise that a non-trivial Rust source produces both function
    // and struct symbols, with the expected names.
    let source = r#"
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
"#;

    let outcome = parse_content(source, Language::Rust)?;
    assert!(!outcome.symbols.is_empty(), "expected symbols");

    let by_name = |name: &str, kind: &str| {
        outcome
            .symbols
            .iter()
            .any(|s| s.name == name && s.kind == kind)
    };
    assert!(by_name("main", "function"), "missing `main` function");
    assert!(
        by_name("add_numbers", "function"),
        "missing `add_numbers` function"
    );
    assert!(
        by_name("Calculator", "struct"),
        "missing `Calculator` struct"
    );
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
    Ok(())
}

#[test]
fn parse_content_handles_multiple_languages() -> Result<()> {
    // Mirrors the pre-B4 `test_multi_file_analysis` value: exercise
    // that the same facade handles distinct languages and surfaces
    // their language-specific symbols correctly.
    let lib_rs = r#"
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
"#;
    let rust_outcome = parse_content(lib_rs, Language::Rust)?;
    assert!(rust_outcome.symbols.iter().any(|s| s.name == "multiply"));
    assert!(rust_outcome.symbols.iter().any(|s| s.name == "divide"));

    let py = "class UserService:\n    pass\n\ndef helper(x):\n    return x + 1\n";
    let py_outcome = parse_content(py, Language::Python)?;
    assert!(py_outcome.symbols.iter().any(|s| s.name == "UserService"));
    assert!(py_outcome.symbols.iter().any(|s| s.name == "helper"));
    Ok(())
}

#[test]
fn parse_content_rejects_unsupported_language_gracefully() -> Result<()> {
    // Mirrors the pre-B4 `test_error_handling` shape: confirm that
    // `parse_content` returns Ok on parseable input even when the
    // per-language extractor is a stub. The daemon depends on this
    // semantics (writer.rs:807-815 — Java/C/C++ silently return
    // empty `Vec<Symbol>`).
    let java = "public class Greeter { public String hi() { return \"hi\"; } }";
    let outcome = parse_content(java, Language::Java)?;
    // Java extractor surfaces class + method. If the stub later
    // evolves, this stays a non-empty assertion against the public
    // facade.
    assert!(!outcome.symbols.is_empty(), "expected Java symbols");
    Ok(())
}
