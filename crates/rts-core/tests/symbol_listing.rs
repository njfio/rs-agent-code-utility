//! Integration tests for `parse_content` against fixture sources.
//!
//! Rewritten in PR-B (B4) to use the public `parse_content` facade
//! instead of the deleted `CodebaseAnalyzer::analyze_directory` path.
//! Exercises the same value (symbols are extracted from a known
//! fixture) against the post-cleanup public surface.

use rust_tree_sitter::{parse_content, Language};

#[test]
fn parse_content_extracts_symbols_from_phase2_demo() -> Result<(), Box<dyn std::error::Error>> {
    let source = std::fs::read_to_string("test_files/phase2_demo.rs")?;
    let outcome = parse_content(&source, Language::Rust)?;
    assert!(
        !outcome.symbols.is_empty(),
        "expected at least one symbol in phase2_demo.rs"
    );
    assert!(
        outcome.symbols.iter().any(|s| s.name == "UserService"),
        "expected `UserService` symbol in {:?}",
        outcome.symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
    Ok(())
}
