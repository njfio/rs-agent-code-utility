
use assert_cmd::Command;
use serde_json::Value;

fn parse_json_from_output(output: &[u8]) -> Value {
    let text = String::from_utf8_lossy(output);
    let start = text.find('{').unwrap_or(0);
    serde_json::from_str(&text[start..]).unwrap()
}

#[test]
fn cli_generates_tree_map_json() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("tree-sitter-cli")?
        .args(["map", "test_files", "--map-type", "tree", "--format", "json", "--max-depth", "2"])
        .output()?;
    assert!(output.status.success());
    let json = parse_json_from_output(&output.stdout);
    assert!(json.get("files").is_some());
    Ok(())
}

use rust_tree_sitter::{CodebaseAnalyzer, build_call_graph, build_module_graph};
use std::fs;

#[test]
fn call_graph_simple() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    fs::write(temp.path().join("util.rs"), "pub fn helper() {}")?;
    fs::write(temp.path().join("main.rs"), "mod util; fn main() { util::helper(); }")?;

    let mut analyzer = CodebaseAnalyzer::new()?;
    let result = analyzer.analyze_directory(temp.path())?;
    let graph = build_call_graph(&result);
    let dot = graph.to_dot();
    assert!(dot.contains("main.rs::main"));
    assert!(dot.contains("util.rs::helper"));
    assert!(dot.contains("main.rs::main"));

    Ok(())
}

#[test]

fn cli_generates_symbol_map_json() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("tree-sitter-cli")?
        .args(["map", "test_files", "--map-type", "symbols", "--format", "json"])
        .output()?;
    assert!(output.status.success());
    let json = parse_json_from_output(&output.stdout);
    assert!(json.as_object().map(|o| !o.is_empty()).unwrap_or(false));
    Ok(())
}

#[test]
fn module_graph_simple() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    fs::write(temp.path().join("moda.rs"), "pub fn a() {}")?;
    fs::write(temp.path().join("modb.rs"), "use crate::moda; fn b() { moda::a(); }")?;

    let mut analyzer = CodebaseAnalyzer::new()?;
    let result = analyzer.analyze_directory(temp.path())?;
    let graph = build_module_graph(&result);
    let dot = graph.to_dot();
    assert!(dot.contains("modb.rs"));
    assert!(dot.contains("moda"));

    Ok(())
}
