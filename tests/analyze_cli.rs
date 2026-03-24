#![cfg(feature = "cli")]

use assert_cmd::Command;
use serde_json::Value;
use std::fs;

fn create_sample_project() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir)?;

    fs::write(
        src_dir.join("lib.rs"),
        r#"
pub struct User {
    name: String,
}

impl User {
    pub fn new(name: String) -> Self {
        Self { name }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

pub fn create_user() -> User {
    User::new("Ada".to_string())
}
"#,
    )?;

    Ok(temp_dir)
}

#[test]
fn cli_analyze_json_include_graph_adds_semantic_graph() -> Result<(), Box<dyn std::error::Error>> {
    let project = create_sample_project()?;
    let output_path = project.path().join("analysis-with-graph.json");
    let project_path = project
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("project path must be valid UTF-8"))?;
    let output_path_str = output_path
        .to_str()
        .ok_or_else(|| std::io::Error::other("output path must be valid UTF-8"))?;

    Command::cargo_bin("tree-sitter-cli")?
        .args([
            "analyze",
            project_path,
            "--format",
            "json",
            "--include-graph",
            "--output",
            output_path_str,
        ])
        .assert()
        .success();

    let json: Value = serde_json::from_str(&fs::read_to_string(&output_path)?)?;
    let graph = json
        .get("semantic_graph")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            std::io::Error::other("semantic_graph should be present when --include-graph is used")
        })?;

    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| std::io::Error::other("semantic graph nodes array should be present"))?;
    let total_nodes = graph
        .get("statistics")
        .and_then(Value::as_object)
        .and_then(|statistics| statistics.get("total_nodes"))
        .and_then(Value::as_u64)
        .ok_or_else(|| std::io::Error::other("semantic graph total_nodes should be present"))?;

    assert!(!nodes.is_empty());
    assert!(total_nodes > 0);

    Ok(())
}

#[test]
fn cli_analyze_json_omits_semantic_graph_without_flag() -> Result<(), Box<dyn std::error::Error>> {
    let project = create_sample_project()?;
    let output_path = project.path().join("analysis.json");
    let project_path = project
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("project path must be valid UTF-8"))?;
    let output_path_str = output_path
        .to_str()
        .ok_or_else(|| std::io::Error::other("output path must be valid UTF-8"))?;

    Command::cargo_bin("tree-sitter-cli")?
        .args([
            "analyze",
            project_path,
            "--format",
            "json",
            "--output",
            output_path_str,
        ])
        .assert()
        .success();

    let json: Value = serde_json::from_str(&fs::read_to_string(&output_path)?)?;
    assert!(json.get("semantic_graph").is_none());

    Ok(())
}
