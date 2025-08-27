use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn analyze_outputs_sorted_files_json() {
    // Run the CLI analyze command on test_files as JSON
    let mut cmd = Command::cargo_bin("tree-sitter-cli").expect("binary exists");
    cmd.args(["analyze", "test_files", "--format", "json", "--threads", "1"]);

    let output = cmd.assert().success().get_output().stdout.clone();
    let v: serde_json::Value = serde_json::from_slice(&output).expect("valid json");
    let files = v.get("files").and_then(|f| f.as_array()).expect("files array");

    let mut paths: Vec<String> = files
        .iter()
        .map(|f| f.get("path").and_then(|p| p.as_str()).unwrap_or("").to_string())
        .collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted, "files should be sorted by relative path");
}

#[test]
fn analyze_prints_schema_v1() {
    let mut cmd = Command::cargo_bin("tree-sitter-cli").expect("binary exists");
    cmd.args(["analyze", "--print-schema", "--schema-version", "1", "."]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("AnalyzeResultV1"));
}

