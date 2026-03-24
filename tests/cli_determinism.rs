#![cfg(feature = "cli")]

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn analyze_outputs_sorted_files_json() -> Result<(), Box<dyn std::error::Error>> {
    // Run the CLI analyze command on test_files as JSON
    let mut cmd = Command::cargo_bin("tree-sitter-cli")?;
    cmd.args([
        "analyze",
        "test_files",
        "--format",
        "json",
        "--threads",
        "1",
    ]);

    let output = cmd.assert().success().get_output().stdout.clone();

    // Find the start of JSON (skip any informational messages)
    let output_str = String::from_utf8_lossy(&output);
    let json_start = output_str.find('{').unwrap_or(0);
    let json_data = &output[json_start..];

    let v: serde_json::Value = serde_json::from_slice(json_data)?;
    let Some(files) = v.get("files").and_then(|f| f.as_array()) else {
        return Err(std::io::Error::other("missing files array in analyze output").into());
    };

    #[allow(unused_mut)]
    let mut paths: Vec<String> = files
        .iter()
        .map(|f| {
            f.get("path")
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string()
        })
        .collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted, "files should be sorted by relative path");

    Ok(())
}

#[test]
fn analyze_prints_schema_v1() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("tree-sitter-cli")?;
    cmd.args(["analyze", "--print-schema", "--schema-version", "1", "."]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("AnalyzeResultV1"));

    Ok(())
}
