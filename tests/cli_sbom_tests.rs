use assert_cmd::prelude::*;
use std::process::Command;
use tempfile::TempDir;
use std::fs;

#[test]
fn dependencies_emits_sbom_when_output_ends_with_sbom_json() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("deps.sbom.json");

    let mut cmd = Command::cargo_bin("tree-sitter-cli").expect("binary exists");
    cmd.args(["dependencies", "test_files", "--format", "json", "--output"])
        .arg(&out);
    cmd.assert().success();

    let content = fs::read_to_string(&out).expect("sbom file written");
    assert!(content.contains("CycloneDX"), "SBOM must contain CycloneDX header");
}

