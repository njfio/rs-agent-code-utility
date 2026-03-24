#![cfg(feature = "cli")]

use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn dependencies_emits_sbom_when_output_ends_with_sbom_json(
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let out = tmp.path().join("deps.sbom.json");

    let mut cmd = Command::cargo_bin("tree-sitter-cli")?;
    cmd.args(["dependencies", "test_files", "--format", "json", "--output"])
        .arg(&out);
    cmd.assert().success();

    let content = fs::read_to_string(&out)?;
    assert!(
        content.contains("CycloneDX"),
        "SBOM must contain CycloneDX header"
    );

    Ok(())
}
