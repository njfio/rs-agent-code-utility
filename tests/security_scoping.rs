use assert_cmd::prelude::*;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn write_file(path: &PathBuf, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

#[test]
fn security_excludes_docs_and_tests_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let root = tmp.path();

    // docs with a fake secret
    write_file(
        &root.join("docs/readme.md"),
        "# Docs\nExample key: sk-example1234567890abcdef12345678",
    );

    // tests directory with a real-looking secret
    write_file(
        &root.join("tests/sample_test.rs"),
        r#"#[test]
fn it_works() { let key = "sk-1234567890abcdef1234567890abcdef"; }"#,
    );

    // minimal src
    write_file(&root.join("src/lib.rs"), "pub fn main() {}\n");

    let output = Command::cargo_bin("tree-sitter-cli")?
        .arg("security")
        .arg(root)
        .arg("--format")
        .arg("json")
        .arg("--summary-only")
        .arg("--no-color")
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout)?;
    // secrets should be empty because only docs/tests contained secrets
    assert!(v["secrets"].as_array().map(|a| a.is_empty()).unwrap_or(true));
    Ok(())
}

#[test]
fn security_includes_tests_when_flag_set() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let root = tmp.path();

    // tests directory with a real-looking secret
    write_file(
        &root.join("tests/alpha.rs"),
        "fn t() { let k = \"AKIA5C38F4W0HTH09SN4\"; }",
    );
    write_file(&root.join("src/lib.rs"), "pub fn main() {}\n");

    let output = Command::cargo_bin("tree-sitter-cli")?
        .arg("security")
        .arg(root)
        .arg("--format")
        .arg("json")
        .arg("--summary-only")
        .arg("--include-tests")
        .arg("--no-color")
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout)?;
    // with include-tests, secrets should have at least one entry
    let secrets_len = v["secrets"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(secrets_len >= 1, "Expected at least 1 secret, got {}", secrets_len);
    Ok(())
}
