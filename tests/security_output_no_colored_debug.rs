use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;
use tempfile::TempDir;

// Ensure security CLI does not leak ColoredString debug output and honors --no-color
#[test]
fn security_output_has_no_coloredstring_debug() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;

    let mut cmd = Command::cargo_bin("tree-sitter-cli")?;
    cmd.arg("security")
        .arg(tmp.path())
        .arg("--format")
        .arg("table")
        .arg("--summary-only")
        .arg("--no-color");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ColoredString { ").not());

    Ok(())
}

#[test]
fn security_output_no_color_has_no_ansi_codes() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;

    let output = Command::cargo_bin("tree-sitter-cli")?
        .arg("security")
        .arg(tmp.path())
        .arg("--format")
        .arg("table")
        .arg("--summary-only")
        .arg("--no-color")
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("\u{1b}[") && !stdout.contains("\x1b["),
        "Output contains ANSI escape sequences: {}",
        stdout
    );
    Ok(())
}

