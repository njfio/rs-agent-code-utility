use assert_cmd::prelude::*;
use std::process::Command;
use tempfile::TempDir;

// Snapshot-lite test for the table renderer: verifies headers and sections
#[test]
fn security_table_snapshot_basic_headers() -> Result<(), Box<dyn std::error::Error>> {
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
    // Headers present
    assert!(stdout.contains("🔍 SECURITY SCAN RESULTS"));
    assert!(stdout.contains("📊 SUMMARY"));
    assert!(stdout.contains("🚨 BY SEVERITY"));
    Ok(())
}

