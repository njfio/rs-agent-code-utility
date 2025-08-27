use assert_cmd::Command;
use serde_json::Value;
use std::fs;

#[test]
fn cli_saves_json_report() -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = tempfile::tempdir()?;
    let output_path = tmp_dir.path().join("report.json");

    Command::cargo_bin("tree-sitter-cli")?
        .args([
            "security",
            "test_files",
            "--format",
            "json",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let data = fs::read_to_string(&output_path)?;
    let json: Value = serde_json::from_str(&data)?;
    assert!(json.get("total_vulnerabilities").is_some());
    Ok(())
}

#[test]
fn cli_filters_by_severity() -> Result<(), Box<dyn std::error::Error>> {
    let tmp_low = tempfile::NamedTempFile::new()?;
    Command::cargo_bin("tree-sitter-cli")?
        .args([
            "security",
            "test_files",
            "--format",
            "json",
            "--min-severity",
            "low",
            "--output",
            tmp_low.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let low_json: Value = serde_json::from_str(&fs::read_to_string(tmp_low.path())?)?;
    let low_total = low_json["total_vulnerabilities"].as_u64().unwrap_or(0);

    let tmp_high = tempfile::NamedTempFile::new()?;
    Command::cargo_bin("tree-sitter-cli")?
        .args([
            "security",
            "test_files",
            "--format",
            "json",
            "--min-severity",
            "critical",
            "--output",
            tmp_high.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let high_json: Value = serde_json::from_str(&fs::read_to_string(tmp_high.path())?)?;
    let high_total = high_json["total_vulnerabilities"].as_u64().unwrap_or(0);

    assert!(high_total <= low_total);
    Ok(())
}

