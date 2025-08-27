use assert_cmd::Command;
use serde_json::Value;

#[test]
fn cli_symbols_json() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("tree-sitter-cli")?
        .args(["symbols", "test_files", "--format", "json"])
        .output()?;
    assert!(output.status.success());
    let data = String::from_utf8(output.stdout)?;
    let json: Value = serde_json::from_str(&data)?;
    assert!(json.as_object().unwrap().len() > 0);
    Ok(())
}
