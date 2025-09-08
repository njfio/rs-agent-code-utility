use assert_cmd::Command;
use serde_json::Value;

#[test]
fn cli_symbols_json() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("tree-sitter-cli")?
        .args(["symbols", "test_files", "--format", "json"])
        .output()?;
    assert!(output.status.success());
    let data = String::from_utf8(output.stdout)?;

    // Find the start of JSON (skip any informational messages)
    let json_start = data.find('{').unwrap_or(0);
    let json_data = &data[json_start..];

    // Find the end of JSON by counting braces
    let mut brace_count = 0;
    let mut json_end = json_start;
    for (i, c) in json_data.chars().enumerate() {
        match c {
            '{' => brace_count += 1,
            '}' => {
                brace_count -= 1;
                if brace_count == 0 {
                    json_end = json_start + i + 1; // +1 to include the closing brace
                    break;
                }
            }
            _ => {}
        }
    }

    let json_str = &data[json_start..json_end];
    let json: Value = serde_json::from_str(json_str)?;
    assert!(json.as_object().unwrap().len() > 0);
    Ok(())
}
