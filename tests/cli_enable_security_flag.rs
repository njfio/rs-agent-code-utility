use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn analyze_json_includes_enable_security_true_when_flag_set() {
    let mut cmd = Command::cargo_bin("tree-sitter-cli").expect("binary exists");
    cmd.args(["analyze", ".", "--format", "json", "--enable-security"]);
    let output = cmd.assert().success().get_output().stdout.clone();
    let v: serde_json::Value = serde_json::from_slice(&output).expect("valid json");
    let cfg = v.get("config").expect("has config");
    assert_eq!(cfg.get("enable_security").and_then(|b| b.as_bool()), Some(true));
}

