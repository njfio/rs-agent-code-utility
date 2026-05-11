use rust_tree_sitter::{AnalysisResult, FileInfo};
use rust_tree_sitter::advanced_security::AdvancedSecurityAnalyzer;
use tempfile::TempDir;
use std::fs;

#[test]
fn detects_python_command_injection_with_argv() {
    let tmp = TempDir::new().unwrap();
    let code = r#"
import os, sys
def f():
    os.system('ls ' + sys.argv[1])
"#;
    let p = tmp.path().join("ci_test.py");
    fs::write(&p, code).unwrap();
    let file = FileInfo { path: p.clone(), language: "Python".into(), size: code.len(), lines: code.lines().count(), parsed_successfully: true, parse_errors: vec![], symbols: vec![], security_vulnerabilities: vec![] };
    let mut ar = AnalysisResult::new();
    ar.root_path = tmp.path().to_path_buf();
    ar.files = vec![file];
    ar.total_files = 1; ar.parsed_files = 1; ar.total_lines = code.lines().count();
    ar.languages.insert("Python".into(), 1);
    let sa = AdvancedSecurityAnalyzer::new().unwrap();
    let res = sa.analyze(&ar).unwrap();
    let count = res.vulnerabilities.iter().filter(|v| v.title.to_lowercase().contains("command") || v.description.to_lowercase().contains("command")).count();
    assert!(count >= 1, "expected >=1 python cmd inj, got {}", count);
}

#[test]
fn detects_js_command_injection_with_exec() {
    let tmp = TempDir::new().unwrap();
    let code = r#"
const child_process = require('child_process');
function f(arg){ child_process.exec('ls ' + arg) }
"#;
    let p = tmp.path().join("ci_test.js");
    fs::write(&p, code).unwrap();
    let file = FileInfo { path: p.clone(), language: "JavaScript".into(), size: code.len(), lines: code.lines().count(), parsed_successfully: true, parse_errors: vec![], symbols: vec![], security_vulnerabilities: vec![] };
    let mut ar = AnalysisResult::new();
    ar.root_path = tmp.path().to_path_buf();
    ar.files = vec![file];
    ar.total_files = 1; ar.parsed_files = 1; ar.total_lines = code.lines().count();
    ar.languages.insert("JavaScript".into(), 1);
    let sa = AdvancedSecurityAnalyzer::new().unwrap();
    let res = sa.analyze(&ar).unwrap();
    let count = res.vulnerabilities.iter().filter(|v| v.title.to_lowercase().contains("command") || v.description.to_lowercase().contains("command")).count();
    assert!(count >= 1, "expected >=1 js cmd inj, got {}", count);
}

#[test]
fn detects_java_runtime_exec_injection() {
    let tmp = TempDir::new().unwrap();
    let code = r#"
class T {
  void f(String a) throws Exception {
    Runtime.getRuntime().exec("ls " + a);
  }
}
"#;
    let p = tmp.path().join("T.java");
    fs::write(&p, code).unwrap();
    let file = FileInfo { path: p.clone(), language: "Java".into(), size: code.len(), lines: code.lines().count(), parsed_successfully: true, parse_errors: vec![], symbols: vec![], security_vulnerabilities: vec![] };
    let mut ar = AnalysisResult::new();
    ar.root_path = tmp.path().to_path_buf();
    ar.files = vec![file];
    ar.total_files = 1; ar.parsed_files = 1; ar.total_lines = code.lines().count();
    ar.languages.insert("Java".into(), 1);
    let sa = AdvancedSecurityAnalyzer::new().unwrap();
    let res = sa.analyze(&ar).unwrap();
    let count = res.vulnerabilities.iter().filter(|v| v.title.to_lowercase().contains("command") || v.description.to_lowercase().contains("command")).count();
    assert!(count >= 1, "expected >=1 java cmd inj, got {}", count);
}
