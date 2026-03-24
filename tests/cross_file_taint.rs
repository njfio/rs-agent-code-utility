use rust_tree_sitter::taint_analysis::TaintStepType;
use rust_tree_sitter::{CodebaseAnalyzer, Language, Parser, TaintAnalyzer, TaintFlow};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn analyze_codebase_taint(
    temp_dir: &TempDir,
    file_paths: &[&str],
    language: Language,
    analyzer_language: &str,
) -> Result<Vec<TaintFlow>, Box<dyn std::error::Error>> {
    let mut analyzer = CodebaseAnalyzer::new()?;
    analyzer.enable_semantic_graph();
    analyzer.analyze_directory(temp_dir.path())?;

    let parser = Parser::new(language)?;
    let mut files = Vec::new();
    for file_path in file_paths {
        let absolute_path = temp_dir.path().join(file_path);
        let source = fs::read_to_string(&absolute_path)?;
        files.push((PathBuf::from(file_path), parser.parse(&source, None)?));
    }

    let mut taint_analyzer = TaintAnalyzer::new(analyzer_language);
    Ok(taint_analyzer.analyze_codebase_with_graph(
        &files,
        analyzer
            .semantic_graph()
            .expect("semantic graph should be available"),
    )?)
}

#[test]
fn test_taint_analysis_propagates_across_rust_files() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    fs::create_dir_all(temp_dir.path().join("src"))?;

    fs::write(
        temp_dir.path().join("src").join("main.rs"),
        r#"
mod service;
mod db;

use crate::service::build_query;

fn handler(user_input: String) {
    build_query(user_input);
}
"#,
    )?;

    fs::write(
        temp_dir.path().join("src").join("service.rs"),
        r#"
use crate::db::run_query;

pub fn build_query(user_input: String) {
    run_query(user_input);
}
"#,
    )?;

    fs::write(
        temp_dir.path().join("src").join("db.rs"),
        r#"
pub fn run_query(user_input: String) {
    sqlx::query(user_input);
}
"#,
    )?;

    let flows = analyze_codebase_taint(
        &temp_dir,
        &["src/main.rs", "src/service.rs", "src/db.rs"],
        Language::Rust,
        "rust",
    )?;

    let flow = flows
        .iter()
        .find(|flow| {
            flow.source.file_path == PathBuf::from("src/main.rs")
                && flow.sink.file_path == PathBuf::from("src/db.rs")
                && flow.sink.name == "sqlx::query"
        })
        .expect("expected a cross-file Rust taint flow");

    assert!(flow.path.iter().any(|step| {
        step.step_type == TaintStepType::FunctionCall && step.name == "build_query"
    }));
    assert!(flow
        .path
        .iter()
        .any(|step| step.step_type == TaintStepType::FunctionCall && step.name == "run_query"));
    assert!(flow.path.iter().any(|step| {
        step.step_type == TaintStepType::Parameter && step.location.file == "src/db.rs"
    }));

    Ok(())
}

#[test]
fn test_taint_analysis_propagates_across_javascript_files() -> Result<(), Box<dyn std::error::Error>>
{
    let temp_dir = TempDir::new()?;

    fs::write(
        temp_dir.path().join("handler.js"),
        r#"
import { buildQuery } from "./service.js";

function handler(userInput) {
  buildQuery(userInput);
}
"#,
    )?;

    fs::write(
        temp_dir.path().join("service.js"),
        r#"
import { runQuery } from "./db.js";

export function buildQuery(userInput) {
  runQuery(userInput);
}
"#,
    )?;

    fs::write(
        temp_dir.path().join("db.js"),
        r#"
export function runQuery(userInput) {
  mysql.query(userInput);
}
"#,
    )?;

    let flows = analyze_codebase_taint(
        &temp_dir,
        &["handler.js", "service.js", "db.js"],
        Language::JavaScript,
        "javascript",
    )?;

    let flow = flows
        .iter()
        .find(|flow| {
            flow.source.file_path == PathBuf::from("handler.js")
                && flow.sink.file_path == PathBuf::from("db.js")
                && flow.sink.name == "mysql.query"
        })
        .expect("expected a cross-file JavaScript taint flow");

    assert!(flow.path.iter().any(|step| {
        step.step_type == TaintStepType::FunctionCall && step.name == "buildQuery"
    }));
    assert!(flow
        .path
        .iter()
        .any(|step| { step.step_type == TaintStepType::FunctionCall && step.name == "runQuery" }));
    assert!(flow.path.iter().any(|step| {
        step.step_type == TaintStepType::Parameter && step.location.file == "db.js"
    }));

    Ok(())
}

#[test]
fn test_taint_analysis_propagates_return_values_across_rust_files(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    fs::create_dir_all(temp_dir.path().join("src"))?;

    fs::write(
        temp_dir.path().join("src").join("main.rs"),
        r#"
mod service;
mod db;

use crate::db::run_query;
use crate::service::build_query;

fn handler(user_input: String) {
    let query = build_query(user_input);
    run_query(query);
}
"#,
    )?;

    fs::write(
        temp_dir.path().join("src").join("service.rs"),
        r#"
pub fn build_query(user_input: String) -> String {
    return user_input;
}
"#,
    )?;

    fs::write(
        temp_dir.path().join("src").join("db.rs"),
        r#"
pub fn run_query(query: String) {
    sqlx::query(query);
}
"#,
    )?;

    let flows = analyze_codebase_taint(
        &temp_dir,
        &["src/main.rs", "src/service.rs", "src/db.rs"],
        Language::Rust,
        "rust",
    )?;

    let flow = flows
        .iter()
        .find(|flow| {
            flow.source.file_path == PathBuf::from("src/main.rs")
                && flow.sink.file_path == PathBuf::from("src/db.rs")
                && flow.sink.name == "sqlx::query"
        })
        .expect("expected a cross-file Rust taint flow through a return value");

    assert!(flow.path.iter().any(|step| {
        step.step_type == TaintStepType::Return && step.location.file == "src/service.rs"
    }));
    assert!(flow.path.iter().any(|step| {
        step.step_type == TaintStepType::Assignment
            && step.location.file == "src/main.rs"
            && step.name == "query"
    }));
    assert!(flow
        .path
        .iter()
        .any(|step| step.step_type == TaintStepType::FunctionCall && step.name == "run_query"));

    Ok(())
}

#[test]
fn test_taint_analysis_propagates_return_values_across_javascript_files(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;

    fs::write(
        temp_dir.path().join("handler.js"),
        r#"
import { buildQuery } from "./service.js";
import { runQuery } from "./db.js";

function handler(userInput) {
  const query = buildQuery(userInput);
  runQuery(query);
}
"#,
    )?;

    fs::write(
        temp_dir.path().join("service.js"),
        r#"
export function buildQuery(userInput) {
  return userInput;
}
"#,
    )?;

    fs::write(
        temp_dir.path().join("db.js"),
        r#"
export function runQuery(query) {
  mysql.query(query);
}
"#,
    )?;

    let flows = analyze_codebase_taint(
        &temp_dir,
        &["handler.js", "service.js", "db.js"],
        Language::JavaScript,
        "javascript",
    )?;

    let flow = flows
        .iter()
        .find(|flow| {
            flow.source.file_path == PathBuf::from("handler.js")
                && flow.sink.file_path == PathBuf::from("db.js")
                && flow.sink.name == "mysql.query"
        })
        .expect("expected a cross-file JavaScript taint flow through a return value");

    assert!(flow.path.iter().any(|step| {
        step.step_type == TaintStepType::Return && step.location.file == "service.js"
    }));
    assert!(flow.path.iter().any(|step| {
        step.step_type == TaintStepType::Assignment
            && step.location.file == "handler.js"
            && step.name == "query"
    }));
    assert!(flow
        .path
        .iter()
        .any(|step| { step.step_type == TaintStepType::FunctionCall && step.name == "runQuery" }));

    Ok(())
}
