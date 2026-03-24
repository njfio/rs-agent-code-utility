use rust_tree_sitter::security::{
    DeclarativeRuleEngine, SecurityFindingType, SecurityPipelineConfig,
};
use rust_tree_sitter::{Language, Parser, SecurityPipeline};
use std::collections::HashSet;
use std::fs;
use tempfile::TempDir;

#[test]
fn declarative_rule_engine_loads_and_evaluates_temp_rules() -> Result<(), Box<dyn std::error::Error>>
{
    let temp_dir = TempDir::new()?;
    fs::write(
        temp_dir.path().join("eval.yaml"),
        r#"
id: js-eval
title: Avoid eval
description: Using eval on untrusted input can execute arbitrary code.
finding_type: injection
severity: critical
confidence: 0.9
languages:
  - javascript
remediation: Replace eval with a fixed dispatch or a parser.
pattern_file: eval.scm
"#,
    )?;
    fs::write(
        temp_dir.path().join("eval.scm"),
        r#"
(call_expression
  function: (identifier) @callee
  arguments: (arguments (_) @input)
  (#eq? @callee "eval")) @finding
"#,
    )?;

    let engine = DeclarativeRuleEngine::load_from_dir(temp_dir.path())?;
    assert_eq!(engine.rule_count(), 1);
    assert_eq!(engine.rules_dir(), temp_dir.path());

    let parser = Parser::new(Language::JavaScript)?;
    let tree = parser.parse("eval(userInput);", None)?;
    let findings = engine.evaluate(&tree, Language::JavaScript, "src/app.js".as_ref())?;

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "Avoid eval");
    assert_eq!(findings[0].finding_type, SecurityFindingType::Injection);
    assert_eq!(findings[0].line_number, 1);

    Ok(())
}

#[test]
fn builtin_rule_directory_loads() -> Result<(), Box<dyn std::error::Error>> {
    let engine = DeclarativeRuleEngine::load_builtin()?;
    assert!(
        engine.rule_count() >= 12,
        "expected the expanded built-in declarative rule set"
    );
    Ok(())
}

#[test]
fn builtin_rules_match_representative_shipped_patterns() -> Result<(), Box<dyn std::error::Error>> {
    let engine = DeclarativeRuleEngine::load_builtin()?;

    assert_titles(
        &engine,
        Language::JavaScript,
        "src/app.js",
        r#"
        eval(userInput);
        child_process.execSync(userInput);
        "#,
        &[
            "Dynamic eval call",
            "Shell execution with child_process.execSync",
        ],
    )?;

    assert_titles(
        &engine,
        Language::Python,
        "src/app.py",
        r#"
        import os
        import yaml

        os.system(user_input)
        yaml.load(payload)
        "#,
        &["Dynamic os.system call", "Unsafe yaml.load usage"],
    )?;

    assert_titles(
        &engine,
        Language::Rust,
        "src/lib.rs",
        r#"
        fn run(user_cmd: &str) {
            std::process::Command::new(user_cmd);
            unsafe {
                std::ptr::read_volatile(0 as *const i32);
            }
        }
        "#,
        &[
            "Process execution with std::process::Command::new",
            "Unsafe block usage",
        ],
    )?;

    Ok(())
}

#[test]
fn security_pipeline_runs_declarative_rule_stage() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    fs::write(
        temp_dir.path().join("eval.yaml"),
        r#"
id: js-eval
title: Avoid eval
description: Using eval on untrusted input can execute arbitrary code.
finding_type: injection
severity: critical
confidence: 0.9
languages:
  - javascript
remediation: Replace eval with a fixed dispatch or a parser.
pattern_file: eval.scm
"#,
    )?;
    fs::write(
        temp_dir.path().join("eval.scm"),
        r#"
(call_expression
  function: (identifier) @callee
  arguments: (arguments (_) @input)
  (#eq? @callee "eval")) @finding
"#,
    )?;

    let pipeline = SecurityPipeline::with_config(SecurityPipelineConfig {
        enable_owasp: false,
        rules_dir: Some(temp_dir.path().to_path_buf()),
        ..SecurityPipelineConfig::default()
    })?;

    let findings = pipeline.analyze_with_path(
        "function run(userInput) { eval(userInput); }",
        std::path::Path::new("src/app.js"),
        Language::JavaScript,
    )?;

    assert!(findings.iter().any(|finding| {
        finding.id.starts_with("rule_js-eval_")
            && finding.title == "Avoid eval"
            && finding.finding_type == SecurityFindingType::Injection
    }));

    Ok(())
}

fn assert_titles(
    engine: &DeclarativeRuleEngine,
    language: Language,
    file_path: &str,
    source: &str,
    expected_titles: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let parser = Parser::new(language)?;
    let tree = parser.parse(source, None)?;
    let findings = engine.evaluate(&tree, language, file_path.as_ref())?;
    let titles: HashSet<_> = findings.into_iter().map(|finding| finding.title).collect();

    for expected_title in expected_titles {
        assert!(
            titles.contains(*expected_title),
            "missing built-in rule finding: {expected_title}; got {titles:?}"
        );
    }

    Ok(())
}
