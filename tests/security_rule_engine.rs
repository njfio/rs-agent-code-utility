use rust_tree_sitter::security::{
    DeclarativeRuleEngine, SecurityFindingType, SecurityPipelineConfig,
};
use rust_tree_sitter::{Language, Parser, SecurityPipeline};
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
        engine.rule_count() >= 6,
        "expected at least the seeded built-in declarative rules"
    );
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
