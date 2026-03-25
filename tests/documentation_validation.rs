use rust_tree_sitter::{
    detect_language_from_extension, detect_language_from_path, supported_languages, AnalysisConfig,
    CodebaseAnalyzer, ComplexityAnalyzer, Language, Parser, PerformanceAnalyzer, VERSION,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_readme_style_parsing_example_smoke() -> rust_tree_sitter::Result<()> {
    let parser = Parser::new(Language::Rust)?;
    let tree = parser.parse("fn main() { println!(\"Hello, world!\"); }", None)?;

    assert_eq!(tree.root_node().kind(), "source_file");
    Ok(())
}

#[test]
fn test_documented_language_detection_smoke() {
    assert_eq!(detect_language_from_extension("rs"), Some(Language::Rust));
    assert_eq!(
        detect_language_from_path("src/main.rs"),
        Some(Language::Rust)
    );
    assert!(supported_languages()
        .iter()
        .any(|language| language.name == "Rust"));
}

#[test]
fn test_documented_codebase_analysis_example_smoke() -> rust_tree_sitter::Result<()> {
    let temp_dir = TempDir::new()?;
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir)?;
    fs::write(
        src_dir.join("main.rs"),
        r#"
fn main() {
    println!("Hello, docs!");
}

fn helper() -> i32 {
    42
}
"#,
    )?;

    let mut analyzer = CodebaseAnalyzer::with_config(AnalysisConfig {
        enable_security: false,
        ..Default::default()
    })?;
    let result = analyzer.analyze_directory(&src_dir)?;

    assert_eq!(result.total_files, 1);
    assert_eq!(result.parsed_files, 1);
    assert!(result.files.iter().any(|file| !file.symbols.is_empty()));

    Ok(())
}

#[test]
fn test_documented_analysis_examples_smoke() -> rust_tree_sitter::Result<()> {
    let parser = Parser::new(Language::Rust)?;
    let tree = parser.parse(
        r#"
fn complex_function(x: i32) -> i32 {
    if x > 0 {
        for i in 0..x {
            if i % 2 == 0 {
                return i;
            }
        }
    }
    0
}
"#,
        None,
    )?;
    let complexity = ComplexityAnalyzer::new("rust");
    let metrics = complexity.analyze_complexity(&tree)?;

    assert!(metrics.cyclomatic_complexity > 0);

    let temp_dir = TempDir::new()?;
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir)?;
    fs::write(
        src_dir.join("perf.rs"),
        "fn perf() { let mut sum = 0; for i in 0..10 { sum += i; } }",
    )?;

    let mut analyzer = CodebaseAnalyzer::new()?;
    let analysis = analyzer.analyze_directory(&src_dir)?;
    let performance = PerformanceAnalyzer::new().analyze(&analysis)?;

    assert!(performance.performance_score <= 100);

    Ok(())
}

#[test]
fn test_documented_examples_and_version_exist() {
    let example_paths = [
        "examples/basic_usage.rs",
        "examples/basic_analysis.rs",
        "examples/analyze_codebase.rs",
        "examples/security_analysis.rs",
        "examples/ast_transformation_demo.rs",
        "examples/code_map.rs",
        "examples/incremental_parsing.rs",
    ];

    for path in example_paths {
        assert!(
            Path::new(path).exists(),
            "missing documented example: {}",
            path
        );
    }

    assert!(!VERSION.is_empty());
}
