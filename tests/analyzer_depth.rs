use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig};
use std::fs;
use tempfile::TempDir;

#[test]
fn respects_max_depth_setting() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    fs::write(tmp.path().join("root.rs"), "fn root() {}")?;
    let sub = tmp.path().join("sub");
    fs::create_dir(&sub)?;
    fs::write(sub.join("child.rs"), "fn child() {}")?;
    let nested = sub.join("nested");
    fs::create_dir(&nested)?;
    fs::write(nested.join("deep.rs"), "fn deep() {}")?;

    let config = AnalysisConfig { max_depth: Some(1), ..AnalysisConfig::default() };
    let mut analyzer = CodebaseAnalyzer::with_config(config)?;
    let result = analyzer.analyze_directory(tmp.path())?;
    assert_eq!(result.total_files, 2);
    assert!(!result.files.iter().any(|f| f.path.ends_with("deep.rs")));
    Ok(())
}
