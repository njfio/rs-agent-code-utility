use rust_tree_sitter::CodebaseAnalyzer;
use std::path::PathBuf;

#[test]
fn analyzer_extracts_symbols() -> Result<(), Box<dyn std::error::Error>> {
    let mut analyzer = CodebaseAnalyzer::new()?;
    let analysis = analyzer.analyze_directory(PathBuf::from("test_files"))?;
    let total_symbols: usize = analysis.files.iter().map(|f| f.symbols.len()).sum();
    assert!(total_symbols > 0);
    let rust_file = analysis.files.iter().find(|f| f.path.ends_with("phase2_demo.rs")).unwrap();
    assert!(rust_file.symbols.iter().any(|s| s.name == "UserService"));
    Ok(())
}
