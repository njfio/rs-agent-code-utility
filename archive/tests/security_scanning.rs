use rust_tree_sitter::{CodebaseAnalyzer, SecurityScanner};
use std::path::PathBuf;

#[test]
fn advanced_security_detects_vulnerabilities() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from("test_files");
    let mut analyzer = CodebaseAnalyzer::new()?;
    let analysis = analyzer.analyze_directory(&root)?;
    // No need to manually modify paths - the security analyzer handles this internally
    let scanner = SecurityScanner::new()?;
    let result = scanner.analyze(&analysis)?;
    assert!(result.total_vulnerabilities > 0);
    Ok(())
}
