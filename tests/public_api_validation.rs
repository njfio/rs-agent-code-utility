use rust_tree_sitter::*;

#[test]
fn test_core_public_api_smoke() -> rust_tree_sitter::Result<()> {
    let parser = Parser::new(Language::Rust)?;
    let tree = parser.parse("fn main() { println!(\"Hello\"); }", None)?;
    let _query = Query::new(Language::Rust, "(function_item) @func")?;

    assert_eq!(tree.root_node().kind(), "source_file");
    assert_eq!(detect_language_from_extension("rs"), Some(Language::Rust));
    assert_eq!(
        detect_language_from_path("src/main.rs"),
        Some(Language::Rust)
    );
    assert!(supported_languages()
        .iter()
        .any(|language| language.name == "Rust"));

    Ok(())
}

#[test]
fn test_analysis_public_api_smoke() -> rust_tree_sitter::Result<()> {
    let _analyzer = CodebaseAnalyzer::new()?;
    let _config = AnalysisConfig::default();
    let _complexity = ComplexityAnalyzer::new("rust");
    let _dependency = DependencyAnalyzer::new();
    let _performance = PerformanceAnalyzer::new();
    let _refactoring = RefactoringAnalyzer::new();
    let _coverage = TestCoverageAnalyzer::new();

    Ok(())
}

#[test]
fn test_security_public_api_smoke() -> rust_tree_sitter::Result<()> {
    let _owasp = OwaspDetector::new()?;
    let _scanner = SecurityScanner::new()?;
    let _sql = SqlInjectionDetector::new("rust");
    let _command = CommandInjectionDetector::new("rust");

    Ok(())
}

#[test]
fn test_specialized_public_api_smoke() -> rust_tree_sitter::Result<()> {
    let _intent_mapping = IntentMappingSystem::new();
    let _memory_tracker = MemoryTracker::new();
    let _cfg_builder = CfgBuilder::new("rust");
    let _taint_analyzer = TaintAnalyzer::new("rust");
    let _symbol_table = SymbolTableAnalyzer::new(Language::Rust);
    let _semantic_context = SemanticContextAnalyzer::new(Language::Rust)?;
    let _transformation_engine = AstTransformationEngine::new();
    let _semantic_validator = SemanticValidator::new();
    let _file_cache = FileCache::new();

    Ok(())
}

#[test]
fn test_common_reexports_and_constants_are_accessible() {
    let _point = Point { row: 0, column: 0 };
    let _range = Range {
        start_byte: 0,
        end_byte: 10,
        start_point: Point { row: 0, column: 0 },
        end_point: Point { row: 0, column: 10 },
    };
    let _risk = RiskLevel::High;
    let _version = VERSION;
    let result: Result<i32> = Ok(42);

    assert!(result.is_ok());
}
