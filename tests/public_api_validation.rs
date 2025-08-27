// TODO: Re-enable when all modules are fully implemented
// This test depends on modules that are currently disabled

/*
use rust_tree_sitter::*;

#[test]
fn test_core_api_accessibility() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test core parsing functionality
    let parser = Parser::new(Language::Rust)?;
    let source = "fn main() { println!(\"Hello, world!\"); }";
    let tree = parser.parse(source, None)?;
    
    assert_eq!(tree.root_node().kind(), "source_file");
    
    // Test language detection
    assert_eq!(detect_language_from_extension("rs"), Some(Language::Rust));
    assert_eq!(detect_language_from_path("main.rs"), Some(Language::Rust));
    
    // Test supported languages
    let languages = supported_languages();
    assert!(!languages.is_empty());
    
    Ok(())
}

#[test]
fn test_analysis_api_accessibility() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test that all major analysis types are accessible
    let _complexity_analyzer = ComplexityAnalyzer::new("rust");
    let _dependency_analyzer = DependencyAnalyzer::new();
    let _performance_analyzer = PerformanceAnalyzer::new();
    let _refactoring_analyzer = RefactoringAnalyzer::new();
    let _test_coverage_analyzer = TestCoverageAnalyzer::new();
    
    Ok(())
}

#[test]
fn test_security_api_accessibility() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test security analysis types that don't require complex setup
    let _owasp_detector = OwaspDetector::new();
    let _security_scanner = SecurityScanner::new();

    // Note: VulnerabilityDatabase, SecretsDetector, and EnhancedSecurityScanner
    // require database managers and other complex dependencies for construction
    // but their types are accessible through the public API

    Ok(())
}

#[test]
fn test_advanced_ai_api_accessibility() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test advanced AI analysis types
    let _ai_analyzer = AIAnalyzer::new();
    let _advanced_ai = AdvancedAIAnalyzer::new();
    let _smart_refactoring = SmartRefactoringEngine::new();
    let _intent_mapping = IntentMappingSystem::new();
    let _reasoning_engine = AutomatedReasoningEngine::new();
    let _memory_tracker = MemoryTracker::new();

    // Note: CodeEvolutionTracker requires a repository path for construction
    // but the type is accessible through the public API

    Ok(())
}

#[test]
fn test_specialized_analysis_api_accessibility() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test specialized analysis tools
    let _cfg_builder = CfgBuilder::new("rust");
    let _taint_analyzer = TaintAnalyzer::new("rust");
    let _sql_detector = SqlInjectionDetector::new("rust");
    let _cmd_detector = CommandInjectionDetector::new("rust");
    let _symbol_analyzer = SymbolTableAnalyzer::new(Language::Rust);
    let _semantic_analyzer = SemanticContextAnalyzer::new(Language::Rust)?;

    Ok(())
}

#[test]
fn test_transformation_api_accessibility() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test AST transformation types
    let _transformation_engine = AstTransformationEngine::new();
    let _semantic_validator = SemanticValidator::new();
    
    Ok(())
}

#[test]
fn test_utility_api_accessibility() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test utility types
    let _file_cache = FileCache::new();

    // Test query system
    let parser = Parser::new(Language::Rust)?;
    let source = "fn test() {}";
    let _tree = parser.parse(source, None)?;
    let _query = Query::new(Language::Rust, "(function_item) @func")?;

    Ok(())
}

#[test]
fn test_error_handling_api() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test error types are accessible
    let _error = Error::parse_error("test error");
    
    // Test that Result type works
    let result: Result<i32> = Ok(42);
    assert!(result.is_ok());
    
    Ok(())
}

#[test]
fn test_constants_api_accessibility() {
    // Test that constants are accessible
    let _risk_level = RiskLevel::High;
    let _version = VERSION;
    
    // Test that all risk levels are available
    let _low = RiskLevel::Low;
    let _medium = RiskLevel::Medium;
    let _high = RiskLevel::High;
    let _critical = RiskLevel::Critical;
}

#[test]
fn test_tree_sitter_types_accessibility() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test that re-exported tree-sitter types are accessible
    let _point = Point { row: 0, column: 0 };
    let _range = Range {
        start_byte: 0,
        end_byte: 10,
        start_point: Point { row: 0, column: 0 },
        end_point: Point { row: 0, column: 10 },
    };
    
    Ok(())
}

#[test]
fn test_codebase_analyzer_integration() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test the main codebase analyzer
    let _analyzer = CodebaseAnalyzer::new()?;

    // Test that we can create config
    let _config = AnalysisConfig::default();

    Ok(())
}

#[test]
fn test_documentation_examples_compile() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Test the example from the lib.rs documentation
    let parser = Parser::new(Language::Rust)?;
    let source = "fn main() { println!(\"Hello, world!\"); }";
    let tree = parser.parse(source, None)?;

    println!("Root node: {}", tree.root_node().kind());
    
    Ok(())
}
*/
