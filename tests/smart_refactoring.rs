use rust_tree_sitter::smart_refactoring::{SmartRefactoringEngine, SmartRefactoringConfig, SmellCategory, PatternType, ModernizationType};
use rust_tree_sitter::CodebaseAnalyzer;
use tempfile::TempDir;
use std::fs;
use std::path::PathBuf;

/// Test comprehensive code smell detection using AST analysis
#[test]
fn test_ast_based_code_smell_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    
    // Create a Rust file with various code smells
    let rust_code = r#"
// Long method with high cyclomatic complexity
fn complex_function(x: i32, y: i32, z: i32, w: i32, a: i32, b: i32) -> i32 {
    let mut result = 0;
    
    if x > 0 {
        if y > 0 {
            if z > 0 {
                if w > 0 {
                    if a > 0 {
                        if b > 0 {
                            result = x + y + z + w + a + b;
                        } else {
                            result = x + y + z + w + a;
                        }
                    } else {
                        result = x + y + z + w;
                    }
                } else {
                    result = x + y + z;
                }
            } else {
                result = x + y;
            }
        } else {
            result = x;
        }
    }
    
    // More complexity
    for i in 0..10 {
        if i % 2 == 0 {
            result += i;
        } else {
            result -= i;
        }
    }
    
    match result {
        0..=10 => result * 2,
        11..=20 => result * 3,
        21..=30 => result * 4,
        _ => result,
    }
}

// Duplicate code pattern
fn calculate_area_rectangle(width: f64, height: f64) -> f64 {
    let area = width * height;
    println!("Calculating area: {}", area);
    area
}

fn calculate_area_square(side: f64) -> f64 {
    let area = side * side;
    println!("Calculating area: {}", area);
    area
}

// Large class with too many responsibilities
struct DataProcessor {
    data: Vec<i32>,
    config: String,
    logger: String,
    cache: Vec<String>,
    network_client: String,
    database_connection: String,
    file_handler: String,
    encryption_key: String,
    compression_settings: String,
    validation_rules: Vec<String>,
}

impl DataProcessor {
    fn new() -> Self { todo!() }
    fn process_data(&self) -> Vec<i32> { todo!() }
    fn validate_data(&self) -> bool { todo!() }
    fn save_to_database(&self) -> Result<(), String> { todo!() }
    fn save_to_file(&self) -> Result<(), String> { todo!() }
    fn compress_data(&self) -> Vec<u8> { todo!() }
    fn encrypt_data(&self) -> Vec<u8> { todo!() }
    fn send_over_network(&self) -> Result<(), String> { todo!() }
    fn log_operation(&self) -> () { todo!() }
    fn cache_result(&self) -> () { todo!() }
    fn clear_cache(&self) -> () { todo!() }
    fn update_config(&self) -> () { todo!() }
    fn reload_config(&self) -> () { todo!() }
    fn validate_config(&self) -> bool { todo!() }
    fn backup_data(&self) -> Result<(), String> { todo!() }
    fn restore_data(&self) -> Result<(), String> { todo!() }
    fn generate_report(&self) -> String { todo!() }
    fn send_notification(&self) -> () { todo!() }
    fn cleanup_resources(&self) -> () { todo!() }
}

// Performance anti-patterns
fn inefficient_string_building() -> String {
    let mut result = String::new();
    for i in 0..1000 {
        result = result + &i.to_string(); // String concatenation in loop
    }
    result
}

fn inefficient_vector_usage() -> Vec<i32> {
    let mut vec = Vec::new(); // No capacity hint
    for i in 0..10000 {
        vec.push(i);
    }
    vec
}

// Nested loops creating O(n²) complexity
fn find_duplicates(data: &[i32]) -> Vec<i32> {
    let mut duplicates = Vec::new();
    for i in 0..data.len() {
        for j in (i + 1)..data.len() {
            if data[i] == data[j] {
                duplicates.push(data[i]);
            }
        }
    }
    duplicates
}
"#;

    let rust_file = temp_dir.path().join("complex_code.rs");
    fs::write(&rust_file, rust_code)?;

    // Analyze the code using the analyzer (like other tests)
    let mut analyzer = CodebaseAnalyzer::new()?;
    let analysis_result = analyzer.analyze_file(&rust_file)?;

    // Run smart refactoring analysis
    let refactoring_config = SmartRefactoringConfig {
        code_smell_fixes: true,
        pattern_recommendations: true,
        performance_optimizations: true,
        modernization: true,
        architectural_improvements: true,
        min_confidence: 0.6,
        max_suggestions_per_category: 20,
    };
    
    let refactoring_engine = SmartRefactoringEngine::with_config(refactoring_config);
    let result = refactoring_engine.analyze(&analysis_result)?;



    // Verify code smell detection
    assert!(!result.code_smell_fixes.is_empty(), "Should detect code smells");

    // Check for long method detection
    let long_method_fixes: Vec<_> = result.code_smell_fixes.iter()
        .filter(|fix| matches!(fix.category, SmellCategory::LongMethod))
        .collect();
    assert!(!long_method_fixes.is_empty(), "Should detect long methods");

    // Check for large class detection
    let large_class_fixes: Vec<_> = result.code_smell_fixes.iter()
        .filter(|fix| matches!(fix.category, SmellCategory::LargeClass))
        .collect();
    assert!(!large_class_fixes.is_empty(), "Should detect large classes");

    // Check for duplicate code detection
    let duplicate_code_fixes: Vec<_> = result.code_smell_fixes.iter()
        .filter(|fix| matches!(fix.category, SmellCategory::DuplicateCode))
        .collect();
    assert!(!duplicate_code_fixes.is_empty(), "Should detect duplicate code");

    // Debug performance optimizations
    println!("Performance optimizations found: {}", result.performance_optimizations.len());
    for opt in &result.performance_optimizations {
        println!("  - {}: {}", opt.name, opt.description);
    }

    // Verify performance optimizations
    assert!(!result.performance_optimizations.is_empty(), "Should detect performance issues");
    
    // Check for string concatenation optimization
    let string_optimizations: Vec<_> = result.performance_optimizations.iter()
        .filter(|opt| opt.name.contains("String"))
        .collect();
    assert!(!string_optimizations.is_empty(), "Should detect string concatenation issues");

    // Check for vector optimization
    let vector_optimizations: Vec<_> = result.performance_optimizations.iter()
        .filter(|opt| opt.name.contains("Vector"))
        .collect();
    assert!(!vector_optimizations.is_empty(), "Should detect vector reallocation issues");

    // Check for nested loop optimization
    let loop_optimizations: Vec<_> = result.performance_optimizations.iter()
        .filter(|opt| opt.name.contains("Loop"))
        .collect();
    assert!(!loop_optimizations.is_empty(), "Should detect nested loop issues");

    // Verify overall metrics
    assert!(result.total_opportunities > 0, "Should find refactoring opportunities");
    assert!(result.refactoring_score > 0, "Should calculate refactoring score");

    println!("Smart refactoring analysis completed successfully!");
    println!("Total opportunities: {}", result.total_opportunities);
    println!("Refactoring score: {}", result.refactoring_score);
    println!("Code smell fixes: {}", result.code_smell_fixes.len());
    println!("Performance optimizations: {}", result.performance_optimizations.len());

    Ok(())
}

/// Test design pattern recommendations
#[test]
fn test_design_pattern_recommendations() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    
    // Create code that could benefit from design patterns
    let pattern_code = r#"
// Multiple creation methods - Factory pattern opportunity
fn create_user(name: String) -> User { User { name } }
fn create_admin(name: String) -> Admin { Admin { name } }
fn create_guest() -> Guest { Guest }
fn build_manager(name: String, team: String) -> Manager { Manager { name, team } }

// Event handling code - Observer pattern opportunity
fn notify_users(event: &str) {
    println!("Notifying users about: {}", event);
}

fn notify_admins(event: &str) {
    println!("Notifying admins about: {}", event);
}

fn handle_user_login(user: &str) {
    notify_users(&format!("User {} logged in", user));
    notify_admins(&format!("User {} logged in", user));
}

struct User { name: String }
struct Admin { name: String }
struct Guest;
struct Manager { name: String, team: String }
"#;

    let pattern_file = temp_dir.path().join("patterns.rs");
    fs::write(&pattern_file, pattern_code)?;

    let mut analyzer = CodebaseAnalyzer::new()?;
    let analysis_result = analyzer.analyze_file(&pattern_file)?;

    let refactoring_engine = SmartRefactoringEngine::new();
    let result = refactoring_engine.analyze(&analysis_result)?;

    // Verify pattern recommendations
    assert!(!result.pattern_recommendations.is_empty(), "Should recommend design patterns");
    
    // Check for Factory pattern recommendation
    let factory_patterns: Vec<_> = result.pattern_recommendations.iter()
        .filter(|rec| matches!(rec.pattern_type, PatternType::Creational))
        .collect();
    assert!(!factory_patterns.is_empty(), "Should recommend Factory pattern");

    // Check for Observer pattern recommendation
    let observer_patterns: Vec<_> = result.pattern_recommendations.iter()
        .filter(|rec| matches!(rec.pattern_type, PatternType::Behavioral))
        .collect();
    assert!(!observer_patterns.is_empty(), "Should recommend Observer pattern");

    Ok(())
}

/// Test modernization suggestions
#[test]
fn test_modernization_suggestions() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap;
    use rust_tree_sitter::{AnalysisResult, FileInfo, AnalysisConfig};

    let temp_dir = TempDir::new()?;

    // Create code with outdated patterns
    let outdated_code = r#"
// Old-style error handling
fn risky_operation() -> i32 {
    let result = some_operation().unwrap(); // Should use expect() or proper error handling
    let value = another_operation().unwrap();
    result + value
}

// Old-style string formatting
fn format_message(name: &str, age: i32, city: &str) -> String {
    format!("Hello {} aged {} from {}", name, age, city) // Should use named parameters
}

fn some_operation() -> Result<i32, &'static str> { Ok(42) }
fn another_operation() -> Result<i32, &'static str> { Ok(24) }
"#;

    let outdated_file = temp_dir.path().join("outdated.rs");
    fs::write(&outdated_file, outdated_code)?;

    // Create analysis result manually to ensure correct paths
    let file_info = FileInfo {
        path: PathBuf::from("outdated.rs"), // Relative path
        language: "Rust".to_string(),
        size: outdated_code.len(),
        lines: outdated_code.lines().count(),
        parsed_successfully: true,
        parse_errors: Vec::new(),
        symbols: Vec::new(),
        security_vulnerabilities: Vec::new(),
    };

    let analysis_result = AnalysisResult {
        root_path: temp_dir.path().to_path_buf(), // Root path
        total_files: 1,
        parsed_files: 1,
        error_files: 0,
        total_lines: outdated_code.lines().count(),
        languages: {
            let mut map = HashMap::new();
            map.insert("Rust".to_string(), 1);
            map
        },
        files: vec![file_info],
        config: AnalysisConfig::default(),
    };

    let refactoring_engine = SmartRefactoringEngine::new();
    let result = refactoring_engine.analyze(&analysis_result)?;

    // Verify modernization suggestions
    assert!(!result.modernization_suggestions.is_empty(), "Should suggest modernizations");

    // Check for error handling modernization
    let error_handling: Vec<_> = result.modernization_suggestions.iter()
        .filter(|sug| matches!(sug.modernization_type, ModernizationType::BestPractices))
        .collect();
    assert!(!error_handling.is_empty(), "Should suggest better error handling");

    // Check for syntax modernization
    let syntax_modern: Vec<_> = result.modernization_suggestions.iter()
        .filter(|sug| matches!(sug.modernization_type, ModernizationType::ModernSyntax))
        .collect();
    assert!(!syntax_modern.is_empty(), "Should suggest modern syntax");

    Ok(())
}

#[test]
fn test_modernization_suggestions_simple() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap;
    use rust_tree_sitter::{AnalysisResult, FileInfo, AnalysisConfig};

    let temp_dir = TempDir::new()?;

    // Create code with outdated patterns
    let outdated_code = r#"
fn risky_operation() -> i32 {
    let result = some_operation().unwrap();
    result
}

fn format_message(name: &str) -> String {
    format!("Hello {}", name)
}

fn some_operation() -> Result<i32, &'static str> { Ok(42) }
"#;

    let outdated_file = temp_dir.path().join("outdated.rs");
    fs::write(&outdated_file, outdated_code)?;

    // Create analysis result manually to ensure correct paths
    let file_info = FileInfo {
        path: PathBuf::from("outdated.rs"), // Relative path
        language: "Rust".to_string(),
        size: outdated_code.len(),
        lines: outdated_code.lines().count(),
        parsed_successfully: true,
        parse_errors: Vec::new(),
        symbols: Vec::new(),
        security_vulnerabilities: Vec::new(),
    };

    let analysis_result = AnalysisResult {
        root_path: temp_dir.path().to_path_buf(), // Root path
        total_files: 1,
        parsed_files: 1,
        error_files: 0,
        total_lines: outdated_code.lines().count(),
        languages: {
            let mut map = HashMap::new();
            map.insert("Rust".to_string(), 1);
            map
        },
        files: vec![file_info],
        config: AnalysisConfig::default(),
    };

    let refactoring_engine = SmartRefactoringEngine::new();
    let result = refactoring_engine.analyze(&analysis_result)?;

    // Verify modernization suggestions
    assert!(!result.modernization_suggestions.is_empty(), "Should suggest modernizations");

    // Check for error handling modernization
    let error_handling: Vec<_> = result.modernization_suggestions.iter()
        .filter(|sug| matches!(sug.modernization_type, ModernizationType::BestPractices))
        .collect();
    assert!(!error_handling.is_empty(), "Should suggest better error handling");

    Ok(())
}
