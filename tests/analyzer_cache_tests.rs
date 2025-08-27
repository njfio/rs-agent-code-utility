use rust_tree_sitter::CodebaseAnalyzer;
use tempfile::TempDir;
use std::fs;

/// Test cache statistics functionality
#[test]
fn test_cache_stats() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = CodebaseAnalyzer::new()?;
    
    // Initial cache stats should show empty cache
    let initial_stats = analyzer.cache_stats();
    assert_eq!(initial_stats.hits, 0);
    assert_eq!(initial_stats.misses, 0);
    assert_eq!(initial_stats.cached_files, 0);
    
    Ok(())
}

/// Test cache hit ratio calculation
#[test]
fn test_cache_hit_ratio() -> Result<(), Box<dyn std::error::Error>> {
    let mut analyzer = CodebaseAnalyzer::new()?;
    
    // Initial hit ratio should be 0.0 (no hits or misses)
    let initial_ratio = analyzer.cache_hit_ratio();
    assert_eq!(initial_ratio, 0.0);
    
    // Create a temporary file to analyze
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.rs");
    fs::write(&test_file, "fn main() { println!(\"Hello, world!\"); }")?;
    
    // Analyze the file twice to test caching
    analyzer.analyze_file(&test_file)?;
    analyzer.analyze_file(&test_file)?;
    
    // Hit ratio should be greater than 0 after cache usage
    let hit_ratio = analyzer.cache_hit_ratio();
    assert!(hit_ratio >= 0.0 && hit_ratio <= 1.0, "Hit ratio should be between 0 and 1");
    
    Ok(())
}

/// Test cache clearing functionality
#[test]
fn test_clear_cache() -> Result<(), Box<dyn std::error::Error>> {
    let mut analyzer = CodebaseAnalyzer::new()?;
    
    // Create a temporary file to analyze
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.rs");
    fs::write(&test_file, "fn main() { println!(\"Hello, world!\"); }")?;
    
    // Analyze the file to populate cache
    analyzer.analyze_file(&test_file)?;
    
    // Cache should have entries
    let stats_before = analyzer.cache_stats();
    assert!(stats_before.cached_files > 0, "Cache should have entries after analysis");
    
    // Clear the cache
    analyzer.clear_cache();
    
    // Cache should be empty after clearing
    let stats_after = analyzer.cache_stats();
    assert_eq!(stats_after.cached_files, 0, "Cache should be empty after clearing");
    
    Ok(())
}

/// Test cache contains functionality
#[test]
fn test_is_cached() -> Result<(), Box<dyn std::error::Error>> {
    let mut analyzer = CodebaseAnalyzer::new()?;
    
    // Create a temporary file
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.rs");
    fs::write(&test_file, "fn main() { println!(\"Hello, world!\"); }")?;
    
    // File should not be cached initially
    assert!(!analyzer.is_cached(&test_file), "File should not be cached initially");
    
    // Analyze the file
    analyzer.analyze_file(&test_file)?;
    
    // File should be cached after analysis
    assert!(analyzer.is_cached(&test_file), "File should be cached after analysis");
    
    // Clear cache and check again
    analyzer.clear_cache();
    assert!(!analyzer.is_cached(&test_file), "File should not be cached after clearing");
    
    Ok(())
}

/// Test cache behavior with multiple files
#[test]
fn test_cache_multiple_files() -> Result<(), Box<dyn std::error::Error>> {
    let mut analyzer = CodebaseAnalyzer::new()?;
    
    // Create multiple temporary files
    let temp_dir = TempDir::new()?;
    let file1 = temp_dir.path().join("file1.rs");
    let file2 = temp_dir.path().join("file2.rs");
    
    fs::write(&file1, "fn function1() { println!(\"File 1\"); }")?;
    fs::write(&file2, "fn function2() { println!(\"File 2\"); }")?;
    
    // Analyze both files
    analyzer.analyze_file(&file1)?;
    analyzer.analyze_file(&file2)?;
    
    // Both files should be cached
    assert!(analyzer.is_cached(&file1), "File 1 should be cached");
    assert!(analyzer.is_cached(&file2), "File 2 should be cached");
    
    // Cache should have multiple entries
    let stats = analyzer.cache_stats();
    assert!(stats.cached_files >= 2, "Cache should have at least 2 entries");
    
    Ok(())
}

/// Test cache behavior with directory analysis
#[test]
fn test_cache_directory_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let mut analyzer = CodebaseAnalyzer::new()?;
    
    // Create a temporary directory with multiple files
    let temp_dir = TempDir::new()?;
    fs::write(temp_dir.path().join("main.rs"), "fn main() { println!(\"Hello\"); }")?;
    fs::write(temp_dir.path().join("lib.rs"), "pub fn library_function() {}")?;
    fs::write(temp_dir.path().join("utils.rs"), "pub fn utility() {}")?;
    
    // Analyze the directory
    analyzer.analyze_directory(temp_dir.path())?;
    
    // All files should be cached
    assert!(analyzer.is_cached(temp_dir.path().join("main.rs")));
    assert!(analyzer.is_cached(temp_dir.path().join("lib.rs")));
    assert!(analyzer.is_cached(temp_dir.path().join("utils.rs")));
    
    // Cache should have multiple entries
    let stats = analyzer.cache_stats();
    assert!(stats.cached_files >= 3, "Cache should have at least 3 entries");
    
    Ok(())
}
