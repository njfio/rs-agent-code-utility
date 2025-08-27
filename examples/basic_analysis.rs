use rust_tree_sitter::CodebaseAnalyzer;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create analyzer with default configuration
    let mut analyzer = CodebaseAnalyzer::new()?;
    
    // Analyze a directory
    let path = PathBuf::from("./src");
    let result = analyzer.analyze_directory(&path)?;
    
    // Display basic statistics
    println!("=== Codebase Analysis Results ===");
    println!("Root path: {}", result.root_path.display());
    println!("Total files: {}", result.total_files);
    println!("Successfully parsed: {}", result.parsed_files);
    println!("Parse errors: {}", result.error_files);
    println!("Total lines of code: {}", result.total_lines);
    
    // Language breakdown
    println!("\n=== Language Breakdown ===");
    for (language, count) in &result.languages {
        println!("{}: {} files", language, count);
    }
    
    // File details
    println!("\n=== File Details ===");
    for file_info in &result.files {
        if file_info.parsed_successfully {
            println!("📁 {} ({} symbols, {} lines)", 
                     file_info.path.display(), 
                     file_info.symbols.len(),
                     file_info.lines);
        } else {
            println!("❌ {} (parse failed)", file_info.path.display());
            for error in &file_info.parse_errors {
                println!("   Error: {}", error);
            }
        }
    }
    
    // Symbol summary
    let total_symbols: usize = result.files.iter()
        .map(|f| f.symbols.len())
        .sum();
    
    println!("\n=== Symbol Summary ===");
    println!("Total symbols extracted: {}", total_symbols);
    
    // Group symbols by type
    let mut symbol_counts = std::collections::HashMap::new();
    for file_info in &result.files {
        for symbol in &file_info.symbols {
            *symbol_counts.entry(symbol.kind.clone()).or_insert(0) += 1;
        }
    }
    
    for (symbol_type, count) in symbol_counts {
        println!("{}: {}", symbol_type, count);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;
    
    #[test]
    fn test_basic_analysis() -> Result<(), Box<dyn std::error::Error>> {
        // Create temporary directory with test files
        let temp_dir = TempDir::new()?;
        let test_file = temp_dir.path().join("test.rs");
        
        fs::write(&test_file, r#"
            fn main() {
                println!("Hello, world!");
            }
            
            struct TestStruct {
                field: i32,
            }
            
            impl TestStruct {
                fn new(field: i32) -> Self {
                    Self { field }
                }
            }
        "#)?;
        
        // Analyze the temporary directory
        let mut analyzer = CodebaseAnalyzer::new()?;
        let result = analyzer.analyze_directory(temp_dir.path())?;
        
        // Verify results
        assert_eq!(result.total_files, 1);
        assert_eq!(result.parsed_files, 1);
        assert_eq!(result.error_files, 0);
        assert!(result.languages.contains_key("rust"));
        
        // Check symbols
        let file_info = &result.files[0];
        assert!(file_info.parsed_successfully);
        assert!(!file_info.symbols.is_empty());
        
        // Should find main function, struct, and impl
        let symbol_names: Vec<&String> = file_info.symbols.iter()
            .map(|s| &s.name)
            .collect();
        
        assert!(symbol_names.contains(&&"main".to_string()));
        assert!(symbol_names.contains(&&"TestStruct".to_string()));
        
        Ok(())
    }
    
    #[test]
    fn test_analysis_with_config() -> Result<(), Box<dyn std::error::Error>> {
        // Create analyzer with custom configuration
        let config = AnalysisConfig {
            max_file_size: Some(1024 * 1024), // 1MB
            include_patterns: vec!["*.rs".to_string()],
            exclude_patterns: vec!["*/target/*".to_string()],
            max_depth: Some(5),
            follow_symlinks: false,
            parse_comments: true,
            extract_documentation: true,
        };
        
        let mut analyzer = CodebaseAnalyzer::with_config(config)?;
        
        // Create test directory
        let temp_dir = TempDir::new()?;
        let src_dir = temp_dir.path().join("src");
        fs::create_dir(&src_dir)?;
        
        let test_file = src_dir.join("lib.rs");
        fs::write(&test_file, r#"
            /// This is a documented function
            pub fn documented_function() -> i32 {
                42
            }
            
            // This is a comment
            fn private_function() {
                // Implementation
            }
        "#)?;
        
        // Analyze with custom config
        let result = analyzer.analyze_directory(temp_dir.path())?;
        
        // Verify configuration was applied
        assert_eq!(result.total_files, 1);
        assert!(result.config.parse_comments);
        assert!(result.config.extract_documentation);
        
        Ok(())
    }
    
    #[test]
    fn test_multi_language_analysis() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        
        // Create files in different languages
        fs::write(temp_dir.path().join("test.rs"), "fn main() {}")?;
        fs::write(temp_dir.path().join("test.py"), "def main(): pass")?;
        fs::write(temp_dir.path().join("test.js"), "function main() {}")?;
        
        let mut analyzer = CodebaseAnalyzer::new()?;
        let result = analyzer.analyze_directory(temp_dir.path())?;
        
        // Should detect all three languages
        assert_eq!(result.total_files, 3);
        assert_eq!(result.languages.len(), 3);
        assert!(result.languages.contains_key("rust"));
        assert!(result.languages.contains_key("python"));
        assert!(result.languages.contains_key("javascript"));
        
        Ok(())
    }
}
