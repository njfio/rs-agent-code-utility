//! Codebase analysis example for AI code agents
//! 
//! This example demonstrates how to analyze an entire codebase and extract
//! structured information about the code for AI agents to understand.

use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig, AnalysisDepth};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Rust Tree-sitter Library - Codebase Analysis Example ===\n");

    // Get the directory to analyze from command line arguments
    let args: Vec<String> = env::args().collect();
    let target_dir = if args.len() > 1 {
        &args[1]
    } else {
        "." // Default to current directory
    };

    println!("Analyzing codebase in: {}", target_dir);

    // Create analyzer with custom configuration
    let config = AnalysisConfig {
        max_file_size: Some(500 * 1024), // 500KB max file size
        include_extensions: None, // Include all supported languages
        exclude_extensions: vec![
            "exe", "bin", "so",
            "png", "jpg", "pdf",
            "zip", "tar", "gz",
        ].into_iter().map(String::from).collect(),
        exclude_dirs: vec![
            ".git", "node_modules", "target",
            ".vscode", ".idea", "build",
            "dist", "__pycache__",
        ].into_iter().map(String::from).collect(),
        follow_symlinks: false,
        max_depth: Some(10),
        include_hidden: false,
        depth: AnalysisDepth::Full,
        enable_parallel: true,
        parallel_threshold: 10,
        thread_count: None,
        enable_security: false,
    };

    let mut analyzer = CodebaseAnalyzer::with_config(config)?;

    // Analyze the directory
    println!("Starting analysis...\n");
    let start_time = std::time::Instant::now();

    let result = analyzer.analyze_directory(target_dir)?;
    
    let analysis_time = start_time.elapsed();
    println!("Analysis completed in {:?}\n", analysis_time);

    // Print summary statistics
    println!("=== Analysis Summary ===");
    println!("Root directory: {}", result.root_path.display());
    println!("Total files processed: {}", result.total_files);
    println!("Successfully parsed: {}", result.parsed_files);
    println!("Files with errors: {}", result.error_files);
    println!("Total lines of code: {}", result.total_lines);
    println!();

    // Print language breakdown
    println!("=== Language Breakdown ===");
    let mut languages: Vec<_> = result.languages.iter().collect();
    languages.sort_by(|a, b| b.1.cmp(a.1)); // Sort by file count descending
    
    for (language, count) in languages {
        let percentage = (*count as f64 / result.total_files as f64) * 100.0;
        println!("  {}: {} files ({:.1}%)", language, count, percentage);
    }
    println!();

    // Print detailed file information
    println!("=== File Details ===");
    for file_info in &result.files {
        println!("📁 {}", file_info.path.display());
        println!("   Language: {}", file_info.language);
        println!("   Size: {} bytes, {} lines", file_info.size, file_info.lines);
        println!("   Parsed: {}", if file_info.parsed_successfully { "✅" } else { "❌" });
        
        if !file_info.parse_errors.is_empty() {
            println!("   Parse errors:");
            for error in &file_info.parse_errors {
                println!("     - {}", error);
            }
        }
        
        if !file_info.symbols.is_empty() {
            println!("   Symbols found: {}", file_info.symbols.len());
            for symbol in &file_info.symbols {
                println!("     - {} {} '{}' at line {}",
                    symbol.visibility, symbol.kind, symbol.name, symbol.start_line);
            }
        }
        println!();
    }

    // Print symbol summary
    println!("=== Symbol Summary ===");
    let mut symbol_counts = std::collections::HashMap::new();
    let mut public_symbols = 0;
    let mut private_symbols = 0;

    for file_info in &result.files {
        for symbol in &file_info.symbols {
            *symbol_counts.entry(symbol.kind.clone()).or_insert(0) += 1;
            if symbol.visibility == "public" {
                public_symbols += 1;
            } else {
                private_symbols += 1;
            }
        }
    }

    let mut symbol_types: Vec<_> = symbol_counts.iter().collect();
    symbol_types.sort_by(|a, b| b.1.cmp(a.1));

    for (symbol_type, count) in symbol_types {
        println!("  {}: {}", symbol_type, count);
    }
    println!("  Public symbols: {}", public_symbols);
    println!("  Private symbols: {}", private_symbols);
    println!();

    // Generate AI-friendly summary
    println!("=== AI Agent Summary ===");
    println!("This codebase contains {} files across {} languages.", 
        result.total_files, result.languages.len());
    
    if let Some((main_language, main_count)) = result.languages.iter()
        .max_by_key(|(_, count)| *count) {
        println!("The primary language is {} with {} files.", main_language, main_count);
    }

    let total_symbols: usize = result.files.iter()
        .map(|f| f.symbols.len())
        .sum();
    
    println!("The codebase defines {} symbols total.", total_symbols);
    
    if public_symbols > 0 {
        println!("There are {} public APIs available for external use.", public_symbols);
    }

    let error_rate = (result.error_files as f64 / result.total_files as f64) * 100.0;
    if error_rate > 0.0 {
        println!("Parse error rate: {:.1}% ({} files)", error_rate, result.error_files);
    } else {
        println!("All files parsed successfully! ✅");
    }

    // Show largest files
    let mut files_by_size: Vec<_> = result.files.iter().collect();
    files_by_size.sort_by(|a, b| b.size.cmp(&a.size));
    
    println!("\nLargest files:");
    for file_info in files_by_size.iter().take(5) {
        println!("  {} ({} bytes, {} lines)", 
            file_info.path.display(), file_info.size, file_info.lines);
    }

    // Show most complex files (by symbol count)
    let mut files_by_complexity: Vec<_> = result.files.iter().collect();
    files_by_complexity.sort_by(|a, b| b.symbols.len().cmp(&a.symbols.len()));
    
    println!("\nMost complex files (by symbol count):");
    for file_info in files_by_complexity.iter().take(5) {
        if file_info.symbols.len() > 0 {
            println!("  {} ({} symbols)", 
                file_info.path.display(), file_info.symbols.len());
        }
    }

    println!("\n=== Analysis Complete ===");
    println!("This structured data can be used by AI agents to understand the codebase structure,");
    println!("identify key components, and make informed decisions about code modifications.");

    Ok(())
}
