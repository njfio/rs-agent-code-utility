//! Stats command implementation

use std::path::PathBuf;
use crate::cli::error::{CliResult, validate_path};
use crate::cli::utils::create_progress_bar;
use crate::AnalysisResult;
use std::collections::HashMap;

#[derive(Debug)]
struct CodebaseStats {
    total_files: usize,
    total_lines: usize,
    total_size: u64,
    languages: HashMap<String, LanguageStats>,
    largest_files: Vec<(PathBuf, u64)>,
    most_complex_files: Vec<(PathBuf, usize)>,
}

#[derive(Debug)]
struct LanguageStats {
    file_count: usize,
    line_count: usize,
    size_bytes: u64,
    symbol_count: usize,
}

pub fn execute(path: &PathBuf, top: usize) -> CliResult<()> {
    validate_path(path)?;
    
    let pb = create_progress_bar("Calculating statistics...");

    use crate::analyzer::CodebaseAnalyzer;

    // Initialize analyzer
    let mut analyzer = CodebaseAnalyzer::new()?;

    // Analyze the target path
    let analysis_result = if path.is_file() {
        analyzer.analyze_file(path)?
    } else {
        analyzer.analyze_directory(path)?
    };

    // Calculate statistics
    let stats = calculate_statistics(&analysis_result, top);

    pb.finish_with_message("Statistics complete!");

    // Output statistics
    output_statistics(&stats);
    
    Ok(())
}

fn calculate_statistics(analysis: &AnalysisResult, top: usize) -> CodebaseStats {
    let mut languages: HashMap<String, LanguageStats> = HashMap::new();
    let mut file_sizes: Vec<(PathBuf, u64)> = Vec::new();
    let mut file_complexity: Vec<(PathBuf, usize)> = Vec::new();

    let total_files = analysis.files.len();
    let total_lines = analysis.total_lines;
    let mut total_size = 0u64;

    for file in &analysis.files {
        total_size += file.size as u64;
        file_sizes.push((file.path.clone(), file.size as u64));
        file_complexity.push((file.path.clone(), file.symbols.len()));

        let lang_stats = languages.entry(file.language.clone()).or_insert(LanguageStats {
            file_count: 0,
            line_count: 0,
            size_bytes: 0,
            symbol_count: 0,
        });

        lang_stats.file_count += 1;
        lang_stats.line_count += file.lines;
        lang_stats.size_bytes += file.size as u64;
        lang_stats.symbol_count += file.symbols.len();
    }

    // Sort and take top N
    file_sizes.sort_by(|a, b| b.1.cmp(&a.1));
    file_sizes.truncate(top);

    file_complexity.sort_by(|a, b| b.1.cmp(&a.1));
    file_complexity.truncate(top);

    CodebaseStats {
        total_files,
        total_lines,
        total_size,
        languages,
        largest_files: file_sizes,
        most_complex_files: file_complexity,
    }
}

fn output_statistics(stats: &CodebaseStats) {
    println!("\n📊 Codebase Statistics");
    println!("═══════════════════════");

    // Overall stats
    println!("\n📈 Overall:");
    println!("   Total files: {}", stats.total_files);
    println!("   Total lines: {}", stats.total_lines);
    println!("   Total size: {:.2} MB", stats.total_size as f64 / 1_048_576.0);

    // Language breakdown
    println!("\n🔤 Languages:");
    let mut lang_vec: Vec<_> = stats.languages.iter().collect();
    lang_vec.sort_by(|a, b| b.1.file_count.cmp(&a.1.file_count));

    for (lang, lang_stats) in lang_vec {
        let percentage = (lang_stats.file_count as f64 / stats.total_files as f64) * 100.0;
        println!("   {}: {} files ({:.1}%), {} lines, {:.2} MB",
            lang,
            lang_stats.file_count,
            percentage,
            lang_stats.line_count,
            lang_stats.size_bytes as f64 / 1_048_576.0
        );
    }

    // Largest files
    if !stats.largest_files.is_empty() {
        println!("\n📁 Largest Files:");
        for (i, (path, size)) in stats.largest_files.iter().enumerate() {
            println!("   {}. {} ({:.2} KB)",
                i + 1,
                path.display(),
                *size as f64 / 1024.0
            );
        }
    }

    // Most complex files (by symbol count)
    if !stats.most_complex_files.is_empty() {
        println!("\n🧩 Most Complex Files (by symbol count):");
        for (i, (path, symbols)) in stats.most_complex_files.iter().enumerate() {
            println!("   {}. {} ({} symbols)",
                i + 1,
                path.display(),
                symbols
            );
        }
    }
}
