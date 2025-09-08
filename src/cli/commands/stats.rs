//! Stats command implementation with enhanced output formatting

use colored::Colorize;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::cli::error::{validate_path, CliResult};
use crate::cli::output::{print_enhanced_header, print_success};
use crate::cli::utils::create_progress_bar;
use crate::{AnalysisResult, CodebaseAnalyzer};

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

    // Output enhanced statistics
    output_enhanced_statistics(&stats, &analysis_result);

    print_success(&format!(
        "Statistics calculated for {} files with {} lines of code",
        stats.total_files, stats.total_lines
    ));

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

        let lang_stats = languages
            .entry(file.language.clone())
            .or_insert(LanguageStats {
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

fn output_enhanced_statistics(stats: &CodebaseStats, analysis: &AnalysisResult) {
    print_enhanced_header("📊 CODEBASE STATISTICS", None, "cyan");

    // Overall statistics with enhanced formatting
    println!("{}", "📈 OVERALL METRICS".bright_yellow().bold());
    println!("{}", "─".repeat(50));

    println!(
        "   Files analyzed: {}",
        stats.total_files.to_string().bright_white()
    );
    println!(
        "   Total lines: {}",
        stats.total_lines.to_string().bright_white()
    );
    println!(
        "   Total size: {:.2} MB",
        stats.total_size as f64 / 1_048_576.0
    );

    let total_symbols: usize = stats.languages.values().map(|l| l.symbol_count).sum();
    if total_symbols > 0 {
        println!(
            "   Total symbols: {}",
            total_symbols.to_string().bright_white()
        );
    }

    // Language breakdown with progress bars
    if !stats.languages.is_empty() {
        println!("\n{}", "🔤 LANGUAGE BREAKDOWN".bright_yellow().bold());
        println!("{}", "─".repeat(50));

        let mut lang_vec: Vec<_> = stats.languages.iter().collect();
        lang_vec.sort_by(|a, b| b.1.file_count.cmp(&a.1.file_count));

        for (lang, lang_stats) in lang_vec.iter().take(8) {
            let percentage = (lang_stats.file_count as f64 / stats.total_files as f64) * 100.0;

            // Create a simple progress bar
            let progress_width = 20;
            let filled = ((percentage / 100.0) * progress_width as f64) as usize;
            let progress_bar = format!(
                "[{}{}] {:.1}%",
                "█".repeat(filled).bright_green(),
                "░".repeat(progress_width - filled).bright_black(),
                percentage
            );

            println!(
                "   {}: {} files, {} lines {}",
                lang.bright_blue().bold(),
                lang_stats.file_count.to_string().bright_white(),
                lang_stats.line_count.to_string().bright_white(),
                progress_bar
            );
        }

        if lang_vec.len() > 8 {
            println!("   ... and {} more languages", lang_vec.len() - 8);
        }
    }

    // File analysis insights
    println!("\n{}", "📁 FILE ANALYSIS".bright_yellow().bold());
    println!("{}", "─".repeat(50));

    // Largest files
    if !stats.largest_files.is_empty() {
        println!("   {}", "Largest Files:".bright_cyan());
        for (i, (path, size)) in stats.largest_files.iter().take(5).enumerate() {
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            let size_kb = *size as f64 / 1024.0;
            println!(
                "     {}. {} ({:.1} KB)",
                i + 1,
                file_name.bright_white(),
                size_kb
            );
        }
    }

    // Most complex files
    if !stats.most_complex_files.is_empty() {
        println!("   {}", "Most Complex Files:".bright_cyan());
        for (i, (path, symbols)) in stats.most_complex_files.iter().take(5).enumerate() {
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            println!(
                "     {}. {} ({} symbols)",
                i + 1,
                file_name.bright_white(),
                symbols.to_string().bright_green()
            );
        }
    }

    // Parse success rate
    let successful_parses = analysis
        .files
        .iter()
        .filter(|f| f.parsed_successfully)
        .count();
    let success_rate = (successful_parses as f64 / stats.total_files as f64) * 100.0;

    println!("   {}", "Parse Success Rate:".bright_cyan());
    if success_rate >= 95.0 {
        println!(
            "     {:.1}% {}",
            success_rate,
            "✅ Excellent".bright_green()
        );
    } else if success_rate >= 80.0 {
        println!("     {:.1}% {}", success_rate, "⚠️ Good".bright_yellow());
    } else {
        println!(
            "     {:.1}% {}",
            success_rate,
            "❌ Needs attention".bright_red()
        );
    }

    // Recommendations
    if success_rate < 100.0 {
        let failed_files = stats.total_files - successful_parses;
        println!("\n{}", "💡 RECOMMENDATIONS".bright_yellow().bold());
        println!("{}", "─".repeat(50));
        println!("   {} files failed to parse completely", failed_files);
        println!("   Consider checking file encodings or syntax errors");
    }

    if stats.languages.len() > 5 {
        println!("   Consider breaking down large codebases by language");
    }
}
