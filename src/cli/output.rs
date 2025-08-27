//! Output formatting utilities for CLI commands
//! 
//! Provides consistent formatting across different output types (table, JSON, markdown).

use colored::*;
use tabled::{Table, Tabled};
use serde::Serialize;
use std::path::PathBuf;

/// Format file size in human-readable format
pub fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Table row for file information
#[derive(Tabled)]
pub struct FileRow {
    #[tabled(rename = "File")]
    pub path: String,
    #[tabled(rename = "Language")]
    pub language: String,
    #[tabled(rename = "Lines")]
    pub lines: usize,
    #[tabled(rename = "Size")]
    pub size: String,
    #[tabled(rename = "Symbols")]
    pub symbols: usize,
    #[tabled(rename = "Status")]
    pub status: String,
}

/// Table row for symbol information
#[derive(Tabled)]
pub struct SymbolRow {
    #[tabled(rename = "Symbol")]
    pub name: String,
    #[tabled(rename = "Type")]
    pub kind: String,
    #[tabled(rename = "File")]
    pub file: String,
    #[tabled(rename = "Line")]
    pub line: usize,
    #[tabled(rename = "Visibility")]
    pub visibility: String,
}

/// Table row for language statistics
#[derive(Tabled)]
pub struct LanguageRow {
    #[tabled(rename = "Language")]
    pub name: String,
    #[tabled(rename = "Files")]
    pub files: usize,
    #[tabled(rename = "Percentage")]
    pub percentage: String,
    #[tabled(rename = "Extensions")]
    pub extensions: String,
}

/// Output format options
#[derive(Debug, Clone)]
pub enum OutputFormat {
    Table,
    Json,
    Sarif,
    Markdown,
    Summary,
    Text,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "markdown" => Ok(OutputFormat::Markdown),
            "summary" => Ok(OutputFormat::Summary),
            "text" => Ok(OutputFormat::Text),
            _ => Err(format!("Unsupported format: {}", s)),
        }
    }
}

/// Print colored header
pub fn print_header(title: &str, color: &str) {
    let colored_title = match color {
        "blue" => title.bright_blue().bold(),
        "cyan" => title.bright_cyan().bold(),
        "green" => title.bright_green().bold(),
        "yellow" => title.bright_yellow().bold(),
        "red" => title.bright_red().bold(),
        _ => title.bright_white().bold(),
    };
    
    println!("\n{}", colored_title);
    println!("{}", "=".repeat(title.len()).color(color));
}

/// Print summary statistics
pub fn print_summary(result: &crate::AnalysisResult) {
    print_header("📊 CODEBASE SUMMARY", "cyan");
    
    println!("\n{}", "📁 Files".bright_yellow().bold());
    println!("Total files: {}", result.files.len().to_string().bright_white());
    println!("Total lines: {}", result.total_lines.to_string().bright_white());
    // Calculate total size from files
    let total_size: usize = result.files.iter().map(|f| f.size).sum();
    println!("Total size: {}", format_size(total_size).bright_white());
    
    if !result.languages.is_empty() {
        println!("\n{}", "🔤 Languages".bright_yellow().bold());
        let mut langs: Vec<_> = result.languages.iter().collect();
        langs.sort_by(|a, b| a.0.cmp(b.0));
        for (lang, count) in langs {
            let percentage = (*count as f64 / result.files.len() as f64) * 100.0;
            println!("  {}: {} files ({:.1}%)", 
                lang.bright_blue(),
                count.to_string().bright_white(),
                percentage.to_string().bright_green()
            );
        }
    }
    
    println!("\n{}", "🔍 Symbols".bright_yellow().bold());
    // Calculate total symbols from files
    let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
    println!("Total symbols: {}", total_symbols.to_string().bright_white());

    // Group symbols by type
    let mut symbol_counts = std::collections::HashMap::new();
    for file in &result.files {
        for symbol in &file.symbols {
            *symbol_counts.entry(&symbol.kind).or_insert(0) += 1;
        }
    }
    
    let mut symbol_vec: Vec<_> = symbol_counts.into_iter().collect();
    symbol_vec.sort_by(|a, b| a.0.cmp(b.0));
    for (kind, count) in symbol_vec {
        println!("  {}: {}", 
            kind.bright_blue(),
            count.to_string().bright_white()
        );
    }
}

/// Save output to file
pub fn save_to_file<T: Serialize>(data: &T, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(data)?;
    std::fs::write(path, json)?;
    println!("\n{}", format!("Results saved to {}", path.display()).green());
    Ok(())
}

/// Print analysis table
pub fn print_analysis_table(result: &crate::AnalysisResult, _detailed: bool) {
    print_header("🔍 ANALYSIS RESULTS", "blue");
    
    if result.files.is_empty() {
        println!("\n{}", "No files found to analyze.".yellow());
        return;
    }
    
    let mut file_rows = Vec::new();
    for file in &result.files {
        let symbol_count = file.symbols.len();
            
        file_rows.push(FileRow {
            path: file.path.to_string_lossy().to_string(),
            language: file.language.to_string(),
            lines: file.lines,
            size: format_size(file.size),
            symbols: symbol_count,
            status: if file.parsed_successfully { "✓".green().to_string() } else { "✗".red().to_string() },
        });
    }
    
    let table = Table::new(file_rows);
    println!("\n{}", table);
    
    // This section was already updated above in the detailed section
    
    print_summary(result);
}
