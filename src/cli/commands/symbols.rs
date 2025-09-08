//! Symbols command implementation with enhanced output formatting

use crate::cli::error::{validate_path, CliError, CliResult};
use crate::cli::output::{
    print_enhanced_header, print_info, print_success, OutputFormat, OutputHandler, SymbolRow,
};
use crate::cli::utils::create_progress_bar;
use crate::{CodebaseAnalyzer, Symbol};
use colored::Colorize;
use serde_json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tabled::Table;

pub fn execute(path: &PathBuf, format: &str) -> CliResult<()> {
    validate_path(path)?;

    let pb = create_progress_bar("Extracting symbols...");

    // Analyze the codebase to extract symbols
    let mut analyzer = CodebaseAnalyzer::new().map_err(|e| CliError::Analysis(e.to_string()))?;
    let analysis_result = analyzer
        .analyze_directory(path)
        .map_err(|e| CliError::Analysis(e.to_string()))?;

    pb.finish_with_message("Symbol extraction complete!");

    // Collect all symbols from all files (deterministic order)
    let mut all_symbols: Vec<(Symbol, String)> = Vec::new();
    for file in &analysis_result.files {
        for symbol in &file.symbols {
            all_symbols.push((symbol.clone(), file.path.to_string_lossy().to_string()));
        }
    }
    // Sort by file path, then by line, then by name
    all_symbols.sort_by(
        |(a_sym, a_file), (b_sym, b_file)| match a_file.cmp(b_file) {
            std::cmp::Ordering::Equal => match a_sym.start_line.cmp(&b_sym.start_line) {
                std::cmp::Ordering::Equal => a_sym.name.cmp(&b_sym.name),
                other => other,
            },
            other => other,
        },
    );

    // Parse output format
    let output_format =
        OutputFormat::from_str(format).map_err(|e| CliError::UnsupportedFormat(e))?;

    let output_handler = OutputHandler::new(output_format.clone(), None, true);

    print_enhanced_header(
        "🔧 SYMBOL ANALYSIS",
        Some(&format!(
            "Found {} symbols across {} files",
            all_symbols.len(),
            analysis_result.files.len()
        )),
        "blue",
    );

    match output_format {
        OutputFormat::Json => {
            // Group symbols by file for JSON output with deterministic key order
            let mut symbols_by_file: BTreeMap<String, Vec<&Symbol>> = BTreeMap::new();
            for (symbol, file_path) in &all_symbols {
                symbols_by_file
                    .entry(file_path.clone())
                    .or_default()
                    .push(symbol);
            }
            let json = serde_json::to_string_pretty(&symbols_by_file)?;
            println!("{}", json);
        }
        OutputFormat::Table => {
            if all_symbols.is_empty() {
                print_info("No symbols found in the specified path");
                return Ok(());
            }

            // Convert to enhanced table rows
            let rows: Vec<SymbolRow> = all_symbols
                .iter()
                .map(|(symbol, file_path)| SymbolRow {
                    name: symbol.name.clone(),
                    kind: symbol.kind.clone(),
                    file: file_path.clone(),
                    line: symbol.start_line.to_string(),
                    visibility: symbol.visibility.clone(),
                })
                .collect();

            let table = Table::new(rows);
            println!("\n{}", table);

            // Enhanced summary with symbol type breakdown
            println!("\n{}", "SYMBOL SUMMARY".bright_yellow().bold());
            println!("{}", "─".repeat(40));

            let mut symbol_types = std::collections::HashMap::new();
            for (symbol, _) in &all_symbols {
                *symbol_types.entry(&symbol.kind).or_insert(0) += 1;
            }

            let mut type_vec: Vec<_> = symbol_types.into_iter().collect();
            type_vec.sort_by(|a, b| b.1.cmp(&a.1));

            for (kind, count) in type_vec.iter().take(10) {
                let percentage = (*count as f64 / all_symbols.len() as f64) * 100.0;
                let icon = match kind.to_lowercase().as_str() {
                    "function" => "*",
                    "class" | "struct" => "+",
                    "method" => "~",
                    "variable" => "-",
                    _ => "o",
                };
                println!("  {} {}: {} ({:.1}%)", icon, kind, count, percentage);
            }

            if type_vec.len() > 10 {
                println!("  ... and {} more types", type_vec.len() - 10);
            }
        }
        OutputFormat::Markdown => {
            let mut md = String::from("# Symbol Analysis Report\n\n");
            md.push_str(&format!("**Total Symbols:** {}\n\n", all_symbols.len()));

            if !all_symbols.is_empty() {
                md.push_str("## Symbols by File\n\n");

                let mut current_file = String::new();
                for (symbol, file_path) in &all_symbols {
                    if *file_path != current_file {
                        if !current_file.is_empty() {
                            md.push_str("\n");
                        }
                        md.push_str(&format!("### {}\n\n", file_path));
                        md.push_str("| Symbol | Type | Line | Visibility |\n");
                        md.push_str("|--------|------|------|------------|\n");
                        current_file = file_path.clone();
                    }
                    md.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        symbol.name, symbol.kind, symbol.start_line, symbol.visibility
                    ));
                }
            }

            println!("{}", md);
        }
        OutputFormat::Csv => {
            println!("Symbol,Type,File,Line,Visibility");
            for (symbol, file_path) in &all_symbols {
                println!(
                    "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
                    symbol.name.replace("\"", "\"\""),
                    symbol.kind,
                    file_path.replace("\"", "\"\""),
                    symbol.start_line,
                    symbol.visibility
                );
            }
        }
        _ => {
            // For other formats, use the table format
            if all_symbols.is_empty() {
                print_info("No symbols found in the specified path");
                return Ok(());
            }

            let rows: Vec<SymbolRow> = all_symbols
                .iter()
                .map(|(symbol, file_path)| SymbolRow {
                    name: symbol.name.clone(),
                    kind: symbol.kind.clone(),
                    file: file_path.clone(),
                    line: symbol.start_line.to_string(),
                    visibility: symbol.visibility.clone(),
                })
                .collect();

            let table = Table::new(rows);
            println!("{}", table);
        }
    }

    print_success(&format!(
        "Successfully analyzed {} symbols",
        all_symbols.len()
    ));
    Ok(())
}
