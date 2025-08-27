//! Symbols command implementation

use std::path::PathBuf;
use std::collections::BTreeMap;
use crate::cli::error::{CliResult, validate_path, CliError};
use crate::cli::utils::create_progress_bar;
use crate::cli::output::{OutputFormat, SymbolRow};
use crate::{CodebaseAnalyzer, Symbol};
use tabled::Table;
use serde_json;

pub fn execute(path: &PathBuf, format: &str) -> CliResult<()> {
    validate_path(path)?;

    let pb = create_progress_bar("Extracting symbols...");

    // Analyze the codebase to extract symbols
    let mut analyzer = CodebaseAnalyzer::new()
        .map_err(|e| CliError::Analysis(e.to_string()))?;
    let analysis_result = analyzer.analyze_directory(path)
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
    all_symbols.sort_by(|(a_sym, a_file), (b_sym, b_file)| {
        match a_file.cmp(b_file) {
            std::cmp::Ordering::Equal => match a_sym.start_line.cmp(&b_sym.start_line) {
                std::cmp::Ordering::Equal => a_sym.name.cmp(&b_sym.name),
                other => other,
            },
            other => other,
        }
    });

    // Parse output format
    let output_format = OutputFormat::from_str(format)
        .map_err(|e| CliError::UnsupportedFormat(e))?;

    match output_format {
        OutputFormat::Json => {
            // Group symbols by file for JSON output with deterministic key order
            let mut symbols_by_file: BTreeMap<String, Vec<&Symbol>> = BTreeMap::new();
            for (symbol, file_path) in &all_symbols {
                symbols_by_file.entry(file_path.clone()).or_default().push(symbol);
            }
            let json = serde_json::to_string_pretty(&symbols_by_file)?;
            println!("{}", json);
        }
        OutputFormat::Table | _ => {
            if all_symbols.is_empty() {
                println!("No symbols found in {}", path.display());
                return Ok(());
            }

            // Convert to table rows
            let rows: Vec<SymbolRow> = all_symbols.iter().map(|(symbol, file_path)| {
                SymbolRow {
                    name: symbol.name.clone(),
                    kind: symbol.kind.clone(),
                    file: file_path.clone(),
                    line: symbol.start_line,
                    visibility: symbol.visibility.clone(),
                }
            }).collect();

            let table = Table::new(rows);
            println!("{}", table);

            println!("\nSummary: {} symbols found across {} files",
                all_symbols.len(),
                analysis_result.files.len()
            );
        }
    }

    Ok(())
}
