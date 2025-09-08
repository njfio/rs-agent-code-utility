//! Symbols command implementation with enhanced output formatting

use crate::cli::error::{validate_path, CliError, CliResult};
use crate::cli::output::{OutputFormat, OutputHandler};
use crate::cli::utils::create_progress_bar;
use crate::{CodebaseAnalyzer, Symbol};
use std::path::PathBuf;

pub fn execute(path: &PathBuf, format: &str) -> CliResult<()> {
    validate_path(path)?;

    let pb = create_progress_bar("Extracting symbols...");

    // Analyze the codebase to extract symbols
    let mut analyzer = CodebaseAnalyzer::new().map_err(|e| CliError::Analysis(e.to_string()))?;
    let analysis_result = analyzer
        .analyze_directory(path)
        .map_err(|e| CliError::Analysis(e.to_string()))?;

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

    // Handle progress bar based on output format
    match output_format {
        // Structured formats - suppress informational output
        OutputFormat::Json | OutputFormat::Csv => {
            pb.finish_and_clear();
        }
        // Human-readable formats - show completion message
        _ => {
            pb.finish_with_message("Symbol extraction complete!");
        }
    }

    // Use the improved OutputHandler for consistent formatting
    let output_handler = OutputHandler::new(output_format.clone(), None, true);
    output_handler.output_symbols(&all_symbols, analysis_result.files.len())?;

    Ok(())
}
