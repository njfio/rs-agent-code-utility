//! Analyze command implementation
//!
//! Provides comprehensive codebase analysis with standardized output formats.

use crate::cli::error::{validate_format, validate_path, CliError, CliResult};
use crate::cli::output::{
    print_enhanced_summary, print_info, print_success, OutputFormat, OutputHandler,
};
use crate::cli::utils::{create_analysis_config, create_progress_bar, validate_output_path};
use crate::CodebaseAnalyzer;
use colored::Colorize;
use std::path::PathBuf;

/// Execute the analyze command
pub fn execute(
    path: &PathBuf,
    format: &str,
    max_size: usize,
    max_depth: usize,
    depth: &str,
    include_hidden: bool,
    exclude_dirs: Option<&String>,
    include_exts: Option<&String>,
    output: Option<&PathBuf>,
    detailed: bool,
    threads: Option<usize>,
    enable_security: bool,
) -> CliResult<()> {
    // Validate inputs
    validate_path(path)?;
    validate_format(format, &["table", "json", "summary", "sarif"])?;

    if let Some(output_path) = output {
        validate_output_path(output_path)?;
    }

    // Create progress bar
    let pb = create_progress_bar("Analyzing codebase...");
    pb.set_message("Scanning files...");

    // Configure analyzer
    let config = create_analysis_config(
        max_size,
        max_depth,
        depth,
        include_hidden,
        exclude_dirs.cloned(),
        include_exts.cloned(),
        threads,
        enable_security,
    )?;

    let mut analyzer =
        CodebaseAnalyzer::with_config(config).map_err(|e| CliError::Analysis(e.to_string()))?;

    // Run analysis
    pb.set_message("Running analysis...");
    let result = analyzer
        .analyze_directory(path)
        .map_err(|e| CliError::Analysis(e.to_string()))?;

    // Display results using the enhanced output system
    let output_format =
        OutputFormat::from_str(format).map_err(|e| CliError::UnsupportedFormat(e))?;

    // Finish progress bar and handle output based on format
    match output_format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Csv => {
            // Suppress all non-JSON output for structured formats
            pb.finish_and_clear();
            let output_handler = OutputHandler::new(output_format.clone(), output.cloned(), true);
            output_handler.output_analysis_result(&result)?;
        }
        OutputFormat::Table => {
            pb.finish_with_message("Analysis complete!");
            let output_handler = OutputHandler::new(output_format.clone(), output.cloned(), true);
            print_info(&format!(
                "Analysis completed successfully - {} files processed",
                result.files.len()
            ));
            print_enhanced_summary(&result);
            if let Some(output_path) = output {
                output_handler.output_analysis_result(&result)?;
            }
        }
        OutputFormat::Summary => {
            pb.finish_with_message("Analysis complete!");
            let output_handler = OutputHandler::new(output_format.clone(), output.cloned(), true);
            print_info(&format!(
                "Analysis completed successfully - {} files processed",
                result.files.len()
            ));
            print_enhanced_summary(&result);
            if let Some(output_path) = output {
                output_handler.output_analysis_result(&result)?;
            }
        }
        _ => {
            pb.finish_with_message("Analysis complete!");
            let output_handler = OutputHandler::new(output_format.clone(), output.cloned(), true);
            output_handler.output_analysis_result(&result)?;
        }
    }

    // Print additional details if requested
    if detailed && result.files.len() > 0 {
        println!("\n{}", "📋 DETAILED ANALYSIS".bright_yellow().bold());
        println!("{}", "─".repeat(50));

        let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
        let avg_symbols = total_symbols as f64 / result.files.len() as f64;
        let avg_lines = result.total_lines as f64 / result.files.len() as f64;

        println!("Average symbols per file: {:.1}", avg_symbols);
        println!("Average lines per file: {:.1}", avg_lines);

        // Show parsing statistics
        let successful_parses = result
            .files
            .iter()
            .filter(|f| f.parsed_successfully)
            .count();
        let success_rate = (successful_parses as f64 / result.files.len() as f64) * 100.0;
        println!("Parse success rate: {:.1}%", success_rate);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    #[test]
    fn test_analyze_command_validation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        // Test valid inputs
        let result = execute(
            &path, "table", 1024, 20, "full", false, None, None, None, false, None,
            false, // enable_security
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_analyze_command_invalid_path() {
        let invalid_path = PathBuf::from("/nonexistent/path");

        let result = execute(
            &invalid_path,
            "table",
            1024,
            20,
            "full",
            false,
            None,
            None,
            None,
            false,
            None,
            false, // enable_security
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CliError::InvalidPath(_)));
    }

    #[test]
    fn test_analyze_command_invalid_format() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let result = execute(
            &path,
            "invalid_format",
            1024,
            20,
            "full",
            false,
            None,
            None,
            None,
            false,
            None,
            false, // enable_security
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CliError::UnsupportedFormat(_)
        ));
    }
}
