//! Analyze command implementation
//!
//! Provides comprehensive codebase analysis with standardized output formats.
#![allow(clippy::too_many_arguments)]

use crate::cli::error::{validate_path, CliError, CliResult};
use crate::cli::output::{OutputFormat, OutputHandler};
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
    include_graph: bool,
) -> CliResult<()> {
    // Validate inputs
    validate_path(path)?;

    // Validate format using OutputFormat::from_str for comprehensive validation
    if OutputFormat::from_str(format).is_err() {
        return Err(CliError::UnsupportedFormat(format.to_string()));
    }

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
    if include_graph {
        analyzer.enable_semantic_graph();
    }

    // Run analysis
    pb.set_message("Running analysis...");
    let result = analyzer
        .analyze_directory(path)
        .map_err(|e| CliError::Analysis(e.to_string()))?;
    let semantic_graph = if include_graph {
        analyzer.semantic_graph().map(|graph| graph.snapshot())
    } else {
        None
    };

    // Display results using the enhanced output system
    let output_format = OutputFormat::from_str(format).map_err(CliError::UnsupportedFormat)?;

    // Create output handler for consistent formatting
    let output_handler = OutputHandler::new(output_format.clone(), output.cloned(), true);

    // Handle progress bar based on output format
    match &output_format {
        // Structured formats - suppress informational output
        OutputFormat::Json
        | OutputFormat::Sarif
        | OutputFormat::CodeClimate
        | OutputFormat::Csv => {
            pb.finish_and_clear();
        }
        // Human-readable formats - show completion message
        _ => {
            pb.finish_with_message("Analysis complete!");
        }
    }

    // Use OutputHandler for standard output; graph-aware JSON is handled inline.
    if output_format == OutputFormat::Json && semantic_graph.is_some() {
        let mut json = serde_json::to_value(&result).map_err(|e| {
            CliError::Internal(format!("Failed to serialize analysis result: {}", e))
        })?;
        if let Some(graph) = semantic_graph {
            json.as_object_mut()
                .ok_or_else(|| {
                    CliError::Internal(
                        "Analyze JSON output must serialize to an object".to_string(),
                    )
                })?
                .insert(
                    "semantic_graph".to_string(),
                    serde_json::to_value(graph).map_err(|e| {
                        CliError::Internal(format!(
                            "Failed to serialize semantic graph snapshot: {}",
                            e
                        ))
                    })?,
                );
        }

        let rendered = serde_json::to_string_pretty(&json).map_err(|e| {
            CliError::Internal(format!("Failed to render analysis JSON output: {}", e))
        })?;
        if let Some(output_path) = output {
            std::fs::write(output_path, rendered).map_err(CliError::Io)?;
        } else {
            println!("{}", rendered);
        }
    } else {
        output_handler
            .output_analysis_result(&result)
            .map_err(|e| CliError::Internal(e.to_string()))?;
    }

    // Print additional details if requested
    if detailed
        && !result.files.is_empty()
        && !matches!(
            output_format,
            OutputFormat::Json
                | OutputFormat::Sarif
                | OutputFormat::CodeClimate
                | OutputFormat::Csv
        )
    {
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
            false, // include_graph
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
            false, // include_graph
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
            false, // include_graph
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CliError::UnsupportedFormat(_)
        ));
    }
}
