//! Analyze command implementation
//! 
//! Provides comprehensive codebase analysis with configurable output formats.

use std::path::PathBuf;
use crate::CodebaseAnalyzer;
use crate::cli::error::{CliError, CliResult, validate_path, validate_format};
use crate::cli::utils::{create_progress_bar, create_analysis_config, validate_output_path, print_success};
use crate::cli::output::{OutputFormat, print_analysis_table, print_summary, save_to_file};

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
    
    let mut analyzer = CodebaseAnalyzer::with_config(config)
        .map_err(|e| CliError::Analysis(e.to_string()))?;
    
    // Run analysis
    pb.set_message("Running analysis...");
    let result = analyzer.analyze_directory(path)
        .map_err(|e| CliError::Analysis(e.to_string()))?;
    
    pb.finish_with_message("Analysis complete!");
    
    // Display results based on format
    let output_format = OutputFormat::from_str(format)
        .map_err(|e| CliError::UnsupportedFormat(e))?;
    
    match output_format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&result)?;
            if let Some(output_path) = output {
                std::fs::write(output_path, &json)?;
                print_success(&format!("Results saved to {}", output_path.display()));
            } else {
                println!("{}", json);
            }
        }
        OutputFormat::Sarif => {
            let sarif = crate::cli::sarif::to_sarif(&result);
            let json = serde_json::to_string_pretty(&sarif)?;
            if let Some(output_path) = output {
                std::fs::write(output_path, &json)?;
                print_success(&format!("SARIF saved to {}", output_path.display()));
            } else {
                println!("{}", json);
            }
        }
        OutputFormat::Summary => {
            print_summary(&result);
            if let Some(output_path) = output {
                save_to_file(&result, output_path)?;
            }
        }
        OutputFormat::Table | _ => {
            print_analysis_table(&result, detailed);
            if let Some(output_path) = output {
                save_to_file(&result, output_path)?;
            }
        }
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
            &path,
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
        assert!(matches!(result.unwrap_err(), CliError::UnsupportedFormat(_)));
    }
}
