//! CLI utility functions
//! 
//! Shared utilities for CLI operations including progress bars, configuration, and validation.

use indicatif::{ProgressBar, ProgressStyle};
use colored::*;
use crate::{AnalysisConfig, AnalysisDepth};
use super::error::{CliError, CliResult};
use std::path::PathBuf;

/// Create a progress bar with spinner for long operations
pub fn create_progress_bar(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap()
    );
    pb.set_message(message.to_string());
    pb
}

/// Create analysis configuration from CLI arguments
pub fn create_analysis_config(
    max_size: usize,
    max_depth: usize,
    depth: &str,
    include_hidden: bool,
    exclude_dirs: Option<String>,
    include_exts: Option<String>,
    threads: Option<usize>,
    enable_security: bool,
) -> CliResult<AnalysisConfig> {
    let mut config = AnalysisConfig::default();
    
    config.max_file_size = Some(max_size * 1024);
    config.max_depth = Some(max_depth);
    config.include_hidden = include_hidden;
    
    // Parse analysis depth
    config.depth = match depth.to_lowercase().as_str() {
        "basic" => AnalysisDepth::Basic,
        "deep" => AnalysisDepth::Deep,
        "full" => AnalysisDepth::Full,
        _ => return Err(CliError::InvalidArgs(format!("Invalid depth: {}", depth))),
    };
    
    // Parse exclude directories
    if let Some(dirs) = exclude_dirs {
        config.exclude_dirs = dirs
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
    }
    
    // Parse include extensions
    if let Some(exts) = include_exts {
        config.include_extensions = Some(
            exts.split(',')
                .map(|s| s.trim().to_string())
                .collect()
        );
    }

    // Apply thread count if provided
    config.thread_count = threads;
    // Enable or disable heavy security scanning
    config.enable_security = enable_security;
    
    Ok(config)
}

/// Parse severity level from string
pub fn parse_severity(severity: &str) -> CliResult<crate::SecuritySeverity> {
    match severity.to_lowercase().as_str() {
        "critical" => Ok(crate::SecuritySeverity::Critical),
        "high" => Ok(crate::SecuritySeverity::High),
        "medium" => Ok(crate::SecuritySeverity::Medium),
        "low" => Ok(crate::SecuritySeverity::Low),
        "info" => Ok(crate::SecuritySeverity::Info),
        _ => Err(CliError::InvalidArgs(format!("Invalid severity level: {}", severity))),
    }
}

/// Check if severity meets threshold
pub fn severity_meets_threshold(
    threshold: &crate::SecuritySeverity,
    actual: &crate::SecuritySeverity,
) -> bool {
    use crate::SecuritySeverity::*;
    let rank = |s: &crate::SecuritySeverity| match s {
        Critical => 5,
        High => 4,
        Medium => 3,
        Low => 2,
        Info => 1,
    };
    rank(actual) >= rank(threshold)
}

/// Validate and normalize file path
pub fn normalize_path(path: &PathBuf) -> CliResult<PathBuf> {
    let canonical = path.canonicalize()
        .map_err(|_| CliError::InvalidPath(path.clone()))?;
    Ok(canonical)
}

/// Parse comma-separated list
pub fn parse_comma_separated(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Validate output directory exists or can be created
pub fn validate_output_path(path: &PathBuf) -> CliResult<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(CliError::Io)?;
        }
    }
    Ok(())
}

/// Get file extension from path
pub fn get_file_extension(path: &PathBuf) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_lowercase())
}

/// Check if file should be included based on extension filters
pub fn should_include_file(path: &PathBuf, include_exts: &Option<Vec<String>>) -> bool {
    if let Some(exts) = include_exts {
        if let Some(file_ext) = get_file_extension(path) {
            return exts.iter().any(|ext| ext.trim_start_matches('.') == file_ext);
        }
        return false;
    }
    true
}

/// Format duration in human-readable format
pub fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{:.1}s", duration.as_secs_f64())
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Print success message with checkmark
pub fn print_success(message: &str) {
    println!("{} {}", "✓".bright_green(), message.bright_white());
}

/// Print warning message
pub fn print_warning(message: &str) {
    println!("{} {}", "⚠".bright_yellow(), message.bright_yellow());
}

/// Print error message
pub fn print_error(message: &str) {
    eprintln!("{} {}", "✗".bright_red(), message.bright_red());
}

/// Print info message
pub fn print_info(message: &str) {
    println!("{} {}", "ℹ".bright_blue(), message.bright_white());
}
