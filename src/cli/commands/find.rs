//! Find command implementation

use std::path::PathBuf;
use crate::cli::error::{CliResult, validate_path};
use crate::cli::utils::create_progress_bar;
use crate::CodebaseAnalyzer;
use colored::Colorize;

pub fn execute(
    path: &PathBuf,
    name: Option<&String>,
    symbol_type: Option<&String>,
    language: Option<&String>,
    public_only: bool,
) -> CliResult<()> {
    validate_path(path)?;

    let pb = create_progress_bar("Finding symbols...");

    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new()
        .map_err(|e| format!("Failed to create analyzer: {}", e))?;
    let analysis_result = analyzer.analyze_directory(path)
        .map_err(|e| format!("Failed to analyze directory: {}", e))?;

    pb.set_message("Searching symbols...");

    // Collect all symbols from all files
    let mut matching_symbols = Vec::new();

    for file in &analysis_result.files {
        // Filter by language if specified
        if let Some(lang_filter) = language {
            if let Some(detected_lang) = crate::detect_language_from_path(&file.path.to_string_lossy()) {
                if detected_lang.name().to_lowercase() != lang_filter.to_lowercase() {
                    continue;
                }
            } else {
                continue;
            }
        }

        for symbol in &file.symbols {
            // Filter by name if specified
            if let Some(name_filter) = name {
                if !symbol.name.to_lowercase().contains(&name_filter.to_lowercase()) {
                    continue;
                }
            }

            // Filter by symbol type if specified
            if let Some(type_filter) = symbol_type {
                if !symbol.kind.to_lowercase().contains(&type_filter.to_lowercase()) {
                    continue;
                }
            }

            // Filter by visibility if public_only is specified
            if public_only {
                if !symbol.visibility.to_lowercase().contains("public") {
                    continue;
                }
            }

            matching_symbols.push((file, symbol));
        }
    }

    pb.finish_with_message("Search complete!");

    // Display results
    if matching_symbols.is_empty() {
        println!("{}", "No matching symbols found.".yellow());
        return Ok(());
    }

    println!("\n{} {} matching symbols found:\n",
        "Found".green().bold(),
        matching_symbols.len().to_string().cyan().bold()
    );

    // Group by file for better organization
    let mut current_file: Option<&PathBuf> = None;

    for (file, symbol) in &matching_symbols {
        // Print file header if it's a new file
        if current_file != Some(&file.path) {
            current_file = Some(&file.path);
            println!("{}", format!("📁 {}", file.path.display()).blue().bold());
        }

        // Format symbol type
        let type_str = match symbol.kind.to_lowercase().as_str() {
            "function" => "fn".magenta(),
            "class" => "class".cyan(),
            "struct" => "struct".cyan(),
            "interface" => "interface".cyan(),
            "enum" => "enum".yellow(),
            "variable" => "var".green(),
            "constant" => "const".green(),
            "method" => "method".magenta(),
            "property" => "prop".blue(),
            "type" => "type".yellow(),
            "module" => "mod".blue(),
            "namespace" => "ns".blue(),
            "trait" => "trait".cyan(),
            "implementation" => "impl".cyan(),
            "macro" => "macro".red(),
            "field" => "field".green(),
            "constructor" => "ctor".magenta(),
            "destructor" => "dtor".magenta(),
            "operator" => "op".magenta(),
            "generic" => "generic".yellow(),
            "annotation" => "anno".blue(),
            _ => "other".white(),
        };

        // Format visibility
        let visibility_str = match symbol.visibility.to_lowercase().as_str() {
            "public" => "pub".green(),
            "private" => "priv".red(),
            "protected" => "prot".yellow(),
            "internal" => "int".blue(),
            _ => "".white(),
        };

        // Print symbol information
        println!("  {} {} {} {} {}",
            format!("{}:", symbol.start_line).white().dimmed(),
            type_str,
            visibility_str,
            symbol.name.white().bold(),
            if let Some(ref doc) = symbol.documentation {
                format!("// {}", doc.lines().next().unwrap_or("")).white().dimmed()
            } else {
                "".white()
            }
        );
    }

    println!();
    Ok(())
}
