//! Enhanced Interactive command implementation with full analysis integration

use crate::cli::error::{validate_path, CliResult};
use crate::{AIAnalyzer, AIConfig, AutomatedReasoningEngine, CodebaseAnalyzer, ReasoningConfig};
use colored::Colorize;
use std::collections::HashSet;
use std::io::{self, Write};
use std::path::PathBuf;

pub fn execute(path: &PathBuf) -> CliResult<()> {
    validate_path(path)?;

    println!(
        "{}",
        "[Enhanced] Interactive Code Analysis Mode".blue().bold()
    );
    println!("{}", "=".repeat(60).blue());
    println!("Analyzing: {}", path.display().to_string().cyan());
    println!("Features: Full analysis integration, AI insights, Symbol search");
    println!("Type 'help' for available commands, 'quit' to exit");
    println!();

    // Initialize analyzers
    let mut codebase_analyzer =
        CodebaseAnalyzer::new().map_err(|e| format!("Failed to create analyzer: {}", e))?;

    let analysis_result = if path.is_file() {
        codebase_analyzer.analyze_file(path)
    } else {
        codebase_analyzer.analyze_directory(path)
    }
    .map_err(|e| format!("Failed to analyze path: {}", e))?;

    let ai_config = AIConfig {
        detailed_explanations: true,
        include_examples: true,
        max_explanation_length: 500,
        pattern_recognition: true,
        architectural_insights: true,
    };
    let ai_analyzer = AIAnalyzer::with_config(ai_config);

    let reasoning_config = ReasoningConfig {
        enable_deductive: true,
        enable_inductive: true,
        enable_abductive: false,
        enable_constraints: true,
        enable_theorem_proving: false,
        max_reasoning_time_ms: 15000,
        confidence_threshold: 0.7,
    };
    let mut reasoning_engine = AutomatedReasoningEngine::with_config(reasoning_config);

    println!(
        "{}",
        "[OK] Analysis complete! Ready for interactive queries.".green()
    );
    println!("Available commands: help, stats, files, symbols, find, explain, insights, quit");
    println!();

    // Interactive loop
    loop {
        print!("{} ", "Search >".cyan().bold());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let command = input.trim().to_lowercase();

                match command.as_str() {
                    "quit" | "exit" | "q" => {
                        println!("{}", "Goodbye!".green());
                        break;
                    }
                    "help" | "h" => {
                        display_help();
                    }
                    "clear" | "cls" => {
                        print!("\x1B[2J\x1B[1;1H");
                        println!("{}", "Screen cleared.".blue());
                    }
                    "stats" | "statistics" => {
                        display_statistics(&analysis_result);
                    }
                    "files" => {
                        display_files(&analysis_result);
                    }
                    "symbols" => {
                        display_symbols(&analysis_result);
                    }
                    "insights" => {
                        display_insights(&mut reasoning_engine, &analysis_result);
                    }
                    "explain" => {
                        display_explanation(&ai_analyzer, &analysis_result);
                    }
                    "security" => {
                        display_security_summary(&analysis_result);
                    }
                    "dependencies" => {
                        display_dependencies(&analysis_result);
                    }
                    _ if command.starts_with("find ") => {
                        let query = command.strip_prefix("find ").unwrap_or("");
                        find_symbols(&analysis_result, query);
                    }
                    _ if command.starts_with("explain ") => {
                        let symbol_name = command.strip_prefix("explain ").unwrap_or("");
                        explain_symbol(&ai_analyzer, &analysis_result, symbol_name);
                    }
                    "" => continue,
                    _ => {
                        println!(
                            "{}",
                            "Error: Unknown command. Type 'help' for available commands.".red()
                        );
                        println!("Available: help, stats, files, symbols, find <name>, explain <symbol>, insights, quit");
                    }
                }
            }
            Err(error) => {
                println!("Error reading input: {}", error);
                break;
            }
        }

        println!();
    }

    Ok(())
}

fn display_help() {
    println!("{}", "Available Commands:".blue().bold());
    println!("{}", "-".repeat(50).blue());
    println!("  help         - Show this help message");
    println!("  stats        - Show codebase statistics");
    println!("  files        - List analyzed files");
    println!("  symbols      - Show all symbols");
    println!("  insights     - Generate code insights");
    println!("  explain      - Get AI explanation of codebase");
    println!("  security     - Show security analysis");
    println!("  dependencies - Show dependencies");
    println!("  find <name>  - Find symbols by name");
    println!("  explain <symbol> - Explain specific symbol");
    println!("  clear        - Clear screen");
    println!("  quit         - Exit interactive mode");
    println!();
    println!("{}", "Examples:".yellow().bold());
    println!("  find main     - Find symbols containing 'main'");
    println!("  explain add   - Explain the 'add' function");
    println!("  stats         - Show codebase statistics");
}

fn display_statistics(result: &crate::AnalysisResult) {
    println!("{}", "Codebase Statistics".green().bold());
    println!("{}", "-".repeat(40).green());
    println!("* Total Files: {}", result.files.len());

    let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
    println!("* Total Symbols: {}", total_symbols);

    println!("* Lines of Code: {}", result.total_lines);

    // Show language breakdown
    if !result.languages.is_empty() {
        println!("* Languages: {:?}", result.languages);
    }

    // Show file size breakdown
    let mut total_size = 0u64;
    for file in &result.files {
        if let Ok(metadata) = std::fs::metadata(&file.path) {
            total_size += metadata.len();
        }
    }
    println!("* Total Size: {:.2} MB", total_size as f64 / 1_000_000.0);
}

fn display_files(result: &crate::AnalysisResult) {
    println!("{}", "Analyzed Files".blue().bold());
    println!("{}", "-".repeat(40).blue());

    for (i, file) in result.files.iter().enumerate().take(15) {
        let size_mb = if let Ok(metadata) = std::fs::metadata(&file.path) {
            format!("{:.2}MB", metadata.len() as f64 / 1_000_000.0)
        } else {
            "N/A".to_string()
        };

        println!(
            "{}. {} ({} symbols, {} LOC, {})",
            i + 1,
            file.path.display().to_string().white(),
            file.symbols.len().to_string().cyan(),
            file.lines.to_string().yellow(),
            size_mb.magenta()
        );
    }

    if result.files.len() > 15 {
        println!("... and {} more files", result.files.len() - 15);
    }
}

fn display_symbols(result: &crate::AnalysisResult) {
    println!("{}", "Symbols Overview".magenta().bold());
    println!("{}", "-".repeat(40).magenta());

    let mut symbol_count = 0;
    let mut type_counts = std::collections::HashMap::new();

    for file in &result.files {
        for symbol in &file.symbols {
            *type_counts.entry(symbol.kind.clone()).or_insert(0) += 1;

            if symbol_count >= 25 {
                println!("... and more symbols (use 'find <name>' to search)");
                break;
            }

            println!(
                "* {} {} ({}:{})",
                symbol.kind.cyan(),
                symbol.name.white().bold(),
                file.path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .white()
                    .dimmed(),
                symbol.start_line.to_string().yellow()
            );
            symbol_count += 1;
        }
        if symbol_count >= 25 {
            break;
        }
    }

    // Show symbol type breakdown
    if !type_counts.is_empty() {
        println!();
        println!("{}", "Symbol Types:".cyan().bold());
        for (kind, count) in type_counts.iter() {
            println!("  {}: {}", kind.cyan(), count);
        }
    }
}

fn display_insights(
    reasoning_engine: &mut AutomatedReasoningEngine,
    result: &crate::AnalysisResult,
) {
    println!("{}", "Generating Insights...".yellow());

    match reasoning_engine.analyze_code(result) {
        Ok(reasoning_result) => {
            if reasoning_result.insights.is_empty() {
                println!("{}", "No specific insights generated.".white().dimmed());
            } else {
                println!("{}", "Code Insights".yellow().bold());
                println!("{}", "-".repeat(40).yellow());

                for (i, insight) in reasoning_result.insights.iter().enumerate().take(8) {
                    println!(
                        "{}. {:?}: {}",
                        i + 1,
                        insight.insight_type.to_string().cyan().bold(),
                        insight.description
                    );
                }

                if reasoning_result.insights.len() > 8 {
                    println!(
                        "... and {} more insights",
                        reasoning_result.insights.len() - 8
                    );
                }
            }
        }
        Err(e) => {
            println!("{}: {}", "Error generating insights".red(), e);
        }
    }
}

fn display_explanation(ai_analyzer: &AIAnalyzer, result: &crate::AnalysisResult) {
    println!("{}", "Generating AI Explanation...".blue());

    let ai_result = ai_analyzer.analyze(result);
    let explanation = &ai_result.codebase_explanation;
    println!("{}", "Codebase Overview".blue().bold());
    println!("{}", "-".repeat(40).blue());
    println!("Purpose: {}", explanation.purpose);
    println!("Architecture: {}", explanation.architecture);

    if !explanation.technologies.is_empty() {
        println!("Technologies: {}", explanation.technologies.join(", "));
    }

    if !explanation.entry_points.is_empty() {
        println!("Entry Points: {}", explanation.entry_points.join(", "));
    }
}

fn display_security_summary(result: &crate::AnalysisResult) {
    println!("{}", "Security Summary".red().bold());
    println!("{}", "-".repeat(40).red());

    // Count vulnerabilities from all files
    let mut total_vulnerabilities = 0;
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;

    for file in &result.files {
        total_vulnerabilities += file.security_vulnerabilities.len();
        for vuln in &file.security_vulnerabilities {
            match vuln.severity {
                crate::SecuritySeverity::Critical => critical_count += 1,
                crate::SecuritySeverity::High => high_count += 1,
                crate::SecuritySeverity::Medium => medium_count += 1,
                crate::SecuritySeverity::Low => low_count += 1,
                crate::SecuritySeverity::Info => low_count += 1,
            }
        }
    }

    if total_vulnerabilities > 0 {
        println!("* Total Vulnerabilities: {}", total_vulnerabilities);
        println!(
            "* Critical Issues: {}",
            critical_count.to_string().red().bold()
        );
        println!("* High Issues: {}", high_count.to_string().yellow().bold());
        println!("* Medium Issues: {}", medium_count.to_string().blue());
        println!("* Low Issues: {}", low_count.to_string().white().dimmed());
        println!();
        println!(
            "{}",
            "Tip: Use 'security' command for detailed analysis".cyan()
        );
    } else {
        println!("{}", "No security vulnerabilities found.".green());
    }
}

fn display_dependencies(result: &crate::AnalysisResult) {
    println!("{}", "Dependencies".green().bold());
    println!("{}", "-".repeat(40).green());

    // Extract dependencies from file analysis
    let mut dependencies = std::collections::HashSet::new();

    for file in &result.files {
        // Look for import/require statements in symbols
        for symbol in &file.symbols {
            if symbol.kind == "import" || symbol.kind == "require" {
                dependencies.insert(symbol.name.clone());
            }
        }
    }

    if dependencies.is_empty() {
        println!(
            "{}",
            "No dependencies detected from imports.".white().dimmed()
        );
        println!(
            "{}",
            "Note: For full dependency analysis, use the 'dependencies' command."
                .white()
                .dimmed()
        );
    } else {
        for (i, dep) in dependencies.iter().enumerate().take(15) {
            println!("{}. {}", i + 1, dep.white().bold());
        }

        if dependencies.len() > 15 {
            println!("... and {} more dependencies", dependencies.len() - 15);
        }
    }
}

fn find_symbols(result: &crate::AnalysisResult, query: &str) {
    if query.is_empty() {
        println!(
            "{}",
            "Error: Please provide a search query. Usage: find <symbol_name>.red()"
        );
        return;
    }

    println!("Searching for symbols matching '{}'", query.cyan());
    println!("{}", "-".repeat(50));

    let mut found_count = 0;
    let mut exact_matches = Vec::new();
    let mut partial_matches = Vec::new();

    for file in &result.files {
        for symbol in &file.symbols {
            if symbol.name.to_lowercase() == query.to_lowercase() {
                exact_matches.push((file, symbol));
            } else if symbol.name.to_lowercase().contains(&query.to_lowercase()) {
                partial_matches.push((file, symbol));
            }
        }
    }

    // Display exact matches first
    if !exact_matches.is_empty() {
        println!("{}", "Exact Matches:".green().bold());
        for (file, symbol) in exact_matches.iter().take(5) {
            println!(
                "* {} {} ({}:{})",
                symbol.kind.cyan(),
                symbol.name.white().bold(),
                file.path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .white()
                    .dimmed(),
                symbol.start_line.to_string().yellow()
            );
            found_count += 1;
        }
    }

    // Display partial matches
    if !partial_matches.is_empty() && found_count < 15 {
        if !exact_matches.is_empty() {
            println!();
            println!("{}", "Partial Matches:".blue().bold());
        }

        for (file, symbol) in partial_matches.iter().take(15 - found_count) {
            println!(
                "* {} {} ({}:{})",
                symbol.kind.cyan(),
                symbol.name.white().bold(),
                file.path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .white()
                    .dimmed(),
                symbol.start_line.to_string().yellow()
            );
            found_count += 1;
        }
    }

    if found_count == 0 {
        println!("{}", "No symbols found matching the query.".yellow());
        println!("Tip: Try using a shorter or different search term.");
    } else if found_count >= 15 {
        println!("... (showing first {} matches)", found_count);
    }
}

fn explain_symbol(_ai_analyzer: &AIAnalyzer, result: &crate::AnalysisResult, symbol_name: &str) {
    if symbol_name.is_empty() {
        println!(
            "{}",
            "Error: Please provide a symbol name. Usage: explain <symbol_name>.red()"
        );
        return;
    }

    println!("Explaining symbol '{}'", symbol_name.cyan());
    println!("{}", "-".repeat(50));

    // Find the symbol first
    let mut found_symbol = None;
    for file in &result.files {
        for symbol in &file.symbols {
            if symbol.name.to_lowercase() == symbol_name.to_lowercase() {
                found_symbol = Some((file, symbol));
                break;
            }
        }
        if found_symbol.is_some() {
            break;
        }
    }

    match found_symbol {
        Some((file, symbol)) => {
            println!(
                "Found: {} {} ({}:{})",
                "Found".green().bold(),
                symbol.name.white().bold(),
                file.path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .white()
                    .dimmed(),
                symbol.start_line.to_string().yellow()
            );
            println!("Type: {}", symbol.kind.cyan().bold());
            println!("Visibility: {}", symbol.visibility);

            if let Some(ref doc) = symbol.documentation {
                println!("Documentation: {}", doc);
            }

            println!("File: {}", file.path.display());
        }
        None => {
            println!(
                "{}",
                format!("Symbol '{}' not found.", symbol_name).yellow()
            );
            println!(
                "Tip: Try using 'find {}' to search for similar symbols.",
                symbol_name
            );
        }
    }
}
