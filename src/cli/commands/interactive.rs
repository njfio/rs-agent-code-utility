//! Interactive command implementation

use std::path::PathBuf;
use std::io::{self, Write};
use crate::cli::error::{CliResult, validate_path};
use crate::{CodebaseAnalyzer, AutomatedReasoningEngine, ReasoningConfig, AIAnalyzer, AIConfig};
use colored::Colorize;

pub fn execute(path: &PathBuf) -> CliResult<()> {
    validate_path(path)?;

    println!("{}", "🚀 Interactive Code Analysis Mode".blue().bold());
    println!("{}", "═".repeat(50).blue());
    println!("Analyzing: {}", path.display().to_string().cyan());
    println!("Type 'help' for available commands, 'quit' to exit\n");

    // Initialize analyzers
    let mut codebase_analyzer = CodebaseAnalyzer::new()
        .map_err(|e| format!("Failed to create analyzer: {}", e))?;
    let analysis_result = if path.is_file() {
        codebase_analyzer.analyze_file(path)
    } else {
        codebase_analyzer.analyze_directory(path)
    }.map_err(|e| format!("Failed to analyze path: {}", e))?;

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

    println!("{}", "✅ Analysis complete! Ready for interactive queries.".green());

    // Interactive loop
    loop {
        print!("{} ", "🔍 >".cyan().bold());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let command = input.trim().to_lowercase();

                match command.as_str() {
                    "quit" | "exit" | "q" => {
                        println!("{}", "👋 Goodbye!".green());
                        break;
                    },
                    "help" | "h" => {
                        display_help();
                    },
                    "stats" | "statistics" => {
                        display_statistics(&analysis_result);
                    },
                    "files" => {
                        display_files(&analysis_result);
                    },
                    "symbols" => {
                        display_symbols(&analysis_result);
                    },
                    "insights" => {
                        display_insights(&mut reasoning_engine, &analysis_result);
                    },
                    "explain" => {
                        display_explanation(&ai_analyzer, &analysis_result);
                    },
                    "security" => {
                        display_security_summary(&analysis_result);
                    },
                    "dependencies" => {
                        display_dependencies(&analysis_result);
                    },
                    _ if command.starts_with("find ") => {
                        let query = command.strip_prefix("find ").unwrap_or("");
                        find_symbols(&analysis_result, query);
                    },
                    _ if command.starts_with("explain ") => {
                        let symbol_name = command.strip_prefix("explain ").unwrap_or("");
                        explain_symbol(&ai_analyzer, &analysis_result, symbol_name);
                    },
                    _ => {
                        println!("{}", "❌ Unknown command. Type 'help' for available commands.".red());
                    }
                }
            },
            Err(error) => {
                println!("Error reading input: {}", error);
                break;
            }
        }

        println!(); // Add spacing between commands
    }

    Ok(())
}

fn display_help() {
    println!("{}", "📚 Available Commands:".blue().bold());
    println!("{}", "─".repeat(30).blue());
    println!("  {} - Show this help message", "help".cyan());
    println!("  {} - Show codebase statistics", "stats".cyan());
    println!("  {} - List analyzed files", "files".cyan());
    println!("  {} - Show all symbols", "symbols".cyan());
    println!("  {} - Generate code insights", "insights".cyan());
    println!("  {} - Get AI explanation of codebase", "explain".cyan());
    println!("  {} - Show security analysis", "security".cyan());
    println!("  {} - Show dependencies", "dependencies".cyan());
    println!("  {} - Find symbols by name", "find <name>".cyan());
    println!("  {} - Explain specific symbol", "explain <symbol>".cyan());
    println!("  {} - Exit interactive mode", "quit".cyan());
}

fn display_statistics(result: &crate::AnalysisResult) {
    println!("{}", "📊 Codebase Statistics".green().bold());
    println!("{}", "─".repeat(30).green());
    println!("• {}: {}", "Total Files".cyan(), result.files.len());

    let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
    println!("• {}: {}", "Total Symbols".cyan(), total_symbols);

    println!("• {}: {}", "Lines of Code".cyan(), result.total_lines);

    // Show language breakdown
    if !result.languages.is_empty() {
        println!("• {}: {:?}", "Languages".cyan(), result.languages);
    }
}

fn display_files(result: &crate::AnalysisResult) {
    println!("{}", "📁 Analyzed Files".blue().bold());
    println!("{}", "─".repeat(30).blue());

    for (i, file) in result.files.iter().enumerate().take(10) {
        println!("{}. {} ({} symbols, {} LOC)",
            i + 1,
            file.path.display().to_string().white(),
            file.symbols.len().to_string().cyan(),
            file.lines.to_string().yellow()
        );
    }

    if result.files.len() > 10 {
        println!("... and {} more files", result.files.len() - 10);
    }
}

fn display_symbols(result: &crate::AnalysisResult) {
    println!("{}", "🔧 Symbols Overview".magenta().bold());
    println!("{}", "─".repeat(30).magenta());

    let mut symbol_count = 0;
    for file in &result.files {
        for symbol in &file.symbols {
            if symbol_count >= 20 { // Limit to first 20 symbols
                println!("... and more symbols (use 'find <name>' to search)");
                return;
            }

            println!("• {} {} ({}:{})",
                symbol.kind.cyan(),
                symbol.name.white().bold(),
                file.path.file_name().unwrap_or_default().to_string_lossy().white().dimmed(),
                symbol.start_line.to_string().yellow()
            );
            symbol_count += 1;
        }
    }
}

fn display_insights(reasoning_engine: &mut AutomatedReasoningEngine, result: &crate::AnalysisResult) {
    println!("{}", "💡 Generating Insights...".yellow());

    match reasoning_engine.analyze_code(result) {
        Ok(reasoning_result) => {
            if reasoning_result.insights.is_empty() {
                println!("{}", "No specific insights generated.".white().dimmed());
            } else {
                println!("{}", "🔍 Code Insights".yellow().bold());
                println!("{}", "─".repeat(30).yellow());

                for insight in reasoning_result.insights.iter().take(5) {
                    println!("• {:?}: {}", insight.insight_type.to_string().cyan().bold(), insight.description);
                }

                if reasoning_result.insights.len() > 5 {
                    println!("... and {} more insights", reasoning_result.insights.len() - 5);
                }
            }
        },
        Err(e) => {
            println!("{}: {}", "Error generating insights".red(), e);
        }
    }
}

fn display_explanation(ai_analyzer: &AIAnalyzer, result: &crate::AnalysisResult) {
    println!("{}", "🤖 Generating AI Explanation...".blue());

    let ai_result = ai_analyzer.analyze(result);
    let explanation = &ai_result.codebase_explanation;
    println!("{}", "📋 Codebase Overview".blue().bold());
    println!("{}", "─".repeat(30).blue());
    println!("{}: {}", "Purpose".cyan().bold(), explanation.purpose);
    println!("{}: {}", "Architecture".cyan().bold(), explanation.architecture);

    if !explanation.technologies.is_empty() {
        println!("{}: {}", "Technologies".cyan().bold(), explanation.technologies.join(", "));
    }
}

fn display_security_summary(result: &crate::AnalysisResult) {
    println!("{}", "🔒 Security Summary".red().bold());
    println!("{}", "─".repeat(30).red());

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
        println!("• {}: {}", "Total Vulnerabilities".cyan(), total_vulnerabilities);
        println!("• {}: {}", "Critical Issues".red().bold(), critical_count);
        println!("• {}: {}", "High Issues".yellow().bold(), high_count);
        println!("• {}: {}", "Medium Issues".blue(), medium_count);
        println!("• {}: {}", "Low Issues".white().dimmed(), low_count);
    } else {
        println!("{}", "No security vulnerabilities found.".green());
    }
}

fn display_dependencies(result: &crate::AnalysisResult) {
    println!("{}", "📦 Dependencies".green().bold());
    println!("{}", "─".repeat(30).green());

    // Extract dependencies from file analysis (this is a simplified approach)
    // In a real implementation, you'd want to parse package.json, Cargo.toml, etc.
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
        println!("{}", "No dependencies detected from imports.".white().dimmed());
        println!("{}", "Note: For full dependency analysis, use the 'dependencies' command.".white().dimmed());
    } else {
        for (i, dep) in dependencies.iter().enumerate().take(10) {
            println!("{}. {}", i + 1, dep.white().bold());
        }

        if dependencies.len() > 10 {
            println!("... and {} more dependencies", dependencies.len() - 10);
        }
    }
}

fn find_symbols(result: &crate::AnalysisResult, query: &str) {
    println!("{} '{}'", "🔍 Searching for symbols matching".blue(), query.cyan());
    println!("{}", "─".repeat(40).blue());

    let mut found_count = 0;
    for file in &result.files {
        for symbol in &file.symbols {
            if symbol.name.to_lowercase().contains(&query.to_lowercase()) {
                println!("• {} {} ({}:{})",
                    symbol.kind.cyan(),
                    symbol.name.white().bold(),
                    file.path.file_name().unwrap_or_default().to_string_lossy().white().dimmed(),
                    symbol.start_line.to_string().yellow()
                );
                found_count += 1;

                if found_count >= 15 {
                    println!("... (showing first 15 matches)");
                    break;
                }
            }
        }
        if found_count >= 15 { break; }
    }

    if found_count == 0 {
        println!("{}", "No symbols found matching the query.".yellow());
    }
}

fn explain_symbol(_ai_analyzer: &AIAnalyzer, result: &crate::AnalysisResult, symbol_name: &str) {
    println!("{} '{}'", "🤖 Explaining symbol".blue(), symbol_name.cyan());
    println!("{}", "─".repeat(40).blue());

    // Find the symbol first
    let mut found_symbol = None;
    for file in &result.files {
        for symbol in &file.symbols {
            if symbol.name.to_lowercase() == symbol_name.to_lowercase() {
                found_symbol = Some((file, symbol));
                break;
            }
        }
        if found_symbol.is_some() { break; }
    }

    match found_symbol {
        Some((file, symbol)) => {
            println!("📍 {}: {} ({}:{})",
                "Found".green().bold(),
                symbol.name.white().bold(),
                file.path.file_name().unwrap_or_default().to_string_lossy().white().dimmed(),
                symbol.start_line.to_string().yellow()
            );
            println!("🔧 {}: {}", "Type".cyan().bold(), symbol.kind);
            println!("👁️ {}: {}", "Visibility".cyan().bold(), symbol.visibility);

            if let Some(ref doc) = symbol.documentation {
                println!("📝 {}: {}", "Documentation".cyan().bold(), doc);
            }
        },
        None => {
            println!("{}", format!("Symbol '{}' not found.", symbol_name).yellow());
        }
    }
}
