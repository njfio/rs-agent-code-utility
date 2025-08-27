//! Explain command implementation

use std::path::PathBuf;
use crate::cli::error::{CliResult, validate_path};
use crate::cli::utils::create_progress_bar;
use crate::{CodebaseAnalyzer, AIAnalyzer, AIConfig};

pub fn execute(
    path: &PathBuf,
    file: Option<&PathBuf>,
    symbol: Option<&String>,
    format: &str,
    detailed: bool,
    learning: bool,
) -> CliResult<()> {
    validate_path(path)?;

    let pb = create_progress_bar("Analyzing codebase...");

    // Determine what to analyze
    let analysis_path = if let Some(specific_file) = file {
        validate_path(specific_file)?;
        specific_file
    } else {
        path
    };

    // Analyze the codebase first
    let mut analyzer = CodebaseAnalyzer::new()?;
    let analysis_result = if analysis_path.is_file() {
        analyzer.analyze_file(analysis_path)
    } else {
        analyzer.analyze_directory(analysis_path)
    }.map_err(|e| format!("Failed to analyze path: {}", e))?;

    pb.set_message("Generating AI explanations...");

    // Create AI analyzer with appropriate configuration
    let ai_config = AIConfig {
        detailed_explanations: detailed,
        include_examples: detailed,
        max_explanation_length: if detailed { 1000 } else { 500 },
        pattern_recognition: detailed,
        architectural_insights: detailed,
    };

    let ai_analyzer = AIAnalyzer::with_config(ai_config);
    let ai_result = ai_analyzer.analyze(&analysis_result);

    pb.finish_with_message("Analysis complete!");

    // Filter by specific symbol if requested
    let filtered_result = if let Some(symbol_name) = symbol {
        filter_by_symbol(&ai_result, symbol_name)
    } else {
        ai_result
    };

    // Display results based on format
    match format.to_lowercase().as_str() {
        "json" => display_json(&filtered_result)?,
        "markdown" => display_markdown(&filtered_result, detailed, learning)?,
        "table" | _ => display_table(&filtered_result, detailed, learning)?,
    }

    Ok(())
}

fn filter_by_symbol(result: &crate::AIAnalysisResult, symbol_name: &str) -> crate::AIAnalysisResult {
    let mut filtered_result = result.clone();

    // Filter symbol explanations to only include those with the specified symbol
    filtered_result.symbol_explanations.retain(|symbol_explanation| {
        symbol_explanation.name.to_lowercase().contains(&symbol_name.to_lowercase())
    });

    filtered_result
}

fn display_json(result: &crate::AIAnalysisResult) -> CliResult<()> {
    #[cfg(feature = "serde")]
    {
        let json = serde_json::to_string_pretty(result)
            .map_err(|e| format!("Failed to serialize to JSON: {}", e))?;
        println!("{}", json);
    }
    #[cfg(not(feature = "serde"))]
    {
        return Err("JSON output requires the 'serde' feature to be enabled".to_string());
    }
    Ok(())
}

fn display_markdown(result: &crate::AIAnalysisResult, detailed: bool, learning: bool) -> CliResult<()> {
    println!("# Code Analysis Report\n");

    // Overall explanation
    let explanation = &result.codebase_explanation;
    println!("## Overview\n");
    println!("**Purpose**: {}\n", explanation.purpose);
    println!("**Architecture**: {}\n", explanation.architecture);

    if detailed {
        if !explanation.technologies.is_empty() {
            println!("### Technologies\n");
            for tech in &explanation.technologies {
                println!("- {}", tech);
            }
            println!();
        }

        if !explanation.entry_points.is_empty() {
            println!("### Entry Points\n");
            for entry in &explanation.entry_points {
                println!("- {}", entry);
            }
            println!();
        }
    }

    if learning && !result.learning_recommendations.is_empty() {
        println!("### Learning Recommendations\n");
        for rec in &result.learning_recommendations {
            println!("- {}", rec);
        }
        println!();
    }

    // File explanations
    if !result.file_explanations.is_empty() {
        println!("## File Analysis\n");
        for file_explanation in &result.file_explanations {
            println!("### {}\n", file_explanation.file_path);
            println!("**Purpose**: {}\n", file_explanation.purpose);
            println!("**Role**: {}\n", file_explanation.role);

            if detailed {
                if !file_explanation.responsibilities.is_empty() {
                    println!("**Responsibilities**:");
                    for resp in &file_explanation.responsibilities {
                        println!("- {}", resp);
                    }
                    println!();
                }

                if !file_explanation.relationships.is_empty() {
                    println!("**Relationships**:");
                    for rel in &file_explanation.relationships {
                        println!("- {}", rel);
                    }
                    println!();
                }
            }
        }
    }

    // Symbol explanations
    if detailed && !result.symbol_explanations.is_empty() {
        println!("## Symbol Analysis\n");
        for symbol_explanation in &result.symbol_explanations {
            println!("### {} ({})\n",
                symbol_explanation.name,
                symbol_explanation.symbol_type
            );
            println!("**Purpose**: {}\n", symbol_explanation.purpose);
            println!("**Usage**: {}\n", symbol_explanation.usage);

            if let Some(ref sig) = symbol_explanation.signature_explanation {
                println!("**Signature**: {}\n", sig);
            }
        }
    }

    Ok(())
}

fn display_table(result: &crate::AIAnalysisResult, detailed: bool, learning: bool) -> CliResult<()> {
    use colored::Colorize;

    // Overall explanation
    let explanation = &result.codebase_explanation;
    println!("{}", "📋 Overall Analysis".blue().bold());
    println!("{}", "─".repeat(50).blue());
    println!("{}: {}", "Purpose".cyan().bold(), explanation.purpose);
    println!("{}: {}\n", "Architecture".cyan().bold(), explanation.architecture);

    if detailed {
        if !explanation.technologies.is_empty() {
            println!("{}", "🔧 Technologies".green().bold());
            println!("{}", "─".repeat(50).green());
            for tech in &explanation.technologies {
                println!("• {}", tech);
            }
            println!();
        }

        if !explanation.entry_points.is_empty() {
            println!("{}", "🚪 Entry Points".yellow().bold());
            println!("{}", "─".repeat(50).yellow());
            for entry in &explanation.entry_points {
                println!("• {}", entry);
            }
            println!();
        }
    }

    if learning && !result.learning_recommendations.is_empty() {
        println!("{}", "📚 Learning Recommendations".magenta().bold());
        println!("{}", "─".repeat(50).magenta());
        for rec in &result.learning_recommendations {
            println!("• {}", rec);
        }
        println!();
    }

    // File explanations
    if !result.file_explanations.is_empty() {
        println!("{}", "📁 File Analysis".blue().bold());
        println!("{}", "═".repeat(60).blue());

        for file_explanation in &result.file_explanations {
            println!("\n{} {}", "📄".blue(), file_explanation.file_path.white().bold());
            println!("{}", "─".repeat(40).white());
            println!("{}: {}", "Purpose".cyan().bold(), file_explanation.purpose);
            println!("{}: {}", "Role".cyan().bold(), file_explanation.role);

            if detailed {
                if !file_explanation.responsibilities.is_empty() {
                    println!("\n{}", "Responsibilities:".cyan().bold());
                    for resp in &file_explanation.responsibilities {
                        println!("  • {}", resp);
                    }
                }

                if !file_explanation.relationships.is_empty() {
                    println!("\n{}", "Relationships:".cyan().bold());
                    for rel in &file_explanation.relationships {
                        println!("  • {}", rel);
                    }
                }
            }
        }
        println!();
    }

    // Symbol explanations
    if detailed && !result.symbol_explanations.is_empty() {
        println!("{}", "🔍 Symbol Analysis".yellow().bold());
        println!("{}", "═".repeat(60).yellow());

        for symbol_explanation in &result.symbol_explanations {
            println!("\n{} {} ({})",
                "🔧".yellow(),
                symbol_explanation.name.white().bold(),
                symbol_explanation.symbol_type.magenta()
            );
            println!("{}", "─".repeat(40).white());
            println!("{}: {}", "Purpose".cyan().bold(), symbol_explanation.purpose);
            println!("{}: {}", "Usage".cyan().bold(), symbol_explanation.usage);

            if let Some(ref sig) = symbol_explanation.signature_explanation {
                println!("{}: {}", "Signature".cyan().bold(), sig);
            }
        }
        println!();
    }

    Ok(())
}
