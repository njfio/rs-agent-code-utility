//! Refactor command implementation
//! 
//! Provides smart refactoring suggestions with configurable output formats.

use std::path::PathBuf;
use colored::*;
use crate::{CodebaseAnalyzer, SmartRefactoringEngine};
use crate::cli::error::{CliError, CliResult, validate_path, validate_format};
use crate::cli::utils::{create_progress_bar, create_analysis_config, validate_output_path, print_success};
use crate::cli::output::OutputFormat;

/// Execute the refactor command
pub fn execute(
    path: &PathBuf,
    category: Option<&String>,
    format: &str,
    quick_wins: bool,
    major_only: bool,
    min_priority: &str,
    output: Option<&PathBuf>,
) -> CliResult<()> {
    // Validate inputs
    validate_path(path)?;
    validate_format(format, &["table", "json", "markdown"])?;
    
    if let Some(output_path) = output {
        validate_output_path(output_path)?;
    }
    
    // Create progress bar
    let pb = create_progress_bar("Analyzing code for refactoring opportunities...");
    
    // Configure analyzer
    let config = create_analysis_config(1024, 20, "full", false, None, None, None, false)?;
    let mut analyzer = CodebaseAnalyzer::with_config(config)
        .map_err(|e| CliError::Refactoring(e.to_string()))?;
    
    // Run analysis first
    pb.set_message("Analyzing codebase...");
    let analysis_result = analyzer.analyze_directory(path)
        .map_err(|e| CliError::Refactoring(e.to_string()))?;
    
    // Run refactoring analysis
    pb.set_message("Identifying refactoring opportunities...");
    let refactoring_engine = SmartRefactoringEngine::new();
    let refactoring_result = refactoring_engine.analyze(&analysis_result)
        .map_err(|e| CliError::Refactoring(e.to_string()))?;
    
    pb.finish_with_message("Refactoring analysis complete!");
    
    // Display results based on format
    let output_format = OutputFormat::from_str(format)
        .map_err(|e| CliError::UnsupportedFormat(e))?;
    
    match output_format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&refactoring_result)?;
            if let Some(output_path) = output {
                std::fs::write(output_path, &json)?;
                print_success(&format!("Refactoring report saved to {}", output_path.display()));
            } else {
                println!("{}", json);
            }
        }
        OutputFormat::Markdown => {
            print_refactoring_markdown(&refactoring_result, category, quick_wins, major_only, min_priority);
            if let Some(output_path) = output {
                let markdown = render_refactoring_markdown(&refactoring_result, category, quick_wins, major_only, min_priority);
                std::fs::write(output_path, markdown)?;
                print_success(&format!("Refactoring report saved to {}", output_path.display()));
            }
        }
        OutputFormat::Table | _ => {
            print_refactoring_table(&refactoring_result, category, quick_wins, major_only, min_priority);
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&refactoring_result)?;
                std::fs::write(output_path, json)?;
                print_success(&format!("Refactoring report saved to {}", output_path.display()));
            }
        }
    }
    
    Ok(())
}

fn print_refactoring_table(
    refactoring_result: &crate::SmartRefactoringResult,
    _category: Option<&String>,
    _quick_wins: bool,
    _major_only: bool,
    _min_priority: &str,
) {
    println!("\n{}", "🎯 REFACTORING ANALYSIS".bright_yellow().bold());
    println!("{}", "=".repeat(60).bright_yellow());

    println!("\n{}", "📊 SUMMARY".bright_cyan().bold());
    println!("Refactoring Score: {}/100",
        if refactoring_result.refactoring_score >= 80 {
            refactoring_result.refactoring_score.to_string().bright_green()
        } else if refactoring_result.refactoring_score >= 60 {
            refactoring_result.refactoring_score.to_string().bright_yellow()
        } else {
            refactoring_result.refactoring_score.to_string().bright_red()
        }
    );
    println!("Total Opportunities: {}", refactoring_result.total_opportunities.to_string().bright_blue());
    println!("Code Smell Fixes: {}", refactoring_result.code_smell_fixes.len().to_string().bright_green());
    println!("Pattern Recommendations: {}", refactoring_result.pattern_recommendations.len().to_string().bright_cyan());

    // For now, just show code smell fixes
    let suggestions_to_show = &refactoring_result.code_smell_fixes;

    if !suggestions_to_show.is_empty() {
        println!("\n{}", "🔧 CODE SMELL FIXES".bright_cyan().bold());
        for (i, fix) in suggestions_to_show.iter().enumerate().take(10) {
            println!("\n{} {}",
                format!("{}.", i + 1).bright_cyan(),
                fix.smell_name.bright_white().bold()
            );
            println!("   Category: {:?} | Confidence: {:.1}% | Effort: {:.1}h",
                format!("{:?}", fix.category).bright_blue(),
                (fix.confidence * 100.0).to_string().bright_yellow(),
                fix.effort.to_string().bright_green()
            );
            println!("   Location: {}", fix.location.file.display().to_string().bright_blue());
            println!("   Description: {}", fix.description.bright_white());

            if !fix.benefits.is_empty() {
                println!("   Benefits: {}", fix.benefits.join(", ").bright_green());
            }
        }
    }

    println!("\n{}", "📈 IMPACT SUMMARY".bright_cyan().bold());
    println!("Overall Impact: {}%", refactoring_result.impact_analysis.overall_impact.to_string().bright_green());
    println!("Quality Impact: {}%", refactoring_result.impact_analysis.quality_impact.readability_improvement.to_string().bright_green());
    println!("Performance Impact: {}%", refactoring_result.impact_analysis.performance_impact.performance_improvement.to_string().bright_green());
    println!("Maintainability Impact: {}%", refactoring_result.impact_analysis.maintainability_impact.complexity_reduction.to_string().bright_blue());
}

fn print_refactoring_markdown(
    refactoring_result: &crate::SmartRefactoringResult,
    _category: Option<&String>,
    _quick_wins: bool,
    _major_only: bool,
    _min_priority: &str,
) {
    println!("# 🎯 Refactoring Analysis Report\n");

    println!("## 📊 Summary\n");
    println!("- **Refactoring Score**: {}/100", refactoring_result.refactoring_score);
    println!("- **Total Opportunities**: {}", refactoring_result.total_opportunities);
    println!("- **Code Smell Fixes**: {}", refactoring_result.code_smell_fixes.len());
    println!("- **Pattern Recommendations**: {}", refactoring_result.pattern_recommendations.len());

    let suggestions_to_show = &refactoring_result.code_smell_fixes;

    if !suggestions_to_show.is_empty() {
        println!("\n## 🔧 Refactoring Suggestions\n");
        for (i, suggestion) in suggestions_to_show.iter().enumerate() {
            println!("### {}. {}\n", i + 1, suggestion.smell_name);
            println!("- **Category**: {:?}", suggestion.category);
            println!("- **Confidence**: {:.1}%", suggestion.confidence * 100.0);
            println!("- **Effort**: {:.1}h", suggestion.effort);
            println!("- **Location**: `{}`", suggestion.location.file.display());
            println!("- **Description**: {}\n", suggestion.description);

            if !suggestion.benefits.is_empty() {
                println!("**Benefits**:");
                for benefit in &suggestion.benefits {
                    println!("- {}", benefit);
                }
                println!();
            }
        }
    }

    println!("## 📈 Expected Impact\n");
    println!("- **Overall Impact**: {}%", refactoring_result.impact_analysis.overall_impact);
    println!("- **Quality Impact**: {}%", refactoring_result.impact_analysis.quality_impact.readability_improvement);
    println!("- **Performance Impact**: {}%", refactoring_result.impact_analysis.performance_impact.performance_improvement);
    println!("- **Maintainability Impact**: {}%", refactoring_result.impact_analysis.maintainability_impact.complexity_reduction);
}

fn render_refactoring_markdown(
    refactoring_result: &crate::SmartRefactoringResult,
    _category: Option<&String>,
    _quick_wins: bool,
    _major_only: bool,
    _min_priority: &str,
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    
    writeln!(out, "# 🎯 Refactoring Analysis Report\n").unwrap();
    writeln!(out, "## 📊 Summary\n").unwrap();
    writeln!(out, "- **Refactoring Score**: {}/100", refactoring_result.refactoring_score).unwrap();
    writeln!(out, "- **Total Opportunities**: {}", refactoring_result.total_opportunities).unwrap();
    writeln!(out, "- **Code Smell Fixes**: {}", refactoring_result.code_smell_fixes.len()).unwrap();
    writeln!(out, "- **Pattern Recommendations**: {}", refactoring_result.pattern_recommendations.len()).unwrap();

    let suggestions_to_show = &refactoring_result.code_smell_fixes;

    if !suggestions_to_show.is_empty() {
        writeln!(out, "\n## 🔧 Refactoring Suggestions\n").unwrap();
        for (i, suggestion) in suggestions_to_show.iter().enumerate() {
            writeln!(out, "### {}. {}\n", i + 1, suggestion.smell_name).unwrap();
            writeln!(out, "- **Category**: {:?}", suggestion.category).unwrap();
            writeln!(out, "- **Confidence**: {:.1}%", suggestion.confidence * 100.0).unwrap();
            writeln!(out, "- **Effort**: {:.1}h", suggestion.effort).unwrap();
            writeln!(out, "- **Location**: `{}`", suggestion.location.file.display()).unwrap();
            writeln!(out, "- **Description**: {}\n", suggestion.description).unwrap();

            if !suggestion.benefits.is_empty() {
                writeln!(out, "**Benefits**:").unwrap();
                for benefit in &suggestion.benefits {
                    writeln!(out, "- {}", benefit).unwrap();
                }
                writeln!(out).unwrap();
            }
        }
    }

    writeln!(out, "## 📈 Expected Impact\n").unwrap();
    writeln!(out, "- **Overall Impact**: {}%", refactoring_result.impact_analysis.overall_impact).unwrap();
    writeln!(out, "- **Quality Impact**: {}%", refactoring_result.impact_analysis.quality_impact.readability_improvement).unwrap();
    writeln!(out, "- **Performance Impact**: {}%", refactoring_result.impact_analysis.performance_impact.performance_improvement).unwrap();
    writeln!(out, "- **Maintainability Impact**: {}%", refactoring_result.impact_analysis.maintainability_impact.complexity_reduction).unwrap();
    
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_refactor_command_validation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();
        
        let result = execute(
            &path,
            None,
            "table",
            false,
            false,
            "low",
            None,
        );
        assert!(result.is_ok());
    }
}
