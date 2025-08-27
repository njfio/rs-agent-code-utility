//! Insights command implementation

use std::path::PathBuf;
use crate::cli::error::{CliResult, validate_path};
use crate::cli::utils::create_progress_bar;
use crate::{CodebaseAnalyzer, AutomatedReasoningEngine, ReasoningConfig};

pub fn execute(path: &PathBuf, focus: &str, format: &str) -> CliResult<()> {
    validate_path(path)?;

    let pb = create_progress_bar("Analyzing codebase for insights...");

    // Analyze the codebase first
    let mut analyzer = CodebaseAnalyzer::new()?;
    let analysis_result = if path.is_file() {
        analyzer.analyze_file(path)
    } else {
        analyzer.analyze_directory(path)
    }.map_err(|e| format!("Failed to analyze path: {}", e))?;

    pb.set_message("Generating insights...");

    // Create reasoning engine for insights
    let reasoning_config = ReasoningConfig {
        enable_deductive: true,
        enable_inductive: true,
        enable_abductive: focus == "detailed",
        enable_constraints: focus == "detailed",
        enable_theorem_proving: focus == "detailed",
        max_reasoning_time_ms: if focus == "detailed" { 30000 } else { 15000 },
        confidence_threshold: 0.7,
    };

    let mut reasoning_engine = AutomatedReasoningEngine::with_config(reasoning_config);
    let reasoning_result = reasoning_engine.analyze_code(&analysis_result)
        .map_err(|e| format!("Failed to analyze code: {}", e))?;

    pb.finish_with_message("Insights generated!");

    // Filter insights based on focus
    let filtered_insights = filter_insights_by_focus(&reasoning_result, focus);

    // Display results based on format
    match format.to_lowercase().as_str() {
        "json" => display_json(&filtered_insights)?,
        "markdown" => display_markdown(&filtered_insights, focus)?,
        "table" | _ => display_table(&filtered_insights, focus)?,
    }

    Ok(())
}

fn filter_insights_by_focus(result: &crate::ReasoningResult, focus: &str) -> crate::ReasoningResult {
    let mut filtered_result = result.clone();

    match focus.to_lowercase().as_str() {
        "security" => {
            filtered_result.insights.retain(|insight| {
                insight.insight_type == crate::InsightType::Security ||
                insight.description.to_lowercase().contains("security") ||
                insight.description.to_lowercase().contains("vulnerability")
            });
        },
        "performance" => {
            filtered_result.insights.retain(|insight| {
                insight.insight_type == crate::InsightType::Performance ||
                insight.description.to_lowercase().contains("performance") ||
                insight.description.to_lowercase().contains("optimization")
            });
        },
        "quality" => {
            filtered_result.insights.retain(|insight| {
                insight.insight_type == crate::InsightType::CodeSmell ||
                insight.description.to_lowercase().contains("quality") ||
                insight.description.to_lowercase().contains("maintainability")
            });
        },
        "architecture" => {
            filtered_result.insights.retain(|insight| {
                insight.insight_type == crate::InsightType::DesignPattern ||
                insight.description.to_lowercase().contains("architecture") ||
                insight.description.to_lowercase().contains("design")
            });
        },
        _ => {
            // "all" or any other value - keep all insights
        }
    }

    filtered_result
}

fn display_json(result: &crate::ReasoningResult) -> CliResult<()> {
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

fn display_markdown(result: &crate::ReasoningResult, focus: &str) -> CliResult<()> {
    println!("# Code Insights Report\n");
    println!("**Focus**: {}\n", focus);

    // Key insights
    if !result.insights.is_empty() {
        println!("## Key Insights\n");
        for insight in &result.insights {
            println!("### {:?}\n", insight.insight_type);
            println!("{}\n", insight.description);

            if !insight.evidence.is_empty() {
                println!("**Evidence**: {}\n", insight.evidence.join(", "));
            }

            println!("**Confidence**: {:.2}\n", insight.confidence);
        }
    }

    // Derived facts
    if !result.derived_facts.is_empty() {
        println!("## Derived Facts\n");
        for fact in &result.derived_facts {
            println!("- **{}**: {} (confidence: {:.2})", fact.predicate, fact.id, fact.confidence);
        }
        println!();
    }

    // Metrics
    println!("## Analysis Metrics\n");
    println!("- **Total Time**: {}ms", result.metrics.total_time_ms);
    println!("- **Facts Derived**: {}", result.derived_facts.len());
    println!("- **Insights Generated**: {}", result.insights.len());

    Ok(())
}

fn display_table(result: &crate::ReasoningResult, focus: &str) -> CliResult<()> {
    use colored::Colorize;

    println!("{} {}", "🔍 Code Insights Report".blue().bold(), format!("(Focus: {})", focus).white().dimmed());
    println!("{}", "═".repeat(60).blue());

    // Key insights
    if !result.insights.is_empty() {
        println!("\n{}", "💡 Key Insights".yellow().bold());
        println!("{}", "─".repeat(50).yellow());

        for insight in &result.insights {
            println!("\n{} {:?}", "•".cyan(), insight.insight_type.to_string().white().bold());
            println!("{}", insight.description);

            if !insight.evidence.is_empty() {
                println!("{} {}", "Evidence:".green().bold(), insight.evidence.join(", ").white().dimmed());
            }

            println!("{} {:.2}", "Confidence:".magenta().bold(), insight.confidence);
        }
        println!();
    } else {
        println!("\n{}", format!("No insights found for focus: {}", focus).yellow());
    }

    // Derived facts
    if !result.derived_facts.is_empty() {
        println!("{}", "📊 Derived Facts".green().bold());
        println!("{}", "─".repeat(50).green());

        for fact in &result.derived_facts {
            println!("• {}: {} (confidence: {:.2})", fact.predicate.yellow().bold(), fact.id, fact.confidence);
        }
        println!();
    }

    // Metrics
    println!("{}", "📈 Analysis Metrics".magenta().bold());
    println!("{}", "─".repeat(50).magenta());
    println!("• {}: {}ms", "Total Time".cyan().bold(), result.metrics.total_time_ms);
    println!("• {}: {}", "Facts Derived".cyan().bold(), result.derived_facts.len());
    println!("• {}: {}", "Insights Generated".cyan().bold(), result.insights.len());

    Ok(())
}
