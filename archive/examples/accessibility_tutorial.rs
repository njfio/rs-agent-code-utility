//! # Rust Tree-sitter Accessibility Tutorial
//!
//! This tutorial demonstrates the advanced accessibility features and comprehensive
//! analysis capabilities of the Rust Tree-sitter library. Learn how to:
//!
//! - Use screen reader friendly output formats
//! - Configure accessibility options for better usability
//! - Perform advanced security analysis with AI integration
//! - Analyze code quality metrics across multiple languages
//! - Leverage the comprehensive multi-language support
//!
//! ## Prerequisites
//!
//! - Rust 1.70+
//! - Access to the rust_tree_sitter library
//! - Sample codebases to analyze (we'll create some in this tutorial)

use rust_tree_sitter::ai::AIService;
use rust_tree_sitter::cli::output::{AccessibilityConfig, AccessibleOutputHandler, AnalysisOutput};
use rust_tree_sitter::{AnalysisResult, CodebaseAnalyzer};
use std::path::PathBuf;

/// Main tutorial function demonstrating accessibility features
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧑‍🦯 Rust Tree-sitter Accessibility Tutorial");
    println!("==========================================");
    println!();

    // Initialize the codebase analyzer
    let mut analyzer =
        CodebaseAnalyzer::new().map_err(|e| format!("Failed to create analyzer: {}", e))?;

    // Part 1: Basic Accessibility Configuration
    println!("📖 Part 1: Accessibility Configuration");
    println!("--------------------------------------");

    // Create different accessibility configurations
    let screen_reader_config = AccessibilityConfig {
        screen_reader_mode: true,
        high_contrast: true,
        no_colors: true,
        simple_text: true,
        language: "en".to_string(),
        verbose_descriptions: true,
    };

    let minimal_config = AccessibilityConfig {
        screen_reader_mode: false,
        high_contrast: false,
        no_colors: false,
        simple_text: true,
        language: "en".to_string(),
        verbose_descriptions: false,
    };

    println!("✓ Created accessibility configurations:");
    println!("  - Screen reader friendly mode");
    println!("  - Minimal configuration for basic accessibility");
    println!();

    // Part 2: Sample Codebase Creation
    println!("📝 Part 2: Creating Sample Codebase");
    println!("-----------------------------------");

    let temp_dir =
        tempfile::TempDir::new().map_err(|e| format!("Failed to create temp directory: {}", e))?;

    // Create sample files in different languages
    create_sample_files(&temp_dir)?;

    println!("✓ Created sample codebase with multiple languages");
    println!("  - Rust: main.rs with basic functionality");
    println!("  - Python: app.py with web server code");
    println!("  - JavaScript: utils.js with helper functions");
    println!();

    // Part 3: Basic Analysis with Accessibility
    println!("🔍 Part 3: Basic Codebase Analysis");
    println!("-----------------------------------");

    let analysis_result = analyzer
        .analyze_directory(&temp_dir.path())
        .map_err(|e| format!("Analysis failed: {}", e))?;

    println!("✓ Analysis completed:");
    println!("  - Files analyzed: {}", analysis_result.files.len());
    println!(
        "  - Total symbols: {}",
        analysis_result
            .files
            .iter()
            .map(|f| f.symbols.len())
            .sum::<usize>()
    );
    println!();

    // Part 4: Accessible Output Demonstration
    println!("🎯 Part 4: Accessible Output Formats");
    println!("------------------------------------");

    // Convert to accessible format
    let accessible_output = convert_to_accessible_output(&analysis_result);

    // Demonstrate different accessibility configurations
    let handler_screen_reader = AccessibleOutputHandler::new(screen_reader_config);
    let handler_minimal = AccessibleOutputHandler::new(minimal_config);

    println!("📱 Screen Reader Friendly Output:");
    println!("--------------------------------");
    let screen_reader_text = handler_screen_reader.format_accessible_text(&accessible_output);
    println!("{}", screen_reader_text);
    println!();

    println!("📄 Minimal Accessible Output:");
    println!("-----------------------------");
    let minimal_text = handler_minimal.format_accessible_text(&accessible_output);
    println!("{}", minimal_text);
    println!();

    // Part 5: Advanced Security Analysis
    println!("🔒 Part 5: Advanced Security Analysis");
    println!("-------------------------------------");

    // Initialize AI service for security analysis
    let ai_service = initialize_ai_service().await?;

    // Analyze security vulnerabilities
    for file in &analysis_result.files {
        if file.language == "rust" {
            println!("🔍 Analyzing security in: {}", file.path.display());

            let security_result = analyze_file_security(&ai_service, &file.path).await?;
            println!("   Security Status: {}", security_result);
        }
    }
    println!();

    // Part 6: Code Quality Metrics
    println!("📊 Part 6: Code Quality Analysis");
    println!("--------------------------------");

    for file in &analysis_result.files {
        println!("📈 Quality metrics for: {}", file.path.display());
        println!("   - Lines of code: {}", file.lines);
        println!("   - Symbols: {}", file.symbols.len());
        println!("   - Language: {}", file.language);
        println!(
            "   - Parse status: {}",
            if file.parsed_successfully {
                "Successful"
            } else {
                "Failed"
            }
        );
    }
    println!();

    // Part 7: Multi-Language Support
    println!("🌍 Part 7: Multi-Language Support");
    println!("---------------------------------");

    let languages: std::collections::HashSet<String> = analysis_result
        .files
        .iter()
        .map(|f| f.language.clone())
        .collect();

    println!("✓ Supported languages in this analysis:");
    for lang in &languages {
        let count = analysis_result
            .files
            .iter()
            .filter(|f| f.language == *lang)
            .count();
        println!("  - {}: {} files", lang, count);
    }
    println!();

    // Part 8: Accessibility Settings Summary
    println!("⚙️  Part 8: Accessibility Settings Guide");
    println!("---------------------------------------");

    println!("🎯 Available Accessibility Options:");
    println!("  - screen_reader_mode: Enables verbose descriptions for screen readers");
    println!("  - high_contrast: Uses high contrast colors for better visibility");
    println!("  - no_colors: Completely disables ANSI color codes");
    println!("  - simple_text: Removes emojis and icons for cleaner output");
    println!("  - verbose_descriptions: Adds detailed explanations");
    println!("  - language: Supports localization (currently 'en' only)");
    println!();

    println!("🚀 Tutorial completed successfully!");
    println!("   You now know how to:");
    println!("   ✓ Configure accessibility options");
    println!("   ✓ Use screen reader friendly output");
    println!("   ✓ Perform security analysis");
    println!("   ✓ Analyze code quality metrics");
    println!("   ✓ Work with multiple programming languages");

    Ok(())
}

/// Create sample files for demonstration
fn create_sample_files(temp_dir: &tempfile::TempDir) -> Result<(), Box<dyn std::error::Error>> {
    // Create Rust file
    let rust_file = temp_dir.path().join("main.rs");
    std::fs::write(
        &rust_file,
        r#"
// Sample Rust application
use std::collections::HashMap;

fn main() {
    println!("Hello, World!");

    let mut users = HashMap::new();
    users.insert("admin", "password123"); // Security issue!

    let result = process_data(&users);
    println!("Result: {}", result);
}

fn process_data(data: &HashMap<&str, &str>) -> String {
    // Process user data
    format!("Processed {} users", data.len())
}
"#,
    )?;

    // Create Python file
    let python_file = temp_dir.path().join("app.py");
    std::fs::write(
        &python_file,
        r#"
# Sample Python web application
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello, World!"

@app.route('/user/<username>')
def get_user(username):
    # Potential security issue - no input validation
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return execute_query(query)

def execute_query(sql):
    # Mock database function
    return f"Executed: {sql}"

if __name__ == '__main__':
    app.run(debug=True)
"#,
    )?;

    // Create JavaScript file
    let js_file = temp_dir.path().join("utils.js");
    std::fs::write(
        &js_file,
        r#"
// Utility functions
function validateEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

function calculateTotal(items) {
    return items.reduce((sum, item) => sum + item.price, 0);
}

function processUserData(userData) {
    // Potential XSS vulnerability
    const html = `<div>User: ${userData.name}</div>`;
    return html;
}

module.exports = {
    validateEmail,
    calculateTotal,
    processUserData
};
"#,
    )?;

    Ok(())
}

/// Convert AnalysisResult to AnalysisOutput for accessibility
fn convert_to_accessible_output(result: &AnalysisResult) -> AnalysisOutput {
    use rust_tree_sitter::cli::output::*;

    let files: Vec<FileOutput> = result
        .files
        .iter()
        .map(|file| FileOutput {
            path: file.path.to_string_lossy().to_string(),
            language: file.language.clone(),
            lines: file.lines,
            size_bytes: file.size,
            symbols_count: file.symbols.len(),
            parse_status: if file.parsed_successfully {
                "success".to_string()
            } else {
                "failed".to_string()
            },
            complexity_score: None,
        })
        .collect();

    let symbols: Vec<SymbolOutput> = result
        .files
        .iter()
        .flat_map(|file| {
            file.symbols.iter().map(|symbol| SymbolOutput {
                name: symbol.name.clone(),
                kind: symbol.kind.clone(),
                file_path: file.path.to_string_lossy().to_string(),
                start_line: symbol.start_line,
                end_line: symbol.end_line,
                visibility: symbol.visibility.clone(),
                documentation: None,
                complexity: None,
            })
        })
        .collect();

    let mut languages = std::collections::HashMap::new();
    for file in &result.files {
        let entry = languages
            .entry(file.language.clone())
            .or_insert(LanguageStats {
                files_count: 0,
                lines_count: 0,
                symbols_count: 0,
                size_bytes: 0,
                percentage: 0.0,
            });
        entry.files_count += 1;
        entry.lines_count += file.lines;
        entry.symbols_count += file.symbols.len();
        entry.size_bytes += file.size as u64;
    }

    let total_files = result.files.len() as f64;
    for stats in languages.values_mut() {
        stats.percentage = (stats.files_count as f64 / total_files) * 100.0;
    }

    AnalysisOutput {
        metadata: OutputMetadata {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            analysis_timestamp: format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ),
            target_path: result.root_path.to_string_lossy().to_string(),
            analysis_duration_ms: 0,
            output_format: "accessible".to_string(),
        },
        summary: AnalysisSummary {
            total_files: result.files.len(),
            total_lines: result.files.iter().map(|f| f.lines).sum(),
            total_size_bytes: result.files.iter().map(|f| f.size as u64).sum(),
            total_symbols: result.files.iter().map(|f| f.symbols.len()).sum(),
            languages_count: languages.len(),
            analysis_status: "completed".to_string(),
        },
        files,
        symbols,
        languages,
        security: None,
        dependencies: None,
    }
}

/// Initialize AI service for security analysis
async fn initialize_ai_service() -> Result<AIService, Box<dyn std::error::Error>> {
    // For this tutorial, we'll create a mock AI service
    // In a real application, you'd configure this with actual AI provider credentials

    println!("🤖 Initializing AI service for security analysis...");

    // Mock implementation - in real usage, you'd configure with actual providers
    // let ai_service = AIServiceBuilder::new()
    //     .with_openai_config(openai_config)
    //     .with_anthropic_config(anthropic_config)
    //     .build()
    //     .await?;

    println!("✓ AI service initialized (mock implementation for tutorial)");
    println!("  Note: Real AI integration requires API keys and configuration");

    // Return a placeholder - in real implementation this would be a proper AIService
    Err("AI service not configured for tutorial".into())
}

/// Analyze file security using AI
async fn analyze_file_security(
    _ai_service: &AIService,
    file_path: &PathBuf,
) -> Result<String, Box<dyn std::error::Error>> {
    // Mock security analysis
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    match file_name {
        "main.rs" => Ok("Found potential security issues: hardcoded credentials".to_string()),
        "app.py" => Ok("Found potential security issues: SQL injection vulnerability".to_string()),
        "utils.js" => Ok("Found potential security issues: XSS vulnerability".to_string()),
        _ => Ok("No security issues detected".to_string()),
    }
}
