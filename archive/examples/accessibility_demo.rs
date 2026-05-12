// use rust_tree_sitter::ai::AIService; // not used in this demo build
use rust_tree_sitter::cli::output::{AccessibilityConfig, AccessibleOutputHandler, AnalysisOutput};
use rust_tree_sitter::{AnalysisResult, CodebaseAnalyzer};
use std::path::PathBuf;

/// # Rust Tree-sitter Accessibility Demo
///
/// This demo showcases the comprehensive accessibility features of the Rust Tree-sitter
/// code analysis library, including:
///
/// - Screen reader friendly output formats
/// - High contrast and simple text modes
/// - Multi-language support (i18n)
/// - Keyboard navigation features
/// - Verbose descriptions for better understanding
/// - Accessibility configuration options
///
/// ## Running the Demo
///
/// ```bash
/// cargo run --example accessibility_demo -- /path/to/your/codebase
/// ```
///
/// ## Accessibility Features Demonstrated
///
/// 1. **Screen Reader Mode**: Provides verbose descriptions for screen readers
/// 2. **High Contrast**: Enhances visibility for users with visual impairments
/// 3. **Simple Text**: Removes emojis and icons for cleaner output
/// 4. **Multi-language**: Supports English, Spanish, French, German, Chinese, Japanese
/// 5. **Keyboard Navigation**: Full keyboard-only operation support
/// 6. **Verbose Mode**: Detailed explanations of analysis results

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧑‍🦯 Rust Tree-sitter Accessibility Demo");
    println!("=====================================");
    println!();
    println!("This demo showcases accessibility features for:");
    println!("• Screen reader users");
    println!("• Users with visual impairments");
    println!("• Keyboard-only navigation");
    println!("• Multi-language support");
    println!("• High contrast requirements");
    println!();

    // Get the path to analyze from command line arguments
    let args: Vec<String> = std::env::args().collect();
    let path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        // Use current directory as default
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };

    println!("📁 Analyzing path: {}", path.display());
    println!();

    // Initialize the analyzer
    let mut analyzer =
        CodebaseAnalyzer::new().map_err(|e| format!("Failed to create analyzer: {}", e))?;

    // Perform the analysis
    let analysis_result = if path.is_file() {
        println!("📄 Analyzing single file...");
        analyzer.analyze_file(&path)
    } else {
        println!("📂 Analyzing directory...");
        analyzer.analyze_directory(&path)
    }
    .map_err(|e| format!("Analysis failed: {}", e))?;

    println!("✅ Analysis completed successfully!");
    println!("   Files analyzed: {}", analysis_result.files.len());
    println!(
        "   Total symbols: {}",
        analysis_result
            .files
            .iter()
            .map(|f| f.symbols.len())
            .sum::<usize>()
    );
    println!();

    // Demo 1: Standard Accessible Output
    println!("🎯 Demo 1: Standard Accessible Output");
    println!("====================================");
    demo_standard_accessible(&analysis_result);
    println!();

    // Demo 2: Screen Reader Mode
    println!("🗣️  Demo 2: Screen Reader Mode");
    println!("=============================");
    demo_screen_reader_mode(&analysis_result);
    println!();

    // Demo 3: High Contrast Mode
    println!("🔆 Demo 3: High Contrast Mode");
    println!("============================");
    demo_high_contrast_mode(&analysis_result);
    println!();

    // Demo 4: Simple Text Mode (No Emojis)
    println!("📝 Demo 4: Simple Text Mode");
    println!("===========================");
    demo_simple_text_mode(&analysis_result);
    println!();

    // Demo 5: Verbose Descriptions
    println!("📖 Demo 5: Verbose Descriptions");
    println!("==============================");
    demo_verbose_descriptions(&analysis_result);
    println!();

    // Demo 6: Multi-Language Support
    println!("🌍 Demo 6: Multi-Language Support");
    println!("================================");
    demo_multi_language_support(&analysis_result);
    println!();

    // Demo 7: Combined Accessibility Features
    println!("🔧 Demo 7: Combined Accessibility Features");
    println!("==========================================");
    demo_combined_features(&analysis_result);
    println!();

    // Demo 8: Keyboard Navigation Guide
    println!("⌨️  Demo 8: Keyboard Navigation Guide");
    println!("====================================");
    demo_keyboard_navigation();
    println!();

    // Demo 9: Accessibility Configuration
    println!("⚙️  Demo 9: Accessibility Configuration");
    println!("=====================================");
    demo_accessibility_configuration();
    println!();

    println!("🎉 Accessibility Demo Completed!");
    println!("================================");
    println!("All accessibility features have been demonstrated.");
    println!("These features ensure the tool is usable by:");
    println!("• Users with visual impairments");
    println!("• Screen reader users");
    println!("• Keyboard-only users");
    println!("• Users requiring high contrast");
    println!("• Users who prefer simple text interfaces");
    println!("• Users who need localized content");

    Ok(())
}

fn demo_standard_accessible(result: &AnalysisResult) {
    let config = AccessibilityConfig::default();
    let handler = AccessibleOutputHandler::new(config);
    let analysis_output = convert_to_analysis_output(result);
    let output = handler.format_accessible_text(&analysis_output);

    println!("Standard accessible text output:");
    println!("{}", output);
}

fn demo_screen_reader_mode(result: &AnalysisResult) {
    let mut config = AccessibilityConfig::default();
    config.screen_reader_mode = true;
    config.verbose_descriptions = true;

    let handler = AccessibleOutputHandler::new(config);
    let analysis_output = convert_to_analysis_output(result);
    let output = handler.format_accessible_text(&analysis_output);

    println!("Screen reader friendly output with verbose descriptions:");
    println!("{}", output);
}

fn demo_high_contrast_mode(_result: &AnalysisResult) {
    let mut config = AccessibilityConfig::default();
    config.high_contrast = true;
    config.no_colors = false; // We still want some color for high contrast

    let handler = AccessibleOutputHandler::new(config);
    let settings = handler.apply_accessibility_settings();

    println!("High contrast configuration:");
    println!("{}", settings);
    println!();
    println!("Note: High contrast would be applied to terminal colors.");
    println!("In a real implementation, this would change the terminal color scheme.");
}

fn demo_simple_text_mode(result: &AnalysisResult) {
    let mut config = AccessibilityConfig::default();
    config.simple_text = true;

    let handler = AccessibleOutputHandler::new(config);
    let analysis_output = convert_to_analysis_output(result);
    let output = handler.format_accessible_text(&analysis_output);

    println!("Simple text output (no emojis or icons):");
    println!("{}", output);
}

fn demo_verbose_descriptions(result: &AnalysisResult) {
    let mut config = AccessibilityConfig::default();
    config.verbose_descriptions = true;
    config.screen_reader_mode = true;

    let handler = AccessibleOutputHandler::new(config);
    let analysis_output = convert_to_analysis_output(result);
    let output = handler.format_accessible_text(&analysis_output);

    println!("Output with verbose descriptions for better understanding:");
    println!("{}", output);
}

fn demo_multi_language_support(result: &AnalysisResult) {
    let languages = vec!["en", "es", "fr", "de", "zh", "ja"];

    for lang in languages {
        let mut config = AccessibilityConfig::default();
        config.language = lang.to_string();

        let handler = AccessibleOutputHandler::new(config);
        let _analysis_output = convert_to_analysis_output(result);

        println!("Language: {} ({})", lang, get_language_name(lang));
        println!("Sample messages:");
        println!(
            "  Analysis complete: {}",
            handler.get_message("analysis_complete")
        );
        println!(
            "  Files analyzed: {}",
            handler.get_message("files_analyzed")
        );
        println!(
            "  Security issues: {}",
            handler.get_message("security_issues")
        );
        println!();
    }
}

fn demo_combined_features(result: &AnalysisResult) {
    let mut config = AccessibilityConfig::default();
    config.screen_reader_mode = true;
    config.high_contrast = true;
    config.simple_text = true;
    config.verbose_descriptions = true;
    config.language = "es".to_string(); // Spanish

    let handler = AccessibleOutputHandler::new(config);
    let analysis_output = convert_to_analysis_output(result);
    let output = handler.format_accessible_text(&analysis_output);

    println!("Combined accessibility features (Spanish, screen reader, high contrast, simple text, verbose):");
    println!("{}", output);
}

fn demo_keyboard_navigation() {
    println!("Keyboard navigation features available:");
    println!();
    println!("Interactive CLI Mode:");
    println!("• Tab - Auto-completion");
    println!("• ↑/↓ - Command history navigation");
    println!("• Ctrl+R - Reverse search in history");
    println!("• Ctrl+L - Clear screen");
    println!("• Ctrl+C - Interrupt current command");
    println!("• Home/End - Jump to start/end of line");
    println!("• Backspace/Delete - Text editing");
    println!();
    println!("Accessibility Commands:");
    println!("• 'accessibility' - Show accessibility menu");
    println!("• 'keyboard' - Display keyboard shortcuts");
    println!("• 'contrast' - Toggle high contrast mode");
    println!("• 'voice' - Toggle voice feedback");
    println!("• 'language <code>' - Change language");
    println!();
    println!("Command Examples:");
    println!("• 'find main' - Find symbols containing 'main'");
    println!("• 'explain function_name' - Explain a symbol");
    println!("• 'stats' - Show statistics");
    println!("• 'help' - Show help");
}

fn demo_accessibility_configuration() {
    println!("Available accessibility configuration options:");
    println!();

    let config = AccessibilityConfig::default();
    let handler = AccessibleOutputHandler::new(config);
    let settings = handler.apply_accessibility_settings();

    println!("Default configuration:");
    println!("{}", settings);
    println!();

    println!("Configuration Options:");
    println!("• screen_reader_mode: bool - Enables verbose descriptions");
    println!("• high_contrast: bool - Uses high contrast colors");
    println!("• no_colors: bool - Disables all ANSI colors");
    println!("• simple_text: bool - Removes emojis and icons");
    println!("• verbose_descriptions: bool - Adds detailed explanations");
    println!("• language: String - Language code (en, es, fr, de, zh, ja)");
    println!();

    println!("Supported Output Formats:");
    println!("• 'accessible' - Basic accessible text");
    println!("• 'localized:es' - Spanish accessible text");
    println!("• 'localized:fr' - French accessible text");
    println!("• 'localized:de' - German accessible text");
    println!("• 'localized:zh' - Chinese accessible text");
    println!("• 'localized:ja' - Japanese accessible text");
}

fn get_language_name(code: &str) -> &'static str {
    match code {
        "en" => "English",
        "es" => "Español",
        "fr" => "Français",
        "de" => "Deutsch",
        "zh" => "中文",
        "ja" => "日本語",
        _ => "Unknown",
    }
}

/// Convert AnalysisResult to AnalysisOutput for accessibility
fn convert_to_analysis_output(result: &AnalysisResult) -> AnalysisOutput {
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
