//! Enhanced Output Formatting System
//!
//! Provides standardized output formats across all CLI commands with:
//! - Consistent JSON schemas
//! - Enhanced table formatting with colors and icons
//! - Markdown output for documentation generation
//! - Custom format templates support

use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tabled::{
    settings::{object::Columns, Alignment, Color, Style},
    Table, Tabled,
};

/// Output format options
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Table,
    Json,
    Sarif,
    Markdown,
    Summary,
    Text,
    Html,
    Csv,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            "summary" => Ok(OutputFormat::Summary),
            "text" => Ok(OutputFormat::Text),
            "html" => Ok(OutputFormat::Html),
            "csv" => Ok(OutputFormat::Csv),
            _ => Err(format!("Unsupported format: {}. Supported: table, json, sarif, markdown, summary, text, html, csv", s)),
        }
    }

    pub fn supported_formats() -> Vec<&'static str> {
        vec![
            "table", "json", "sarif", "markdown", "summary", "text", "html", "csv",
        ]
    }
}

/// Standardized JSON schema for analysis results
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnalysisOutput {
    pub metadata: OutputMetadata,
    pub summary: AnalysisSummary,
    pub files: Vec<FileOutput>,
    pub symbols: Vec<SymbolOutput>,
    pub languages: HashMap<String, LanguageStats>,
    pub security: Option<SecurityOutput>,
    pub dependencies: Option<DependencyOutput>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputMetadata {
    pub tool_version: String,
    pub analysis_timestamp: String,
    pub target_path: String,
    pub analysis_duration_ms: u64,
    pub output_format: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnalysisSummary {
    pub total_files: usize,
    pub total_lines: usize,
    pub total_size_bytes: u64,
    pub total_symbols: usize,
    pub languages_count: usize,
    pub analysis_status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileOutput {
    pub path: String,
    pub language: String,
    pub lines: usize,
    pub size_bytes: usize,
    pub symbols_count: usize,
    pub parse_status: String,
    pub complexity_score: Option<f64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SymbolOutput {
    pub name: String,
    pub kind: String,
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub visibility: String,
    pub documentation: Option<String>,
    pub complexity: Option<usize>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LanguageStats {
    pub files_count: usize,
    pub lines_count: usize,
    pub symbols_count: usize,
    pub size_bytes: u64,
    pub percentage: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityOutput {
    pub total_issues: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub vulnerabilities: Vec<VulnerabilityOutput>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilityOutput {
    pub severity: String,
    pub rule_id: String,
    pub message: String,
    pub file_path: String,
    pub line: Option<usize>,
    pub code_snippet: Option<String>,
    pub suggestion: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DependencyOutput {
    pub total_dependencies: usize,
    pub direct_dependencies: usize,
    pub transitive_dependencies: usize,
    pub vulnerabilities_found: usize,
    pub dependencies: Vec<DependencyInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DependencyInfo {
    pub name: String,
    pub version: Option<String>,
    pub kind: String,
    pub source: Option<String>,
    pub vulnerabilities: Vec<String>,
}

/// Enhanced table formatting with colors and icons
pub trait EnhancedTable {
    fn to_colored_table(&self) -> String;
    fn to_markdown_table(&self) -> String;
    fn to_csv(&self) -> String;
}

/// Table row for file information with enhanced formatting
#[derive(Tabled, Serialize, Deserialize, Debug, Clone)]
pub struct FileRow {
    #[tabled(rename = "📁 File")]
    pub path: String,
    #[tabled(rename = "🔤 Language")]
    pub language: String,
    #[tabled(rename = "📊 Lines")]
    pub lines: String,
    #[tabled(rename = "💾 Size")]
    pub size: String,
    #[tabled(rename = "🔧 Symbols")]
    pub symbols: String,
    #[tabled(rename = "✅ Status")]
    pub status: String,
}

impl FileRow {
    pub fn new(file: &crate::FileInfo) -> Self {
        let status_icon = if file.parsed_successfully {
            "✅"
        } else {
            "❌"
        };
        let status_color = if file.parsed_successfully {
            "green"
        } else {
            "red"
        };

        Self {
            path: file.path.to_string_lossy().to_string(),
            language: file.language.clone(),
            lines: file.lines.to_string(),
            size: format_size(file.size),
            symbols: file.symbols.len().to_string(),
            status: format!(
                "{} {}",
                status_icon,
                if file.parsed_successfully {
                    "OK"
                } else {
                    "Failed"
                }
            ),
        }
    }
}

impl EnhancedTable for Vec<FileRow> {
    fn to_colored_table(&self) -> String {
        let mut table = Table::new(self);
        table
            .with(Style::modern())
            .with(Color::BG_BLUE)
            .with(Alignment::left());

        // Apply color to status column
        for (i, row) in self.iter().enumerate() {
            if row.status.contains("❌") {
                // This would apply red color to failed rows in a real implementation
            }
        }

        table.to_string()
    }

    fn to_markdown_table(&self) -> String {
        let mut md = String::from("| File | Language | Lines | Size | Symbols | Status |\n");
        md.push_str("|------|----------|-------|------|---------|--------|\n");

        for row in self {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                row.path, row.language, row.lines, row.size, row.symbols, row.status
            ));
        }

        md
    }

    fn to_csv(&self) -> String {
        let mut csv = String::from("File,Language,Lines,Size,Symbols,Status\n");

        for row in self {
            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                row.path.replace("\"", "\"\""),
                row.language,
                row.lines,
                row.size,
                row.symbols,
                row.status
            ));
        }

        csv
    }
}

/// Enhanced symbol table with better formatting
#[derive(Tabled, Serialize, Deserialize, Debug, Clone)]
pub struct SymbolRow {
    #[tabled(rename = "🔧 Symbol")]
    pub name: String,
    #[tabled(rename = "📋 Type")]
    pub kind: String,
    #[tabled(rename = "📁 File")]
    pub file: String,
    #[tabled(rename = "📍 Line")]
    pub line: String,
    #[tabled(rename = "👁️ Visibility")]
    pub visibility: String,
}

impl SymbolRow {
    pub fn new(symbol: &crate::Symbol, file_path: &str) -> Self {
        Self {
            name: symbol.name.clone(),
            kind: format_symbol_type(&symbol.kind),
            file: file_path.to_string(),
            line: symbol.start_line.to_string(),
            visibility: symbol.visibility.clone(),
        }
    }
}

impl EnhancedTable for Vec<SymbolRow> {
    fn to_colored_table(&self) -> String {
        let mut table = Table::new(self);
        table
            .with(Style::modern())
            .with(Color::BG_CYAN)
            .with(Alignment::left());

        table.to_string()
    }

    fn to_markdown_table(&self) -> String {
        let mut md = String::from("| Symbol | Type | File | Line | Visibility |\n");
        md.push_str("|--------|------|------|------|------------|\n");

        for row in self {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                row.name, row.kind, row.file, row.line, row.visibility
            ));
        }

        md
    }

    fn to_csv(&self) -> String {
        let mut csv = String::from("Symbol,Type,File,Line,Visibility\n");

        for row in self {
            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                row.name.replace("\"", "\"\""),
                row.kind,
                row.file.replace("\"", "\"\""),
                row.line,
                row.visibility
            ));
        }

        csv
    }
}

/// Format file size in human-readable format with colors
pub fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{}B", bytes).bright_white().to_string()
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
            .bright_yellow()
            .to_string()
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
            .bright_red()
            .to_string()
    }
}

/// Format symbol type with appropriate icon
pub fn format_symbol_type(kind: &str) -> String {
    match kind.to_lowercase().as_str() {
        "function" => format!("🔧 {}", kind),
        "class" | "struct" => format!("🏗️ {}", kind),
        "method" => format!("⚡ {}", kind),
        "variable" | "const" => format!("📦 {}", kind),
        "enum" => format!("🔢 {}", kind),
        "interface" | "trait" => format!("🔗 {}", kind),
        "module" => format!("📁 {}", kind),
        "import" => format!("📥 {}", kind),
        _ => kind.to_string(),
    }
}

/// Create enhanced header with colors and styling
pub fn print_enhanced_header(title: &str, subtitle: Option<&str>, color: &str) {
    let separator = "═".repeat(title.len().max(50));

    let colored_title = match color {
        "blue" => title.bright_blue().bold(),
        "cyan" => title.bright_cyan().bold(),
        "green" => title.bright_green().bold(),
        "yellow" => title.bright_yellow().bold(),
        "red" => title.bright_red().bold(),
        "magenta" => title.bright_magenta().bold(),
        _ => title.bright_white().bold(),
    };

    println!("\n{}", colored_title);
    println!("{}", separator.color(color));

    if let Some(sub) = subtitle {
        println!("{}", sub.bright_black());
    }
    println!();
}

/// Print comprehensive summary with enhanced formatting
pub fn print_enhanced_summary(result: &crate::AnalysisResult) {
    print_enhanced_header("📊 CODEBASE ANALYSIS SUMMARY", None, "cyan");

    // Overall statistics
    println!("{}", "📈 OVERALL STATISTICS".bright_yellow().bold());
    println!(
        "   Files analyzed: {}",
        result.files.len().to_string().bright_white()
    );
    println!(
        "   Total lines: {}",
        result.total_lines.to_string().bright_white()
    );

    let total_size: usize = result.files.iter().map(|f| f.size).sum();
    println!("   Total size: {}", format_size(total_size));
    println!();

    // Language breakdown
    if !result.languages.is_empty() {
        println!("{}", "🔤 LANGUAGE BREAKDOWN".bright_yellow().bold());
        let mut langs: Vec<_> = result.languages.iter().collect();
        langs.sort_by(|a, b| b.1.cmp(a.1));

        for (lang, count) in langs.iter().take(5) {
            let percentage = (**count as f64 / result.files.len() as f64) * 100.0;
            let progress_bar = create_progress_bar(percentage);
            println!(
                "   {}: {} files ({:.1}%) {}",
                lang.bright_blue(),
                count,
                percentage,
                progress_bar
            );
        }

        if langs.len() > 5 {
            println!("   ... and {} more languages", langs.len() - 5);
        }
        println!();
    }

    // Symbol statistics
    let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
    if total_symbols > 0 {
        println!("{}", "🔧 SYMBOL STATISTICS".bright_yellow().bold());
        println!(
            "   Total symbols: {}",
            total_symbols.to_string().bright_white()
        );

        let mut symbol_counts = HashMap::new();
        for file in &result.files {
            for symbol in &file.symbols {
                *symbol_counts.entry(&symbol.kind).or_insert(0) += 1;
            }
        }

        let mut symbol_vec: Vec<_> = symbol_counts.into_iter().collect();
        symbol_vec.sort_by(|a, b| b.1.cmp(&a.1));

        for (kind, count) in symbol_vec.iter().take(5) {
            let percentage = (*count as f64 / total_symbols as f64) * 100.0;
            let icon = match kind.to_lowercase().as_str() {
                "function" => "🔧",
                "class" | "struct" => "🏗️",
                "method" => "⚡",
                "variable" => "📦",
                _ => "🔸",
            };
            println!("   {} {}: {} ({:.1}%)", icon, kind, count, percentage);
        }
        println!();
    }

    // File analysis summary
    let parsed_files = result
        .files
        .iter()
        .filter(|f| f.parsed_successfully)
        .count();
    let failed_files = result.files.len() - parsed_files;

    println!("{}", "📁 FILE ANALYSIS".bright_yellow().bold());
    println!(
        "   Successfully parsed: {} files",
        parsed_files.to_string().bright_green()
    );

    if failed_files > 0 {
        println!(
            "   Failed to parse: {} files",
            failed_files.to_string().bright_red()
        );
    }

    if let Some(largest_file) = result.files.iter().max_by_key(|f| f.size) {
        println!(
            "   Largest file: {} ({})",
            largest_file
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            format_size(largest_file.size)
        );
    }

    if let Some(most_complex) = result.files.iter().max_by_key(|f| f.symbols.len()) {
        println!(
            "   Most complex: {} ({} symbols)",
            most_complex
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            most_complex.symbols.len()
        );
    }
}

/// Create a simple progress bar
fn create_progress_bar(percentage: f64) -> String {
    let width = 20;
    let filled = ((percentage / 100.0) * width as f64) as usize;
    let empty = width - filled;

    let filled_bar = "█".repeat(filled);
    let empty_bar = "░".repeat(empty);

    format!(
        "[{}{}] {:.1}%",
        filled_bar.bright_green(),
        empty_bar.bright_black(),
        percentage
    )
}

/// Generate comprehensive markdown report
pub fn generate_markdown_report(result: &crate::AnalysisResult) -> String {
    let mut md = String::new();

    md.push_str("# Codebase Analysis Report\n\n");
    md.push_str(&format!(
        "**Generated:** {}\n\n",
        chrono::Utc::now().to_rfc3339()
    ));

    // Summary section
    md.push_str("## Summary\n\n");
    md.push_str(&format!("- **Files Analyzed:** {}\n", result.files.len()));
    md.push_str(&format!("- **Total Lines:** {}\n", result.total_lines));
    md.push_str(&format!("- **Languages:** {}\n", result.languages.len()));

    let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
    md.push_str(&format!("- **Total Symbols:** {}\n\n", total_symbols));

    // Languages section
    if !result.languages.is_empty() {
        md.push_str("## Languages\n\n");
        md.push_str("| Language | Files | Percentage |\n");
        md.push_str("|----------|-------|------------|\n");

        let mut langs: Vec<_> = result.languages.iter().collect();
        langs.sort_by(|a, b| b.1.cmp(a.1));

        for (lang, count) in langs {
            let percentage = (*count as f64 / result.files.len() as f64) * 100.0;
            md.push_str(&format!("| {} | {} | {:.1}% |\n", lang, count, percentage));
        }
        md.push_str("\n");
    }

    // Top files section
    md.push_str("## Largest Files\n\n");
    md.push_str("| File | Size | Lines |\n");
    md.push_str("|------|------|-------|\n");

    let mut largest_files: Vec<_> = result.files.iter().collect();
    largest_files.sort_by(|a, b| b.size.cmp(&a.size));

    for file in largest_files.iter().take(10) {
        md.push_str(&format!(
            "| {} | {} | {} |\n",
            file.path.file_name().unwrap_or_default().to_string_lossy(),
            format_size(file.size),
            file.lines
        ));
    }

    md
}

/// Generate HTML report with enhanced styling
pub fn generate_html_report(result: &crate::AnalysisResult) -> String {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n");
    html.push_str("<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("<title>Codebase Analysis Report</title>\n");
    html.push_str("<style>\n");
    html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }\n");
    html.push_str(".container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }\n");
    html.push_str(
        "h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }\n",
    );
    html.push_str("h2 { color: #34495e; margin-top: 30px; }\n");
    html.push_str(".stat-card { background: #ecf0f1; padding: 20px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #3498db; }\n");
    html.push_str(".stat-number { font-size: 2em; font-weight: bold; color: #2c3e50; }\n");
    html.push_str("table { width: 100%; border-collapse: collapse; margin: 20px 0; }\n");
    html.push_str("th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }\n");
    html.push_str("th { background-color: #3498db; color: white; }\n");
    html.push_str("tr:hover { background-color: #f5f5f5; }\n");
    html.push_str(".progress-bar { width: 100px; height: 8px; background: #ecf0f1; border-radius: 4px; overflow: hidden; }\n");
    html.push_str(".progress-fill { height: 100%; background: #27ae60; }\n");
    html.push_str("</style>\n");
    html.push_str("</head>\n<body>\n");
    html.push_str("<div class=\"container\">\n");

    html.push_str("<h1>📊 Codebase Analysis Report</h1>\n");
    html.push_str(&format!(
        "<p><strong>Generated:</strong> {}</p>\n",
        chrono::Utc::now().to_rfc3339()
    ));

    // Summary cards
    html.push_str("<div style=\"display: flex; gap: 20px; margin: 30px 0;\">\n");
    html.push_str(&format!("<div class=\"stat-card\"><div class=\"stat-number\">{}</div><div>Files Analyzed</div></div>\n", result.files.len()));
    html.push_str(&format!("<div class=\"stat-card\"><div class=\"stat-number\">{}</div><div>Total Lines</div></div>\n", result.total_lines));

    let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
    html.push_str(&format!("<div class=\"stat-card\"><div class=\"stat-number\">{}</div><div>Total Symbols</div></div>\n", total_symbols));
    html.push_str(&format!(
        "<div class=\"stat-card\"><div class=\"stat-number\">{}</div><div>Languages</div></div>\n",
        result.languages.len()
    ));
    html.push_str("</div>\n");

    // Languages table
    if !result.languages.is_empty() {
        html.push_str("<h2>🔤 Languages</h2>\n");
        html.push_str("<table>\n");
        html.push_str("<tr><th>Language</th><th>Files</th><th>Lines</th><th>Progress</th></tr>\n");

        let mut langs: Vec<_> = result.languages.iter().collect();
        langs.sort_by(|a, b| b.1.cmp(a.1));

        for (lang, count) in langs {
            let percentage = (*count as f64 / result.files.len() as f64) * 100.0;
            let lines_for_lang: usize = result
                .files
                .iter()
                .filter(|f| &f.language == lang)
                .map(|f| f.lines)
                .sum();

            html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td><div class=\"progress-bar\"><div class=\"progress-fill\" style=\"width: {}%\"></div></div></td></tr>\n",
                lang, count, lines_for_lang, percentage));
        }
        html.push_str("</table>\n");
    }

    html.push_str("</div>\n</body>\n</html>\n");
    html
}

/// Save output to file with format-specific handling
pub fn save_output_to_file<T: Serialize>(
    data: &T,
    path: &PathBuf,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(data)?;
            std::fs::write(path, json)?;
        }
        OutputFormat::Markdown => {
            // For now, use JSON format for non-AnalysisResult types
            let json = serde_json::to_string_pretty(data)?;
            std::fs::write(path, json)?;
        }
        OutputFormat::Html => {
            // For now, use JSON format for non-AnalysisResult types
            let json = serde_json::to_string_pretty(data)?;
            std::fs::write(path, json)?;
        }
        OutputFormat::Csv => {
            // For now, use JSON format for non-AnalysisResult types
            let json = serde_json::to_string_pretty(data)?;
            std::fs::write(path, json)?;
        }
        _ => {
            let json = serde_json::to_string_pretty(data)?;
            std::fs::write(path, json)?;
        }
    }

    println!(
        "\n{}",
        format!("Results saved to {}", path.display()).green()
    );
    Ok(())
}

/// Save analysis result to file with full format support
pub fn save_analysis_result_to_file(
    result: &crate::AnalysisResult,
    path: &PathBuf,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(result)?;
            std::fs::write(path, json)?;
        }
        OutputFormat::Markdown => {
            let markdown = generate_markdown_report(result);
            std::fs::write(path, markdown)?;
        }
        OutputFormat::Html => {
            let html = generate_html_report(result);
            std::fs::write(path, html)?;
        }
        OutputFormat::Csv => {
            let csv = generate_csv_output(result);
            std::fs::write(path, csv)?;
        }
        _ => {
            let json = serde_json::to_string_pretty(result)?;
            std::fs::write(path, json)?;
        }
    }

    println!(
        "\n{}",
        format!("Results saved to {}", path.display()).green()
    );
    Ok(())
}

/// Generate CSV output for analysis results
pub fn generate_csv_output(result: &crate::AnalysisResult) -> String {
    let mut csv = String::from("File,Language,Lines,Size,Symbols,Status\n");

    for file in &result.files {
        let status = if file.parsed_successfully {
            "OK"
        } else {
            "Failed"
        };
        csv.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            file.path.to_string_lossy().replace("\"", "\"\""),
            file.language,
            file.lines,
            file.size,
            file.symbols.len(),
            status
        ));
    }

    csv
}

/// Print success message with enhanced formatting
pub fn print_success(message: &str) {
    println!("{}", format!("✅ {}", message).green().bold());
}

/// Print error message with enhanced formatting
pub fn print_error(message: &str) {
    eprintln!("{}", format!("❌ {}", message).red().bold());
}

/// Print warning message with enhanced formatting
pub fn print_warning(message: &str) {
    println!("{}", format!("⚠️  {}", message).yellow().bold());
}

/// Print info message with enhanced formatting
pub fn print_info(message: &str) {
    println!("{}", format!("ℹ️  {}", message).blue().bold());
}

/// Create a unified output handler for consistent formatting across commands
pub struct OutputHandler {
    pub format: OutputFormat,
    pub output_path: Option<PathBuf>,
    pub show_progress: bool,
}

impl OutputHandler {
    pub fn new(format: OutputFormat, output_path: Option<PathBuf>, show_progress: bool) -> Self {
        Self {
            format,
            output_path,
            show_progress,
        }
    }

    pub fn output_analysis_result(
        &self,
        result: &crate::AnalysisResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.format {
            OutputFormat::Table => {
                print_enhanced_summary(result);
                if let Some(path) = &self.output_path {
                    save_analysis_result_to_file(result, path, &self.format)?;
                }
            }
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(result)?;
                if let Some(path) = &self.output_path {
                    std::fs::write(path, json)?;
                    print_success(&format!("JSON results saved to {}", path.display()));
                } else {
                    println!("{}", json);
                }
            }
            OutputFormat::Markdown => {
                let markdown = generate_markdown_report(result);
                if let Some(path) = &self.output_path {
                    std::fs::write(path, markdown)?;
                    print_success(&format!("Markdown report saved to {}", path.display()));
                } else {
                    println!("{}", markdown);
                }
            }
            OutputFormat::Html => {
                let html = generate_html_report(result);
                if let Some(path) = &self.output_path {
                    std::fs::write(path, html)?;
                    print_success(&format!("HTML report saved to {}", path.display()));
                } else {
                    println!("{}", html);
                }
            }
            OutputFormat::Summary => {
                print_enhanced_summary(result);
            }
            OutputFormat::Text => {
                print_enhanced_summary(result);
            }
            OutputFormat::Csv => {
                let csv = generate_csv_output(result);
                if let Some(path) = &self.output_path {
                    std::fs::write(path, csv)?;
                    print_success(&format!("CSV data saved to {}", path.display()));
                } else {
                    println!("{}", csv);
                }
            }
            OutputFormat::Sarif => {
                // SARIF format would require additional implementation
                print_warning("SARIF format not yet implemented, using JSON instead");
                let json = serde_json::to_string_pretty(result)?;
                if let Some(path) = &self.output_path {
                    std::fs::write(path, json)?;
                    print_success(&format!("Results saved to {}", path.display()));
                } else {
                    println!("{}", json);
                }
            }
        }

        Ok(())
    }
}

/// Template system for custom output formats
pub struct OutputTemplate {
    pub name: String,
    pub template: String,
    pub variables: HashMap<String, String>,
}

impl OutputTemplate {
    pub fn new(name: &str, template: &str) -> Self {
        Self {
            name: name.to_string(),
            template: template.to_string(),
            variables: HashMap::new(),
        }
    }

    pub fn with_variable(mut self, key: &str, value: &str) -> Self {
        self.variables.insert(key.to_string(), value.to_string());
        self
    }

    pub fn render(&self, data: &HashMap<String, String>) -> String {
        let mut result = self.template.clone();

        for (key, value) in &self.variables {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }

        for (key, value) in data {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }

        result
    }
}

/// Predefined templates for common output formats
pub fn get_template(name: &str) -> Option<OutputTemplate> {
    match name {
        "simple_summary" => Some(OutputTemplate::new(
            "simple_summary",
            "Codebase contains {{{total_files}}} files with {{{total_lines}}} lines of code in {{{languages}}} languages."
        )),
        "detailed_report" => Some(OutputTemplate::new(
            "detailed_report",
            "# Codebase Report\n\n- Files: {{{total_files}}}\n- Lines: {{{total_lines}}}\n- Languages: {{{languages}}}\n- Symbols: {{{total_symbols}}}\n\nGenerated on: {{{timestamp}}}"
        )),
        "ci_summary" => Some(OutputTemplate::new(
            "ci_summary",
            "::set-output name=files::{{{total_files}}}\n::set-output name=lines::{{{total_lines}}}\n::set-output name=languages::{{{languages}}}"
        )),
        _ => None,
    }
}
