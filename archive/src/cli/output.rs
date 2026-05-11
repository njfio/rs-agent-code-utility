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
    settings::{Alignment, Color, Style},
    Table, Tabled,
};

/// Accessibility configuration for CLI output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibilityConfig {
    /// Enable screen reader friendly output
    pub screen_reader_mode: bool,
    /// Use high contrast colors
    pub high_contrast: bool,
    /// Disable ANSI color codes entirely
    pub no_colors: bool,
    /// Use simple text output without emojis/icons
    pub simple_text: bool,
    /// Language for localized messages
    pub language: String,
    /// Enable verbose descriptions
    pub verbose_descriptions: bool,
}

impl Default for AccessibilityConfig {
    fn default() -> Self {
        Self {
            screen_reader_mode: false,
            high_contrast: true, // Default to high contrast for better accessibility
            no_colors: false,
            simple_text: false,
            language: "en".to_string(),
            verbose_descriptions: false,
        }
    }
}

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
    Template(String),
    /// Accessibility-focused text output
    AccessibleText,
    /// Localized accessible text output
    LocalizedAccessibleText(String), // Language code
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self, String> {
        // Check for template format first (case-sensitive)
        if s.starts_with("template:") {
            let template_name = s.strip_prefix("template:").unwrap_or(s);
            return Ok(OutputFormat::Template(template_name.to_string()));
        }

        // Check for localized format
        if s.starts_with("localized:") {
            let lang_code = s.strip_prefix("localized:").unwrap_or("en");
            if AccessibleOutputHandler::is_language_supported(lang_code) {
                return Ok(OutputFormat::LocalizedAccessibleText(lang_code.to_string()));
            } else {
                return Err(format!(
                    "Unsupported language: {}. Supported languages: en, es, fr, de, zh, ja",
                    lang_code
                ));
            }
        }

        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            "summary" => Ok(OutputFormat::Summary),
            "text" => Ok(OutputFormat::Text),
            "html" => Ok(OutputFormat::Html),
            "csv" => Ok(OutputFormat::Csv),
            "accessible" | "a11y" => Ok(OutputFormat::AccessibleText),
            _ => Err(format!("Unsupported format: {}. Supported: table, json, sarif, markdown, summary, text, html, csv, accessible, localized:<lang>, template:<name>", s)),
        }
    }

    pub fn supported_formats() -> Vec<&'static str> {
        vec![
            "table",
            "json",
            "sarif",
            "markdown",
            "summary",
            "text",
            "html",
            "csv",
            "accessible",
            "localized:<lang>", // e.g., localized:es, localized:fr
            "template:<name>",
        ]
    }
}

/// Output handler with accessibility support
#[derive(Debug, Clone)]
pub struct AccessibleOutputHandler {
    config: AccessibilityConfig,
    localized_messages: HashMap<String, String>,
}

impl AccessibleOutputHandler {
    pub fn new(config: AccessibilityConfig) -> Self {
        let mut localized_messages = HashMap::new();

        // Initialize localized messages based on language
        match config.language.as_str() {
            "en" | "" => Self::load_english_messages(&mut localized_messages),
            "es" => Self::load_spanish_messages(&mut localized_messages),
            "fr" => Self::load_french_messages(&mut localized_messages),
            "de" => Self::load_german_messages(&mut localized_messages),
            "zh" => Self::load_chinese_messages(&mut localized_messages),
            "ja" => Self::load_japanese_messages(&mut localized_messages),
            _ => {
                // Fallback to English for unsupported languages
                Self::load_english_messages(&mut localized_messages);
            }
        }

        Self {
            config,
            localized_messages,
        }
    }

    fn load_english_messages(messages: &mut HashMap<String, String>) {
        messages.insert(
            "analysis_complete".to_string(),
            "Analysis completed successfully".to_string(),
        );
        messages.insert("files_analyzed".to_string(), "Files analyzed".to_string());
        messages.insert("symbols_found".to_string(), "Symbols found".to_string());
        messages.insert(
            "security_issues".to_string(),
            "Security issues detected".to_string(),
        );
        messages.insert("no_issues".to_string(), "No issues found".to_string());
        messages.insert(
            "error_occurred".to_string(),
            "An error occurred".to_string(),
        );
        messages.insert("summary".to_string(), "SUMMARY".to_string());
        messages.insert(
            "security_analysis".to_string(),
            "SECURITY ANALYSIS".to_string(),
        );
        messages.insert(
            "files_analyzed_header".to_string(),
            "FILES ANALYZED".to_string(),
        );
        messages.insert("file".to_string(), "File".to_string());
        messages.insert("language".to_string(), "Language".to_string());
        messages.insert("lines".to_string(), "Lines".to_string());
        messages.insert("symbols".to_string(), "Symbols".to_string());
        messages.insert("status".to_string(), "Status".to_string());
        messages.insert("critical".to_string(), "Critical".to_string());
        messages.insert("high".to_string(), "High".to_string());
        messages.insert("medium".to_string(), "Medium".to_string());
        messages.insert("low".to_string(), "Low".to_string());
        messages.insert(
            "screen_reader_mode".to_string(),
            "Screen reader mode".to_string(),
        );
        messages.insert(
            "high_contrast".to_string(),
            "High contrast colors".to_string(),
        );
        messages.insert("ansi_colors".to_string(), "ANSI colors".to_string());
        messages.insert("simple_text".to_string(), "Simple text mode".to_string());
        messages.insert(
            "verbose_descriptions".to_string(),
            "Verbose descriptions".to_string(),
        );
        messages.insert(
            "accessibility_settings".to_string(),
            "Accessibility Settings".to_string(),
        );
    }

    fn load_spanish_messages(messages: &mut HashMap<String, String>) {
        messages.insert(
            "analysis_complete".to_string(),
            "Análisis completado exitosamente".to_string(),
        );
        messages.insert(
            "files_analyzed".to_string(),
            "Archivos analizados".to_string(),
        );
        messages.insert(
            "symbols_found".to_string(),
            "Símbolos encontrados".to_string(),
        );
        messages.insert(
            "security_issues".to_string(),
            "Problemas de seguridad detectados".to_string(),
        );
        messages.insert(
            "no_issues".to_string(),
            "No se encontraron problemas".to_string(),
        );
        messages.insert("error_occurred".to_string(), "Ocurrió un error".to_string());
        messages.insert("summary".to_string(), "RESUMEN".to_string());
        messages.insert(
            "security_analysis".to_string(),
            "ANÁLISIS DE SEGURIDAD".to_string(),
        );
        messages.insert(
            "files_analyzed_header".to_string(),
            "ARCHIVOS ANALIZADOS".to_string(),
        );
        messages.insert("file".to_string(), "Archivo".to_string());
        messages.insert("language".to_string(), "Lenguaje".to_string());
        messages.insert("lines".to_string(), "Líneas".to_string());
        messages.insert("symbols".to_string(), "Símbolos".to_string());
        messages.insert("status".to_string(), "Estado".to_string());
        messages.insert("critical".to_string(), "Crítico".to_string());
        messages.insert("high".to_string(), "Alto".to_string());
        messages.insert("medium".to_string(), "Medio".to_string());
        messages.insert("low".to_string(), "Bajo".to_string());
        messages.insert(
            "screen_reader_mode".to_string(),
            "Modo lector de pantalla".to_string(),
        );
        messages.insert(
            "high_contrast".to_string(),
            "Colores de alto contraste".to_string(),
        );
        messages.insert("ansi_colors".to_string(), "Colores ANSI".to_string());
        messages.insert("simple_text".to_string(), "Modo texto simple".to_string());
        messages.insert(
            "verbose_descriptions".to_string(),
            "Descripciones detalladas".to_string(),
        );
        messages.insert(
            "accessibility_settings".to_string(),
            "Configuración de Accesibilidad".to_string(),
        );
    }

    fn load_french_messages(messages: &mut HashMap<String, String>) {
        messages.insert(
            "analysis_complete".to_string(),
            "Analyse terminée avec succès".to_string(),
        );
        messages.insert(
            "files_analyzed".to_string(),
            "Fichiers analysés".to_string(),
        );
        messages.insert("symbols_found".to_string(), "Symboles trouvés".to_string());
        messages.insert(
            "security_issues".to_string(),
            "Problèmes de sécurité détectés".to_string(),
        );
        messages.insert("no_issues".to_string(), "Aucun problème trouvé".to_string());
        messages.insert(
            "error_occurred".to_string(),
            "Une erreur s'est produite".to_string(),
        );
        messages.insert("summary".to_string(), "RÉSUMÉ".to_string());
        messages.insert(
            "security_analysis".to_string(),
            "ANALYSE DE SÉCURITÉ".to_string(),
        );
        messages.insert(
            "files_analyzed_header".to_string(),
            "FICHIERS ANALYSÉS".to_string(),
        );
        messages.insert("file".to_string(), "Fichier".to_string());
        messages.insert("language".to_string(), "Langage".to_string());
        messages.insert("lines".to_string(), "Lignes".to_string());
        messages.insert("symbols".to_string(), "Symboles".to_string());
        messages.insert("status".to_string(), "Statut".to_string());
        messages.insert("critical".to_string(), "Critique".to_string());
        messages.insert("high".to_string(), "Élevé".to_string());
        messages.insert("medium".to_string(), "Moyen".to_string());
        messages.insert("low".to_string(), "Faible".to_string());
        messages.insert(
            "screen_reader_mode".to_string(),
            "Mode lecteur d'écran".to_string(),
        );
        messages.insert(
            "high_contrast".to_string(),
            "Couleurs à haut contraste".to_string(),
        );
        messages.insert("ansi_colors".to_string(), "Couleurs ANSI".to_string());
        messages.insert("simple_text".to_string(), "Mode texte simple".to_string());
        messages.insert(
            "verbose_descriptions".to_string(),
            "Descriptions détaillées".to_string(),
        );
        messages.insert(
            "accessibility_settings".to_string(),
            "Paramètres d'Accessibilité".to_string(),
        );
    }

    fn load_german_messages(messages: &mut HashMap<String, String>) {
        messages.insert(
            "analysis_complete".to_string(),
            "Analyse erfolgreich abgeschlossen".to_string(),
        );
        messages.insert(
            "files_analyzed".to_string(),
            "Dateien analysiert".to_string(),
        );
        messages.insert("symbols_found".to_string(), "Symbole gefunden".to_string());
        messages.insert(
            "security_issues".to_string(),
            "Sicherheitsprobleme erkannt".to_string(),
        );
        messages.insert(
            "no_issues".to_string(),
            "Keine Probleme gefunden".to_string(),
        );
        messages.insert(
            "error_occurred".to_string(),
            "Ein Fehler ist aufgetreten".to_string(),
        );
        messages.insert("summary".to_string(), "ZUSAMMENFASSUNG".to_string());
        messages.insert(
            "security_analysis".to_string(),
            "SICHERHEITSANALYSE".to_string(),
        );
        messages.insert(
            "files_analyzed_header".to_string(),
            "ANALYSIERTE DATEIEN".to_string(),
        );
        messages.insert("file".to_string(), "Datei".to_string());
        messages.insert("language".to_string(), "Sprache".to_string());
        messages.insert("lines".to_string(), "Zeilen".to_string());
        messages.insert("symbols".to_string(), "Symbole".to_string());
        messages.insert("status".to_string(), "Status".to_string());
        messages.insert("critical".to_string(), "Kritisch".to_string());
        messages.insert("high".to_string(), "Hoch".to_string());
        messages.insert("medium".to_string(), "Mittel".to_string());
        messages.insert("low".to_string(), "Niedrig".to_string());
        messages.insert(
            "screen_reader_mode".to_string(),
            "Bildschirmleser-Modus".to_string(),
        );
        messages.insert("high_contrast".to_string(), "Hoher Kontrast".to_string());
        messages.insert("ansi_colors".to_string(), "ANSI-Farben".to_string());
        messages.insert("simple_text".to_string(), "Einfacher Textmodus".to_string());
        messages.insert(
            "verbose_descriptions".to_string(),
            "Ausführliche Beschreibungen".to_string(),
        );
        messages.insert(
            "accessibility_settings".to_string(),
            "Barrierefreiheitseinstellungen".to_string(),
        );
    }

    fn load_chinese_messages(messages: &mut HashMap<String, String>) {
        messages.insert("analysis_complete".to_string(), "分析成功完成".to_string());
        messages.insert("files_analyzed".to_string(), "已分析文件".to_string());
        messages.insert("symbols_found".to_string(), "找到的符号".to_string());
        messages.insert("security_issues".to_string(), "检测到安全问题".to_string());
        messages.insert("no_issues".to_string(), "未发现问题".to_string());
        messages.insert("error_occurred".to_string(), "发生错误".to_string());
        messages.insert("summary".to_string(), "摘要".to_string());
        messages.insert("security_analysis".to_string(), "安全分析".to_string());
        messages.insert(
            "files_analyzed_header".to_string(),
            "已分析文件".to_string(),
        );
        messages.insert("file".to_string(), "文件".to_string());
        messages.insert("language".to_string(), "语言".to_string());
        messages.insert("lines".to_string(), "行数".to_string());
        messages.insert("symbols".to_string(), "符号".to_string());
        messages.insert("status".to_string(), "状态".to_string());
        messages.insert("critical".to_string(), "严重".to_string());
        messages.insert("high".to_string(), "高".to_string());
        messages.insert("medium".to_string(), "中".to_string());
        messages.insert("low".to_string(), "低".to_string());
        messages.insert(
            "screen_reader_mode".to_string(),
            "屏幕阅读器模式".to_string(),
        );
        messages.insert("high_contrast".to_string(), "高对比度".to_string());
        messages.insert("ansi_colors".to_string(), "ANSI颜色".to_string());
        messages.insert("simple_text".to_string(), "简单文本模式".to_string());
        messages.insert("verbose_descriptions".to_string(), "详细描述".to_string());
        messages.insert(
            "accessibility_settings".to_string(),
            "辅助功能设置".to_string(),
        );
    }

    fn load_japanese_messages(messages: &mut HashMap<String, String>) {
        messages.insert(
            "analysis_complete".to_string(),
            "分析が正常に完了しました".to_string(),
        );
        messages.insert(
            "files_analyzed".to_string(),
            "分析されたファイル".to_string(),
        );
        messages.insert(
            "symbols_found".to_string(),
            "見つかったシンボル".to_string(),
        );
        messages.insert(
            "security_issues".to_string(),
            "セキュリティ問題が検出されました".to_string(),
        );
        messages.insert("no_issues".to_string(), "問題が見つかりません".to_string());
        messages.insert(
            "error_occurred".to_string(),
            "エラーが発生しました".to_string(),
        );
        messages.insert("summary".to_string(), "概要".to_string());
        messages.insert(
            "security_analysis".to_string(),
            "セキュリティ分析".to_string(),
        );
        messages.insert(
            "files_analyzed_header".to_string(),
            "分析されたファイル".to_string(),
        );
        messages.insert("file".to_string(), "ファイル".to_string());
        messages.insert("language".to_string(), "言語".to_string());
        messages.insert("lines".to_string(), "行数".to_string());
        messages.insert("symbols".to_string(), "シンボル".to_string());
        messages.insert("status".to_string(), "状態".to_string());
        messages.insert("critical".to_string(), "重大".to_string());
        messages.insert("high".to_string(), "高".to_string());
        messages.insert("medium".to_string(), "中".to_string());
        messages.insert("low".to_string(), "低".to_string());
        messages.insert(
            "screen_reader_mode".to_string(),
            "スクリーンリーダーモード".to_string(),
        );
        messages.insert("high_contrast".to_string(), "高コントラスト".to_string());
        messages.insert("ansi_colors".to_string(), "ANSIカラー".to_string());
        messages.insert(
            "simple_text".to_string(),
            "シンプルテキストモード".to_string(),
        );
        messages.insert("verbose_descriptions".to_string(), "詳細な説明".to_string());
        messages.insert(
            "accessibility_settings".to_string(),
            "アクセシビリティ設定".to_string(),
        );
    }

    pub fn get_message(&self, key: &str) -> String {
        self.localized_messages
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.to_string())
    }

    pub fn format_accessible_text(&self, analysis: &AnalysisOutput) -> String {
        let mut output = String::new();

        // Header with screen reader friendly format
        output.push_str(&format!(
            "{}: {}\n",
            self.get_message("analysis_complete"),
            analysis.metadata.tool_version
        ));

        if self.config.verbose_descriptions {
            output.push_str(&format!(
                "Analysis performed on: {}\n",
                analysis.metadata.target_path
            ));
            output.push_str(&format!(
                "Duration: {} milliseconds\n",
                analysis.metadata.analysis_duration_ms
            ));
        }

        // Summary section
        output.push_str(&format!("\n{}:\n", self.get_message("summary")));
        output.push_str(&format!(
            "{}: {}\n",
            self.get_message("files_analyzed"),
            analysis.summary.total_files
        ));
        output.push_str(&format!(
            "Total lines of code: {}\n",
            analysis.summary.total_lines
        ));
        output.push_str(&format!(
            "{}: {}\n",
            self.get_message("symbols_found"),
            analysis.summary.total_symbols
        ));

        // Security section
        if let Some(security) = &analysis.security {
            output.push_str(&format!("\n{}:\n", self.get_message("security_analysis")));
            if security.total_issues > 0 {
                output.push_str(&format!(
                    "{}: {}\n",
                    self.get_message("security_issues"),
                    security.total_issues
                ));
                output.push_str(&format!(
                    "{}: {}\n",
                    self.get_message("critical"),
                    security.critical_count
                ));
                output.push_str(&format!(
                    "{}: {}\n",
                    self.get_message("high"),
                    security.high_count
                ));
                output.push_str(&format!(
                    "{}: {}\n",
                    self.get_message("medium"),
                    security.medium_count
                ));
                output.push_str(&format!(
                    "{}: {}\n",
                    self.get_message("low"),
                    security.low_count
                ));
            } else {
                output.push_str(&format!("{}\n", self.get_message("no_issues")));
            }
        }

        // Files section
        if !analysis.files.is_empty() {
            output.push_str(&format!(
                "\n{}:\n",
                self.get_message("files_analyzed_header")
            ));
            for file in &analysis.files {
                output.push_str(&format!(
                    "{}: {}, {}: {}, {}: {}, {}: {}\n",
                    self.get_message("file"),
                    file.path,
                    self.get_message("language"),
                    file.language,
                    self.get_message("lines"),
                    file.lines,
                    self.get_message("symbols"),
                    file.symbols_count
                ));
            }
        }

        output
    }

    pub fn apply_accessibility_settings(&self) -> String {
        let mut settings = Vec::new();

        if self.config.screen_reader_mode {
            settings.push(format!(
                "{}: {}",
                self.get_message("screen_reader_mode"),
                "ENABLED"
            ));
        }

        if self.config.high_contrast {
            settings.push(format!(
                "{}: {}",
                self.get_message("high_contrast"),
                "ENABLED"
            ));
        }

        if self.config.no_colors {
            settings.push(format!(
                "{}: {}",
                self.get_message("ansi_colors"),
                "DISABLED"
            ));
        }

        if self.config.simple_text {
            settings.push(format!(
                "{}: {}",
                self.get_message("simple_text"),
                "ENABLED"
            ));
        }

        if self.config.verbose_descriptions {
            settings.push(format!(
                "{}: {}",
                self.get_message("verbose_descriptions"),
                "ENABLED"
            ));
        }

        settings.push(format!(
            "{}: {}",
            self.get_message("language"),
            self.config.language
        ));

        format!(
            "{}:\n{}",
            self.get_message("accessibility_settings"),
            settings.join("\n")
        )
    }

    /// Get supported languages
    pub fn supported_languages() -> Vec<(&'static str, &'static str)> {
        vec![
            ("en", "English"),
            ("es", "Español"),
            ("fr", "Français"),
            ("de", "Deutsch"),
            ("zh", "中文"),
            ("ja", "日本語"),
        ]
    }

    /// Check if a language is supported
    pub fn is_language_supported(lang_code: &str) -> bool {
        Self::supported_languages()
            .iter()
            .any(|(code, _)| *code == lang_code)
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
    #[tabled(rename = "File")]
    pub path: String,
    #[tabled(rename = "Language")]
    pub language: String,
    #[tabled(rename = "Lines")]
    pub lines: String,
    #[tabled(rename = "Size")]
    pub size: String,
    #[tabled(rename = "Symbols")]
    pub symbols: String,
    #[tabled(rename = "Status")]
    pub status: String,
}

impl FileRow {
    pub fn new(file: &crate::FileInfo) -> Self {
        Self::new_with_accessibility(file, &AccessibilityConfig::default())
    }

    pub fn new_with_accessibility(
        file: &crate::FileInfo,
        accessibility: &AccessibilityConfig,
    ) -> Self {
        let (status_icon, status_text) = if file.parsed_successfully {
            if accessibility.simple_text {
                ("", "OK")
            } else {
                ("✅", "OK")
            }
        } else {
            if accessibility.simple_text {
                ("", "Failed")
            } else {
                ("❌", "Failed")
            }
        };

        let status = if accessibility.screen_reader_mode {
            format!("Status: {}", status_text)
        } else if accessibility.simple_text {
            status_text.to_string()
        } else {
            format!("{} {}", status_icon, status_text)
        };

        Self {
            path: file.path.to_string_lossy().to_string(),
            language: file.language.clone(),
            lines: file.lines.to_string(),
            size: format_size(file.size),
            symbols: file.symbols.len().to_string(),
            status,
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
        for (_i, row) in self.iter().enumerate() {
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
    #[tabled(rename = "Symbol")]
    pub name: String,
    #[tabled(rename = "Type")]
    pub kind: String,
    #[tabled(rename = "File")]
    pub file: String,
    #[tabled(rename = "Line")]
    pub line: String,
    #[tabled(rename = "Visibility")]
    pub visibility: String,
}

impl SymbolRow {
    pub fn new(symbol: &crate::Symbol, file_path: &str) -> Self {
        Self::new_with_accessibility(symbol, file_path, &AccessibilityConfig::default())
    }

    pub fn new_with_accessibility(
        symbol: &crate::Symbol,
        file_path: &str,
        accessibility: &AccessibilityConfig,
    ) -> Self {
        Self {
            name: if accessibility.verbose_descriptions {
                format!("Symbol: {}", symbol.name)
            } else {
                symbol.name.clone()
            },
            kind: format_symbol_type(&symbol.kind),
            file: file_path.to_string(),
            line: symbol.start_line.to_string(),
            visibility: if accessibility.screen_reader_mode {
                format!("Visibility: {}", symbol.visibility)
            } else {
                symbol.visibility.clone()
            },
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
/// Convert crate::AnalysisResult to AnalysisOutput for accessibility formatting
fn convert_to_analysis_output(result: &crate::AnalysisResult) -> AnalysisOutput {
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
            complexity_score: None, // Could be calculated if needed
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
                documentation: None, // Could be extracted if available
                complexity: None,
            })
        })
        .collect();

    let mut languages = HashMap::new();
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

    // Calculate percentages
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
            analysis_duration_ms: 0, // Could be tracked if needed
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
        security: None, // Could be populated if security analysis is available
        dependencies: None,
    }
}

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

    /// Output analysis result with consistent formatting across all formats
    pub fn output_analysis_result(
        &self,
        result: &crate::AnalysisResult,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match &self.format {
            // Structured formats - no informational output, just data
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(result)?;
                if let Some(path) = &self.output_path {
                    std::fs::write(path, json)?;
                    print_success(&format!("JSON results saved to {}", path.display()));
                } else {
                    println!("{}", json);
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
            OutputFormat::Csv => {
                let csv = generate_csv_output(result);
                if let Some(path) = &self.output_path {
                    std::fs::write(path, csv)?;
                    print_success(&format!("CSV data saved to {}", path.display()));
                } else {
                    println!("{}", csv);
                }
            }
            OutputFormat::Template(template_name) => {
                self.output_with_template(result, template_name)?;
            }
            // Human-readable formats with enhanced output
            OutputFormat::Table => {
                print_enhanced_summary(result);
                if let Some(path) = &self.output_path {
                    save_analysis_result_to_file(result, path, &self.format)?;
                }
            }
            OutputFormat::Summary => {
                print_enhanced_summary(result);
                if let Some(path) = &self.output_path {
                    save_analysis_result_to_file(result, path, &self.format)?;
                }
            }
            OutputFormat::Text => {
                print_enhanced_summary(result);
                if let Some(path) = &self.output_path {
                    save_analysis_result_to_file(result, path, &self.format)?;
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
            OutputFormat::AccessibleText => {
                let accessibility_config = AccessibilityConfig::default();
                let handler = AccessibleOutputHandler::new(accessibility_config);
                let analysis_output = convert_to_analysis_output(result);
                let accessible_text = handler.format_accessible_text(&analysis_output);
                if let Some(path) = &self.output_path {
                    std::fs::write(path, accessible_text)?;
                    print_success(&format!(
                        "Accessible text results saved to {}",
                        path.display()
                    ));
                } else {
                    println!("{}", accessible_text);
                }
            }
            OutputFormat::LocalizedAccessibleText(lang_code) => {
                let mut accessibility_config = AccessibilityConfig::default();
                accessibility_config.language = lang_code.clone();
                let handler = AccessibleOutputHandler::new(accessibility_config);
                let analysis_output = convert_to_analysis_output(result);
                let localized_text = handler.format_accessible_text(&analysis_output);
                if let Some(path) = &self.output_path {
                    std::fs::write(path, localized_text)?;
                    print_success(&format!(
                        "Localized accessible text results saved to {} (language: {})",
                        path.display(),
                        lang_code
                    ));
                } else {
                    println!("{}", localized_text);
                }
            }
        }

        Ok(())
    }

    /// Output symbols with consistent formatting across all formats
    pub fn output_symbols(
        &self,
        symbols: &[(crate::Symbol, String)],
        file_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.format {
            // Structured formats - no informational output, just data
            OutputFormat::Json => {
                // Group symbols by file for JSON output with deterministic key order
                let mut symbols_by_file: std::collections::BTreeMap<String, Vec<&crate::Symbol>> =
                    std::collections::BTreeMap::new();
                for (symbol, file_path) in symbols {
                    symbols_by_file
                        .entry(file_path.clone())
                        .or_default()
                        .push(symbol);
                }
                let json = serde_json::to_string_pretty(&symbols_by_file)?;
                if let Some(path) = &self.output_path {
                    std::fs::write(path, json)?;
                    print_success(&format!("JSON symbols saved to {}", path.display()));
                } else {
                    println!("{}", json);
                }
            }
            OutputFormat::Csv => {
                let mut csv = String::from("Symbol,Type,File,Line,Visibility\n");
                for (symbol, file_path) in symbols {
                    csv.push_str(&format!(
                        "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                        symbol.name.replace("\"", "\"\""),
                        symbol.kind,
                        file_path.replace("\"", "\"\""),
                        symbol.start_line,
                        symbol.visibility
                    ));
                }
                if let Some(path) = &self.output_path {
                    std::fs::write(path, csv)?;
                    print_success(&format!("CSV symbols saved to {}", path.display()));
                } else {
                    println!("{}", csv);
                }
            }
            // Human-readable formats with enhanced output
            _ => {
                print_enhanced_header(
                    "🔧 SYMBOL ANALYSIS",
                    Some(&format!(
                        "Found {} symbols across {} files",
                        symbols.len(),
                        file_count
                    )),
                    "blue",
                );

                if symbols.is_empty() {
                    print_info("No symbols found in the specified path");
                    return Ok(());
                }

                // Convert to enhanced table rows
                let rows: Vec<SymbolRow> = symbols
                    .iter()
                    .map(|(symbol, file_path)| SymbolRow {
                        name: symbol.name.clone(),
                        kind: format_symbol_type(&symbol.kind),
                        file: file_path.clone(),
                        line: symbol.start_line.to_string(),
                        visibility: symbol.visibility.clone(),
                    })
                    .collect();

                let table = Table::new(rows);
                println!("\n{}", table);

                // Enhanced summary with symbol type breakdown
                println!("\n{}", "SYMBOL SUMMARY".bright_yellow().bold());
                println!("{}", "─".repeat(40));

                let mut symbol_types = std::collections::HashMap::new();
                for (symbol, _) in symbols {
                    *symbol_types.entry(&symbol.kind).or_insert(0) += 1;
                }

                let mut symbol_vec: Vec<_> = symbol_types.into_iter().collect();
                symbol_vec.sort_by(|a, b| b.1.cmp(&a.1));

                for (kind, count) in symbol_vec.iter().take(5) {
                    let percentage = (*count as f64 / symbols.len() as f64) * 100.0;
                    let icon = match kind.to_lowercase().as_str() {
                        "function" => "🔧",
                        "class" | "struct" => "🏗️",
                        "method" => "⚡",
                        "variable" => "📦",
                        _ => "🔸",
                    };
                    println!("   {} {}: {} ({:.1}%)", icon, kind, count, percentage);
                }

                if let Some(path) = &self.output_path {
                    // For file output, create the grouped structure
                    let mut symbols_by_file: std::collections::BTreeMap<
                        String,
                        Vec<&crate::Symbol>,
                    > = std::collections::BTreeMap::new();
                    for (symbol, file_path) in symbols {
                        symbols_by_file
                            .entry(file_path.clone())
                            .or_default()
                            .push(symbol);
                    }
                    save_output_to_file(&symbols_by_file, path, &self.format)?;
                }
            }
        }

        Ok(())
    }

    /// Output analysis result using a custom template
    pub fn output_with_template(
        &self,
        result: &crate::AnalysisResult,
        template_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let engine = TemplateEngine::new();

        if let Some(template) = engine.get_template(template_name) {
            // Prepare template data
            let mut data = HashMap::new();
            data.insert("total_files".to_string(), result.files.len().to_string());
            data.insert("total_lines".to_string(), result.total_lines.to_string());
            data.insert("languages".to_string(), result.languages.len().to_string());

            let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
            data.insert("total_symbols".to_string(), total_symbols.to_string());

            // Add largest file info
            if let Some(largest_file) = result.files.iter().max_by_key(|f| f.size) {
                data.insert(
                    "largest_file".to_string(),
                    largest_file.path.to_string_lossy().to_string(),
                );
            }

            // Add most complex file info
            if let Some(most_complex) = result.files.iter().max_by_key(|f| f.symbols.len()) {
                data.insert(
                    "most_complex".to_string(),
                    most_complex.path.to_string_lossy().to_string(),
                );
            }

            // Add timestamp
            data.insert("timestamp".to_string(), chrono::Utc::now().to_rfc3339());

            // Add averages
            let avg_lines = if result.files.is_empty() {
                0.0
            } else {
                result.total_lines as f64 / result.files.len() as f64
            };
            let avg_symbols = if result.files.is_empty() {
                0.0
            } else {
                total_symbols as f64 / result.files.len() as f64
            };
            data.insert("avg_lines".to_string(), format!("{:.1}", avg_lines));
            data.insert("avg_symbols".to_string(), format!("{:.1}", avg_symbols));

            // Add language breakdown
            let mut lang_breakdown = String::new();
            let mut langs: Vec<_> = result.languages.iter().collect();
            langs.sort_by(|a, b| b.1.cmp(a.1));
            for (lang, count) in langs.iter().take(5) {
                let percentage = (**count as f64 / result.files.len() as f64) * 100.0;
                lang_breakdown.push_str(&format!(
                    "- {}: {} files ({:.1}%)\n",
                    lang, count, percentage
                ));
            }
            data.insert("language_breakdown".to_string(), lang_breakdown);

            let rendered = template.render(&data);

            if let Some(path) = &self.output_path {
                std::fs::write(path, &rendered)?;
                print_success(&format!("Template output saved to {}", path.display()));
            } else {
                println!("{}", rendered);
            }
        } else {
            return Err(format!("Template '{}' not found", template_name).into());
        }

        Ok(())
    }
}

/// Template system for custom output formats
#[derive(Clone)]
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

/// Enhanced template system with custom format support
pub struct TemplateEngine {
    templates: HashMap<String, OutputTemplate>,
}

impl TemplateEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            templates: HashMap::new(),
        };
        engine.load_builtin_templates();
        engine
    }

    fn load_builtin_templates(&mut self) {
        // Simple summary templates
        self.templates.insert(
            "simple_summary".to_string(),
            OutputTemplate::new(
                "simple_summary",
                "Codebase contains {{{total_files}}} files with {{{total_lines}}} lines of code in {{{languages}}} languages."
            )
        );

        self.templates.insert(
            "compact_summary".to_string(),
            OutputTemplate::new(
                "compact_summary",
                "{{{total_files}}} files, {{{total_lines}}} lines, {{{languages}}} languages, {{{total_symbols}}} symbols"
            )
        );

        // Detailed report templates
        self.templates.insert(
            "detailed_report".to_string(),
            OutputTemplate::new(
                "detailed_report",
                "# Codebase Analysis Report\n\n## Overview\n- **Files:** {{{total_files}}}\n- **Lines:** {{{total_lines}}}\n- **Languages:** {{{languages}}}\n- **Symbols:** {{{total_symbols}}}\n\n## Statistics\n- **Largest File:** {{{largest_file}}}\n- **Most Complex:** {{{most_complex}}}\n\n*Generated on: {{{timestamp}}}*"
            )
        );

        self.templates.insert(
            "security_report".to_string(),
            OutputTemplate::new(
                "security_report",
                "# Security Analysis Report\n\n## Summary\n- **Total Issues:** {{{security_issues}}}\n- **Critical:** {{{critical_count}}}\n- **High:** {{{high_count}}}\n- **Files Scanned:** {{{total_files}}}\n\n## Recommendations\n{{{security_recommendations}}}\n\n*Generated on: {{{timestamp}}}*"
            )
        );

        // CI/CD templates
        self.templates.insert(
            "ci_summary".to_string(),
            OutputTemplate::new(
                "ci_summary",
                "::set-output name=files::{{{total_files}}}\n::set-output name=lines::{{{total_lines}}}\n::set-output name=languages::{{{languages}}}\n::set-output name=symbols::{{{total_symbols}}}"
            )
        );

        self.templates.insert(
            "github_summary".to_string(),
            OutputTemplate::new(
                "github_summary",
                "## 📊 Codebase Analysis\n\n| Metric | Value |\n|--------|-------|\n| Files | {{{total_files}}} |\n| Lines | {{{total_lines}}} |\n| Languages | {{{languages}}} |\n| Symbols | {{{total_symbols}}} |"
            )
        );

        // Custom format templates
        self.templates.insert(
            "json_minimal".to_string(),
            OutputTemplate::new(
                "json_minimal",
                "{\"files\":{{{total_files}}},\"lines\":{{{total_lines}}},\"languages\":{{{languages}}},\"symbols\":{{{total_symbols}}}}"
            )
        );

        self.templates.insert(
            "xml_report".to_string(),
            OutputTemplate::new(
                "xml_report",
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<codebase-analysis>\n  <files>{{{total_files}}}</files>\n  <lines>{{{total_lines}}}</lines>\n  <languages>{{{languages}}}</languages>\n  <symbols>{{{total_symbols}}}</symbols>\n  <generated>{{{timestamp}}}</generated>\n</codebase-analysis>"
            )
        );

        // Development templates
        self.templates.insert(
            "dev_status".to_string(),
            OutputTemplate::new(
                "dev_status",
                "🚀 Development Status\nFiles: {{{total_files}}} | Lines: {{{total_lines}}} | Languages: {{{languages}}}\nLast updated: {{{timestamp}}}"
            )
        );

        self.templates.insert(
            "code_metrics".to_string(),
            OutputTemplate::new(
                "code_metrics",
                "# Code Metrics\n\n## Size Metrics\n- Total Files: {{{total_files}}}\n- Total Lines: {{{total_lines}}}\n- Average Lines/File: {{{avg_lines}}}\n\n## Language Distribution\n{{{language_breakdown}}}\n\n## Complexity\n- Total Symbols: {{{total_symbols}}}\n- Average Symbols/File: {{{avg_symbols}}}"
            )
        );
    }

    pub fn get_template(&self, name: &str) -> Option<&OutputTemplate> {
        self.templates.get(name)
    }

    pub fn add_template(&mut self, name: String, template: OutputTemplate) {
        self.templates.insert(name, template);
    }

    pub fn list_templates(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.templates.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }

    pub fn render_template(&self, name: &str, data: &HashMap<String, String>) -> Option<String> {
        self.get_template(name)
            .map(|template| template.render(data))
    }
}

/// Predefined templates for common output formats (legacy function)
pub fn get_template(name: &str) -> Option<OutputTemplate> {
    let engine = TemplateEngine::new();
    engine.get_template(name).cloned()
}
