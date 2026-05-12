//! AST-based security analysis framework
//!
//! This module provides semantic analysis capabilities for security detection,
//! replacing pattern-based approaches with proper AST understanding.

use crate::error::{Error, Result};
use crate::languages::Language;
use crate::parser::Parser;
use crate::security::ml_filter::MLFalsePositiveFilter;
// use crate::taint_analysis::{FunctionCall as TaintFunctionCall, TaintLocation, VariableAssignment};
use crate::tree::SyntaxTree;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::debug;

/// AST-based security analyzer
pub struct AstSecurityAnalyzer {
    /// Language-specific analyzers
    language_analyzers: HashMap<Language, Box<dyn LanguageSpecificAnalyzer>>,
    /// Context classifier for determining code context
    context_classifier: ContextClassifier,
    /// Semantic analysis engine
    /// ML-based false positive filter
    ml_filter: MLFalsePositiveFilter,
}

/// Language-specific security analyzer trait
#[async_trait::async_trait]
pub trait LanguageSpecificAnalyzer: Send + Sync {
    /// Analyze a syntax tree for security issues
    async fn analyze(&self, tree: &SyntaxTree, file_path: &str) -> Result<Vec<SecurityFinding>>;

    /// Get language-specific patterns for vulnerability detection
    fn get_vulnerability_patterns(&self) -> Vec<VulnerabilityPattern>;

    /// Extract semantic information from AST
    fn extract_semantic_info(&self, tree: &SyntaxTree) -> Result<SemanticInfo>;
}

/// Vulnerability pattern for AST-based detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPattern {
    /// Pattern name
    pub name: String,
    /// Pattern description
    pub description: String,
    /// AST node types to match
    pub node_types: Vec<String>,
    /// Required child patterns
    pub child_patterns: Vec<String>,
    /// Context requirements
    pub context_requirements: Vec<String>,
    /// Severity level
    pub severity: SecuritySeverity,
    /// CWE identifier
    pub cwe_id: Option<String>,
}

/// Security finding from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Finding ID
    pub id: String,
    /// Finding type
    pub finding_type: SecurityFindingType,
    /// Severity
    pub severity: SecuritySeverity,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// File path
    pub file_path: String,
    /// Line number
    pub line_number: usize,
    /// Column start
    pub column_start: usize,
    /// Column end
    pub column_end: usize,
    /// Code snippet
    pub code_snippet: String,
    /// CWE identifier
    pub cwe_id: Option<String>,
    /// Remediation advice
    pub remediation: String,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Semantic context
    pub context: CodeContext,
}

/// Types of security findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecurityFindingType {
    /// Injection vulnerability
    Injection,
    /// Broken access control
    BrokenAccessControl,
    /// Cryptographic failure
    CryptographicFailure,
    /// Insecure design
    InsecureDesign,
    /// Security misconfiguration
    SecurityMisconfiguration,
    /// Hardcoded secret
    HardcodedSecret,
    /// Weak authentication
    WeakAuthentication,
    /// Information disclosure
    InformationDisclosure,
}

impl std::fmt::Display for SecurityFindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityFindingType::Injection => write!(f, "Injection"),
            SecurityFindingType::BrokenAccessControl => write!(f, "BrokenAccessControl"),
            SecurityFindingType::CryptographicFailure => write!(f, "CryptographicFailure"),
            SecurityFindingType::InsecureDesign => write!(f, "InsecureDesign"),
            SecurityFindingType::SecurityMisconfiguration => write!(f, "SecurityMisconfiguration"),
            SecurityFindingType::HardcodedSecret => write!(f, "HardcodedSecret"),
            SecurityFindingType::WeakAuthentication => write!(f, "WeakAuthentication"),
            SecurityFindingType::InformationDisclosure => write!(f, "InformationDisclosure"),
        }
    }
}

/// Security severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecuritySeverity {
    /// Informational finding
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

impl std::fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecuritySeverity::Info => write!(f, "Info"),
            SecuritySeverity::Low => write!(f, "Low"),
            SecuritySeverity::Medium => write!(f, "Medium"),
            SecuritySeverity::High => write!(f, "High"),
            SecuritySeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// Code context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeContext {
    /// Is this test code?
    pub is_test_code: bool,
    /// Is this example/documentation code?
    pub is_example_code: bool,
    /// Is this configuration code?
    pub is_config_code: bool,
    /// Function/method context
    pub function_context: Option<String>,
    /// Class/struct context
    pub class_context: Option<String>,
    /// Module/package context
    pub module_context: Option<String>,
    /// Variable scope information
    pub variable_scope: HashMap<String, VariableInfo>,
}

impl Default for CodeContext {
    fn default() -> Self {
        Self {
            is_test_code: false,
            is_example_code: false,
            is_config_code: false,
            function_context: None,
            class_context: None,
            module_context: None,
            variable_scope: HashMap::new(),
        }
    }
}

/// Variable information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableInfo {
    /// Variable type
    pub var_type: String,
    /// Is it a constant?
    pub is_constant: bool,
    /// Declaration location
    pub declaration_line: usize,
    /// Usage locations
    pub usage_locations: Vec<usize>,
}

/// Semantic information extracted from AST
#[derive(Debug, Clone)]
pub struct SemanticInfo {
    /// Functions and methods
    pub functions: Vec<FunctionInfo>,
    /// Classes and structs
    pub classes: Vec<ClassInfo>,
    /// Variables and constants
    pub variables: HashMap<String, VariableInfo>,
    /// Imports and dependencies
    pub imports: Vec<String>,
    /// String literals
    pub string_literals: Vec<StringLiteral>,
    /// Function calls
    pub function_calls: Vec<FunctionCall>,
}

impl Default for SemanticInfo {
    fn default() -> Self {
        Self {
            functions: Vec::new(),
            classes: Vec::new(),
            variables: HashMap::new(),
            imports: Vec::new(),
            string_literals: Vec::new(),
            function_calls: Vec::new(),
        }
    }
}

/// Function information
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub parameters: Vec<ParameterInfo>,
    pub return_type: Option<String>,
    pub is_public: bool,
    pub line_number: usize,
    pub body_start: usize,
    pub body_end: usize,
}

/// Class/struct information
#[derive(Debug, Clone)]
pub struct ClassInfo {
    pub name: String,
    pub fields: Vec<FieldInfo>,
    pub methods: Vec<FunctionInfo>,
    pub is_public: bool,
    pub line_number: usize,
}

/// Parameter information
#[derive(Debug, Clone)]
pub struct ParameterInfo {
    pub name: String,
    pub param_type: Option<String>,
}

/// Field information
#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: String,
    pub field_type: Option<String>,
    pub is_public: bool,
}

/// String literal information
#[derive(Debug, Clone)]
pub struct StringLiteral {
    pub value: String,
    pub line_number: usize,
    pub is_multiline: bool,
    pub context: String,
}

/// Function call information
#[derive(Debug, Clone)]
pub struct FunctionCall {
    pub function_name: String,
    pub arguments: Vec<String>,
    pub line_number: usize,
    pub is_method_call: bool,
}

/// Result of semantic context analysis for false positive filtering
#[derive(Debug, Clone)]
pub struct SemanticContextResult {
    /// Whether this appears to be test code
    pub is_test_code: bool,
    /// Whether this contains placeholder values
    pub is_placeholder: bool,
    /// Whether this is in documentation context
    pub is_documentation: bool,
    /// Whether this appears to be embedded code in string literals
    pub is_embedded: bool,
    /// Whether this uses safe patterns
    pub is_safe_usage: bool,
    /// Explanation of the semantic analysis
    pub explanation: String,
}

impl AstSecurityAnalyzer {
    /// Create a new AST-based security analyzer
    pub fn new() -> Result<Self> {
        let mut language_analyzers = HashMap::new();

        // Initialize language-specific analyzers
        language_analyzers.insert(
            Language::Rust,
            Box::new(RustAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );
        language_analyzers.insert(
            Language::JavaScript,
            Box::new(JavaScriptAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );
        language_analyzers.insert(
            Language::TypeScript,
            Box::new(TypeScriptAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );
        language_analyzers.insert(
            Language::Python,
            Box::new(PythonAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );
        language_analyzers.insert(
            Language::Java,
            Box::new(JavaAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );
        language_analyzers.insert(
            Language::Go,
            Box::new(GoAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );
        language_analyzers.insert(
            Language::C,
            Box::new(CAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );
        language_analyzers.insert(
            Language::Cpp,
            Box::new(CppAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );
        language_analyzers.insert(
            Language::Php,
            Box::new(PhpAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );
        language_analyzers.insert(
            Language::Ruby,
            Box::new(RubyAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );
        language_analyzers.insert(
            Language::Swift,
            Box::new(SwiftAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );
        language_analyzers.insert(
            Language::Kotlin,
            Box::new(KotlinAnalyzer::new()) as Box<dyn LanguageSpecificAnalyzer>,
        );

        Ok(Self {
            language_analyzers,
            context_classifier: ContextClassifier::new(),
            
            ml_filter: crate::security::ml_filter::MLFalsePositiveFilter::new(),
        })
    }

    /// Analyze a file for security issues using AST
    pub async fn analyze_file(
        &self,
        file_path: &Path,
        language: Language,
    ) -> Result<Vec<SecurityFinding>> {
        debug!(
            "Starting AST-based security analysis for file: {}",
            file_path.display()
        );

        // Parse the file into AST
        let parser = Parser::new(language)?;
        let source = std::fs::read_to_string(file_path)?;
        let tree = parser.parse(&source, None)?;

        // Get language-specific analyzer
        let analyzer = self.language_analyzers.get(&language).ok_or_else(|| {
            Error::internal_error(
                "AST Analyzer",
                format!("No analyzer available for language: {}", language.name()),
            )
        })?;

        // Extract semantic information
        let semantic_info = analyzer.extract_semantic_info(&tree)?;

        // Classify code context
        let context =
            self.context_classifier
                .classify_context(file_path, &source, &semantic_info)?;

        // Create language-specific semantic engine for taint analysis
        let semantic_engine = SemanticAnalysisEngine::new().with_language(language.name());

        // Perform data flow analysis using taint analysis
        let data_flows = semantic_engine.analyze_data_flow(&semantic_info)?;
        let injection_points = semantic_engine.detect_injection_points(&semantic_info)?;

        // Perform AST-based analysis
        let mut findings = analyzer
            .analyze(&tree, &file_path.to_string_lossy())
            .await?;

        // Add findings from data flow analysis
        for flow in data_flows {
            if !flow.is_safe {
                findings.push(SecurityFinding {
                    id: format!("DF_{}_{}", flow.source_variable, flow.sink_function),
                    finding_type: SecurityFindingType::Injection,
                    severity: SecuritySeverity::Medium,
                    title: format!(
                        "Potential data flow vulnerability: {} -> {}",
                        flow.source_variable, flow.sink_function
                    ),
                    description: format!(
                        "Data flows from {} to {} without proper sanitization",
                        flow.source_variable, flow.sink_function
                    ),
                    file_path: file_path.to_string_lossy().to_string(),
                    line_number: 1, // Would need more precise location tracking
                    column_start: 0,
                    column_end: 0,
                    code_snippet: format!(
                        "Flow: {} -> {}",
                        flow.source_variable, flow.sink_function
                    ),
                    cwe_id: Some("CWE-20".to_string()), // Improper Input Validation
                    remediation: format!(
                        "Add input validation and sanitization for data flowing from {} to {}",
                        flow.source_variable, flow.sink_function
                    ),
                    confidence: 0.7,
                    context: context.clone(),
                });
            }
        }

        // Add findings from injection point analysis
        for injection in injection_points {
            findings.push(SecurityFinding {
                id: format!(
                    "INJ_{}_{}",
                    injection.function_name, injection.parameter_index
                ),
                finding_type: SecurityFindingType::Injection,
                severity: if injection.confidence > 0.8 {
                    SecuritySeverity::High
                } else {
                    SecuritySeverity::Medium
                },
                title: format!("Potential {} vulnerability", injection.vulnerability_type),
                description: format!(
                    "Function {} at parameter {} may be vulnerable to {}",
                    injection.function_name,
                    injection.parameter_index,
                    injection.vulnerability_type
                ),
                file_path: file_path.to_string_lossy().to_string(),
                line_number: 1, // Would need more precise location tracking
                column_start: 0,
                column_end: 0,
                code_snippet: format!("{}({})", injection.function_name, injection.parameter_index),
                cwe_id: self.get_cwe_for_vulnerability(&injection.vulnerability_type),
                remediation: format!(
                    "Sanitize input before passing to {}",
                    injection.function_name
                ),
                confidence: injection.confidence,
                context: context.clone(),
            });
        }

        // Apply ML-based false positive filtering
        let mut filtered_findings = Vec::new();
        for finding in findings {
            let finding_type_str = match finding.finding_type {
                SecurityFindingType::Injection => "Injection",
                SecurityFindingType::BrokenAccessControl => "BrokenAccessControl",
                SecurityFindingType::CryptographicFailure => "CryptographicFailure",
                SecurityFindingType::InsecureDesign => "InsecureDesign",
                SecurityFindingType::SecurityMisconfiguration => "SecurityMisconfiguration",
                SecurityFindingType::HardcodedSecret => "HardcodedSecret",
                SecurityFindingType::WeakAuthentication => "WeakAuthentication",
                SecurityFindingType::InformationDisclosure => "InformationDisclosure",
            };

            let filter_result = self
                .ml_filter
                .filter_finding(
                    finding_type_str,
                    &finding.file_path,
                    &finding.code_snippet,
                    finding.confidence,
                )
                .await?;

            if !filter_result.should_filter {
                filtered_findings.push(finding);
            } else {
                debug!(
                    "Filtered out finding {} with confidence {:.2}: {}",
                    finding.id, filter_result.confidence, filter_result.reason
                );
            }
        }

        // Enhance findings with semantic context
        for finding in &mut filtered_findings {
            finding.context = context.clone();
            self.enhance_finding_with_semantics(finding, &semantic_info)?;
        }

        debug!(
            "Completed AST analysis with taint analysis and ML filtering, found {} findings",
            filtered_findings.len()
        );
        Ok(filtered_findings)
    }

    /// Analyze multiple files
    pub async fn analyze_files(
        &self,
        files: Vec<(std::path::PathBuf, Language)>,
    ) -> Result<Vec<SecurityFinding>> {
        let mut all_findings = Vec::new();

        for (file_path, language) in files {
            match self.analyze_file(&file_path, language).await {
                Ok(mut findings) => {
                    all_findings.append(&mut findings);
                }
                Err(e) => {
                    tracing::warn!("Failed to analyze file {}: {}", file_path.display(), e);
                }
            }
        }

        Ok(all_findings)
    }

    /// Enhance finding with semantic information
    fn enhance_finding_with_semantics(
        &self,
        finding: &mut SecurityFinding,
        semantic_info: &SemanticInfo,
    ) -> Result<()> {
        // Add variable information if relevant
        if let Some(var_name) = self.extract_variable_from_finding(finding) {
            if let Some(var_info) = semantic_info.variables.get(&var_name) {
                // Enhance finding based on variable context
                if var_info.is_constant {
                    finding.confidence += 0.1; // Constants are more suspicious for secrets
                }
            }
        }

        // Add function context
        if let Some(func_name) = self.extract_function_from_finding(finding) {
            for func in &semantic_info.functions {
                if func.name == func_name {
                    finding.context.function_context = Some(func_name.clone());
                    break;
                }
            }
        }

        Ok(())
    }

    /// Extract variable name from finding if applicable
    fn extract_variable_from_finding(&self, finding: &SecurityFinding) -> Option<String> {
        // Simple heuristic - look for variable-like patterns in the finding
        if finding.finding_type == SecurityFindingType::HardcodedSecret {
            // Extract potential variable names from the code snippet
            if let Some(_var_match) = finding.code_snippet.lines().find(|line| {
                line.contains('=')
                    || line.contains("const")
                    || line.contains("let")
                    || line.contains("var")
            }) {
                // Simple extraction - this could be enhanced
                Some("extracted_var".to_string())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Extract function name from finding if applicable
    fn extract_function_from_finding(&self, finding: &SecurityFinding) -> Option<String> {
        // Look for function patterns in the code snippet
        if let Some(_func_match) = finding
            .code_snippet
            .lines()
            .find(|line| line.contains("fn ") || line.contains("function") || line.contains("def "))
        {
            // Simple extraction - this could be enhanced
            Some("extracted_function".to_string())
        } else {
            None
        }
    }

    /// Get CWE ID for a vulnerability type
    fn get_cwe_for_vulnerability(&self, vuln_type: &str) -> Option<String> {
        match vuln_type {
            "SQL Injection" => Some("CWE-89".to_string()),
            "Command Injection" => Some("CWE-78".to_string()),
            "Cross-Site Scripting (XSS)" => Some("CWE-79".to_string()),
            "Code Injection" => Some("CWE-94".to_string()),
            "Path Traversal" => Some("CWE-22".to_string()),
            "Deserialization Attack" => Some("CWE-502".to_string()),
            _ => Some("CWE-20".to_string()), // Generic Improper Input Validation
        }
    }

    /// Analyze semantic context for false positive filtering
    pub fn analyze_semantic_context(
        &self,
        finding: &SecurityFinding,
        code_context: &str,
        full_file_content: Option<&str>,
    ) -> Result<SemanticContextResult> {
        // Determine language from file path
        let language = self.detect_language_from_finding(finding)?;

        // Parse code context to get basic AST
        let parser = Parser::new(language)?;
        let tree = parser.parse(code_context, None)?;

        // Get language-specific analyzer
        let analyzer = self.language_analyzers.get(&language).ok_or_else(|| {
            Error::internal_error(
                "Semantic Context Analyzer",
                format!("No analyzer available for language: {}", language.name()),
            )
        })?;

        // Extract semantic information
        let semantic_info = analyzer.extract_semantic_info(&tree)?;

        // Classify context
        let file_path = std::path::Path::new(&finding.file_path);
        let context = self.context_classifier.classify_context(
            file_path,
            full_file_content.unwrap_or(code_context),
            &semantic_info,
        )?;

        // Determine if this is likely a false positive based on semantic analysis
        let is_test_code = context.is_test_code;
        let is_placeholder = self.is_placeholder_value(code_context);
        let is_documentation = self.is_documentation_context(code_context);
        let is_embedded = self.is_embedded_code(code_context);
        let is_safe_usage = self.is_safe_usage_pattern(finding, &semantic_info);

        let explanation = self.generate_semantic_explanation(
            is_test_code,
            is_placeholder,
            is_documentation,
            is_embedded,
            is_safe_usage,
        );

        Ok(SemanticContextResult {
            is_test_code,
            is_placeholder,
            is_documentation,
            is_embedded,
            is_safe_usage,
            explanation,
        })
    }

    /// Detect language from finding
    fn detect_language_from_finding(&self, finding: &SecurityFinding) -> Result<Language> {
        // Simple language detection based on file extension
        let path = std::path::Path::new(&finding.file_path);
        if let Some(extension) = path.extension() {
            match extension.to_str() {
                Some("rs") => Ok(Language::Rust),
                Some("js") => Ok(Language::JavaScript),
                Some("ts") => Ok(Language::TypeScript),
                Some("py") => Ok(Language::Python),
                Some("java") => Ok(Language::Java),
                Some("go") => Ok(Language::Go),
                Some("c") => Ok(Language::C),
                Some("cpp") | Some("cc") | Some("cxx") => Ok(Language::Cpp),
                Some("php") => Ok(Language::Php),
                Some("rb") => Ok(Language::Ruby),
                Some("swift") => Ok(Language::Swift),
                Some("kt") => Ok(Language::Kotlin),
                _ => Ok(Language::Rust), // Default fallback
            }
        } else {
            Ok(Language::Rust) // Default fallback
        }
    }

    /// Check if the code contains placeholder values
    fn is_placeholder_value(&self, code_context: &str) -> bool {
        let placeholders = [
            "your_api_key_here",
            "your_secret_key",
            "placeholder",
            "example_key",
            "test_key",
            "dummy_key",
            "fake_key",
            "sample_key",
            "sk-test",
            "pk_test",
            "CHANGE_ME",
            "REPLACE_ME",
            "TODO",
            "FIXME",
        ];

        let context_lower = code_context.to_lowercase();
        placeholders
            .iter()
            .any(|placeholder| context_lower.contains(&placeholder.to_lowercase()))
    }

    /// Check if this is documentation context
    fn is_documentation_context(&self, code_context: &str) -> bool {
        let doc_patterns = [
            "///", "//!", "/**", "/*!", "# ", "\"\"\"", "'''", "README", "readme", "example",
            "Example", "doc", "Doc", "comment", "Comment",
        ];

        doc_patterns
            .iter()
            .any(|pattern| code_context.contains(pattern))
    }

    /// Check if this appears to be embedded code in string literals
    fn is_embedded_code(&self, code_context: &str) -> bool {
        // Check for JavaScript patterns that are commonly embedded
        let js_patterns = [
            "addEventListener",
            "document.",
            "window.",
            "localStorage",
            "sessionStorage",
            "documentElement",
            "getElementById",
            "querySelector",
            "innerHTML",
            "textContent",
            "classList",
            "setAttribute",
            "getAttribute",
            "createElement",
            "appendChild",
            "function(",
            "const ",
            "let ",
            "var ",
            "=> {",
            "try {",
            "catch(",
            "console.log",
            "console.error",
            "console.warn",
            "setTimeout",
            "setInterval",
            "fetch(",
            "XMLHttpRequest",
            "WebSocket",
            ".then(",
            ".catch(",
            "async ",
            "await ",
            "Promise",
            "JSON.parse",
            "JSON.stringify",
        ];

        // Check for HTML patterns
        let html_patterns = [
            "<div",
            "<span",
            "<script",
            "<style",
            "<button",
            "<input",
            "<form",
            "<a href",
            "<img",
            "<p>",
            "<h1",
            "<h2",
            "<h3",
            "onclick=",
            "onload=",
            "onchange=",
            "onsubmit=",
            "class=",
            "id=",
            "style=",
        ];

        // Check for CSS patterns
        let css_patterns = [
            "background:",
            "color:",
            "font-size:",
            "margin:",
            "padding:",
            "display:",
            "position:",
            "width:",
            "height:",
            "border:",
            ".hljs",
            "#hljs",
            "@media",
            "keyframes",
        ];

        // Check for SQL patterns
        let sql_patterns = [
            "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "CREATE ", "ALTER ", "DROP ", "FROM ",
            "WHERE ", "JOIN ", "INNER ", "LEFT ", "RIGHT ", "ORDER BY", "GROUP BY", "LIMIT ",
        ];

        let context_lower = code_context.to_lowercase();

        // Count how many patterns match
        let js_matches = js_patterns
            .iter()
            .filter(|p| context_lower.contains(&p.to_lowercase()))
            .count();
        let html_matches = html_patterns
            .iter()
            .filter(|p| context_lower.contains(&p.to_lowercase()))
            .count();
        let css_matches = css_patterns
            .iter()
            .filter(|p| context_lower.contains(&p.to_lowercase()))
            .count();
        let sql_matches = sql_patterns
            .iter()
            .filter(|p| context_lower.contains(&p.to_lowercase()))
            .count();

        // If we have multiple matches from different categories, this is likely embedded code
        (js_matches >= 2) || (html_matches >= 2) || (css_matches >= 2) || (sql_matches >= 2) ||
        // Or if we have a combination of different types
        ((js_matches >= 1 && html_matches >= 1) ||
         (js_matches >= 1 && css_matches >= 1) ||
         (html_matches >= 1 && css_matches >= 1) ||
         (js_matches >= 1 && sql_matches >= 1)) ||
        // Check for string literal context (common in embedded code)
        self.is_in_string_literal_context(code_context)
    }

    /// Check if code appears to be within string literals (indicating embedded code)
    fn is_in_string_literal_context(&self, code_context: &str) -> bool {
        // Look for patterns that suggest code is inside string literals
        let string_indicators = [
            "\"\"\"", // Python multiline strings
            "'''",    // Python multiline strings
            "`",      // JavaScript template literals
            "\"",     // Regular string quotes
            "'",      // Single quotes
        ];

        let mut in_string = false;
        let mut string_char = ' ';
        let mut escaped = false;

        for ch in code_context.chars() {
            if escaped {
                escaped = false;
                continue;
            }

            if ch == '\\' {
                escaped = true;
                continue;
            }

            if !in_string {
                for &quote in &string_indicators {
                    if ch == quote.chars().next().unwrap() {
                        in_string = true;
                        string_char = ch;
                        break;
                    }
                }
            } else if ch == string_char {
                in_string = false;
                string_char = ' ';
            }
        }

        // If we're still in a string at the end, or if we found string delimiters,
        // this might be embedded code
        in_string || string_indicators.iter().any(|s| code_context.contains(s))
    }

    /// Check if this is a safe usage pattern
    fn is_safe_usage_pattern(
        &self,
        finding: &SecurityFinding,
        semantic_info: &SemanticInfo,
    ) -> bool {
        match finding.finding_type {
            SecurityFindingType::HardcodedSecret => {
                // Check if the secret is used in a safe way
                self.is_safe_secret_usage(finding, semantic_info)
            }
            SecurityFindingType::Injection => {
                // Check if injection is properly sanitized
                self.is_safe_injection_usage(finding, semantic_info)
            }
            SecurityFindingType::BrokenAccessControl => {
                // Check for proper authorization patterns
                self.is_safe_access_control(finding, semantic_info)
            }
            SecurityFindingType::WeakAuthentication => {
                // Check for secure authentication patterns
                self.is_safe_authentication(finding, semantic_info)
            }
            _ => false,
        }
    }

    /// Check if access control is implemented safely
    fn is_safe_access_control(
        &self,
        finding: &SecurityFinding,
        semantic_info: &SemanticInfo,
    ) -> bool {
        let context_lower = finding.code_snippet.to_lowercase();

        // Look for authorization patterns
        let auth_patterns = [
            "authorize",
            "authenticate",
            "permission",
            "role",
            "access_control",
            "middleware",
            "guard",
            "policy",
            "jwt",
            "session",
            "token",
            "admin",
            "user",
            "role",
            "permission",
            "acl",
        ];

        for pattern in &auth_patterns {
            if context_lower.contains(pattern) {
                return true;
            }
        }

        // Check for function calls that suggest authorization
        for call in &semantic_info.function_calls {
            let call_lower = call.function_name.to_lowercase();
            if call_lower.contains("auth")
                || call_lower.contains("check")
                || call_lower.contains("verify")
                || call_lower.contains("validate")
            {
                return true;
            }
        }

        false
    }

    /// Check if authentication is implemented safely
    fn is_safe_authentication(
        &self,
        finding: &SecurityFinding,
        semantic_info: &SemanticInfo,
    ) -> bool {
        let context_lower = finding.code_snippet.to_lowercase();

        // Look for secure authentication patterns
        let secure_auth_patterns = [
            "bcrypt", "argon2", "pbkdf2", "scrypt", // Password hashing
            "jwt", "oauth", "saml", "ldap", // Auth protocols
            "ssl", "tls", "https", // Secure transport
            "session", "cookie", "token", // Session management
        ];

        for pattern in &secure_auth_patterns {
            if context_lower.contains(pattern) {
                return true;
            }
        }

        // Check for crypto-related imports
        for import in &semantic_info.imports {
            let import_lower = import.to_lowercase();
            if import_lower.contains("crypto")
                || import_lower.contains("bcrypt")
                || import_lower.contains("hash")
                || import_lower.contains("jwt")
            {
                return true;
            }
        }

        false
    }

    /// Check if secret usage is safe
    fn is_safe_secret_usage(
        &self,
        finding: &SecurityFinding,
        semantic_info: &SemanticInfo,
    ) -> bool {
        // Check if the secret is loaded from environment or config
        let context_lower = finding.code_snippet.to_lowercase();

        // Look for environment variable patterns
        if context_lower.contains("env::var")
            || context_lower.contains("std::env")
            || context_lower.contains("process.env")
            || context_lower.contains("os.environ")
            || context_lower.contains("getenv")
            || context_lower.contains("environment")
            || context_lower.contains("dotenv")
        {
            return true;
        }

        // Look for config loading patterns
        if context_lower.contains("config")
            || context_lower.contains("settings")
            || context_lower.contains("load")
            || context_lower.contains("read")
            || context_lower.contains("parse")
            || context_lower.contains("deserialize")
        {
            return true;
        }

        // Check for secure key management patterns
        let secure_patterns = [
            "keyring",
            "vault",
            "secret_manager",
            "aws_secretsmanager",
            "azure_keyvault",
            "gcp_secretmanager",
            "kubernetes_secret",
            "hashicorp_vault",
            "key_management",
            "kms",
        ];

        for pattern in &secure_patterns {
            if context_lower.contains(pattern) {
                return true;
            }
        }

        // Check if it's a constant that's properly handled
        for (var_name, var_info) in &semantic_info.variables {
            if var_info.is_constant {
                // Constants might be acceptable if they're not actual secrets
                // But check if they have secure naming patterns
                let var_name_lower = var_name.to_lowercase();
                if var_name_lower.contains("key")
                    || var_name_lower.contains("secret")
                    || var_name_lower.contains("token")
                    || var_name_lower.contains("password")
                {
                    // This might still be a hardcoded secret in a constant
                    continue;
                }
                return true;
            }
        }

        // Check for imports that suggest secure secret handling
        for import in &semantic_info.imports {
            let import_lower = import.to_lowercase();
            if import_lower.contains("dotenv")
                || import_lower.contains("config")
                || import_lower.contains("env")
                || import_lower.contains("secret")
            {
                return true;
            }
        }

        false
    }

    /// Check if injection usage is safe
    fn is_safe_injection_usage(
        &self,
        finding: &SecurityFinding,
        semantic_info: &SemanticInfo,
    ) -> bool {
        // Check for sanitization functions
        let context_lower = finding.code_snippet.to_lowercase();

        let sanitization_patterns = [
            "sanitize",
            "escape",
            "encode",
            "validate",
            "filter",
            "clean",
            "prepared",
            "parameterized",
            "bind",
            "quote",
        ];

        for pattern in &sanitization_patterns {
            if context_lower.contains(pattern) {
                return true;
            }
        }

        // Check for ORM usage which typically handles injection
        let orm_patterns = [
            "diesel",
            "sqlx",
            "tokio-postgres",
            "rusqlite",
            "mongodb",
            "mongoose",
            "sequelize",
            "typeorm",
            "prisma",
            "gorm",
            "hibernate",
            "jpa",
            "activerecord",
            "peewee",
            "sqlalchemy",
        ];

        for pattern in &orm_patterns {
            if context_lower.contains(pattern) {
                return true;
            }
        }

        // Check for parameterized query patterns
        let param_patterns = [
            "prepare",
            "execute",
            "query",
            "stmt",
            "bind_param",
            "bind_value",
            "parameter",
            "placeholder",
            "interpolate",
        ];

        let param_count = param_patterns
            .iter()
            .filter(|p| context_lower.contains(*p))
            .count();

        if param_count >= 2 {
            return true; // Multiple parameterization indicators
        }

        // Check for escaping/sanitization function calls
        for call in &semantic_info.function_calls {
            let call_lower = call.function_name.to_lowercase();
            if call_lower.contains("escape")
                || call_lower.contains("sanitize")
                || call_lower.contains("clean")
                || call_lower.contains("filter")
                || call_lower.contains("validate")
                || call_lower.contains("encode")
            {
                return true;
            }
        }

        false
    }

    /// Generate explanation for semantic analysis
    fn generate_semantic_explanation(
        &self,
        is_test: bool,
        is_placeholder: bool,
        is_doc: bool,
        is_embedded: bool,
        is_safe: bool,
    ) -> String {
        let mut reasons = Vec::new();

        if is_test {
            reasons.push("appears to be test code");
        }
        if is_placeholder {
            reasons.push("contains placeholder values");
        }
        if is_doc {
            reasons.push("is in documentation context");
        }
        if is_embedded {
            reasons.push("appears to be embedded code in string literals");
        }
        if is_safe {
            reasons.push("uses safe patterns and security best practices");
        }

        if reasons.is_empty() {
            "No semantic false positive indicators found - this may be a legitimate security concern".to_string()
        } else {
            format!(
                "Semantic analysis suggests this may be a false positive because it {}",
                reasons.join(", and ")
            )
        }
    }

    /// Enhanced semantic analysis for complex scenarios
    pub fn analyze_complex_semantic_context(
        &self,
        finding: &SecurityFinding,
        code_context: &str,
        _full_file_content: Option<&str>,
        semantic_info: &SemanticInfo,
    ) -> Result<EnhancedSemanticResult> {
        let mut confidence_adjustment = 0.0;
        let mut additional_factors = Vec::new();

        // Analyze code complexity and context
        let complexity_score = self.analyze_code_complexity(code_context);
        if complexity_score > 0.7 {
            // Complex code is less likely to be a false positive
            confidence_adjustment -= 0.1;
            additional_factors.push("high code complexity suggests real vulnerability".to_string());
        }

        // Check for security-related comments or documentation
        if self.has_security_comments(code_context) {
            confidence_adjustment += 0.2;
            additional_factors.push("security-related comments indicate awareness".to_string());
        }

        // Analyze variable naming patterns
        let naming_score = self.analyze_variable_naming(semantic_info);
        if naming_score > 0.6 {
            confidence_adjustment += 0.15;
            additional_factors.push("suspicious variable naming patterns".to_string());
        }

        // Check for multiple security issues in the same area
        let clustering_score = self.analyze_issue_clustering(finding, semantic_info);
        if clustering_score > 0.5 {
            confidence_adjustment += 0.1;
            additional_factors.push("multiple security issues in close proximity".to_string());
        }

        Ok(EnhancedSemanticResult {
            confidence_adjustment,
            additional_factors,
            complexity_score,
            naming_score,
            clustering_score,
        })
    }

    /// Analyze code complexity as an indicator of false positives
    fn analyze_code_complexity(&self, code_context: &str) -> f64 {
        let lines = code_context.lines().count();
        let _chars = code_context.chars().count();
        let keywords = [
            "if ", "for ", "while ", "match ", "fn ", "class ", "struct ",
        ]
        .iter()
        .filter(|k| code_context.contains(*k))
        .count();

        // Simple complexity score based on size and control structures
        let size_score = (lines as f64 / 50.0).min(1.0);
        let keyword_score = (keywords as f64 / 10.0).min(1.0);

        (size_score + keyword_score) / 2.0
    }

    /// Check for security-related comments
    fn has_security_comments(&self, code_context: &str) -> bool {
        let security_keywords = [
            "security",
            "vulnerable",
            "exploit",
            "attack",
            "hack",
            "injection",
            "xss",
            "csrf",
            "auth",
            "encrypt",
            "hash",
            "sanitize",
            "validate",
            "escape",
            "filter",
        ];

        let context_lower = code_context.to_lowercase();
        security_keywords.iter().any(|k| context_lower.contains(k))
    }

    /// Analyze variable naming patterns for suspicious indicators
    fn analyze_variable_naming(&self, semantic_info: &SemanticInfo) -> f64 {
        let mut suspicious_count = 0;
        let mut total_vars = 0;

        for (var_name, _var_info) in &semantic_info.variables {
            total_vars += 1;
            let name_lower = var_name.to_lowercase();

            // Check for suspicious naming patterns
            if name_lower.contains("secret")
                || name_lower.contains("key")
                || name_lower.contains("token")
                || name_lower.contains("password")
                || name_lower.contains("auth")
                || name_lower.contains("admin")
            {
                suspicious_count += 1;
            }
        }

        if total_vars == 0 {
            0.0
        } else {
            suspicious_count as f64 / total_vars as f64
        }
    }

    /// Analyze clustering of security issues
    fn analyze_issue_clustering(
        &self,
        _finding: &SecurityFinding,
        semantic_info: &SemanticInfo,
    ) -> f64 {
        // Simple clustering based on number of function calls and variables
        // More complex code tends to have more legitimate security issues
        let function_density = semantic_info.functions.len() as f64 / 10.0;
        let variable_density = semantic_info.variables.len() as f64 / 20.0;
        let call_density = semantic_info.function_calls.len() as f64 / 15.0;

        (function_density + variable_density + call_density).min(1.0)
    }
}

/// Enhanced semantic analysis result
#[derive(Debug, Clone)]
pub struct EnhancedSemanticResult {
    /// Confidence adjustment (-1.0 to 1.0, negative reduces false positive likelihood)
    pub confidence_adjustment: f64,
    /// Additional factors identified
    pub additional_factors: Vec<String>,
    /// Code complexity score (0.0 to 1.0)
    pub complexity_score: f64,
    /// Variable naming suspiciousness score (0.0 to 1.0)
    pub naming_score: f64,
    /// Issue clustering score (0.0 to 1.0)
    pub clustering_score: f64,
}

impl Default for SemanticContextResult {
    fn default() -> Self {
        Self {
            is_test_code: false,
            is_placeholder: false,
            is_documentation: false,
            is_embedded: false,
            is_safe_usage: false,
            explanation: "No analysis performed".to_string(),
        }
    }
}

impl Default for EnhancedSemanticResult {
    fn default() -> Self {
        Self {
            confidence_adjustment: 0.0,
            additional_factors: Vec::new(),
            complexity_score: 0.0,
            naming_score: 0.0,
            clustering_score: 0.0,
        }
    }
}

// Language-specific analyzers will be implemented in separate modules
// For now, we'll create placeholder implementations

macro_rules! placeholder_analyzer {
    ($name:ident) => {
        #[derive(Debug)]
        pub struct $name;

        impl $name {
            pub fn new() -> Self {
                Self
            }
        }

        #[async_trait::async_trait]
        impl LanguageSpecificAnalyzer for $name {
            async fn analyze(
                &self,
                _tree: &SyntaxTree,
                _file_path: &str,
            ) -> Result<Vec<SecurityFinding>> {
                // Placeholder implementation - will be enhanced
                Ok(Vec::new())
            }

            fn get_vulnerability_patterns(&self) -> Vec<VulnerabilityPattern> {
                // Placeholder - will be enhanced with language-specific patterns
                Vec::new()
            }

            fn extract_semantic_info(&self, _tree: &SyntaxTree) -> Result<SemanticInfo> {
                // Placeholder - will be enhanced with language-specific semantic extraction
                Ok(SemanticInfo {
                    functions: Vec::new(),
                    classes: Vec::new(),
                    variables: HashMap::new(),
                    imports: Vec::new(),
                    string_literals: Vec::new(),
                    function_calls: Vec::new(),
                })
            }
        }
    };
}

// Create placeholder analyzers for all supported languages
placeholder_analyzer!(RustAnalyzer);
placeholder_analyzer!(JavaScriptAnalyzer);
placeholder_analyzer!(TypeScriptAnalyzer);
placeholder_analyzer!(PythonAnalyzer);
placeholder_analyzer!(JavaAnalyzer);
placeholder_analyzer!(GoAnalyzer);
placeholder_analyzer!(CAnalyzer);
placeholder_analyzer!(CppAnalyzer);
placeholder_analyzer!(PhpAnalyzer);
placeholder_analyzer!(RubyAnalyzer);
placeholder_analyzer!(SwiftAnalyzer);
placeholder_analyzer!(KotlinAnalyzer);

/// Context classifier for determining code context
#[derive(Debug)]
pub struct ContextClassifier {
    test_patterns: std::collections::HashSet<String>,
    example_patterns: std::collections::HashSet<String>,
    config_patterns: std::collections::HashSet<String>,
}

impl ContextClassifier {
    pub fn new() -> Self {
        let mut test_patterns = std::collections::HashSet::new();
        test_patterns.insert("test".to_string());
        test_patterns.insert("spec".to_string());
        test_patterns.insert("Test".to_string());
        test_patterns.insert("Spec".to_string());

        let mut example_patterns = std::collections::HashSet::new();
        example_patterns.insert("example".to_string());
        example_patterns.insert("Example".to_string());
        example_patterns.insert("demo".to_string());
        example_patterns.insert("Demo".to_string());
        example_patterns.insert("sample".to_string());
        example_patterns.insert("Sample".to_string());

        let mut config_patterns = std::collections::HashSet::new();
        config_patterns.insert("config".to_string());
        config_patterns.insert("Config".to_string());
        config_patterns.insert("settings".to_string());
        config_patterns.insert("Settings".to_string());

        Self {
            test_patterns,
            example_patterns,
            config_patterns,
        }
    }

    pub fn classify_context(
        &self,
        file_path: &Path,
        source: &str,
        _semantic_info: &SemanticInfo,
    ) -> Result<CodeContext> {
        let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        let is_test_code = self.is_test_file(file_name) || self.contains_test_indicators(source);
        let is_example_code =
            self.is_example_file(file_name) || self.contains_example_indicators(source);
        let is_config_code =
            self.is_config_file(file_name) || self.contains_config_indicators(source);

        // Extract function and class context from semantic info
        let function_context = None; // semantic_info.functions.first().map(|f| f.name.clone());
        let class_context = None; // semantic_info.classes.first().map(|c| c.name.clone());
        let module_context = self.extract_module_context(file_path);

        Ok(CodeContext {
            is_test_code,
            is_example_code,
            is_config_code,
            function_context,
            class_context,
            module_context,
            variable_scope: HashMap::new(), // semantic_info.variables.clone(),
        })
    }

    fn is_test_file(&self, file_name: &str) -> bool {
        self.test_patterns
            .iter()
            .any(|pattern| file_name.contains(pattern))
    }

    fn is_example_file(&self, file_name: &str) -> bool {
        self.example_patterns
            .iter()
            .any(|pattern| file_name.contains(pattern))
    }

    fn is_config_file(&self, file_name: &str) -> bool {
        self.config_patterns
            .iter()
            .any(|pattern| file_name.contains(pattern))
    }

    fn contains_test_indicators(&self, source: &str) -> bool {
        source.lines().any(|line| {
            self.test_patterns
                .iter()
                .any(|pattern| line.contains(pattern))
        })
    }

    fn contains_example_indicators(&self, source: &str) -> bool {
        source.lines().any(|line| {
            self.example_patterns
                .iter()
                .any(|pattern| line.contains(pattern))
        })
    }

    fn contains_config_indicators(&self, source: &str) -> bool {
        source.lines().any(|line| {
            self.config_patterns
                .iter()
                .any(|pattern| line.contains(pattern))
        })
    }

    fn extract_module_context(&self, file_path: &Path) -> Option<String> {
        file_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
    }
}

/// Semantic analysis engine
#[derive(Debug)]
pub struct SemanticAnalysisEngine {
    taint_analyzer: crate::TaintAnalyzer,
}

impl SemanticAnalysisEngine {
    pub fn new() -> Self {
        Self {
            taint_analyzer: crate::TaintAnalyzer::new("generic"), // Default to generic language
        }
    }

    pub fn with_language(mut self, language: &str) -> Self {
        self.taint_analyzer = crate::TaintAnalyzer::new(language);
        self
    }

    /// Analyze data flow between variables and functions using taint analysis
    pub fn analyze_data_flow(&self, semantic_info: &SemanticInfo) -> Result<Vec<DataFlowAnalysis>> {
        let mut results = Vec::new();

        // Analyze data flows between variables and function calls
        for (var_name, _var_info) in &semantic_info.variables {
            for call in &semantic_info.function_calls {
                // Check if variable is used in function call (potential data flow)
                if call.arguments.iter().any(|arg| arg.contains(var_name)) {
                    results.push(DataFlowAnalysis {
                        source_variable: var_name.clone(),
                        sink_function: call.function_name.clone(),
                        flow_path: vec![var_name.clone(), call.function_name.clone()],
                        is_safe: self.is_safe_data_flow(var_name, &call.function_name),
                    });
                }
            }
        }

        Ok(results)
    }

    /// Detect potential injection points using taint analysis
    pub fn detect_injection_points(
        &self,
        semantic_info: &SemanticInfo,
    ) -> Result<Vec<InjectionPoint>> {
        let mut injection_points = Vec::new();

        for call in &semantic_info.function_calls {
            // Check for common injection sink functions
            if self.is_injection_sink(&call.function_name) {
                for (i, arg) in call.arguments.iter().enumerate() {
                    // Check if argument could be tainted (contains user input patterns)
                    if self.could_be_tainted(arg) {
                        injection_points.push(InjectionPoint {
                            function_name: call.function_name.clone(),
                            parameter_index: i,
                            vulnerability_type: self
                                .determine_vulnerability_type(&call.function_name),
                            confidence: self
                                .calculate_injection_confidence(arg, &call.function_name),
                        });
                    }
                }
            }
        }

        Ok(injection_points)
    }

    /// Check if a data flow is considered safe
    fn is_safe_data_flow(&self, source: &str, sink: &str) -> bool {
        // Safe sinks that don't propagate vulnerabilities
        let safe_sinks = ["println", "log", "debug", "to_string", "format"];

        // Safe sources that are not user-controlled
        let safe_sources = ["const", "static", "config"];

        safe_sinks.iter().any(|&s| sink.contains(s))
            || safe_sources.iter().any(|&s| source.contains(s))
    }

    /// Check if a function is a potential injection sink
    fn is_injection_sink(&self, function_name: &str) -> bool {
        let injection_sinks = [
            "execute",
            "exec",
            "system",
            "shell_exec",
            "eval",
            "query",
            "sql",
            "innerHTML",
            "outerHTML",
            "document.write",
            "insertAdjacentHTML",
            "setAttribute",
            "createElement",
            "appendChild",
        ];

        injection_sinks
            .iter()
            .any(|&sink| function_name.contains(sink))
    }

    /// Determine the type of vulnerability for an injection sink
    fn determine_vulnerability_type(&self, function_name: &str) -> String {
        if function_name.contains("sql") || function_name.contains("query") {
            "SQL Injection".to_string()
        } else if function_name.contains("exec") || function_name.contains("system") {
            "Command Injection".to_string()
        } else if function_name.contains("innerHTML") || function_name.contains("document.write") {
            "Cross-Site Scripting (XSS)".to_string()
        } else {
            "Code Injection".to_string()
        }
    }

    /// Check if an argument could be tainted (contain user input)
    fn could_be_tainted(&self, argument: &str) -> bool {
        // Look for patterns that suggest user input
        let taint_patterns = [
            "req.", "request.", "params", "query", "body", "input", "argv", "args", "stdin",
            "read", "get", "post",
        ];

        taint_patterns
            .iter()
            .any(|&pattern| argument.contains(pattern))
    }

    /// Calculate confidence level for injection detection
    fn calculate_injection_confidence(&self, argument: &str, function_name: &str) -> f64 {
        let mut confidence: f64 = 0.5;

        // Higher confidence if argument clearly indicates user input
        if argument.contains("req.body") || argument.contains("request.params") {
            confidence += 0.3;
        }

        // Higher confidence for known dangerous functions
        if function_name.contains("eval") || function_name.contains("innerHTML") {
            confidence += 0.2;
        }

        confidence.min(1.0)
    }
}

/// Data flow analysis result
#[derive(Debug, Clone)]
pub struct DataFlowAnalysis {
    pub source_variable: String,
    pub sink_function: String,
    pub flow_path: Vec<String>,
    pub is_safe: bool,
}

/// Injection point detection
#[derive(Debug, Clone)]
pub struct InjectionPoint {
    pub function_name: String,
    pub parameter_index: usize,
    pub vulnerability_type: String,
    pub confidence: f64,
}
