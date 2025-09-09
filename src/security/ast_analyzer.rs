//! AST-based security analysis framework
//!
//! This module provides semantic analysis capabilities for security detection,
//! replacing pattern-based approaches with proper AST understanding.

use crate::error::{Error, Result};
use crate::languages::Language;
use crate::parser::Parser;
use crate::tree::{Node, SyntaxTree};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::{debug, warn};

/// AST-based security analyzer
pub struct AstSecurityAnalyzer {
    /// Language-specific analyzers
    language_analyzers: HashMap<Language, Box<dyn LanguageSpecificAnalyzer>>,
    /// Context classifier for determining code context
    context_classifier: ContextClassifier,
    /// Semantic analysis engine
    semantic_engine: SemanticAnalysisEngine,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
            semantic_engine: SemanticAnalysisEngine::new(),
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

        // Perform AST-based analysis
        let mut findings = analyzer
            .analyze(&tree, &file_path.to_string_lossy())
            .await?;

        // Enhance findings with semantic context
        for finding in &mut findings {
            finding.context = context.clone();
            self.enhance_finding_with_semantics(finding, &semantic_info)?;
        }

        debug!("Completed AST analysis, found {} findings", findings.len());
        Ok(findings)
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
                    warn!("Failed to analyze file {}: {}", file_path.display(), e);
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
            if let Some(var_match) = finding.code_snippet.lines().find(|line| {
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
        if let Some(func_match) = finding
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
    test_patterns: HashSet<String>,
    example_patterns: HashSet<String>,
    config_patterns: HashSet<String>,
}

impl ContextClassifier {
    pub fn new() -> Self {
        let mut test_patterns = HashSet::new();
        test_patterns.insert("test".to_string());
        test_patterns.insert("spec".to_string());
        test_patterns.insert("Test".to_string());
        test_patterns.insert("Spec".to_string());

        let mut example_patterns = HashSet::new();
        example_patterns.insert("example".to_string());
        example_patterns.insert("Example".to_string());
        example_patterns.insert("demo".to_string());
        example_patterns.insert("Demo".to_string());
        example_patterns.insert("sample".to_string());
        example_patterns.insert("Sample".to_string());

        let mut config_patterns = HashSet::new();
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
pub struct SemanticAnalysisEngine;

impl SemanticAnalysisEngine {
    pub fn new() -> Self {
        Self
    }

    /// Analyze data flow between variables and functions
    pub fn analyze_data_flow(&self, semantic_info: &SemanticInfo) -> Result<Vec<DataFlowAnalysis>> {
        // Placeholder implementation - will be enhanced
        Ok(Vec::new())
    }

    /// Detect potential injection points
    pub fn detect_injection_points(
        &self,
        semantic_info: &SemanticInfo,
    ) -> Result<Vec<InjectionPoint>> {
        // Placeholder implementation - will be enhanced
        Ok(Vec::new())
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
