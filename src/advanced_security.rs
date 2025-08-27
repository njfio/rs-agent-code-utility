//! Advanced security analysis for source code vulnerability detection
//!
//! **⚠️ IMPLEMENTATION STATUS: PATTERN-BASED WITH HIGH FALSE POSITIVES**
//!
//! This module implements basic pattern-based security scanning but has significant limitations:
//!
//! **What's Actually Implemented:**
//! - Pattern-based vulnerability detection (250+ patterns)
//! - Basic secrets detection using regex patterns
//! - Simple OWASP category classification
//! - Extensive type definitions for security analysis
//!
//! **Major Limitations:**
//! - **High false positive rate** - Many findings are not actual vulnerabilities
//! - **No semantic analysis** - Cannot understand code context or data flow
//! - **No real CVE integration** - Despite infrastructure, no actual vulnerability database lookup
//! - **Basic pattern matching only** - No sophisticated static analysis
//! - **Limited language understanding** - Generic patterns across all languages
//!
//! **Current Reality:** Suitable for basic security awareness but not for production
//! security audits. Claims of "enterprise-grade" and "comprehensive" analysis are
//! not supported by the current implementation quality.

use crate::{AnalysisResult, FileInfo, Result, Error};
use crate::parser::Parser;
use crate::tree::{SyntaxTree, Node};
use crate::languages::detect_language_from_path;
use std::collections::HashMap;
use std::path::PathBuf;


#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Advanced security analyzer for source code vulnerability detection
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AdvancedSecurityAnalyzer {
    /// Configuration for advanced security analysis
    pub config: AdvancedSecurityConfig,
}

/// Configuration for advanced security analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AdvancedSecurityConfig {
    /// Enable OWASP Top 10 vulnerability detection
    pub owasp_analysis: bool,
    /// Enable secrets detection
    pub secrets_detection: bool,
    /// Enable input validation analysis
    pub input_validation: bool,
    /// Enable injection vulnerability detection
    pub injection_analysis: bool,
    /// Enable security best practices validation
    pub best_practices: bool,
    /// Minimum severity level to report
    pub min_severity: SecuritySeverity,
    /// Custom security rules
    pub custom_rules: Vec<CustomSecurityRule>,
}

/// Context information for AST-based analysis
#[derive(Debug, Clone)]
struct SecurityContext {
    /// Current function name
    function_name: Option<String>,
    /// Whether we're in a test file
    is_test_file: bool,
    /// Whether we're in a comment
    is_comment: bool,
    /// Variable assignments in current scope
    variable_assignments: HashMap<String, String>,
    /// Function calls in current scope
    function_calls: Vec<String>,
    /// Whether user input is involved
    has_user_input: bool,
    /// Whether we're in a web context
    is_web_context: bool,
}

/// Results of advanced security analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AdvancedSecurityResult {
    /// Overall security score (0-100)
    pub security_score: u8,
    /// Total vulnerabilities found
    pub total_vulnerabilities: usize,
    /// Vulnerabilities by severity
    pub vulnerabilities_by_severity: HashMap<SecuritySeverity, usize>,
    /// Vulnerabilities by OWASP category
    pub owasp_categories: HashMap<OwaspCategory, usize>,
    /// Detected vulnerabilities
    pub vulnerabilities: Vec<SecurityVulnerability>,
    /// Detected secrets and sensitive data
    pub secrets: Vec<DetectedSecret>,
    /// Input validation issues
    pub input_validation_issues: Vec<InputValidationIssue>,
    /// Injection vulnerabilities
    pub injection_vulnerabilities: Vec<InjectionVulnerability>,
    /// Security best practice violations
    pub best_practice_violations: Vec<BestPracticeViolation>,
    /// Security recommendations
    pub recommendations: Vec<SecurityRecommendation>,
    /// Compliance assessment
    pub compliance: ComplianceAssessment,
}

/// Security vulnerability severity levels
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// OWASP Top 10 categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OwaspCategory {
    /// A01:2021 – Broken Access Control
    BrokenAccessControl,
    /// A02:2021 – Cryptographic Failures
    CryptographicFailures,
    /// A03:2021 – Injection
    Injection,
    /// A04:2021 – Insecure Design
    InsecureDesign,
    /// A05:2021 – Security Misconfiguration
    SecurityMisconfiguration,
    /// A06:2021 – Vulnerable and Outdated Components
    VulnerableComponents,
    /// A07:2021 – Identification and Authentication Failures
    AuthenticationFailures,
    /// A08:2021 – Software and Data Integrity Failures
    IntegrityFailures,
    /// A09:2021 – Security Logging and Monitoring Failures
    LoggingFailures,
    /// A10:2021 – Server-Side Request Forgery
    SSRF,
}

/// A detected security vulnerability
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityVulnerability {
    /// Vulnerability ID
    pub id: String,
    /// Vulnerability title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: SecuritySeverity,
    /// OWASP category
    pub owasp_category: OwaspCategory,
    /// CWE (Common Weakness Enumeration) ID
    pub cwe_id: Option<String>,
    /// Location in code
    pub location: VulnerabilityLocation,
    /// Vulnerable code snippet
    pub code_snippet: String,
    /// Impact assessment
    pub impact: SecurityImpact,
    /// Remediation guidance
    pub remediation: RemediationGuidance,
    /// Confidence level of detection
    pub confidence: ConfidenceLevel,
}

/// Location of a vulnerability
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VulnerabilityLocation {
    /// File path
    pub file: PathBuf,
    /// Function or method name
    pub function: Option<String>,
    /// Start line number
    pub start_line: usize,
    /// End line number
    pub end_line: usize,
    /// Column position
    pub column: usize,
}

/// Security impact assessment
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityImpact {
    /// Confidentiality impact
    pub confidentiality: ImpactLevel,
    /// Integrity impact
    pub integrity: ImpactLevel,
    /// Availability impact
    pub availability: ImpactLevel,
    /// Overall impact score (0-10)
    pub overall_score: f64,
}

/// Impact levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImpactLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Remediation guidance
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RemediationGuidance {
    /// Short remediation summary
    pub summary: String,
    /// Detailed remediation steps
    pub steps: Vec<String>,
    /// Code examples for fixes
    pub code_examples: Vec<CodeExample>,
    /// References and links
    pub references: Vec<String>,
    /// Estimated effort to fix
    pub effort: RemediationEffort,
}

/// Code example for remediation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CodeExample {
    /// Description of the example
    pub description: String,
    /// Vulnerable code (before)
    pub vulnerable_code: String,
    /// Secure code (after)
    pub secure_code: String,
    /// Programming language
    pub language: String,
}

/// Remediation effort levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RemediationEffort {
    Trivial,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Confidence level of vulnerability detection
#[derive(Debug, Clone, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

/// Detected secret or sensitive data
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DetectedSecret {
    /// Secret type
    pub secret_type: SecretType,
    /// Location in code
    pub location: VulnerabilityLocation,
    /// Masked value (for display)
    pub masked_value: String,
    /// Entropy score (0-1)
    pub entropy: f64,
    /// Confidence level
    pub confidence: ConfidenceLevel,
    /// Remediation advice
    pub remediation: String,
}

/// Types of secrets
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SecretType {
    ApiKey,
    Password,
    Token,
    PrivateKey,
    DatabaseConnection,
    AwsCredentials,
    GenericSecret,
}

/// Input validation issue
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InputValidationIssue {
    /// Issue type
    pub issue_type: InputValidationType,
    /// Location in code
    pub location: VulnerabilityLocation,
    /// Description
    pub description: String,
    /// Severity
    pub severity: SecuritySeverity,
    /// Remediation advice
    pub remediation: String,
}

/// Types of input validation issues
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum InputValidationType {
    MissingValidation,
    InsufficientValidation,
    UnsanitizedInput,
    TrustBoundaryViolation,
}

/// Injection vulnerability
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InjectionVulnerability {
    /// Injection type
    pub injection_type: InjectionType,
    /// Location in code
    pub location: VulnerabilityLocation,
    /// Vulnerable code pattern
    pub pattern: String,
    /// Severity
    pub severity: SecuritySeverity,
    /// Remediation guidance
    pub remediation: RemediationGuidance,
}

/// Types of injection vulnerabilities
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum InjectionType {
    SqlInjection,
    CommandInjection,
    CodeInjection,
    XssInjection,
    LdapInjection,
    XpathInjection,
}

/// Security best practice violation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BestPracticeViolation {
    /// Practice category
    pub category: BestPracticeCategory,
    /// Violation description
    pub description: String,
    /// Location in code
    pub location: VulnerabilityLocation,
    /// Severity
    pub severity: SecuritySeverity,
    /// Recommendation
    pub recommendation: String,
}

/// Best practice categories
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum BestPracticeCategory {
    Cryptography,
    Authentication,
    Authorization,
    SessionManagement,
    ErrorHandling,
    Logging,
    Configuration,
}

/// Security recommendation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityRecommendation {
    /// Recommendation category
    pub category: String,
    /// Recommendation text
    pub recommendation: String,
    /// Priority level
    pub priority: RecommendationPriority,
    /// Affected files
    pub affected_files: Vec<PathBuf>,
    /// Implementation guidance
    pub implementation: Vec<String>,
    /// Expected security improvement
    pub security_improvement: f64,
}

/// Recommendation priority levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RecommendationPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Compliance assessment
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ComplianceAssessment {
    /// OWASP Top 10 compliance score
    pub owasp_score: u8,
    /// CWE compliance assessment
    pub cwe_coverage: HashMap<String, bool>,
    /// Security standards compliance
    pub standards_compliance: HashMap<String, ComplianceStatus>,
    /// Overall compliance status
    pub overall_status: ComplianceStatus,
}

/// Compliance status levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ComplianceStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotApplicable,
}

/// Custom security rule
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CustomSecurityRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Pattern to match
    pub pattern: String,
    /// Severity level
    pub severity: SecuritySeverity,
    /// Languages this rule applies to
    pub languages: Vec<String>,
}

impl Default for AdvancedSecurityConfig {
    fn default() -> Self {
        Self {
            owasp_analysis: true,
            secrets_detection: true,
            input_validation: true,
            injection_analysis: true,
            best_practices: true,
            min_severity: SecuritySeverity::Low,
            custom_rules: Vec::new(),
        }
    }
}

impl Default for AdvancedSecurityAnalyzer {
    fn default() -> Self {
        Self {
            config: AdvancedSecurityConfig::default(),
        }
    }
}

impl AdvancedSecurityAnalyzer {
    /// Create a new advanced security analyzer with default configuration
    pub fn new() -> Result<Self> {
        let config = AdvancedSecurityConfig::default();

        Ok(Self {
            config,
        })
    }

    /// Create a new advanced security analyzer with custom configuration
    pub fn with_config(config: AdvancedSecurityConfig) -> Result<Self> {
        Ok(Self {
            config,
        })
    }

    /// Helper function to create vulnerability location without cloning file path repeatedly
    fn create_vulnerability_location(
        file_path: &std::path::Path,
        function_name: Option<&str>,
        start_line: usize,
        end_line: usize,
        column: usize,
    ) -> VulnerabilityLocation {
        VulnerabilityLocation {
            file: file_path.to_path_buf(),
            function: function_name.map(|s| s.to_string()),
            start_line,
            end_line,
            column,
        }
    }
    
    /// Perform comprehensive security analysis on a codebase
    pub fn analyze(&self, analysis_result: &AnalysisResult) -> Result<AdvancedSecurityResult> {
        let mut vulnerabilities = Vec::new();
        let mut secrets = Vec::new();
        let mut input_validation_issues = Vec::new();
        let mut injection_vulnerabilities = Vec::new();
        let mut best_practice_violations = Vec::new();

        // Analyze each file for security issues
        for file in &analysis_result.files {
            // Create a file info with absolute path for security analysis
            let absolute_path = analysis_result.root_path.join(&file.path);
            let file_with_absolute_path = FileInfo {
                path: absolute_path,
                language: file.language.clone(),
                size: file.size,
                lines: file.lines,
                parsed_successfully: file.parsed_successfully,
                parse_errors: file.parse_errors.clone(),
                symbols: file.symbols.clone(),
                security_vulnerabilities: file.security_vulnerabilities.clone(),
            };

            if self.config.owasp_analysis {
                let mut file_vulnerabilities = self.detect_owasp_vulnerabilities(&file_with_absolute_path)?;
                // Update paths to use relative paths for consistency
                for vuln in &mut file_vulnerabilities {
                    vuln.location.file = file.path.clone();
                }
                vulnerabilities.extend(file_vulnerabilities);
            }

            if self.config.secrets_detection {
                let mut file_secrets = self.detect_secrets(&file_with_absolute_path)?;
                // Update paths to use relative paths for consistency
                for secret in &mut file_secrets {
                    secret.location.file = file.path.clone();
                }
                secrets.extend(file_secrets);
            }

            if self.config.input_validation {
                let mut file_input_issues = self.detect_input_validation_issues(&file_with_absolute_path)?;
                // Update paths to use relative paths for consistency
                for issue in &mut file_input_issues {
                    issue.location.file = file.path.clone();
                }
                input_validation_issues.extend(file_input_issues);
            }

            if self.config.injection_analysis {
                let mut file_injection_vulns = self.detect_injection_vulnerabilities(&file_with_absolute_path)?;
                // Update paths to use relative paths for consistency
                for vuln in &mut file_injection_vulns {
                    vuln.location.file = file.path.clone();
                }
                injection_vulnerabilities.extend(file_injection_vulns);
            }

            if self.config.best_practices {
                let mut file_best_practices = self.detect_best_practice_violations(&file_with_absolute_path)?;
                // Update paths to use relative paths for consistency
                for violation in &mut file_best_practices {
                    violation.location.file = file.path.clone();
                }
                best_practice_violations.extend(file_best_practices);
            }
        }
        
        // Filter by minimum severity
        vulnerabilities.retain(|v| self.meets_severity_threshold(&v.severity));
        
        // Calculate metrics
        let total_vulnerabilities = vulnerabilities.len() + secrets.len() + 
                                   input_validation_issues.len() + injection_vulnerabilities.len() + 
                                   best_practice_violations.len();
        
        let vulnerabilities_by_severity = self.categorize_by_severity(&vulnerabilities);
        let owasp_categories = self.categorize_by_owasp(&vulnerabilities);
        
        // Generate recommendations
        let recommendations = self.generate_security_recommendations(
            &vulnerabilities,
            &secrets,
            &input_validation_issues,
            &injection_vulnerabilities,
            &best_practice_violations,
        )?;
        
        // Assess compliance
        let compliance = self.assess_compliance(&vulnerabilities, &owasp_categories)?;
        
        // Calculate security score
        let security_score = self.calculate_security_score(
            total_vulnerabilities,
            &vulnerabilities_by_severity,
            &compliance,
        );
        
        Ok(AdvancedSecurityResult {
            security_score,
            total_vulnerabilities,
            vulnerabilities_by_severity,
            owasp_categories,
            vulnerabilities,
            secrets,
            input_validation_issues,
            injection_vulnerabilities,
            best_practice_violations,
            recommendations,
            compliance,
        })
    }

    /// Check if severity meets the minimum threshold
    fn meets_severity_threshold(&self, severity: &SecuritySeverity) -> bool {
        match (&self.config.min_severity, severity) {
            (SecuritySeverity::Critical, SecuritySeverity::Critical) => true,
            (SecuritySeverity::High, SecuritySeverity::Critical | SecuritySeverity::High) => true,
            (SecuritySeverity::Medium, SecuritySeverity::Critical | SecuritySeverity::High | SecuritySeverity::Medium) => true,
            (SecuritySeverity::Low, _) => true,
            (SecuritySeverity::Info, _) => true,
            _ => false,
        }
    }

    /// Detect OWASP Top 10 vulnerabilities using AST-based analysis
    pub fn detect_owasp_vulnerabilities(&self, file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Try AST-based analysis first
        match self.analyze_with_ast(file) {
            Ok(ast_vulnerabilities) => {
                vulnerabilities.extend(ast_vulnerabilities);
            }
            Err(e) => {
                eprintln!("Warning: AST-based security analysis failed for {}: {}", file.path.display(), e);
                // Will rely on string-based analysis
            }
        }

        // Always run string-based analysis as well to catch patterns AST might miss
        match self.analyze_with_string_matching(file) {
            Ok(string_vulnerabilities) => {
                // Deduplicate vulnerabilities by checking if similar ones already exist
                for vuln in string_vulnerabilities {
                    let is_duplicate = vulnerabilities.iter().any(|existing| {
                        existing.location.start_line == vuln.location.start_line &&
                        existing.owasp_category == vuln.owasp_category
                    });

                    if !is_duplicate {
                        vulnerabilities.push(vuln);
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: String-based security analysis failed for {}: {}", file.path.display(), e);
                // Continue with AST results only
            }
        }

        Ok(vulnerabilities)
    }

    /// AST-based vulnerability analysis
    fn analyze_with_ast(&self, file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Detect language and create parser
        let language = detect_language_from_path(&file.path)
            .ok_or_else(|| Error::language_error("unknown", "Unable to detect language for AST analysis"))?;

        let parser = Parser::new(language)?;
        let content = std::fs::read_to_string(&file.path)?;
        let tree = parser.parse(&content, None)?;

        // Create security context
        let context = self.build_security_context(&tree, file);

        // Analyze different vulnerability types using enhanced AST analysis
        vulnerabilities.extend(self.detect_sql_injection_ast(&tree, &content, file, &context)?);
        vulnerabilities.extend(self.detect_command_injection_ast(&tree, &content, file, &context)?);
        vulnerabilities.extend(self.detect_hardcoded_secrets_ast(&tree, &content, file, &context)?);
        vulnerabilities.extend(self.detect_weak_crypto_ast(&tree, &content, file, &context)?);

        // Add enhanced detection methods
        vulnerabilities.extend(self.detect_enhanced_injection_ast(&tree, &content, file, &context)?);
        vulnerabilities.extend(self.detect_access_control_ast(&tree, &content, file, &context)?);

        Ok(vulnerabilities)
    }

    /// Fallback string-based analysis
    fn analyze_with_string_matching(&self, file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Read file content for analysis
        let content = std::fs::read_to_string(&file.path)?;
        let lines: Vec<&str> = content.lines().collect();

        // A01: Broken Access Control
        vulnerabilities.extend(self.detect_access_control_issues(&content, &lines, file)?);

        // A02: Cryptographic Failures
        vulnerabilities.extend(self.detect_cryptographic_failures(&content, &lines, file)?);

        // A03: Injection
        vulnerabilities.extend(self.detect_injection_issues(&content, &lines, file)?);

        // A04: Insecure Design
        vulnerabilities.extend(self.detect_insecure_design(&content, &lines, file)?);

        // A05: Security Misconfiguration
        vulnerabilities.extend(self.detect_security_misconfiguration(&content, &lines, file)?);

        // Additional lightweight detectors for common patterns across languages
        vulnerabilities.extend(self.detect_command_injection_strings(&content, file)?);
        vulnerabilities.extend(self.detect_path_traversal_strings(&content, file)?);
        vulnerabilities.extend(self.detect_insecure_random_strings(&content, file)?);
        vulnerabilities.extend(self.detect_xss_strings(&content, file)?);

        Ok(vulnerabilities)
    }

    /// Heuristic command injection detection via string search (e.g., Rust std::process::Command)
    fn detect_command_injection_strings(&self, content: &str, file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulns = Vec::new();
        if content.contains("Command::new(\"sh\")") || content.contains("Command::new(\"bash\")") {
            if content.contains(".arg(\"-c\")") {
                // Look for an .arg( that likely references a variable or expression
                if content.contains(".arg(") && (content.contains("user_") || content.contains("input") || content.contains("arg") || content.contains("cmd")) {
                    vulns.push(SecurityVulnerability {
                        id: "STR_CMD_001".to_string(),
                        title: "Potential command injection (shell -c)".to_string(),
                        description: "Spawning a shell with '-c' and user-controlled arguments may allow command injection".to_string(),
                        severity: SecuritySeverity::Critical,
                        owasp_category: OwaspCategory::Injection,
                        cwe_id: Some("CWE-78".to_string()),
                        location: VulnerabilityLocation { file: file.path.clone(), function: None, start_line: 1, end_line: 1, column: 0 },
                        code_snippet: "Command::new(\"sh\").arg(\"-c\").arg(...)".to_string(),
                        impact: SecurityImpact { confidentiality: ImpactLevel::Critical, integrity: ImpactLevel::Critical, availability: ImpactLevel::Critical, overall_score: 9.5 },
                        remediation: RemediationGuidance { summary: "Avoid shell with -c; use safe APIs".to_string(), steps: vec!["Avoid passing user input to shell".to_string(), "Use direct exec with separated args".to_string()], code_examples: vec![], references: vec![], effort: RemediationEffort::High },
                        confidence: ConfidenceLevel::Medium,
                    });
                }
            }
        }
        Ok(vulns)
    }

    /// Heuristic path traversal detection (e.g., read_to_string with variable input)
    fn detect_path_traversal_strings(&self, content: &str, file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulns = Vec::new();
        // Simple pattern: read_to_string(ident) without quotes
        for (idx, line) in content.lines().enumerate() {
            if line.contains("read_to_string(") {
                let after = line.split("read_to_string(").nth(1).unwrap_or("");
                let arg = after.split(')').next().unwrap_or("").trim();
                if !arg.starts_with('"') && !arg.starts_with('\'') {
                    vulns.push(SecurityVulnerability {
                        id: format!("STR_PATH_{}", idx + 1),
                        title: "Potential path traversal / unvalidated file read".to_string(),
                        description: "Reading from a path derived from user input without validation".to_string(),
                        severity: SecuritySeverity::High,
                        owasp_category: OwaspCategory::SecurityMisconfiguration,
                        cwe_id: Some("CWE-22".to_string()),
                        location: VulnerabilityLocation { file: file.path.clone(), function: None, start_line: idx + 1, end_line: idx + 1, column: 0 },
                        code_snippet: line.to_string(),
                        impact: SecurityImpact { confidentiality: ImpactLevel::High, integrity: ImpactLevel::Medium, availability: ImpactLevel::Low, overall_score: 7.0 },
                        remediation: RemediationGuidance { summary: "Validate and sanitize file paths".to_string(), steps: vec!["Normalize and restrict paths".to_string(), "Use allowlists or sandboxed dirs".to_string()], code_examples: vec![], references: vec![], effort: RemediationEffort::Medium },
                        confidence: ConfidenceLevel::Medium,
                    });
                }
            }
        }
        Ok(vulns)
    }

    /// Heuristic insecure random detection
    fn detect_insecure_random_strings(&self, content: &str, file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulns = Vec::new();
        if content.contains("RandomState::new") || content.contains("DefaultHasher::new") {
            vulns.push(SecurityVulnerability {
                id: "STR_RAND_001".to_string(),
                title: "Potential insecure randomness".to_string(),
                description: "Use of predictable hashing or default states may lead to insecure tokens".to_string(),
                severity: SecuritySeverity::Medium,
                owasp_category: OwaspCategory::InsecureDesign,
                cwe_id: Some("CWE-330".to_string()),
                location: VulnerabilityLocation { file: file.path.clone(), function: None, start_line: 1, end_line: 1, column: 0 },
                code_snippet: "RandomState::new / DefaultHasher::new".to_string(),
                impact: SecurityImpact { confidentiality: ImpactLevel::Medium, integrity: ImpactLevel::Medium, availability: ImpactLevel::Low, overall_score: 5.0 },
                remediation: RemediationGuidance { summary: "Use cryptographically secure RNGs".to_string(), steps: vec!["Use rand::rngs::OsRng or ring".to_string()], code_examples: vec![], references: vec![], effort: RemediationEffort::Low },
                confidence: ConfidenceLevel::Medium,
            });
        }
        Ok(vulns)
    }

    /// Heuristic XSS detection (JS innerHTML sinks)
    fn detect_xss_strings(&self, content: &str, file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulns = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            if line.contains("innerHTML") && (line.contains("=") || line.contains("+=")) {
                vulns.push(SecurityVulnerability {
                    id: format!("STR_XSS_{}", idx + 1),
                    title: "Potential XSS via innerHTML".to_string(),
                    description: "Assigning user-controlled data to innerHTML can lead to XSS".to_string(),
                    severity: SecuritySeverity::High,
                    owasp_category: OwaspCategory::Injection,
                    cwe_id: Some("CWE-79".to_string()),
                    location: VulnerabilityLocation { file: file.path.clone(), function: None, start_line: idx + 1, end_line: idx + 1, column: 0 },
                    code_snippet: line.to_string(),
                    impact: SecurityImpact { confidentiality: ImpactLevel::High, integrity: ImpactLevel::High, availability: ImpactLevel::Low, overall_score: 8.0 },
                    remediation: RemediationGuidance { summary: "Avoid innerHTML or sanitize data".to_string(), steps: vec!["Use textContent or safe templating".to_string()], code_examples: vec![], references: vec![], effort: RemediationEffort::Medium },
                    confidence: ConfidenceLevel::Medium,
                });
            }
        }
        Ok(vulns)
    }

    /// Detect access control issues
    fn detect_access_control_issues(&self, _content: &str, lines: &[&str], file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for missing authorization checks
        for (line_num, line) in lines.iter().enumerate() {
            if line.contains("admin") && !line.contains("auth") && !line.contains("check") {
                vulnerabilities.push(SecurityVulnerability {
                    id: format!("AC001_{}", line_num),
                    title: "Potential missing authorization check".to_string(),
                    description: "Admin functionality detected without apparent authorization check".to_string(),
                    severity: SecuritySeverity::High,
                    owasp_category: OwaspCategory::BrokenAccessControl,
                    cwe_id: Some("CWE-862".to_string()),
                    location: Self::create_vulnerability_location(
                        &file.path,
                        None,
                        line_num + 1,
                        line_num + 1,
                        0,
                    ),
                    code_snippet: line.to_string(),
                    impact: SecurityImpact {
                        confidentiality: ImpactLevel::High,
                        integrity: ImpactLevel::High,
                        availability: ImpactLevel::Medium,
                        overall_score: 8.5,
                    },
                    remediation: RemediationGuidance {
                        summary: "Implement proper authorization checks before admin operations".to_string(),
                        steps: vec![
                            "Add authentication verification".to_string(),
                            "Implement role-based access control".to_string(),
                            "Validate user permissions".to_string(),
                        ],
                        code_examples: vec![
                            CodeExample {
                                description: "Add authorization check".to_string(),
                                vulnerable_code: "admin_operation()".to_string(),
                                secure_code: "if (user.hasRole('admin')) { admin_operation() }".to_string(),
                                language: "generic".to_string(),
                            }
                        ],
                        references: vec![
                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/".to_string(),
                        ],
                        effort: RemediationEffort::Medium,
                    },
                    confidence: ConfidenceLevel::Medium,
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Detect cryptographic failures
    fn detect_cryptographic_failures(&self, _content: &str, lines: &[&str], file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for weak cryptographic algorithms
        for (line_num, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();

            if line_lower.contains("md5") || line_lower.contains("sha1") {
                vulnerabilities.push(SecurityVulnerability {
                    id: format!("CF001_{}", line_num),
                    title: "Weak cryptographic algorithm detected".to_string(),
                    description: "Use of MD5 or SHA1 which are cryptographically weak".to_string(),
                    severity: SecuritySeverity::Medium,
                    owasp_category: OwaspCategory::CryptographicFailures,
                    cwe_id: Some("CWE-327".to_string()),
                    location: Self::create_vulnerability_location(
                        &file.path,
                        None,
                        line_num + 1,
                        line_num + 1,
                        0,
                    ),
                    code_snippet: line.to_string(),
                    impact: SecurityImpact {
                        confidentiality: ImpactLevel::Medium,
                        integrity: ImpactLevel::High,
                        availability: ImpactLevel::Low,
                        overall_score: 6.0,
                    },
                    remediation: RemediationGuidance {
                        summary: "Replace with stronger cryptographic algorithms".to_string(),
                        steps: vec![
                            "Replace MD5/SHA1 with SHA-256 or better".to_string(),
                            "Use bcrypt for password hashing".to_string(),
                            "Consider using authenticated encryption".to_string(),
                        ],
                        code_examples: vec![
                            CodeExample {
                                description: "Replace weak hash with strong one".to_string(),
                                vulnerable_code: "hash = md5(password)".to_string(),
                                secure_code: "hash = bcrypt.hashpw(password, bcrypt.gensalt())".to_string(),
                                language: "python".to_string(),
                            }
                        ],
                        references: vec![
                            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/".to_string(),
                        ],
                        effort: RemediationEffort::Low,
                    },
                    confidence: ConfidenceLevel::High,
                });
            }

            // Check for hardcoded encryption keys
            if line_lower.contains("key") && (line_lower.contains("=") || line_lower.contains(":")) {
                if line.len() > 20 && line.chars().filter(|c| c.is_alphanumeric()).count() > 16 {
                    vulnerabilities.push(SecurityVulnerability {
                        id: format!("CF002_{}", line_num),
                        title: "Potential hardcoded encryption key".to_string(),
                        description: "Encryption key appears to be hardcoded in source code".to_string(),
                        severity: SecuritySeverity::Critical,
                        owasp_category: OwaspCategory::CryptographicFailures,
                        cwe_id: Some("CWE-798".to_string()),
                        location: VulnerabilityLocation {
                            file: file.path.clone(),
                            function: None,
                            start_line: line_num + 1,
                            end_line: line_num + 1,
                            column: 0,
                        },
                        code_snippet: line.to_string(),
                        impact: SecurityImpact {
                            confidentiality: ImpactLevel::Critical,
                            integrity: ImpactLevel::High,
                            availability: ImpactLevel::Medium,
                            overall_score: 9.0,
                        },
                        remediation: RemediationGuidance {
                            summary: "Move encryption keys to secure configuration".to_string(),
                            steps: vec![
                                "Remove hardcoded keys from source code".to_string(),
                                "Use environment variables or secure key management".to_string(),
                                "Implement key rotation policies".to_string(),
                            ],
                            code_examples: vec![
                                CodeExample {
                                    description: "Use environment variable for key".to_string(),
                                    vulnerable_code: "key = 'hardcoded_key_123'".to_string(),
                                    secure_code: "key = os.getenv('ENCRYPTION_KEY')".to_string(),
                                    language: "python".to_string(),
                                }
                            ],
                            references: vec![
                                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/".to_string(),
                            ],
                            effort: RemediationEffort::Medium,
                        },
                        confidence: ConfidenceLevel::Medium,
                    });
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Detect injection issues
    fn detect_injection_issues(&self, _content: &str, lines: &[&str], file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for SQL injection patterns
        for (line_num, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();

            // SQL injection patterns
            if (line_lower.contains("select") || line_lower.contains("insert") ||
                line_lower.contains("update") || line_lower.contains("delete")) &&
               (line.contains("+") || line.contains("format") || line.contains("{}")) {

                vulnerabilities.push(SecurityVulnerability {
                    id: format!("INJ001_{}", line_num),
                    title: "Potential SQL injection vulnerability".to_string(),
                    description: "SQL query appears to use string concatenation which may allow injection".to_string(),
                    severity: SecuritySeverity::High,
                    owasp_category: OwaspCategory::Injection,
                    cwe_id: Some("CWE-89".to_string()),
                    location: Self::create_vulnerability_location(
                        &file.path,
                        None,
                        line_num + 1,
                        line_num + 1,
                        0,
                    ),
                    code_snippet: line.to_string(),
                    impact: SecurityImpact {
                        confidentiality: ImpactLevel::High,
                        integrity: ImpactLevel::High,
                        availability: ImpactLevel::Medium,
                        overall_score: 8.0,
                    },
                    remediation: RemediationGuidance {
                        summary: "Use parameterized queries to prevent SQL injection".to_string(),
                        steps: vec![
                            "Replace string concatenation with parameterized queries".to_string(),
                            "Use prepared statements".to_string(),
                            "Validate and sanitize all user inputs".to_string(),
                        ],
                        code_examples: vec![
                            CodeExample {
                                description: "Use parameterized query".to_string(),
                                vulnerable_code: "query = \"SELECT * FROM users WHERE id = \" + user_id".to_string(),
                                secure_code: "query = \"SELECT * FROM users WHERE id = ?\"; execute(query, [user_id])".to_string(),
                                language: "sql".to_string(),
                            }
                        ],
                        references: vec![
                            "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                        ],
                        effort: RemediationEffort::Medium,
                    },
                    confidence: ConfidenceLevel::Medium,
                });
            }

            // Command injection patterns
            if (line_lower.contains("exec") || line_lower.contains("system") ||
                line_lower.contains("shell") || line_lower.contains("cmd")) &&
               (line.contains("+") || line.contains("format") || line.contains("{}")) {

                vulnerabilities.push(SecurityVulnerability {
                    id: format!("INJ002_{}", line_num),
                    title: "Potential command injection vulnerability".to_string(),
                    description: "Command execution with user input may allow command injection".to_string(),
                    severity: SecuritySeverity::Critical,
                    owasp_category: OwaspCategory::Injection,
                    cwe_id: Some("CWE-78".to_string()),
                    location: VulnerabilityLocation {
                        file: file.path.clone(),
                        function: None,
                        start_line: line_num + 1,
                        end_line: line_num + 1,
                        column: 0,
                    },
                    code_snippet: line.to_string(),
                    impact: SecurityImpact {
                        confidentiality: ImpactLevel::Critical,
                        integrity: ImpactLevel::Critical,
                        availability: ImpactLevel::Critical,
                        overall_score: 9.5,
                    },
                    remediation: RemediationGuidance {
                        summary: "Avoid command execution with user input".to_string(),
                        steps: vec![
                            "Use safe APIs instead of shell commands".to_string(),
                            "Validate and whitelist allowed commands".to_string(),
                            "Escape shell metacharacters".to_string(),
                        ],
                        code_examples: vec![
                            CodeExample {
                                description: "Use safe API instead of shell".to_string(),
                                vulnerable_code: "os.system('ls ' + user_input)".to_string(),
                                secure_code: "subprocess.run(['ls', user_input], check=True)".to_string(),
                                language: "python".to_string(),
                            }
                        ],
                        references: vec![
                            "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                        ],
                        effort: RemediationEffort::High,
                    },
                    confidence: ConfidenceLevel::High,
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Detect insecure design patterns
    fn detect_insecure_design(&self, _content: &str, lines: &[&str], file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for insecure random number generation
        for (line_num, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();

            if line_lower.contains("math.random") || line_lower.contains("rand()") {
                vulnerabilities.push(SecurityVulnerability {
                    id: format!("ID001_{}", line_num),
                    title: "Insecure random number generation".to_string(),
                    description: "Use of weak random number generator for security purposes".to_string(),
                    severity: SecuritySeverity::Medium,
                    owasp_category: OwaspCategory::InsecureDesign,
                    cwe_id: Some("CWE-338".to_string()),
                    location: VulnerabilityLocation {
                        file: file.path.clone(),
                        function: None,
                        start_line: line_num + 1,
                        end_line: line_num + 1,
                        column: 0,
                    },
                    code_snippet: line.to_string(),
                    impact: SecurityImpact {
                        confidentiality: ImpactLevel::Medium,
                        integrity: ImpactLevel::Medium,
                        availability: ImpactLevel::Low,
                        overall_score: 5.5,
                    },
                    remediation: RemediationGuidance {
                        summary: "Use cryptographically secure random number generator".to_string(),
                        steps: vec![
                            "Replace with cryptographically secure PRNG".to_string(),
                            "Use appropriate entropy sources".to_string(),
                        ],
                        code_examples: vec![
                            CodeExample {
                                description: "Use secure random generator".to_string(),
                                vulnerable_code: "token = Math.random()".to_string(),
                                secure_code: "token = crypto.getRandomValues(new Uint8Array(32))".to_string(),
                                language: "javascript".to_string(),
                            }
                        ],
                        references: vec![
                            "https://owasp.org/Top10/A04_2021-Insecure_Design/".to_string(),
                        ],
                        effort: RemediationEffort::Low,
                    },
                    confidence: ConfidenceLevel::High,
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Detect security misconfiguration
    fn detect_security_misconfiguration(&self, _content: &str, lines: &[&str], file: &FileInfo) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Check for debug mode in production
        for (line_num, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();

            if (line_lower.contains("debug") && line_lower.contains("true")) ||
               (line_lower.contains("development") && line_lower.contains("true")) {
                vulnerabilities.push(SecurityVulnerability {
                    id: format!("SM001_{}", line_num),
                    title: "Debug mode enabled".to_string(),
                    description: "Debug mode may be enabled in production environment".to_string(),
                    severity: SecuritySeverity::Medium,
                    owasp_category: OwaspCategory::SecurityMisconfiguration,
                    cwe_id: Some("CWE-489".to_string()),
                    location: VulnerabilityLocation {
                        file: file.path.clone(),
                        function: None,
                        start_line: line_num + 1,
                        end_line: line_num + 1,
                        column: 0,
                    },
                    code_snippet: line.to_string(),
                    impact: SecurityImpact {
                        confidentiality: ImpactLevel::Medium,
                        integrity: ImpactLevel::Low,
                        availability: ImpactLevel::Low,
                        overall_score: 4.0,
                    },
                    remediation: RemediationGuidance {
                        summary: "Disable debug mode in production".to_string(),
                        steps: vec![
                            "Set debug mode to false in production".to_string(),
                            "Use environment-specific configuration".to_string(),
                            "Remove debug information from error messages".to_string(),
                        ],
                        code_examples: vec![
                            CodeExample {
                                description: "Environment-based debug setting".to_string(),
                                vulnerable_code: "debug = true".to_string(),
                                secure_code: "debug = process.env.NODE_ENV !== 'production'".to_string(),
                                language: "javascript".to_string(),
                            }
                        ],
                        references: vec![
                            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string(),
                        ],
                        effort: RemediationEffort::Trivial,
                    },
                    confidence: ConfidenceLevel::Medium,
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Detect secrets in source code
    fn detect_secrets(&self, file: &FileInfo) -> Result<Vec<DetectedSecret>> {
        let mut secrets = Vec::new();
        let content = std::fs::read_to_string(&file.path)?;
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // Check for API keys
            if let Some(secret) = self.detect_api_key(line, line_num, file) {
                secrets.push(secret);
            }

            // Check for passwords
            if let Some(secret) = self.detect_password(line, line_num, file) {
                secrets.push(secret);
            }

            // Check for tokens
            if let Some(secret) = self.detect_token(line, line_num, file) {
                secrets.push(secret);
            }
        }

        Ok(secrets)
    }

    /// Detect API keys
    fn detect_api_key(&self, line: &str, line_num: usize, file: &FileInfo) -> Option<DetectedSecret> {
        let line_lower = line.to_lowercase();

        if (line_lower.contains("api_key") || line_lower.contains("apikey")) &&
           (line.contains("=") || line.contains(":")) {

            // Extract potential key value
            let parts: Vec<&str> = line.split(&['=', ':'][..]).collect();
            if parts.len() >= 2 {
                let value = parts[1].trim().trim_matches(&['"', '\'', ' '][..]);
                if value.len() > 10 && value.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                    return Some(DetectedSecret {
                        secret_type: SecretType::ApiKey,
                        location: VulnerabilityLocation {
                            file: file.path.clone(),
                            function: None,
                            start_line: line_num + 1,
                            end_line: line_num + 1,
                            column: 0,
                        },
                        masked_value: format!("{}***", &value[..value.len().min(4)]),
                        entropy: self.calculate_entropy(value),
                        confidence: ConfidenceLevel::Medium,
                        remediation: "Move API key to environment variables or secure configuration".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Detect passwords
    fn detect_password(&self, line: &str, line_num: usize, file: &FileInfo) -> Option<DetectedSecret> {
        let line_lower = line.to_lowercase();

        if (line_lower.contains("password") || line_lower.contains("passwd")) &&
           (line.contains("=") || line.contains(":")) &&
           !line_lower.contains("input") && !line_lower.contains("field") {

            let parts: Vec<&str> = line.split(&['=', ':'][..]).collect();
            if parts.len() >= 2 {
                let value = parts[1].trim().trim_matches(&['"', '\'', ' '][..]);
                if value.len() > 4 && !value.is_empty() {
                    return Some(DetectedSecret {
                        secret_type: SecretType::Password,
                        location: VulnerabilityLocation {
                            file: file.path.clone(),
                            function: None,
                            start_line: line_num + 1,
                            end_line: line_num + 1,
                            column: 0,
                        },
                        masked_value: "***".to_string(),
                        entropy: self.calculate_entropy(value),
                        confidence: ConfidenceLevel::Medium,
                        remediation: "Remove hardcoded password and use secure authentication".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Detect tokens
    fn detect_token(&self, line: &str, line_num: usize, file: &FileInfo) -> Option<DetectedSecret> {
        let line_lower = line.to_lowercase();

        if (line_lower.contains("token") || line_lower.contains("jwt")) &&
           (line.contains("=") || line.contains(":")) {

            let parts: Vec<&str> = line.split(&['=', ':'][..]).collect();
            if parts.len() >= 2 {
                let value = parts[1].trim().trim_matches(&['"', '\'', ' '][..]);
                if value.len() > 20 {
                    return Some(DetectedSecret {
                        secret_type: SecretType::Token,
                        location: VulnerabilityLocation {
                            file: file.path.clone(),
                            function: None,
                            start_line: line_num + 1,
                            end_line: line_num + 1,
                            column: 0,
                        },
                        masked_value: format!("{}***", &value[..value.len().min(6)]),
                        entropy: self.calculate_entropy(value),
                        confidence: ConfidenceLevel::Medium,
                        remediation: "Move token to secure storage and use proper token management".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Calculate entropy of a string
    pub fn calculate_entropy(&self, s: &str) -> f64 {
        let mut char_counts = HashMap::new();
        for c in s.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for count in char_counts.values() {
            let p = *count as f64 / len;
            entropy -= p * p.log2();
        }

        entropy
    }

    /// Detect input validation issues
    fn detect_input_validation_issues(&self, file: &FileInfo) -> Result<Vec<InputValidationIssue>> {
        let mut issues = Vec::new();
        let content = std::fs::read_to_string(&file.path)?;
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // Check for direct user input usage without validation
            if (line.contains("request.") || line.contains("input") || line.contains("params")) &&
               !line.contains("validate") && !line.contains("sanitize") && !line.contains("escape") {

                issues.push(InputValidationIssue {
                    issue_type: InputValidationType::MissingValidation,
                    location: VulnerabilityLocation {
                        file: file.path.clone(),
                        function: None,
                        start_line: line_num + 1,
                        end_line: line_num + 1,
                        column: 0,
                    },
                    description: "User input used without apparent validation".to_string(),
                    severity: SecuritySeverity::Medium,
                    remediation: "Add input validation and sanitization".to_string(),
                });
            }
        }

        Ok(issues)
    }

    /// Detect injection vulnerabilities
    fn detect_injection_vulnerabilities(&self, file: &FileInfo) -> Result<Vec<InjectionVulnerability>> {
        let mut vulnerabilities = Vec::new();
        let content = std::fs::read_to_string(&file.path)?;
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // XSS vulnerabilities
            if line.contains("innerHTML") || line.contains("document.write") {
                vulnerabilities.push(InjectionVulnerability {
                    injection_type: InjectionType::XssInjection,
                    location: VulnerabilityLocation {
                        file: file.path.clone(),
                        function: None,
                        start_line: line_num + 1,
                        end_line: line_num + 1,
                        column: 0,
                    },
                    pattern: line.to_string(),
                    severity: SecuritySeverity::High,
                    remediation: RemediationGuidance {
                        summary: "Use safe DOM manipulation methods".to_string(),
                        steps: vec![
                            "Replace innerHTML with textContent".to_string(),
                            "Use DOM methods instead of document.write".to_string(),
                            "Sanitize user input before rendering".to_string(),
                        ],
                        code_examples: vec![
                            CodeExample {
                                description: "Safe DOM manipulation".to_string(),
                                vulnerable_code: "element.innerHTML = userInput".to_string(),
                                secure_code: "element.textContent = userInput".to_string(),
                                language: "javascript".to_string(),
                            }
                        ],
                        references: vec![
                            "https://owasp.org/www-community/attacks/xss/".to_string(),
                        ],
                        effort: RemediationEffort::Low,
                    },
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Detect best practice violations
    fn detect_best_practice_violations(&self, file: &FileInfo) -> Result<Vec<BestPracticeViolation>> {
        let mut violations = Vec::new();
        let content = std::fs::read_to_string(&file.path)?;
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // Check for console.log in production code
            if line.contains("console.log") || line.contains("print(") {
                violations.push(BestPracticeViolation {
                    category: BestPracticeCategory::Logging,
                    description: "Debug logging statements in production code".to_string(),
                    location: VulnerabilityLocation {
                        file: file.path.clone(),
                        function: None,
                        start_line: line_num + 1,
                        end_line: line_num + 1,
                        column: 0,
                    },
                    severity: SecuritySeverity::Low,
                    recommendation: "Remove debug statements or use proper logging framework".to_string(),
                });
            }

            // Check for TODO/FIXME comments
            if line.to_lowercase().contains("todo") || line.to_lowercase().contains("fixme") {
                violations.push(BestPracticeViolation {
                    category: BestPracticeCategory::Configuration,
                    description: "Unresolved TODO/FIXME comment".to_string(),
                    location: VulnerabilityLocation {
                        file: file.path.clone(),
                        function: None,
                        start_line: line_num + 1,
                        end_line: line_num + 1,
                        column: 0,
                    },
                    severity: SecuritySeverity::Info,
                    recommendation: "Resolve pending issues before production deployment".to_string(),
                });
            }
        }

        Ok(violations)
    }

    /// Categorize vulnerabilities by severity
    fn categorize_by_severity(&self, vulnerabilities: &[SecurityVulnerability]) -> HashMap<SecuritySeverity, usize> {
        let mut counts = HashMap::new();
        for vuln in vulnerabilities {
            *counts.entry(vuln.severity.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Categorize vulnerabilities by OWASP category
    fn categorize_by_owasp(&self, vulnerabilities: &[SecurityVulnerability]) -> HashMap<OwaspCategory, usize> {
        let mut counts = HashMap::new();
        for vuln in vulnerabilities {
            *counts.entry(vuln.owasp_category.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Generate security recommendations
    fn generate_security_recommendations(
        &self,
        vulnerabilities: &[SecurityVulnerability],
        secrets: &[DetectedSecret],
        _input_issues: &[InputValidationIssue],
        _injection_vulns: &[InjectionVulnerability],
        _best_practices: &[BestPracticeViolation],
    ) -> Result<Vec<SecurityRecommendation>> {
        let mut recommendations = Vec::new();

        // Critical vulnerabilities
        let critical_count = vulnerabilities.iter()
            .filter(|v| v.severity == SecuritySeverity::Critical)
            .count();

        if critical_count > 0 {
            recommendations.push(SecurityRecommendation {
                category: "Critical Security Issues".to_string(),
                recommendation: format!("Address {} critical security vulnerabilities immediately", critical_count),
                priority: RecommendationPriority::Critical,
                affected_files: vulnerabilities.iter()
                    .filter(|v| v.severity == SecuritySeverity::Critical)
                    .map(|v| v.location.file.clone())
                    .collect(),
                implementation: vec![
                    "Review and fix critical vulnerabilities".to_string(),
                    "Implement security testing in CI/CD".to_string(),
                    "Conduct security code review".to_string(),
                ],
                security_improvement: 40.0,
            });
        }

        // Secrets management
        if !secrets.is_empty() {
            recommendations.push(SecurityRecommendation {
                category: "Secrets Management".to_string(),
                recommendation: format!("Remove {} hardcoded secrets from source code", secrets.len()),
                priority: RecommendationPriority::High,
                affected_files: secrets.iter().map(|s| s.location.file.clone()).collect(),
                implementation: vec![
                    "Move secrets to environment variables".to_string(),
                    "Use secure secret management service".to_string(),
                    "Implement secret rotation policies".to_string(),
                ],
                security_improvement: 30.0,
            });
        }

        // General security improvements
        recommendations.push(SecurityRecommendation {
            category: "Security Best Practices".to_string(),
            recommendation: "Implement comprehensive security testing and monitoring".to_string(),
            priority: RecommendationPriority::Medium,
            affected_files: Vec::new(),
            implementation: vec![
                "Add automated security scanning to CI/CD".to_string(),
                "Implement security logging and monitoring".to_string(),
                "Conduct regular security assessments".to_string(),
            ],
            security_improvement: 20.0,
        });

        Ok(recommendations)
    }

    /// Assess compliance with security standards
    fn assess_compliance(
        &self,
        vulnerabilities: &[SecurityVulnerability],
        owasp_categories: &HashMap<OwaspCategory, usize>,
    ) -> Result<ComplianceAssessment> {
        // Calculate OWASP Top 10 compliance score
        let total_owasp_issues: usize = owasp_categories.values().sum();
        let owasp_score = if total_owasp_issues == 0 {
            100
        } else {
            (100 - (total_owasp_issues * 10).min(100)) as u8
        };

        // CWE coverage assessment
        let mut cwe_coverage = HashMap::new();
        for vuln in vulnerabilities {
            if let Some(cwe) = &vuln.cwe_id {
                cwe_coverage.insert(cwe.clone(), true);
            }
        }

        // Standards compliance
        let mut standards_compliance = HashMap::new();
        standards_compliance.insert("OWASP Top 10".to_string(),
            if owasp_score >= 80 { ComplianceStatus::Compliant }
            else if owasp_score >= 60 { ComplianceStatus::PartiallyCompliant }
            else { ComplianceStatus::NonCompliant }
        );

        let overall_status = if owasp_score >= 80 {
            ComplianceStatus::Compliant
        } else if owasp_score >= 60 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::NonCompliant
        };

        Ok(ComplianceAssessment {
            owasp_score,
            cwe_coverage,
            standards_compliance,
            overall_status,
        })
    }

    /// Calculate overall security score
    fn calculate_security_score(
        &self,
        _total_vulnerabilities: usize,
        severity_counts: &HashMap<SecuritySeverity, usize>,
        compliance: &ComplianceAssessment,
    ) -> u8 {
        let mut score = 100.0;

        // Deduct points for vulnerabilities by severity
        if let Some(critical) = severity_counts.get(&SecuritySeverity::Critical) {
            score -= *critical as f64 * 25.0;
        }
        if let Some(high) = severity_counts.get(&SecuritySeverity::High) {
            score -= *high as f64 * 15.0;
        }
        if let Some(medium) = severity_counts.get(&SecuritySeverity::Medium) {
            score -= *medium as f64 * 8.0;
        }
        if let Some(low) = severity_counts.get(&SecuritySeverity::Low) {
            score -= *low as f64 * 3.0;
        }

        // Factor in compliance score
        score = score * (compliance.owasp_score as f64 / 100.0);

        score.max(0.0).min(100.0) as u8
    }
    /// Build security context from AST
    fn build_security_context(&self, tree: &SyntaxTree, file: &FileInfo) -> SecurityContext {
        let root = tree.root_node();
        let mut context = SecurityContext {
            function_name: None,
            is_test_file: file.path.to_string_lossy().contains("test"),
            is_comment: false,
            variable_assignments: HashMap::new(),
            function_calls: Vec::new(),
            has_user_input: false, // Will be set during AST traversal
            is_web_context: file.path.to_string_lossy().contains("web") ||
                           file.path.to_string_lossy().contains("http") ||
                           file.path.to_string_lossy().contains("api"),
        };

        // Walk the tree to build context
        self.walk_node_for_context(&root, &mut context);
        context
    }

    /// Walk AST node to build security context
    fn walk_node_for_context(&self, node: &Node, context: &mut SecurityContext) {
        match node.kind() {
            "function_item" | "function_declaration" | "method_definition" => {
                // Extract function name if available
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.text() {
                        context.function_name = Some(name.to_string());
                    }
                }
            }
            "assignment_expression" | "variable_declaration" => {
                // Track variable assignments for taint analysis
                if let Some(value_node) = node.child_by_field_name("value") {
                    if let Ok(value_text) = value_node.text() {
                        if let Some(var_node) = node.child_by_field_name("left") {
                            if let Ok(var_name) = var_node.text() {
                                context.variable_assignments.insert(var_name.to_string(), value_text.to_string());
                            }
                        }
                    }
                }
            }
            "call_expression" => {
                // Track function calls and detect user input sources
                if let Some(function_node) = node.child_by_field_name("function") {
                    if let Ok(function_name) = function_node.text() {
                        context.function_calls.push(function_name.to_string());

                        // Check if this is a user input function
                        if self.is_user_input_function(&function_name.to_lowercase()) {
                            context.has_user_input = true;
                        }
                    }
                }
            }
            "comment" => {
                context.is_comment = true;
            }
            _ => {}
        }

        // Recursively process children
        for child in node.children() {
            self.walk_node_for_context(&child, context);
        }
    }

    /// Check if function name indicates user input source
    fn is_user_input_function(&self, function_name: &str) -> bool {
        let user_input_functions = [
            // Web/HTTP input
            "request", "req", "input", "param", "query", "body", "form", "post", "get",
            "header", "cookie", "session", "url", "uri", "path",
            // Console/CLI input
            "stdin", "readline", "read_line", "input", "prompt", "getline", "scanf", "cin",
            "gets", "fgets", "getchar", "getch",
            // File input
            "read", "readfile", "load", "open", "file", "upload",
            // Network input
            "recv", "receive", "socket", "connect", "accept", "listen",
            // Environment input
            "env", "getenv", "environ", "argv", "args", "cmdline",
            // Database input (from external sources)
            "fetch", "select", "find", "search", "lookup",
            // API/External service input
            "api", "service", "external", "remote", "http", "https", "curl", "wget",
        ];

        user_input_functions.iter().any(|&input_func| function_name.contains(input_func))
    }

    /// Detect SQL injection using AST analysis
    fn detect_sql_injection_ast(&self, tree: &SyntaxTree, content: &str, file: &FileInfo, context: &SecurityContext) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();
        let root = tree.root_node();

        self.analyze_node_for_sql_injection(&root, content, file, context, &mut vulnerabilities)?;

        // Filter out false positives using AST context
        vulnerabilities = self.filter_sql_injection_false_positives(vulnerabilities, tree, content, context)?;

        Ok(vulnerabilities)
    }

    /// Filter SQL injection false positives using AST context
    fn filter_sql_injection_false_positives(&self, vulnerabilities: Vec<SecurityVulnerability>, _tree: &SyntaxTree, _content: &str, context: &SecurityContext) -> Result<Vec<SecurityVulnerability>> {
        let mut filtered = Vec::new();

        for vuln in vulnerabilities {
            let mut is_false_positive = false;

            // Check if it's in a test file
            if context.is_test_file {
                is_false_positive = true;
            }

            // Check if it's in a comment
            if context.is_comment {
                is_false_positive = true;
            }

            // Check if the SQL string is parameterized (using placeholders)
            if self.is_parameterized_query(&vuln.code_snippet) {
                is_false_positive = true;
            }

            // Check if it's a static query without user input
            if !context.has_user_input && self.is_static_query(&vuln.code_snippet) {
                is_false_positive = true;
            }

            // Check if it's using an ORM or query builder
            if self.is_using_orm_or_query_builder(&vuln.code_snippet) {
                is_false_positive = true;
            }

            if !is_false_positive {
                filtered.push(vuln);
            }
        }

        Ok(filtered)
    }

    /// Check if query uses parameterized statements
    fn is_parameterized_query(&self, code: &str) -> bool {
        // Look for common parameterized query patterns
        code.contains("?") || // JDBC style
        code.contains("$1") || code.contains("$2") || // PostgreSQL style
        code.contains(":param") || // Named parameters
        code.contains("@param") || // SQL Server style
        code.contains("%(") // Python style
    }

    /// Check if query is static (no concatenation or interpolation)
    fn is_static_query(&self, code: &str) -> bool {
        // Look for signs of dynamic query construction
        !(code.contains("+") || // String concatenation
          code.contains("format!") || // Rust formatting
          code.contains("sprintf") || // C style formatting
          code.contains("f\"") || // Python f-strings
          code.contains("${") || // Template literals
          code.contains("concat"))
    }

    /// Check if code is using ORM or query builder
    fn is_using_orm_or_query_builder(&self, code: &str) -> bool {
        let orm_patterns = [
            "sqlx::", "diesel::", "sea_orm::", // Rust ORMs
            "ActiveRecord", "Eloquent", // Ruby/PHP ORMs
            "SQLAlchemy", "Django.orm", // Python ORMs
            "Sequelize", "TypeORM", "Prisma", // JavaScript ORMs
            "Hibernate", "JPA", "MyBatis", // Java ORMs
        ];

        orm_patterns.iter().any(|pattern| code.contains(pattern))
    }

    /// Analyze node for SQL injection patterns
    fn analyze_node_for_sql_injection(&self, node: &Node, content: &str, file: &FileInfo, context: &SecurityContext, vulnerabilities: &mut Vec<SecurityVulnerability>) -> Result<()> {
        // Look for call expressions that might be database operations
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                if let Ok(function_name) = function_node.text() {
                    let function_name_lower = function_name.to_lowercase();

                    // Check if this is a database function
                    if self.is_database_function(&function_name_lower) {
                        // Analyze arguments for potential injection
                        if let Some(args_node) = node.child_by_field_name("arguments") {
                            if self.has_string_concatenation_in_args(&args_node, content) {
                                // Only flag if we're confident this is a real SQL operation
                                let confidence = self.calculate_sql_injection_confidence(node, content, context);

                                if confidence >= ConfidenceLevel::Medium {
                                    vulnerabilities.push(SecurityVulnerability {
                                        id: format!("AST_SQL_{}", node.start_position().row),
                                        title: "SQL injection vulnerability detected".to_string(),
                                        description: "Database operation uses string concatenation which may allow SQL injection".to_string(),
                                        severity: SecuritySeverity::High,
                                        owasp_category: OwaspCategory::Injection,
                                        cwe_id: Some("CWE-89".to_string()),
                                        location: VulnerabilityLocation {
                                            file: file.path.clone(),
                                            function: context.function_name.clone(),
                                            start_line: node.start_position().row + 1,
                                            end_line: node.end_position().row + 1,
                                            column: node.start_position().column,
                                        },
                                        code_snippet: node.text().unwrap_or("").to_string(),
                                        impact: SecurityImpact {
                                            confidentiality: ImpactLevel::High,
                                            integrity: ImpactLevel::High,
                                            availability: ImpactLevel::Medium,
                                            overall_score: 8.0,
                                        },
                                        remediation: RemediationGuidance {
                                            summary: "Use parameterized queries to prevent SQL injection".to_string(),
                                            steps: vec![
                                                "Replace string concatenation with parameterized queries".to_string(),
                                                "Use prepared statements".to_string(),
                                                "Validate and sanitize all user inputs".to_string(),
                                            ],
                                            code_examples: vec![
                                                CodeExample {
                                                    description: "Use parameterized query".to_string(),
                                                    vulnerable_code: "query = \"SELECT * FROM users WHERE id = \" + user_id".to_string(),
                                                    secure_code: "query = \"SELECT * FROM users WHERE id = ?\"; execute(query, [user_id])".to_string(),
                                                    language: "sql".to_string(),
                                                }
                                            ],
                                            references: vec![
                                                "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                                            ],
                                            effort: RemediationEffort::Medium,
                                        },
                                        confidence,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Recursively analyze children
        for child in node.children() {
            self.analyze_node_for_sql_injection(&child, content, file, context, vulnerabilities)?;
        }

        Ok(())
    }

    /// Check if function name indicates database operation
    fn is_database_function(&self, function_name: &str) -> bool {
        let db_functions = [
            "query", "execute", "exec", "prepare", "select", "insert", "update", "delete",
            "find", "findone", "findall", "save", "create", "destroy", "remove",
            "sql", "raw", "rawquery", "executesql", "runsql"
        ];

        db_functions.iter().any(|&db_func| function_name.contains(db_func))
    }

    /// Check if arguments contain string concatenation
    fn has_string_concatenation_in_args(&self, args_node: &Node, _content: &str) -> bool {
        // Look for binary expressions with + operator or string interpolation
        for child in args_node.children() {
            if child.kind() == "binary_expression" {
                if let Some(operator_node) = child.child_by_field_name("operator") {
                    if let Ok(operator) = operator_node.text() {
                        if operator == "+" {
                            return true;
                        }
                    }
                }
            }
            // Check for template literals or string interpolation
            if child.kind() == "template_string" || child.kind() == "formatted_string" {
                return true;
            }
        }
        false
    }

    /// Calculate confidence level for SQL injection detection
    fn calculate_sql_injection_confidence(&self, node: &Node, _content: &str, context: &SecurityContext) -> ConfidenceLevel {
        let mut confidence_score = 0;

        // Higher confidence if in a non-test file
        if !context.is_test_file {
            confidence_score += 2;
        }

        // Higher confidence if function name clearly indicates database operation
        if let Some(function_node) = node.child_by_field_name("function") {
            if let Ok(function_name) = function_node.text() {
                let function_name_lower = function_name.to_lowercase();
                if function_name_lower.contains("sql") || function_name_lower.contains("query") {
                    confidence_score += 3;
                }
            }
        }

        // Lower confidence if in comments or documentation
        if context.is_comment {
            confidence_score -= 2;
        }

        match confidence_score {
            5.. => ConfidenceLevel::High,
            3..=4 => ConfidenceLevel::Medium,
            _ => ConfidenceLevel::Low,
        }
    }

    /// Detect command injection using AST analysis
    fn detect_command_injection_ast(&self, tree: &SyntaxTree, content: &str, file: &FileInfo, context: &SecurityContext) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();
        let root = tree.root_node();

        self.analyze_node_for_command_injection(&root, content, file, context, &mut vulnerabilities)?;

        // Filter out false positives using AST context
        vulnerabilities = self.filter_command_injection_false_positives(vulnerabilities, tree, content, context)?;

        Ok(vulnerabilities)
    }

    /// Filter command injection false positives using AST context
    fn filter_command_injection_false_positives(&self, vulnerabilities: Vec<SecurityVulnerability>, _tree: &SyntaxTree, _content: &str, context: &SecurityContext) -> Result<Vec<SecurityVulnerability>> {
        let mut filtered = Vec::new();

        for vuln in vulnerabilities {
            let mut is_false_positive = false;

            // Check if it's in a test file
            if context.is_test_file {
                is_false_positive = true;
            }

            // Check if it's in a comment
            if context.is_comment {
                is_false_positive = true;
            }

            // Check if command is hardcoded (no user input)
            if !context.has_user_input && self.is_hardcoded_command(&vuln.code_snippet) {
                is_false_positive = true;
            }

            // Check if using safe command execution patterns
            if self.is_using_safe_command_execution(&vuln.code_snippet) {
                is_false_positive = true;
            }

            // Check if it's a build script or development tool
            if self.is_build_or_dev_script(&vuln.location.file.to_string_lossy()) {
                is_false_positive = true;
            }

            if !is_false_positive {
                filtered.push(vuln);
            }
        }

        Ok(filtered)
    }

    /// Check if command is hardcoded without user input
    fn is_hardcoded_command(&self, code: &str) -> bool {
        // Look for static command strings
        let has_quotes = code.contains("\"") || code.contains("'");
        let has_concatenation = code.contains("+") || code.contains("format!") || code.contains("&");

        has_quotes && !has_concatenation
    }

    /// Check if using safe command execution patterns
    fn is_using_safe_command_execution(&self, code: &str) -> bool {
        // Look for safe execution patterns
        code.contains("Command::new") || // Rust std::process::Command
        code.contains("execve") || // Direct syscall
        code.contains("spawn") || // Controlled spawning
        code.contains("ProcessBuilder") // Build tools
    }

    /// Check if file is a build script or development tool
    fn is_build_or_dev_script(&self, file_path: &str) -> bool {
        let build_patterns = [
            "build.rs", "Makefile", "CMakeLists.txt",
            "package.json", "Cargo.toml", "setup.py",
            "gulpfile", "webpack.config", "rollup.config"
        ];

        build_patterns.iter().any(|pattern| file_path.contains(pattern)) ||
        file_path.contains("/scripts/") ||
        file_path.contains("/build/") ||
        file_path.contains("/tools/")
    }

    /// Analyze node for command injection patterns
    fn analyze_node_for_command_injection(&self, node: &Node, content: &str, file: &FileInfo, context: &SecurityContext, vulnerabilities: &mut Vec<SecurityVulnerability>) -> Result<()> {
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                if let Ok(function_name) = function_node.text() {
                    let function_name_lower = function_name.to_lowercase();

                    // Check if this is a command execution function
                    if self.is_command_execution_function(&function_name_lower) {
                        if let Some(args_node) = node.child_by_field_name("arguments") {
                            if self.has_string_concatenation_in_args(&args_node, content) {
                                let confidence = self.calculate_command_injection_confidence(node, content, context);

                                if confidence >= ConfidenceLevel::Medium {
                                    vulnerabilities.push(SecurityVulnerability {
                                        id: format!("AST_CMD_{}", node.start_position().row),
                                        title: "Command injection vulnerability detected".to_string(),
                                        description: "Command execution with user input may allow command injection".to_string(),
                                        severity: SecuritySeverity::Critical,
                                        owasp_category: OwaspCategory::Injection,
                                        cwe_id: Some("CWE-78".to_string()),
                                        location: VulnerabilityLocation {
                                            file: file.path.clone(),
                                            function: context.function_name.clone(),
                                            start_line: node.start_position().row + 1,
                                            end_line: node.end_position().row + 1,
                                            column: node.start_position().column,
                                        },
                                        code_snippet: node.text().unwrap_or("").to_string(),
                                        impact: SecurityImpact {
                                            confidentiality: ImpactLevel::Critical,
                                            integrity: ImpactLevel::Critical,
                                            availability: ImpactLevel::Critical,
                                            overall_score: 9.5,
                                        },
                                        remediation: RemediationGuidance {
                                            summary: "Avoid command execution with user input".to_string(),
                                            steps: vec![
                                                "Use safe APIs instead of shell commands".to_string(),
                                                "Validate and whitelist allowed commands".to_string(),
                                                "Escape shell metacharacters".to_string(),
                                            ],
                                            code_examples: vec![
                                                CodeExample {
                                                    description: "Use safe API instead of shell".to_string(),
                                                    vulnerable_code: "os.system('ls ' + user_input)".to_string(),
                                                    secure_code: "subprocess.run(['ls', user_input], check=True)".to_string(),
                                                    language: "python".to_string(),
                                                }
                                            ],
                                            references: vec![
                                                "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                                            ],
                                            effort: RemediationEffort::High,
                                        },
                                        confidence,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Recursively analyze children
        for child in node.children() {
            self.analyze_node_for_command_injection(&child, content, file, context, vulnerabilities)?;
        }

        Ok(())
    }

    /// Check if function name indicates command execution
    fn is_command_execution_function(&self, function_name: &str) -> bool {
        let cmd_functions = [
            "exec", "system", "shell", "cmd", "spawn", "popen", "run", "call",
            "execute", "eval", "subprocess", "process", "command"
        ];

        cmd_functions.iter().any(|&cmd_func| function_name.contains(cmd_func))
    }

    /// Calculate confidence level for command injection detection
    fn calculate_command_injection_confidence(&self, node: &Node, _content: &str, context: &SecurityContext) -> ConfidenceLevel {
        let mut confidence_score = 0;

        // Higher confidence if in a non-test file
        if !context.is_test_file {
            confidence_score += 2;
        }

        // Higher confidence if function name clearly indicates command execution
        if let Some(function_node) = node.child_by_field_name("function") {
            if let Ok(function_name) = function_node.text() {
                let function_name_lower = function_name.to_lowercase();
                if function_name_lower.contains("exec") || function_name_lower.contains("system") {
                    confidence_score += 3;
                }
            }
        }

        // Lower confidence if in comments
        if context.is_comment {
            confidence_score -= 2;
        }

        match confidence_score {
            5.. => ConfidenceLevel::High,
            3..=4 => ConfidenceLevel::Medium,
            _ => ConfidenceLevel::Low,
        }
    }

    /// Detect hardcoded secrets using AST analysis
    fn detect_hardcoded_secrets_ast(&self, tree: &SyntaxTree, content: &str, file: &FileInfo, context: &SecurityContext) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();
        let root = tree.root_node();

        self.analyze_node_for_hardcoded_secrets(&root, content, file, context, &mut vulnerabilities)?;

        // Filter out false positives using AST context
        vulnerabilities = self.filter_secrets_false_positives(vulnerabilities, tree, content, context)?;

        Ok(vulnerabilities)
    }

    /// Filter secrets false positives using AST context
    fn filter_secrets_false_positives(&self, vulnerabilities: Vec<SecurityVulnerability>, _tree: &SyntaxTree, _content: &str, context: &SecurityContext) -> Result<Vec<SecurityVulnerability>> {
        let mut filtered = Vec::new();

        for vuln in vulnerabilities {
            let mut is_false_positive = false;

            // Check if it's in a test file
            if context.is_test_file {
                is_false_positive = true;
            }

            // Check if it's in a comment or documentation
            if context.is_comment {
                is_false_positive = true;
            }

            // Check if it's a placeholder or example value
            if self.is_placeholder_secret(&vuln.code_snippet) {
                is_false_positive = true;
            }

            // Check if it's a configuration template
            if self.is_config_template(&vuln.code_snippet) {
                is_false_positive = true;
            }

            // Check if it's a public key or certificate
            if self.is_public_key_or_cert(&vuln.code_snippet) {
                is_false_positive = true;
            }

            // Check if entropy is too low (likely not a real secret)
            if self.calculate_entropy(&vuln.code_snippet) < 3.0 {
                is_false_positive = true;
            }

            if !is_false_positive {
                filtered.push(vuln);
            }
        }

        Ok(filtered)
    }

    /// Check if secret is a placeholder or example
    fn is_placeholder_secret(&self, secret: &str) -> bool {
        let placeholder_patterns = [
            "example", "placeholder", "dummy", "test", "fake",
            "your_", "my_", "insert_", "replace_", "change_",
            "xxx", "yyy", "zzz", "123", "abc",
            "password", "secret", "key", "token"
        ];

        let secret_lower = secret.to_lowercase();
        placeholder_patterns.iter().any(|pattern| secret_lower.contains(pattern))
    }

    /// Check if it's a configuration template
    fn is_config_template(&self, secret: &str) -> bool {
        secret.contains("${") || // Environment variable template
        secret.contains("{{") || // Handlebars/Mustache template
        secret.contains("%{") || // ERB template
        secret.contains("<") && secret.contains(">") // XML-style template
    }

    /// Check if it's a public key or certificate
    fn is_public_key_or_cert(&self, secret: &str) -> bool {
        secret.contains("-----BEGIN PUBLIC KEY-----") ||
        secret.contains("-----BEGIN CERTIFICATE-----") ||
        secret.contains("-----BEGIN RSA PUBLIC KEY-----") ||
        secret.contains("ssh-rsa") ||
        secret.contains("ssh-ed25519")
    }



    /// Analyze node for hardcoded secrets
    fn analyze_node_for_hardcoded_secrets(&self, node: &Node, content: &str, file: &FileInfo, context: &SecurityContext, vulnerabilities: &mut Vec<SecurityVulnerability>) -> Result<()> {
        // Look for string literals that might contain secrets
        if node.kind() == "string_literal" || node.kind() == "string" {
            if let Ok(string_value) = node.text() {
                if self.looks_like_secret(string_value) && !context.is_test_file {
                    let confidence = self.calculate_secret_confidence(string_value, context);

                    if confidence >= ConfidenceLevel::Medium {
                        vulnerabilities.push(SecurityVulnerability {
                            id: format!("AST_SECRET_{}", node.start_position().row),
                            title: "Hardcoded secret detected".to_string(),
                            description: "Potential secret or credential hardcoded in source code".to_string(),
                            severity: SecuritySeverity::Critical,
                            owasp_category: OwaspCategory::CryptographicFailures,
                            cwe_id: Some("CWE-798".to_string()),
                            location: VulnerabilityLocation {
                                file: file.path.clone(),
                                function: context.function_name.clone(),
                                start_line: node.start_position().row + 1,
                                end_line: node.end_position().row + 1,
                                column: node.start_position().column,
                            },
                            code_snippet: string_value.to_string(),
                            impact: SecurityImpact {
                                confidentiality: ImpactLevel::Critical,
                                integrity: ImpactLevel::High,
                                availability: ImpactLevel::Medium,
                                overall_score: 9.0,
                            },
                            remediation: RemediationGuidance {
                                summary: "Move secrets to secure configuration".to_string(),
                                steps: vec![
                                    "Remove hardcoded secrets from source code".to_string(),
                                    "Use environment variables or secure key management".to_string(),
                                    "Implement secret rotation policies".to_string(),
                                ],
                                code_examples: vec![
                                    CodeExample {
                                        description: "Use environment variable for secret".to_string(),
                                        vulnerable_code: "api_key = 'hardcoded_key_123'".to_string(),
                                        secure_code: "api_key = os.getenv('API_KEY')".to_string(),
                                        language: "python".to_string(),
                                    }
                                ],
                                references: vec![
                                    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/".to_string(),
                                ],
                                effort: RemediationEffort::Medium,
                            },
                            confidence,
                        });
                    }
                }
            }
        }

        // Recursively analyze children
        for child in node.children() {
            self.analyze_node_for_hardcoded_secrets(&child, content, file, context, vulnerabilities)?;
        }

        Ok(())
    }

    /// Check if string looks like a secret
    fn looks_like_secret(&self, value: &str) -> bool {
        // Remove quotes
        let clean_value = value.trim_matches('"').trim_matches('\'');

        // Skip very short strings
        if clean_value.len() < 8 {
            return false;
        }

        // Check for high entropy (likely random string)
        let entropy = self.calculate_entropy(clean_value);
        if entropy > 4.5 {
            return true;
        }

        // Check for common secret patterns
        let secret_patterns = [
            "key", "secret", "token", "password", "pass", "pwd", "api", "auth"
        ];

        secret_patterns.iter().any(|&pattern| clean_value.to_lowercase().contains(pattern))
    }



    /// Calculate confidence level for secret detection
    fn calculate_secret_confidence(&self, value: &str, context: &SecurityContext) -> ConfidenceLevel {
        let mut confidence_score = 0;

        // Higher confidence for high entropy strings
        let entropy = self.calculate_entropy(value);
        if entropy > 5.0 {
            confidence_score += 3;
        } else if entropy > 4.0 {
            confidence_score += 2;
        }

        // Higher confidence if not in test file
        if !context.is_test_file {
            confidence_score += 2;
        }

        // Lower confidence for common test values
        let test_values = ["test", "example", "demo", "sample", "placeholder"];
        if test_values.iter().any(|&test_val| value.to_lowercase().contains(test_val)) {
            confidence_score -= 3;
        }

        match confidence_score {
            5.. => ConfidenceLevel::High,
            3..=4 => ConfidenceLevel::Medium,
            _ => ConfidenceLevel::Low,
        }
    }

    /// Detect weak cryptography using AST analysis
    fn detect_weak_crypto_ast(&self, tree: &SyntaxTree, content: &str, file: &FileInfo, context: &SecurityContext) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();
        let root = tree.root_node();

        self.analyze_node_for_weak_crypto(&root, content, file, context, &mut vulnerabilities)?;
        Ok(vulnerabilities)
    }

    /// Analyze node for weak cryptography
    fn analyze_node_for_weak_crypto(&self, node: &Node, content: &str, file: &FileInfo, context: &SecurityContext, vulnerabilities: &mut Vec<SecurityVulnerability>) -> Result<()> {
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                if let Ok(function_name) = function_node.text() {
                    let function_name_lower = function_name.to_lowercase();

                    // Check for weak hash functions
                    if function_name_lower.contains("md5") || function_name_lower.contains("sha1") {
                        vulnerabilities.push(SecurityVulnerability {
                            id: format!("AST_CRYPTO_{}", node.start_position().row),
                            title: "Weak cryptographic algorithm detected".to_string(),
                            description: "Use of MD5 or SHA1 which are cryptographically weak".to_string(),
                            severity: SecuritySeverity::Medium,
                            owasp_category: OwaspCategory::CryptographicFailures,
                            cwe_id: Some("CWE-327".to_string()),
                            location: VulnerabilityLocation {
                                file: file.path.clone(),
                                function: context.function_name.clone(),
                                start_line: node.start_position().row + 1,
                                end_line: node.end_position().row + 1,
                                column: node.start_position().column,
                            },
                            code_snippet: node.text().unwrap_or("").to_string(),
                            impact: SecurityImpact {
                                confidentiality: ImpactLevel::Medium,
                                integrity: ImpactLevel::High,
                                availability: ImpactLevel::Low,
                                overall_score: 6.0,
                            },
                            remediation: RemediationGuidance {
                                summary: "Replace with stronger cryptographic algorithms".to_string(),
                                steps: vec![
                                    "Replace MD5/SHA1 with SHA-256 or better".to_string(),
                                    "Use bcrypt for password hashing".to_string(),
                                    "Consider using authenticated encryption".to_string(),
                                ],
                                code_examples: vec![
                                    CodeExample {
                                        description: "Replace weak hash with strong one".to_string(),
                                        vulnerable_code: "hash = md5(password)".to_string(),
                                        secure_code: "hash = bcrypt.hashpw(password, bcrypt.gensalt())".to_string(),
                                        language: "python".to_string(),
                                    }
                                ],
                                references: vec![
                                    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/".to_string(),
                                ],
                                effort: RemediationEffort::Low,
                            },
                            confidence: ConfidenceLevel::High,
                        });
                    }
                }
            }
        }

        // Recursively analyze children
        for child in node.children() {
            self.analyze_node_for_weak_crypto(&child, content, file, context, vulnerabilities)?;
        }

        Ok(())
    }

    /// Detect access control issues using AST analysis
    fn detect_access_control_ast(&self, tree: &SyntaxTree, content: &str, file: &FileInfo, context: &SecurityContext) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();
        let root = tree.root_node();

        self.analyze_node_for_access_control(&root, content, file, context, &mut vulnerabilities)?;
        Ok(vulnerabilities)
    }

    /// Analyze node for access control issues
    fn analyze_node_for_access_control(&self, node: &Node, content: &str, file: &FileInfo, context: &SecurityContext, vulnerabilities: &mut Vec<SecurityVulnerability>) -> Result<()> {
        // Look for function definitions that might be admin functions
        if node.kind() == "function_definition" || node.kind() == "function_declaration" || node.kind() == "method_definition" {
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(function_name) = name_node.text() {
                    let function_name_lower = function_name.to_lowercase();

                    // Check if this looks like an admin function
                    if self.is_admin_function(&function_name_lower) {
                        // Check if there are authorization checks in the function body
                        if let Some(body_node) = node.child_by_field_name("body") {
                            if !self.has_authorization_checks_in_body(&body_node, content) {
                                vulnerabilities.push(SecurityVulnerability {
                                    id: format!("AST_AC_{}", node.start_position().row),
                                    title: "Missing authorization check in admin function".to_string(),
                                    description: format!("Function '{}' appears to be an admin function but lacks authorization checks", function_name),
                                    severity: SecuritySeverity::High,
                                    owasp_category: OwaspCategory::BrokenAccessControl,
                                    cwe_id: Some("CWE-862".to_string()),
                                    location: VulnerabilityLocation {
                                        file: file.path.clone(),
                                        function: Some(function_name.to_string()),
                                        start_line: node.start_position().row + 1,
                                        end_line: node.end_position().row + 1,
                                        column: node.start_position().column,
                                    },
                                    code_snippet: node.text().unwrap_or("").lines().take(3).collect::<Vec<_>>().join("\n"),
                                    impact: SecurityImpact {
                                        confidentiality: ImpactLevel::High,
                                        integrity: ImpactLevel::High,
                                        availability: ImpactLevel::Medium,
                                        overall_score: 8.0,
                                    },
                                    remediation: RemediationGuidance {
                                        summary: "Add proper authorization checks before admin operations".to_string(),
                                        steps: vec![
                                            "Add authentication verification at function start".to_string(),
                                            "Implement role-based access control".to_string(),
                                            "Validate user permissions for admin operations".to_string(),
                                        ],
                                        code_examples: vec![
                                            CodeExample {
                                                description: "Add authorization check".to_string(),
                                                vulnerable_code: format!("def {}():\n    # admin operation", function_name),
                                                secure_code: format!("def {}():\n    if not user.has_role('admin'):\n        raise Unauthorized()\n    # admin operation", function_name),
                                                language: "python".to_string(),
                                            }
                                        ],
                                        references: vec![
                                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/".to_string(),
                                        ],
                                        effort: RemediationEffort::Medium,
                                    },
                                    confidence: ConfidenceLevel::High,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Recursively analyze children
        for child in node.children() {
            self.analyze_node_for_access_control(&child, content, file, context, vulnerabilities)?;
        }

        Ok(())
    }

    /// Check if function name suggests admin functionality
    fn is_admin_function(&self, function_name: &str) -> bool {
        let admin_patterns = [
            "admin", "administrator", "delete_user", "create_user", "modify_user",
            "delete_all", "drop_table", "reset_password", "change_role", "grant_permission",
            "revoke_permission", "system_config", "backup", "restore", "migrate"
        ];

        admin_patterns.iter().any(|&pattern| function_name.contains(pattern))
    }

    /// Check if function body contains authorization checks
    fn has_authorization_checks_in_body(&self, body_node: &Node, content: &str) -> bool {
        // Look for authorization-related function calls or conditions
        self.find_authorization_patterns(body_node, content)
    }

    /// Find authorization patterns in AST node
    fn find_authorization_patterns(&self, node: &Node, content: &str) -> bool {
        // Check current node for authorization patterns
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                if let Ok(function_name) = function_node.text() {
                    let function_name_lower = function_name.to_lowercase();
                    if self.is_authorization_function(&function_name_lower) {
                        return true;
                    }
                }
            }
        }

        // Check for conditional statements that might be authorization checks
        if node.kind() == "if_statement" || node.kind() == "conditional_expression" {
            if let Ok(node_text) = node.text() {
                let node_text_lower = node_text.to_lowercase();
                if self.contains_authorization_keywords(&node_text_lower) {
                    return true;
                }
            }
        }

        // Recursively check children
        for child in node.children() {
            if self.find_authorization_patterns(&child, content) {
                return true;
            }
        }

        false
    }

    /// Check if function name is related to authorization
    fn is_authorization_function(&self, function_name: &str) -> bool {
        let auth_patterns = [
            "check_auth", "verify_auth", "authenticate", "authorize", "has_role",
            "has_permission", "check_permission", "verify_role", "is_admin",
            "require_auth", "ensure_auth", "validate_token", "check_access"
        ];

        auth_patterns.iter().any(|&pattern| function_name.contains(pattern))
    }

    /// Check if text contains authorization keywords
    fn contains_authorization_keywords(&self, text: &str) -> bool {
        let auth_keywords = [
            "auth", "permission", "role", "access", "token", "session",
            "login", "user", "admin", "unauthorized", "forbidden"
        ];

        auth_keywords.iter().any(|&keyword| text.contains(keyword))
    }



    /// Enhanced injection detection with better AST analysis
    fn detect_enhanced_injection_ast(&self, tree: &SyntaxTree, content: &str, file: &FileInfo, context: &SecurityContext) -> Result<Vec<SecurityVulnerability>> {
        let mut vulnerabilities = Vec::new();
        let root = tree.root_node();

        // Detect SQL injection with better context awareness
        self.analyze_node_for_enhanced_sql_injection(&root, content, file, context, &mut vulnerabilities)?;

        // Detect command injection with better context awareness
        self.analyze_node_for_enhanced_command_injection(&root, content, file, context, &mut vulnerabilities)?;

        // Detect XSS vulnerabilities
        self.analyze_node_for_xss(&root, content, file, context, &mut vulnerabilities)?;

        Ok(vulnerabilities)
    }

    /// Enhanced SQL injection detection
    fn analyze_node_for_enhanced_sql_injection(&self, node: &Node, content: &str, file: &FileInfo, context: &SecurityContext, vulnerabilities: &mut Vec<SecurityVulnerability>) -> Result<()> {
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                if let Ok(function_name) = function_node.text() {
                    let function_name_lower = function_name.to_lowercase();

                    // Check for database-related function calls
                    if self.is_database_function_enhanced(&function_name_lower) {
                        if let Some(args_node) = node.child_by_field_name("arguments") {
                            // Check if any argument contains string concatenation or interpolation
                            if self.has_dynamic_sql_construction(&args_node, content) {
                                let confidence = self.calculate_enhanced_sql_injection_confidence(node, content, context);

                                vulnerabilities.push(SecurityVulnerability {
                                    id: format!("AST_SQL_{}", node.start_position().row),
                                    title: "SQL injection vulnerability detected".to_string(),
                                    description: format!("Function '{}' uses dynamic SQL construction which may allow SQL injection", function_name),
                                    severity: SecuritySeverity::High,
                                    owasp_category: OwaspCategory::Injection,
                                    cwe_id: Some("CWE-89".to_string()),
                                    location: VulnerabilityLocation {
                                        file: file.path.clone(),
                                        function: context.function_name.clone(),
                                        start_line: node.start_position().row + 1,
                                        end_line: node.end_position().row + 1,
                                        column: node.start_position().column,
                                    },
                                    code_snippet: node.text().unwrap_or("").to_string(),
                                    impact: SecurityImpact {
                                        confidentiality: ImpactLevel::High,
                                        integrity: ImpactLevel::High,
                                        availability: ImpactLevel::Medium,
                                        overall_score: 8.5,
                                    },
                                    remediation: RemediationGuidance {
                                        summary: "Use parameterized queries to prevent SQL injection".to_string(),
                                        steps: vec![
                                            "Replace string concatenation with parameterized queries".to_string(),
                                            "Use prepared statements or ORM methods".to_string(),
                                            "Validate and sanitize all user inputs".to_string(),
                                            "Implement input validation at application boundaries".to_string(),
                                        ],
                                        code_examples: vec![
                                            CodeExample {
                                                description: "Use parameterized query instead of concatenation".to_string(),
                                                vulnerable_code: "query = \"SELECT * FROM users WHERE id = \" + user_id".to_string(),
                                                secure_code: "query = \"SELECT * FROM users WHERE id = ?\"; cursor.execute(query, (user_id,))".to_string(),
                                                language: "python".to_string(),
                                            }
                                        ],
                                        references: vec![
                                            "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
                                        ],
                                        effort: RemediationEffort::Medium,
                                    },
                                    confidence,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Recursively analyze children
        for child in node.children() {
            self.analyze_node_for_enhanced_sql_injection(&child, content, file, context, vulnerabilities)?;
        }

        Ok(())
    }

    /// Check if function is database-related (enhanced version)
    fn is_database_function_enhanced(&self, function_name: &str) -> bool {
        let db_functions = [
            "execute", "query", "exec", "prepare", "cursor", "select", "insert",
            "update", "delete", "create", "drop", "alter", "sql", "db", "database",
            "find", "findone", "aggregate", "collection"
        ];

        db_functions.iter().any(|&func| function_name.contains(func))
    }

    /// Check for dynamic SQL construction patterns
    fn has_dynamic_sql_construction(&self, args_node: &Node, _content: &str) -> bool {
        for child in args_node.children() {
            // Check for string concatenation
            if child.kind() == "binary_expression" {
                if let Some(operator_node) = child.child_by_field_name("operator") {
                    if let Ok(operator) = operator_node.text() {
                        if operator == "+" {
                            // Check if this involves SQL keywords
                            if let Ok(expr_text) = child.text() {
                                if self.contains_sql_keywords(&expr_text.to_lowercase()) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            // Check for template literals or f-strings
            if child.kind() == "template_string" || child.kind() == "formatted_string" {
                if let Ok(template_text) = child.text() {
                    if self.contains_sql_keywords(&template_text.to_lowercase()) {
                        return true;
                    }
                }
            }

            // Check for format strings
            if child.kind() == "call_expression" {
                if let Some(func_node) = child.child_by_field_name("function") {
                    if let Ok(func_name) = func_node.text() {
                        if func_name.contains("format") {
                            if let Ok(call_text) = child.text() {
                                if self.contains_sql_keywords(&call_text.to_lowercase()) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if text contains SQL keywords
    fn contains_sql_keywords(&self, text: &str) -> bool {
        let sql_keywords = [
            "select", "insert", "update", "delete", "create", "drop", "alter",
            "from", "where", "join", "union", "order by", "group by", "having"
        ];

        sql_keywords.iter().any(|&keyword| text.contains(keyword))
    }

    /// Calculate enhanced confidence for SQL injection
    fn calculate_enhanced_sql_injection_confidence(&self, node: &Node, content: &str, context: &SecurityContext) -> ConfidenceLevel {
        let mut confidence_score = 0;

        // Higher confidence if SQL keywords are present
        if let Ok(node_text) = node.text() {
            if self.contains_sql_keywords(&node_text.to_lowercase()) {
                confidence_score += 3;
            }
        }

        // Higher confidence if user input is involved
        if context.has_user_input {
            confidence_score += 2;
        }

        // Higher confidence if in a web context
        if context.is_web_context {
            confidence_score += 1;
        }

        // Lower confidence if in test files
        if context.is_test_file {
            confidence_score -= 2;
        }

        // Lower confidence if parameterized query patterns are nearby
        if self.has_nearby_parameterized_patterns(node, content) {
            confidence_score -= 1;
        }

        match confidence_score {
            5.. => ConfidenceLevel::High,
            3..=4 => ConfidenceLevel::Medium,
            _ => ConfidenceLevel::Low,
        }
    }

    /// Check for nearby parameterized query patterns
    fn has_nearby_parameterized_patterns(&self, node: &Node, _content: &str) -> bool {
        // Look for patterns like ?, $1, :param, etc. in the vicinity
        if let Ok(node_text) = node.text() {
            node_text.contains('?') ||
            node_text.contains("$1") ||
            node_text.contains(":") ||
            node_text.contains("prepare")
        } else {
            false
        }
    }



    /// Enhanced command injection detection
    fn analyze_node_for_enhanced_command_injection(&self, node: &Node, content: &str, file: &FileInfo, context: &SecurityContext, vulnerabilities: &mut Vec<SecurityVulnerability>) -> Result<()> {
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                if let Ok(function_name) = function_node.text() {
                    let function_name_lower = function_name.to_lowercase();

                    // Check for command execution functions
                    if self.is_command_execution_function_enhanced(&function_name_lower) {
                        if let Some(args_node) = node.child_by_field_name("arguments") {
                            // Check if command is constructed dynamically
                            if self.has_dynamic_command_construction(&args_node, content) {
                                let confidence = self.calculate_command_injection_confidence(node, content, context);

                                vulnerabilities.push(SecurityVulnerability {
                                    id: format!("AST_CMD_{}", node.start_position().row),
                                    title: "Command injection vulnerability detected".to_string(),
                                    description: format!("Function '{}' executes dynamically constructed commands which may allow command injection", function_name),
                                    severity: SecuritySeverity::Critical,
                                    owasp_category: OwaspCategory::Injection,
                                    cwe_id: Some("CWE-78".to_string()),
                                    location: VulnerabilityLocation {
                                        file: file.path.clone(),
                                        function: context.function_name.clone(),
                                        start_line: node.start_position().row + 1,
                                        end_line: node.end_position().row + 1,
                                        column: node.start_position().column,
                                    },
                                    code_snippet: node.text().unwrap_or("").to_string(),
                                    impact: SecurityImpact {
                                        confidentiality: ImpactLevel::Critical,
                                        integrity: ImpactLevel::Critical,
                                        availability: ImpactLevel::Critical,
                                        overall_score: 9.5,
                                    },
                                    remediation: RemediationGuidance {
                                        summary: "Avoid dynamic command construction and use safe APIs".to_string(),
                                        steps: vec![
                                            "Use safe APIs instead of shell command execution".to_string(),
                                            "Validate and whitelist allowed commands".to_string(),
                                            "Escape shell metacharacters if shell execution is necessary".to_string(),
                                            "Use subprocess with argument arrays instead of shell strings".to_string(),
                                        ],
                                        code_examples: vec![
                                            CodeExample {
                                                description: "Use safe subprocess call instead of shell".to_string(),
                                                vulnerable_code: "os.system('ls ' + user_input)".to_string(),
                                                secure_code: "subprocess.run(['ls', user_input], check=True)".to_string(),
                                                language: "python".to_string(),
                                            }
                                        ],
                                        references: vec![
                                            "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                                            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html".to_string(),
                                        ],
                                        effort: RemediationEffort::High,
                                    },
                                    confidence,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Recursively analyze children
        for child in node.children() {
            self.analyze_node_for_enhanced_command_injection(&child, content, file, context, vulnerabilities)?;
        }

        Ok(())
    }

    /// Check if function executes commands (enhanced version)
    fn is_command_execution_function_enhanced(&self, function_name: &str) -> bool {
        let cmd_functions = [
            "system", "exec", "shell", "cmd", "popen", "subprocess", "spawn",
            "execve", "execl", "execlp", "execv", "execvp", "run", "call",
            "check_output", "getoutput", "getstatusoutput"
        ];

        cmd_functions.iter().any(|&func| function_name.contains(func))
    }

    /// Check for dynamic command construction
    fn has_dynamic_command_construction(&self, args_node: &Node, _content: &str) -> bool {
        for child in args_node.children() {
            // Check for string concatenation
            if child.kind() == "binary_expression" {
                if let Some(operator_node) = child.child_by_field_name("operator") {
                    if let Ok(operator) = operator_node.text() {
                        if operator == "+" {
                            return true;
                        }
                    }
                }
            }

            // Check for template literals or f-strings
            if child.kind() == "template_string" || child.kind() == "formatted_string" {
                return true;
            }

            // Check for format strings
            if child.kind() == "call_expression" {
                if let Some(func_node) = child.child_by_field_name("function") {
                    if let Ok(func_name) = func_node.text() {
                        if func_name.contains("format") {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// XSS vulnerability detection
    fn analyze_node_for_xss(&self, node: &Node, content: &str, file: &FileInfo, context: &SecurityContext, vulnerabilities: &mut Vec<SecurityVulnerability>) -> Result<()> {
        // Look for output functions that might render user input
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                if let Ok(function_name) = function_node.text() {
                    let function_name_lower = function_name.to_lowercase();

                    // Check for output/rendering functions
                    if self.is_output_function(&function_name_lower) {
                        if let Some(args_node) = node.child_by_field_name("arguments") {
                            // Check if output contains unescaped user input
                            if self.has_unescaped_user_input(&args_node, content, context) {
                                vulnerabilities.push(SecurityVulnerability {
                                    id: format!("AST_XSS_{}", node.start_position().row),
                                    title: "Cross-Site Scripting (XSS) vulnerability detected".to_string(),
                                    description: format!("Function '{}' outputs user input without proper escaping", function_name),
                                    severity: SecuritySeverity::High,
                                    owasp_category: OwaspCategory::Injection,
                                    cwe_id: Some("CWE-79".to_string()),
                                    location: VulnerabilityLocation {
                                        file: file.path.clone(),
                                        function: context.function_name.clone(),
                                        start_line: node.start_position().row + 1,
                                        end_line: node.end_position().row + 1,
                                        column: node.start_position().column,
                                    },
                                    code_snippet: node.text().unwrap_or("").to_string(),
                                    impact: SecurityImpact {
                                        confidentiality: ImpactLevel::Medium,
                                        integrity: ImpactLevel::High,
                                        availability: ImpactLevel::Low,
                                        overall_score: 7.0,
                                    },
                                    remediation: RemediationGuidance {
                                        summary: "Properly escape user input before output".to_string(),
                                        steps: vec![
                                            "Use context-appropriate output encoding".to_string(),
                                            "Implement Content Security Policy (CSP)".to_string(),
                                            "Validate and sanitize user input".to_string(),
                                            "Use templating engines with auto-escaping".to_string(),
                                        ],
                                        code_examples: vec![
                                            CodeExample {
                                                description: "Escape HTML output".to_string(),
                                                vulnerable_code: "output = '<div>' + user_input + '</div>'".to_string(),
                                                secure_code: "output = '<div>' + html.escape(user_input) + '</div>'".to_string(),
                                                language: "python".to_string(),
                                            }
                                        ],
                                        references: vec![
                                            "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html".to_string(),
                                        ],
                                        effort: RemediationEffort::Medium,
                                    },
                                    confidence: ConfidenceLevel::Medium,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Recursively analyze children
        for child in node.children() {
            self.analyze_node_for_xss(&child, content, file, context, vulnerabilities)?;
        }

        Ok(())
    }

    /// Check if function outputs content
    fn is_output_function(&self, function_name: &str) -> bool {
        let output_functions = [
            "print", "write", "render", "send", "response", "output", "echo",
            "innerHTML", "outerHTML", "document.write", "append", "html",
            "text", "val", "attr", "prop"
        ];

        output_functions.iter().any(|&func| function_name.contains(func))
    }

    /// Check for unescaped user input
    fn has_unescaped_user_input(&self, args_node: &Node, _content: &str, _context: &SecurityContext) -> bool {
        // This is a simplified check - in a real implementation, you'd track data flow
        for child in args_node.children() {
            if let Ok(arg_text) = child.text() {
                let arg_text_lower = arg_text.to_lowercase();

                // Look for variables that might contain user input
                if self.looks_like_user_input(&arg_text_lower) &&
                   !self.has_escaping_function(&arg_text_lower) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if variable name suggests user input
    fn looks_like_user_input(&self, var_name: &str) -> bool {
        let user_input_patterns = [
            "user", "input", "request", "param", "query", "form", "post",
            "get", "body", "data", "payload", "content"
        ];

        user_input_patterns.iter().any(|&pattern| var_name.contains(pattern))
    }

    /// Check if escaping function is used
    fn has_escaping_function(&self, text: &str) -> bool {
        let escape_functions = [
            "escape", "encode", "sanitize", "clean", "filter", "safe"
        ];

        escape_functions.iter().any(|&func| text.contains(func))
    }

}



// Display implementations
impl std::fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecuritySeverity::Critical => write!(f, "Critical"),
            SecuritySeverity::High => write!(f, "High"),
            SecuritySeverity::Medium => write!(f, "Medium"),
            SecuritySeverity::Low => write!(f, "Low"),
            SecuritySeverity::Info => write!(f, "Info"),
        }
    }
}

impl std::fmt::Display for OwaspCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OwaspCategory::BrokenAccessControl => write!(f, "Broken Access Control"),
            OwaspCategory::CryptographicFailures => write!(f, "Cryptographic Failures"),
            OwaspCategory::Injection => write!(f, "Injection"),
            OwaspCategory::InsecureDesign => write!(f, "Insecure Design"),
            OwaspCategory::SecurityMisconfiguration => write!(f, "Security Misconfiguration"),
            OwaspCategory::VulnerableComponents => write!(f, "Vulnerable Components"),
            OwaspCategory::AuthenticationFailures => write!(f, "Authentication Failures"),
            OwaspCategory::IntegrityFailures => write!(f, "Integrity Failures"),
            OwaspCategory::LoggingFailures => write!(f, "Logging Failures"),
            OwaspCategory::SSRF => write!(f, "Server-Side Request Forgery"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileInfo, Symbol, AnalysisResult};
    use std::path::PathBuf;
    use std::collections::HashMap;

    fn create_test_analysis_result() -> AnalysisResult {
        use std::io::Write;
        use tempfile::Builder;

        // Create a temporary file for testing with automatic cleanup
        // Use persist() to keep the file alive for the duration of the test
        let temp_file = Builder::new()
            .prefix("test_security_")
            .suffix(".rs")
            .tempfile()
            .expect("Failed to create temporary file for testing");

        let (mut file, temp_path) = temp_file.keep().expect("Failed to persist temporary file");
        writeln!(file, "fn vulnerable_function() {{").expect("Failed to write function declaration to test file");
        writeln!(file, "    let password = \"hardcoded_password\";").expect("Failed to write password line to test file");
        writeln!(file, "    println!(\"Password: {{}}\", password);").expect("Failed to write println line to test file");
        writeln!(file, "}}").expect("Failed to write function closing brace to test file");

        // Ensure the file is flushed and closed
        drop(file);

        let symbols = vec![
            Symbol {
                name: "vulnerable_function".to_string(),
                kind: "function".to_string(),
                start_line: 1,
                end_line: 4,
                start_column: 0,
                end_column: 1,
                visibility: "public".to_string(),
                documentation: Some("A potentially vulnerable function".to_string()),
            }
        ];

        let file_info = FileInfo {
            path: temp_path,
            language: "rust".to_string(),
            size: 500,
            lines: 4,
            parsed_successfully: true,
            parse_errors: Vec::new(),
            symbols,
            security_vulnerabilities: Vec::new(),
        };

        AnalysisResult {
            root_path: PathBuf::from("."),
            total_files: 1,
            parsed_files: 1,
            error_files: 0,
            total_lines: 4,
            languages: HashMap::new(),
            files: vec![file_info],
            config: crate::AnalysisConfig::default(),
        }
    }

    #[test]
    fn test_advanced_security_scanner_creation() {
        let _config = AdvancedSecurityConfig::default();
        let scanner = AdvancedSecurityAnalyzer::new().expect("Failed to create AdvancedSecurityAnalyzer with default config");

        assert!(scanner.config.owasp_analysis);
        assert!(scanner.config.secrets_detection);
        assert_eq!(scanner.config.min_severity, SecuritySeverity::Low);
    }

    #[test]
    fn test_scan_analysis_result() {
        let _config = AdvancedSecurityConfig::default();
        let scanner = AdvancedSecurityAnalyzer::new().expect("Failed to create AdvancedSecurityAnalyzer for scan test");
        let analysis = create_test_analysis_result();

        let result = scanner.analyze(&analysis);
        if let Err(e) = &result {
            eprintln!("Security analysis failed: {:?}", e);
        }
        assert!(result.is_ok());

        let security_result = result.expect("Security analysis should succeed with test data");
        // Vulnerabilities should be counted
        assert!(security_result.security_score <= 100);
    }

    #[test]
    fn test_user_input_function_detection() {
        let _config = AdvancedSecurityConfig::default();
        let scanner = AdvancedSecurityAnalyzer::new().expect("Failed to create AdvancedSecurityAnalyzer for user input test");

        // Test user input function detection
        assert!(scanner.is_user_input_function("request"));
        assert!(scanner.is_user_input_function("input"));
        assert!(scanner.is_user_input_function("stdin"));
        assert!(scanner.is_user_input_function("readline"));
        assert!(scanner.is_user_input_function("getenv"));
        assert!(!scanner.is_user_input_function("println"));
        assert!(!scanner.is_user_input_function("calculate"));
    }

    #[test]
    fn test_security_config_default() {
        let config = AdvancedSecurityConfig::default();

        assert!(config.owasp_analysis);
        assert!(config.secrets_detection);
        assert!(config.input_validation);
        assert_eq!(config.min_severity, SecuritySeverity::Low);
        assert!(config.custom_rules.is_empty());
        assert!(config.injection_analysis);
    }

    #[test]
    fn test_entropy_calculation() {
        let _config = AdvancedSecurityConfig::default();
        let scanner = AdvancedSecurityAnalyzer::new().expect("Failed to create AdvancedSecurityAnalyzer for entropy test");

        // High entropy string (likely secret)
        let high_entropy = "sk-1234567890abcdef1234567890abcdef";
        assert!(scanner.calculate_entropy(high_entropy) > 4.0);

        // Low entropy string (unlikely secret)
        let low_entropy = "password123";
        assert!(scanner.calculate_entropy(low_entropy) < 4.0);
    }
}
