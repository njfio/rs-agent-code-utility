//! Real secrets detection engine
//!
//! Provides entropy-based detection, pattern matching, and ML-based
//! classification for detecting secrets in source code.

use crate::infrastructure::DatabaseManager;
use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::{debug, warn};
use uuid;

/// Static regex patterns for secret extraction
static QUOTE_REGEX: OnceLock<Regex> = OnceLock::new();
static ASSIGNMENT_REGEX: OnceLock<Regex> = OnceLock::new();

/// Real secrets detector with multiple detection methods
#[derive(Debug)]
pub struct SecretsDetector {
    patterns: Vec<CompiledPattern>,
    entropy_threshold: f64,
    min_confidence: f64,
    context_analyzer: ContextAnalyzer,
    false_positive_filter: FalsePositiveFilter,
}

/// Compiled regex pattern with metadata
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub name: String,
    pub regex: Regex,
    pub entropy_threshold: Option<f64>,
    pub confidence: f64,
    pub enabled: bool,
}

/// Secret finding with detailed information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub id: String,
    pub secret_type: SecretType,
    pub confidence: f64,
    pub entropy: f64,
    pub line_number: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub matched_text: String,
    pub context: String,
    pub file_path: String,
    pub severity: SecretSeverity,
    pub is_false_positive: bool,
    pub remediation: String,
}

/// Types of secrets that can be detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretType {
    ApiKey,
    AwsAccessKey,
    AwsSecretKey,
    GitHubToken,
    JwtToken,
    PrivateKey,
    DatabaseUrl,
    Password,
    GenericSecret,
    HighEntropy,
}

/// Severity levels for secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Context analyzer for reducing false positives
#[derive(Debug)]
pub struct ContextAnalyzer {
    test_file_patterns: Vec<Regex>,
    comment_patterns: Vec<Regex>,
}

/// False positive filter
#[derive(Debug)]
pub struct FalsePositiveFilter {
    known_false_positives: HashMap<String, Vec<String>>,
    placeholder_patterns: Vec<Regex>,
}

impl SecretsDetector {
    /// Create a new secrets detector
    pub async fn new(database: &DatabaseManager) -> Result<Self> {
        Self::with_thresholds(database, None, None).await
    }

    /// Create a new secrets detector without database (uses default patterns)
    pub fn new_without_database() -> Result<Self> {
        Self::with_defaults()
    }

    /// Create a new secrets detector with custom thresholds
    pub async fn with_thresholds(
        database: &DatabaseManager,
        entropy_threshold: Option<f64>,
        min_confidence: Option<f64>,
    ) -> Result<Self> {
        let patterns = Self::load_patterns_from_database(database).await?;
        let entropy_threshold = entropy_threshold.unwrap_or(4.5);
        let min_confidence = min_confidence.unwrap_or(0.1);
        let context_analyzer = ContextAnalyzer::new()?;
        let false_positive_filter = FalsePositiveFilter::new()?;

        Ok(Self {
            patterns,
            entropy_threshold,
            min_confidence,
            context_analyzer,
            false_positive_filter,
        })
    }

    /// Create a new secrets detector with default patterns (no database required)
    pub fn with_defaults() -> Result<Self> {
        let patterns = Self::load_default_patterns()?;
        let entropy_threshold = 4.5;
        let min_confidence = 0.1;
        let context_analyzer = ContextAnalyzer::new()?;
        let false_positive_filter = FalsePositiveFilter::new()?;

        Ok(Self {
            patterns,
            entropy_threshold,
            min_confidence,
            context_analyzer,
            false_positive_filter,
        })
    }

    /// Detect secrets in source code
    pub fn detect_secrets(&self, content: &str, file_path: &str) -> Result<Vec<SecretFinding>> {
        let mut findings = Vec::new();
        let mut detected_strings = std::collections::HashSet::new();

        // Pattern-based detection
        let pattern_findings = self.pattern_detection(content, file_path)?;
        for finding in &pattern_findings {
            detected_strings.insert(finding.matched_text.clone());
        }
        findings.extend(pattern_findings);

        // Entropy-based detection (skip already detected strings)
        let entropy_findings =
            self.entropy_detection_with_filter(content, file_path, &detected_strings)?;
        findings.extend(entropy_findings);

        // Filter false positives
        findings = self.filter_false_positives(findings, content, file_path)?;

        // Sort by confidence (highest first)
        findings.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(findings)
    }

    /// Pattern-based secret detection
    fn pattern_detection(&self, content: &str, file_path: &str) -> Result<Vec<SecretFinding>> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.patterns {
                if !pattern.enabled {
                    continue;
                }

                for mat in pattern.regex.find_iter(line) {
                    let matched_text = mat.as_str();
                    let entropy = self.calculate_shannon_entropy(matched_text);

                    // Check entropy threshold only if explicitly specified for this pattern
                    if let Some(threshold) = pattern.entropy_threshold {
                        if entropy < threshold {
                            continue;
                        }
                    }

                    let secret_type = self.classify_secret_type(&pattern.name);
                    let severity = self.determine_severity(&secret_type, entropy);

                    let finding = SecretFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        secret_type: secret_type.clone(),
                        confidence: (pattern.confidence * (entropy / 8.0).min(1.0).max(0.6))
                            .min(1.0),
                        entropy,
                        line_number: line_num + 1,
                        column_start: mat.start(),
                        column_end: mat.end(),
                        matched_text: matched_text.to_string(),
                        context: self.extract_context(content, line_num, 2),
                        file_path: file_path.to_string(),
                        severity,
                        is_false_positive: false,
                        remediation: self.generate_remediation(&secret_type),
                    };

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    /// Entropy-based secret detection
    fn entropy_detection(&self, content: &str, file_path: &str) -> Result<Vec<SecretFinding>> {
        self.entropy_detection_with_filter(content, file_path, &std::collections::HashSet::new())
    }

    /// Entropy-based secret detection with filtering for already detected strings
    fn entropy_detection_with_filter(
        &self,
        content: &str,
        file_path: &str,
        detected_strings: &std::collections::HashSet<String>,
    ) -> Result<Vec<SecretFinding>> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            // Look for high-entropy strings
            let words = self.extract_potential_secrets(line);

            for word in words {
                // Skip strings that have already been detected by pattern-based detection
                if detected_strings.contains(&word.text) {
                    continue;
                }

                let entropy = self.calculate_shannon_entropy(&word.text);

                if entropy > self.entropy_threshold && word.text.len() >= 16 {
                    let finding = SecretFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        secret_type: SecretType::HighEntropy,
                        confidence: (entropy / 8.0).min(1.0) * crate::constants::security::ENTROPY_CONFIDENCE_MULTIPLIER * 1.2, // Boost confidence for entropy-only
                        entropy,
                        line_number: line_num + 1,
                        column_start: word.start,
                        column_end: word.end,
                        matched_text: word.text.clone(),
                        context: self.extract_context(content, line_num, 2),
                        file_path: file_path.to_string(),
                        severity: self.determine_severity(&SecretType::HighEntropy, entropy),
                        is_false_positive: false,
                        remediation: "Review this high-entropy string to determine if it contains sensitive data".to_string(),
                    };

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    /// Calculate Shannon entropy of a string
    fn calculate_shannon_entropy(&self, text: &str) -> f64 {
        if text.is_empty() {
            return 0.0;
        }

        let mut char_counts = HashMap::new();
        for ch in text.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }

        let length = text.len() as f64;
        let mut entropy = 0.0;

        for count in char_counts.values() {
            let probability = *count as f64 / length;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    /// Extract potential secret strings from a line
    fn extract_potential_secrets(&self, line: &str) -> Vec<PotentialSecret> {
        let mut secrets = Vec::new();

        // Look for quoted strings
        let quote_regex = QUOTE_REGEX.get_or_init(|| {
            Regex::new(r#"["']([^"']{16,})["']"#)
                .expect("Failed to compile quote regex: hardcoded regex pattern should be valid")
        });
        for mat in quote_regex.find_iter(line) {
            if let Some(captures) = quote_regex.captures(mat.as_str()) {
                if let Some(content) = captures.get(1) {
                    secrets.push(PotentialSecret {
                        text: content.as_str().to_string(),
                        start: mat.start() + 1,
                        end: mat.end() - 1,
                    });
                }
            }
        }

        // Look for assignment values
        let assignment_regex = ASSIGNMENT_REGEX.get_or_init(|| {
            Regex::new(r"=\s*([a-zA-Z0-9+/=]{16,})").expect(
                "Failed to compile assignment regex: hardcoded regex pattern should be valid",
            )
        });
        for mat in assignment_regex.find_iter(line) {
            if let Some(captures) = assignment_regex.captures(mat.as_str()) {
                if let Some(content) = captures.get(1) {
                    secrets.push(PotentialSecret {
                        text: content.as_str().to_string(),
                        start: content.start(),
                        end: content.end(),
                    });
                }
            }
        }

        secrets
    }

    /// Filter false positives
    fn filter_false_positives(
        &self,
        mut findings: Vec<SecretFinding>,
        content: &str,
        file_path: &str,
    ) -> Result<Vec<SecretFinding>> {
        for finding in &mut findings {
            let mut confidence_multiplier = 1.0;
            let mut is_false_positive = false;

            // Check if it's in a test file
            if self.context_analyzer.is_test_file(file_path) {
                confidence_multiplier *= 0.3; // Reduce confidence for test files
            }

            // Check if it's in a comment
            if self.context_analyzer.is_in_comment(&finding.context) {
                confidence_multiplier *= 0.5; // Reduce confidence for comments
            }

            // Enhanced semantic context analysis
            if self.is_in_semantic_false_positive_context(content, finding) {
                confidence_multiplier *= 0.2;
                is_false_positive = true;
            }

            // Check if it's an example or placeholder
            if self
                .false_positive_filter
                .is_placeholder(&finding.matched_text)
            {
                is_false_positive = true;
                confidence_multiplier *= 0.1;
            }

            // Check against known false positives for this secret type
            if self
                .false_positive_filter
                .is_known_false_positive(&finding.secret_type, &finding.matched_text)
            {
                is_false_positive = true;
                confidence_multiplier *= 0.1;
            }

            // Also check for known false positives in all categories
            if self
                .false_positive_filter
                .is_any_known_false_positive(&finding.matched_text)
            {
                is_false_positive = true;
                confidence_multiplier *= 0.1;
            }

            // Check for common false positive patterns in code context
            if self.is_common_false_positive_pattern(&finding.matched_text, &finding.context) {
                confidence_multiplier *= 0.4;
            }

            // Apply entropy-based false positive detection
            if self.is_entropy_false_positive(finding.entropy, &finding.secret_type) {
                confidence_multiplier *= 0.6;
            }

            finding.confidence *= confidence_multiplier;
            if is_false_positive && finding.confidence < 0.3 {
                finding.is_false_positive = true;
            }
        }

        // Remove findings with very low confidence OR known false positives
        findings.retain(|f| f.confidence > self.min_confidence && !f.is_false_positive);

        Ok(findings)
    }

    /// Extract context around a line
    fn extract_context(&self, content: &str, line_num: usize, context_lines: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let start = line_num.saturating_sub(context_lines);
        let end = (line_num + context_lines + 1).min(lines.len());

        lines[start..end].join("\n")
    }

    /// Check if finding is in a semantic false positive context
    fn is_in_semantic_false_positive_context(
        &self,
        content: &str,
        finding: &SecretFinding,
    ) -> bool {
        // Consider only the line containing the finding
        let current_line = content
            .lines()
            .nth(finding.line_number.saturating_sub(1))
            .unwrap_or("");

        // If on a comment line, likely an example or placeholder
        if self.context_analyzer.is_comment_line(current_line) {
            let doc_patterns = [
                r"(?i)example|sample|demo|test|placeholder|template",
                r"(?i)documentation|docs|readme|guide",
                r"(?i)fake|mock|stub|dummy",
                r"(?i)your_.*_here|replace_with",
                r"(?i)config\.|settings\.|env\.",
            ];
            for pattern in &doc_patterns {
                if regex::Regex::new(pattern).unwrap().is_match(current_line) {
                    return true;
                }
            }
            return true;
        }

        // For code lines, only treat explicit placeholder-like variable names as FP
        let placeholder_var_regex = regex::Regex::new(
            r"(?i)\b(let|const|var)\s+(test|demo|example|sample|fake|mock|dummy|placeholder)_?\w*\s*=",
        )
        .unwrap();
        if placeholder_var_regex.is_match(current_line) {
            return true;
        }

        // Logging on same line indicates illustrative code
        if current_line.contains("println") || current_line.contains("log") || current_line.contains("debug") {
            return true;
        }

        false
    }

    /// Check for common false positive patterns in code
    fn is_common_false_positive_pattern(&self, text: &str, context: &str) -> bool {
        // Check for obvious test/example patterns
        if text.contains("test") || text.contains("example") || text.contains("sample") {
            return true;
        }

        // Check for common placeholder patterns
        let placeholders = [
            "your_api_key",
            "your_secret",
            "your_token",
            "your_password",
            "api_key_here",
            "secret_here",
            "token_here",
            "password_here",
            "xxxxxxxx",
            "********",
            "......",
        ];

        for placeholder in &placeholders {
            if text.to_lowercase().contains(placeholder) {
                return true;
            }
        }

        // Check if it's in a configuration template context
        if context.contains("config")
            || context.contains("Config")
            || context.contains("settings")
            || context.contains("Settings")
        {
            return true;
        }

        false
    }

    /// Check if entropy suggests this might be a false positive
    fn is_entropy_false_positive(&self, entropy: f64, secret_type: &SecretType) -> bool {
        match secret_type {
            SecretType::ApiKey | SecretType::GitHubToken | SecretType::JwtToken => {
                // API keys and tokens should have high entropy, but not suspiciously high
                entropy < 3.5 || entropy > 6.5
            }
            SecretType::Password => {
                // Passwords can have variable entropy
                entropy < 2.5
            }
            SecretType::PrivateKey => {
                // Private keys should have very high entropy
                entropy < 4.0
            }
            _ => {
                // For other types, be more conservative
                entropy < 3.0 || entropy > 7.0
            }
        }
    }

    /// Classify secret type from pattern name
    fn classify_secret_type(&self, pattern_name: &str) -> SecretType {
        match pattern_name.to_lowercase().as_str() {
            name if name.contains("aws access") => SecretType::AwsAccessKey,
            name if name.contains("aws secret") => SecretType::AwsSecretKey,
            name if name.contains("github") => SecretType::GitHubToken,
            name if name.contains("jwt") => SecretType::JwtToken,
            name if name.contains("private key") => SecretType::PrivateKey,
            name if name.contains("database") => SecretType::DatabaseUrl,
            name if name.contains("password") => SecretType::Password,
            name if name.contains("api") => SecretType::ApiKey,
            _ => SecretType::GenericSecret,
        }
    }

    /// Determine severity based on secret type and entropy
    fn determine_severity(&self, secret_type: &SecretType, entropy: f64) -> SecretSeverity {
        match secret_type {
            SecretType::PrivateKey | SecretType::AwsSecretKey => SecretSeverity::Critical,
            SecretType::AwsAccessKey | SecretType::GitHubToken | SecretType::DatabaseUrl => {
                SecretSeverity::High
            }
            SecretType::ApiKey | SecretType::JwtToken => SecretSeverity::Medium,
            SecretType::Password => SecretSeverity::Medium,
            SecretType::HighEntropy => {
                if entropy > 6.0 {
                    SecretSeverity::High
                } else if entropy > 5.0 {
                    SecretSeverity::Medium
                } else {
                    SecretSeverity::Low
                }
            }
            SecretType::GenericSecret => SecretSeverity::Low,
        }
    }

    /// Generate remediation advice
    fn generate_remediation(&self, secret_type: &SecretType) -> String {
        match secret_type {
            SecretType::AwsAccessKey | SecretType::AwsSecretKey => {
                "Remove AWS credentials from code. Use AWS IAM roles, environment variables, or AWS Secrets Manager.".to_string()
            }
            SecretType::GitHubToken => {
                "Remove GitHub token from code. Use GitHub Secrets or environment variables.".to_string()
            }
            SecretType::PrivateKey => {
                "Remove private key from code. Store in secure key management system.".to_string()
            }
            SecretType::DatabaseUrl => {
                "Remove database URL from code. Use environment variables or configuration files.".to_string()
            }
            SecretType::ApiKey => {
                "Remove API key from code. Use environment variables or secure configuration.".to_string()
            }
            SecretType::Password => {
                "Remove password from code. Use secure authentication mechanisms.".to_string()
            }
            SecretType::JwtToken => {
                "Remove JWT token from code. Generate tokens at runtime.".to_string()
            }
            SecretType::HighEntropy => {
                "Review this high-entropy string. If it's sensitive, move to secure storage.".to_string()
            }
            SecretType::GenericSecret => {
                "Review this potential secret. If sensitive, move to secure configuration.".to_string()
            }
        }
    }

    /// Load patterns from database
    async fn load_patterns_from_database(
        database: &DatabaseManager,
    ) -> Result<Vec<CompiledPattern>> {
        let secret_patterns = database.get_secret_patterns().await?;
        let mut compiled_patterns = Vec::new();

        for pattern in secret_patterns {
            match Regex::new(&pattern.pattern) {
                Ok(regex) => {
                    compiled_patterns.push(CompiledPattern {
                        name: pattern.name,
                        regex,
                        entropy_threshold: pattern.entropy_threshold,
                        confidence: pattern.confidence,
                        enabled: pattern.enabled,
                    });
                }
                Err(e) => {
                    warn!("Failed to compile regex pattern '{}': {}", pattern.name, e);
                }
            }
        }

        debug!(
            "Loaded {} secret detection patterns",
            compiled_patterns.len()
        );
        Ok(compiled_patterns)
    }

    /// Load default patterns (no database required)
    fn load_default_patterns() -> Result<Vec<CompiledPattern>> {
        let default_patterns = vec![
            ("AWS Access Key", r"AKIA[0-9A-Z]{16}", None, 0.9),
            ("AWS Secret Key", r"[0-9a-zA-Z/+]{40}", Some(4.5), 0.8),
            ("GitHub Token", r"ghp_[0-9a-zA-Z]{36}", None, 0.95),
            ("API Key", r"api[_]?key.*[0-9a-zA-Z]{32,45}", Some(4.0), 0.7),
            (
                "JWT Token",
                r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.]+",
                None,
                0.85,
            ),
            ("Private Key", r"-----BEGIN.*PRIVATE.*KEY-----", None, 0.95),
            (
                "Database URL",
                r"(postgres|mysql|mongodb)://[^\s]+",
                None,
                0.8,
            ),
            (
                "Password",
                r"(password|passwd|pwd).*=[^;]{8,}",
                Some(3.5),
                0.6,
            ),
            ("High Entropy", r"[A-Za-z0-9+/=]{32,}", Some(4.5), 0.5),
        ];

        let mut compiled_patterns = Vec::new();

        for (name, pattern, entropy_threshold, confidence) in default_patterns {
            match Regex::new(pattern) {
                Ok(regex) => {
                    compiled_patterns.push(CompiledPattern {
                        name: name.to_string(),
                        regex,
                        entropy_threshold,
                        confidence,
                        enabled: true,
                    });
                }
                Err(e) => {
                    warn!("Failed to compile default regex pattern '{}': {}", name, e);
                }
            }
        }

        debug!(
            "Loaded {} default secret detection patterns",
            compiled_patterns.len()
        );
        Ok(compiled_patterns)
    }
}

/// Potential secret found in text
#[derive(Debug, Clone)]
struct PotentialSecret {
    text: String,
    start: usize,
    end: usize,
}

impl ContextAnalyzer {
    /// Create a new context analyzer
    fn new() -> Result<Self> {
        let test_file_patterns = vec![
            Regex::new(r"(^|/)test")?,    // test files
            Regex::new(r"(^|/)spec")?,    // spec files
            Regex::new(r"(^|/)example")?, // example files
            Regex::new(r"(^|/)demo")?,    // demo files
            Regex::new(r"_test\.")?,      // *_test.* files
            Regex::new(r"test_")?,        // test_* files
            Regex::new(r"spec_")?,        // spec_* files
            Regex::new(r"example_")?,     // example_* files
            Regex::new(r"demo_")?,        // demo_* files
            Regex::new(r"fixture")?,      // fixture files
            Regex::new(r"mock")?,         // mock files
            Regex::new(r"stub")?,         // stub files
        ];

        let comment_patterns = vec![
            Regex::new(r"^\s*//")?,   // Single line comments (Rust, C++, Java, etc.)
            Regex::new(r"^\s*/\*")?,  // Multi-line comment start (C-style)
            Regex::new(r"^\s*#")?,    // Hash comments (Python, Ruby, Shell, etc.)
            Regex::new(r"^\s*<!--")?, // HTML/XML comments
            Regex::new(r"^\s*'{3}")?, // Python docstrings
            Regex::new(r#"^\s*"""#)?, // Python docstrings
            Regex::new(r"^\s*--")?,   // SQL comments
            Regex::new(r"^\s*%")?,    // MATLAB/Octave comments
            Regex::new(r"^\s*!")?,    // Fortran comments
            Regex::new(r"^\s*C\s")?,  // Fortran alternative comments
            Regex::new(r"^\s*\*")?,   // COBOL comments
        ];

        Ok(Self {
            test_file_patterns,
            comment_patterns,
        })
    }

    /// Check if file is a test file
    fn is_test_file(&self, file_path: &str) -> bool {
        let file_path_lower = file_path.to_lowercase();
        self.test_file_patterns
            .iter()
            .any(|pattern| pattern.is_match(&file_path_lower))
    }

    /// Check if text is in a comment
    fn is_in_comment(&self, context: &str) -> bool {
        context.lines().any(|line| {
            self.comment_patterns
                .iter()
                .any(|pattern| pattern.is_match(line))
        })
    }

    /// Check if a single line is a comment line
    fn is_comment_line(&self, line: &str) -> bool {
        self.comment_patterns
            .iter()
            .any(|pattern| pattern.is_match(line))
    }
}

impl FalsePositiveFilter {
    /// Create a new false positive filter
    fn new() -> Result<Self> {
        let mut known_false_positives = HashMap::new();

        // Common false positives for different secret types
        known_false_positives.insert(
            "ApiKey".to_string(),
            vec![
                "your_api_key_here".to_string(),
                "api_key_placeholder".to_string(),
                "xxxxxxxxxxxxxxxx".to_string(),
                "1234567890abcdef".to_string(),
                "sk-test1234567890abcdef".to_string(),
                "pk-test1234567890abcdef".to_string(),
                "example_api_key".to_string(),
                "demo_api_key".to_string(),
                "test_api_key".to_string(),
                "sample_api_key".to_string(),
                "fake_api_key".to_string(),
                "mock_api_key".to_string(),
            ],
        );

        known_false_positives.insert(
            "AwsAccessKey".to_string(),
            vec![
                "AKIAIOSFODNN7EXAMPLE".to_string(),
                "AKIA1234567890123456".to_string(),
                "AKIAIOSFODNN7TEST".to_string(),
                "AKIAIOSFODNN7DEMO".to_string(),
                "AKIAIOSFODNN7SAMPLE".to_string(),
            ],
        );

        known_false_positives.insert(
            "HighEntropy".to_string(),
            vec![
                "AKIAIOSFODNN7EXAMPLE".to_string(),
                "AKIA1234567890123456".to_string(),
                "your_api_key_here".to_string(),
                "api_key_placeholder".to_string(),
                "xxxxxxxxxxxxxxxx".to_string(),
                "1234567890abcdef".to_string(),
                "sk-test1234567890abcdef1234567890abcdef".to_string(),
                "pk-test1234567890abcdef1234567890abcdef".to_string(),
                "ghp_test1234567890abcdef1234567890abcdef".to_string(),
                "example_high_entropy_string".to_string(),
                "demo_high_entropy_string".to_string(),
                "test_high_entropy_string".to_string(),
            ],
        );

        let placeholder_patterns = vec![
            Regex::new(r"^[x]+$")?,
            Regex::new(r"^[0-9]+$")?,
            Regex::new(r"^[a-f0-9]+$")?,
            Regex::new(r"example|placeholder|sample|demo|test|fake|mock|dummy|bogus")?,
            Regex::new(r"your_.*_here")?,
            Regex::new(r".*_placeholder")?,
            Regex::new(r".*_example")?,
            Regex::new(r".*_demo")?,
            Regex::new(r".*_test")?,
            Regex::new(r".*_sample")?,
            Regex::new(r".*_fake")?,
            Regex::new(r".*_mock")?,
        ];

        Ok(Self {
            known_false_positives,
            placeholder_patterns,
        })
    }

    /// Check if text is a known false positive
    fn is_known_false_positive(&self, secret_type: &SecretType, text: &str) -> bool {
        let type_key = format!("{:?}", secret_type);
        if let Some(false_positives) = self.known_false_positives.get(&type_key) {
            false_positives
                .iter()
                .any(|fp| fp.eq_ignore_ascii_case(text))
        } else {
            false
        }
    }

    /// Check if text is a placeholder
    fn is_placeholder(&self, text: &str) -> bool {
        self.placeholder_patterns
            .iter()
            .any(|pattern| pattern.is_match(text))
    }

    /// Check if text is a known false positive in any category
    fn is_any_known_false_positive(&self, text: &str) -> bool {
        self.known_false_positives
            .values()
            .flatten()
            .any(|fp| fp.eq_ignore_ascii_case(text))
    }
}
