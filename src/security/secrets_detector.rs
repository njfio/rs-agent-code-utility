//! Real secrets detection engine
//! 
//! Provides entropy-based detection, pattern matching, and ML-based
//! classification for detecting secrets in source code.

use crate::infrastructure::DatabaseManager;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::{debug, warn};
use anyhow::Result;

/// Static regex patterns for secret extraction
static QUOTE_REGEX: OnceLock<Regex> = OnceLock::new();
static ASSIGNMENT_REGEX: OnceLock<Regex> = OnceLock::new();

/// Real secrets detector with multiple detection methods
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
pub struct ContextAnalyzer {
    test_file_patterns: Vec<Regex>,
    comment_patterns: Vec<Regex>,
}

/// False positive filter
pub struct FalsePositiveFilter {
    known_false_positives: HashMap<String, Vec<String>>,
    placeholder_patterns: Vec<Regex>,
}

impl SecretsDetector {
    /// Create a new secrets detector
    pub async fn new(database: &DatabaseManager) -> Result<Self> {
        Self::with_thresholds(database, None, None).await
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

    /// Detect secrets in source code
    pub fn detect_secrets(&self, content: &str, file_path: &str) -> Result<Vec<SecretFinding>> {
        let mut findings = Vec::new();

        // Pattern-based detection
        findings.extend(self.pattern_detection(content, file_path)?);

        // Entropy-based detection
        findings.extend(self.entropy_detection(content, file_path)?);

        // Filter false positives
        findings = self.filter_false_positives(findings, content, file_path)?;

        // Sort by confidence (highest first)
        findings.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

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

                    // Check entropy threshold if specified, otherwise use global threshold
                    let threshold = pattern.entropy_threshold.unwrap_or(self.entropy_threshold);
                    if entropy < threshold {
                        continue;
                    }

                    let secret_type = self.classify_secret_type(&pattern.name);
                    let severity = self.determine_severity(&secret_type, entropy);

                    let finding = SecretFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        secret_type: secret_type.clone(),
                        confidence: pattern.confidence * (entropy / 8.0).min(1.0),
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
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            // Look for high-entropy strings
            let words = self.extract_potential_secrets(line);
            
            for word in words {
                let entropy = self.calculate_shannon_entropy(&word.text);
                
                if entropy > self.entropy_threshold && word.text.len() >= 16 {
                    let finding = SecretFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        secret_type: SecretType::HighEntropy,
                        confidence: (entropy / 8.0).min(1.0) * crate::constants::security::ENTROPY_CONFIDENCE_MULTIPLIER, // Lower confidence for entropy-only
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
            Regex::new(r#"["']([^"']{16,})["']"#).expect("Failed to compile quote regex: hardcoded regex pattern should be valid")
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
            Regex::new(r"=\s*([a-zA-Z0-9+/=]{16,})").expect("Failed to compile assignment regex: hardcoded regex pattern should be valid")
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
    fn filter_false_positives(&self, mut findings: Vec<SecretFinding>, _content: &str, file_path: &str) -> Result<Vec<SecretFinding>> {
        for finding in &mut findings {
            // Check if it's in a test file
            if self.context_analyzer.is_test_file(file_path) {
                finding.confidence *= 0.3; // Reduce confidence for test files
            }

            // Check if it's in a comment
            if self.context_analyzer.is_in_comment(&finding.context) {
                finding.confidence *= 0.5; // Reduce confidence for comments
            }

            // Check if it's an example or placeholder
            if self.false_positive_filter.is_placeholder(&finding.matched_text) {
                finding.is_false_positive = true;
                finding.confidence *= 0.1;
            }

            // Check against known false positives
            if self.false_positive_filter.is_known_false_positive(&finding.secret_type, &finding.matched_text) {
                finding.is_false_positive = true;
                finding.confidence *= 0.1;
            }
        }

        // Remove findings with very low confidence
        findings.retain(|f| f.confidence > self.min_confidence);

        Ok(findings)
    }

    /// Extract context around a line
    fn extract_context(&self, content: &str, line_num: usize, context_lines: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let start = line_num.saturating_sub(context_lines);
        let end = (line_num + context_lines + 1).min(lines.len());
        
        lines[start..end].join("\n")
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
            SecretType::AwsAccessKey | SecretType::GitHubToken | SecretType::DatabaseUrl => SecretSeverity::High,
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
    async fn load_patterns_from_database(database: &DatabaseManager) -> Result<Vec<CompiledPattern>> {
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

        debug!("Loaded {} secret detection patterns", compiled_patterns.len());
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
            Regex::new(r"test")?,
            Regex::new(r"spec")?,
            Regex::new(r"example")?,
            Regex::new(r"demo")?,
        ];



        let comment_patterns = vec![
            Regex::new(r"^\s*//")?,
            Regex::new(r"^\s*/\*")?,
            Regex::new(r"^\s*#")?,
            Regex::new(r"^\s*<!--")?,
        ];

        Ok(Self {
            test_file_patterns,
            comment_patterns,
        })
    }

    /// Check if file is a test file
    fn is_test_file(&self, file_path: &str) -> bool {
        let file_path_lower = file_path.to_lowercase();
        self.test_file_patterns.iter().any(|pattern| pattern.is_match(&file_path_lower))
    }

    /// Check if text is in a comment
    fn is_in_comment(&self, context: &str) -> bool {
        context.lines().any(|line| {
            self.comment_patterns.iter().any(|pattern| pattern.is_match(line))
        })
    }
}

impl FalsePositiveFilter {
    /// Create a new false positive filter
    fn new() -> Result<Self> {
        let mut known_false_positives = HashMap::new();
        
        // Common false positives for different secret types
        known_false_positives.insert("ApiKey".to_string(), vec![
            "your_api_key_here".to_string(),
            "api_key_placeholder".to_string(),
            "xxxxxxxxxxxxxxxx".to_string(),
            "1234567890abcdef".to_string(),
        ]);

        known_false_positives.insert("AwsAccessKey".to_string(), vec![
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            "AKIA1234567890123456".to_string(),
        ]);

        let placeholder_patterns = vec![
            Regex::new(r"^[x]+$")?,
            Regex::new(r"^[0-9]+$")?,
            Regex::new(r"^[a-f0-9]+$")?,
            Regex::new(r"example|placeholder|sample|demo|test")?,
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
            false_positives.iter().any(|fp| fp.eq_ignore_ascii_case(text))
        } else {
            false
        }
    }

    /// Check if text is a placeholder
    fn is_placeholder(&self, text: &str) -> bool {
        self.placeholder_patterns.iter().any(|pattern| pattern.is_match(text))
    }
}
