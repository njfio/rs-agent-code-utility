//! ML-based False Positive Filter
//!
//! This module provides intelligent filtering of security findings to reduce false positives
//! using machine learning techniques and pattern recognition.

use crate::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// ML-based false positive filter
#[derive(Debug)]
pub struct MLFalsePositiveFilter {
    /// Historical patterns and their false positive rates
    pattern_database: Arc<RwLock<HashMap<String, PatternStats>>>,
    /// Confidence thresholds for different finding types
    confidence_thresholds: HashMap<String, f64>,
    /// Contextual patterns that indicate false positives
    false_positive_patterns: Vec<FalsePositivePattern>,
}

/// Statistics for a pattern
#[derive(Debug, Clone)]
pub struct PatternStats {
    /// Number of times this pattern was seen
    occurrences: u32,
    /// Number of times it was a false positive
    false_positives: u32,
    /// Average confidence when it was a false positive
    avg_false_positive_confidence: f64,
    /// Last updated timestamp
    last_updated: std::time::SystemTime,
}

/// Pattern that indicates a likely false positive
#[derive(Debug, Clone)]
pub struct FalsePositivePattern {
    /// Pattern name
    name: String,
    /// Keywords that indicate this is likely a false positive
    keywords: Vec<String>,
    /// File patterns where this applies
    file_patterns: Vec<String>,
    /// False positive probability (0.0 to 1.0)
    probability: f64,
    /// Reason for being a false positive
    reason: String,
}

/// Filtering result
#[derive(Debug, Clone)]
pub struct FilterResult {
    /// Whether the finding should be filtered out
    pub should_filter: bool,
    /// Confidence in the filtering decision (0.0 to 1.0)
    pub confidence: f64,
    /// Reason for the filtering decision
    pub reason: String,
    /// Suggested adjustments to severity/confidence
    pub adjustments: HashMap<String, f64>,
}

impl MLFalsePositiveFilter {
    /// Create a new ML-based false positive filter
    pub fn new() -> Self {
        let mut confidence_thresholds = HashMap::new();
        confidence_thresholds.insert("HardcodedSecret".to_string(), 0.6);
        confidence_thresholds.insert("Injection".to_string(), 0.5);
        confidence_thresholds.insert("WeakAuthentication".to_string(), 0.7);
        confidence_thresholds.insert("InsecureDesign".to_string(), 0.4);

        let false_positive_patterns = vec![
            FalsePositivePattern {
                name: "Test File Pattern".to_string(),
                keywords: vec![
                    "test".to_string(),
                    "spec".to_string(),
                    "_test".to_string(),
                    "example".to_string(),
                    "demo".to_string(),
                ],
                file_patterns: vec![
                    "*test*.rs".to_string(),
                    "*spec*.rs".to_string(),
                    "*example*.rs".to_string(),
                    "*demo*.rs".to_string(),
                ],
                probability: 0.85,
                reason: "Finding in test/example file".to_string(),
            },
            FalsePositivePattern {
                name: "Documentation Pattern".to_string(),
                keywords: vec![
                    "readme".to_string(),
                    "doc".to_string(),
                    "comment".to_string(),
                    "documentation".to_string(),
                ],
                file_patterns: vec![
                    "README.md".to_string(),
                    "docs/*".to_string(),
                    "*.md".to_string(),
                ],
                probability: 0.9,
                reason: "Finding in documentation file".to_string(),
            },
            FalsePositivePattern {
                name: "Configuration Pattern".to_string(),
                keywords: vec![
                    "config".to_string(),
                    "settings".to_string(),
                    "const".to_string(),
                    "static".to_string(),
                ],
                file_patterns: vec!["*config*.rs".to_string(), "*settings*.rs".to_string()],
                probability: 0.7,
                reason: "Finding in configuration file with constants".to_string(),
            },
            FalsePositivePattern {
                name: "Safe Usage Pattern".to_string(),
                keywords: vec![
                    "safe".to_string(),
                    "sanitized".to_string(),
                    "validated".to_string(),
                    "escaped".to_string(),
                ],
                file_patterns: vec![],
                probability: 0.6,
                reason: "Code appears to use safe patterns".to_string(),
            },
        ];

        Self {
            pattern_database: Arc::new(RwLock::new(HashMap::new())),
            confidence_thresholds,
            false_positive_patterns,
        }
    }

    /// Filter a security finding
    pub async fn filter_finding(
        &self,
        finding_type: &str,
        file_path: &str,
        code_snippet: &str,
        current_confidence: f64,
    ) -> Result<FilterResult> {
        let mut should_filter = false;
        let mut confidence = 0.0;
        let mut reason = "No filtering pattern matched".to_string();
        let mut adjustments = HashMap::new();

        // Check file-based patterns
        for pattern in &self.false_positive_patterns {
            if self.matches_file_pattern(file_path, &pattern.file_patterns) {
                should_filter = true;
                confidence = pattern.probability;
                reason = pattern.reason.clone();
                break;
            }
        }

        // Check keyword-based patterns
        if !should_filter {
            for pattern in &self.false_positive_patterns {
                if self.contains_keywords(code_snippet, &pattern.keywords) {
                    should_filter = true;
                    confidence = pattern.probability;
                    reason = pattern.reason.clone();
                    break;
                }
            }
        }

        // Check historical patterns
        let pattern_key = self.generate_pattern_key(finding_type, file_path, code_snippet);
        if let Some(stats) = self.get_pattern_stats(&pattern_key).await {
            let historical_fp_rate = stats.false_positives as f64 / stats.occurrences as f64;
            if historical_fp_rate > 0.7 {
                should_filter = true;
                confidence = historical_fp_rate;
                reason = format!(
                    "Historical false positive rate: {:.1}%",
                    historical_fp_rate * 100.0
                );
            }
        }

        // Check confidence threshold (only if no pattern has already set confidence)
        if confidence == 0.0 {
            if let Some(threshold) = self.confidence_thresholds.get(finding_type) {
                if current_confidence < *threshold {
                    should_filter = true;
                    confidence = (1.0 - current_confidence / *threshold).min(0.8);
                    reason = format!(
                        "Confidence below threshold ({:.2} < {:.2})",
                        current_confidence, threshold
                    );
                }
            }
        }

        // Suggest adjustments
        if should_filter && confidence > 0.5 {
            adjustments.insert("severity_reduction".to_string(), confidence * 0.5);
            adjustments.insert("confidence_boost".to_string(), -confidence * 0.3);
        }

        Ok(FilterResult {
            should_filter,
            confidence,
            reason,
            adjustments,
        })
    }

    /// Update pattern statistics based on user feedback
    pub async fn update_pattern_stats(
        &self,
        finding_type: &str,
        file_path: &str,
        code_snippet: &str,
        was_false_positive: bool,
        confidence: f64,
    ) -> Result<()> {
        let pattern_key = self.generate_pattern_key(finding_type, file_path, code_snippet);
        let mut db = self.pattern_database.write().await;

        let stats = db.entry(pattern_key).or_insert(PatternStats {
            occurrences: 0,
            false_positives: 0,
            avg_false_positive_confidence: 0.0,
            last_updated: std::time::SystemTime::now(),
        });

        stats.occurrences += 1;
        if was_false_positive {
            stats.false_positives += 1;
            // Update rolling average
            let alpha = 0.1; // Smoothing factor
            stats.avg_false_positive_confidence =
                stats.avg_false_positive_confidence * (1.0 - alpha) + confidence * alpha;
        }
        stats.last_updated = std::time::SystemTime::now();

        Ok(())
    }

    /// Get statistics for a pattern
    async fn get_pattern_stats(&self, pattern_key: &str) -> Option<PatternStats> {
        let db = self.pattern_database.read().await;
        db.get(pattern_key).cloned()
    }

    /// Generate a unique key for a pattern
    fn generate_pattern_key(
        &self,
        finding_type: &str,
        file_path: &str,
        code_snippet: &str,
    ) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        finding_type.hash(&mut hasher);
        file_path.hash(&mut hasher);
        code_snippet.len().hash(&mut hasher); // Use length instead of full content for performance
        format!("{:x}", hasher.finish())
    }

    /// Check if file path matches any of the patterns
    fn matches_file_pattern(&self, file_path: &str, patterns: &[String]) -> bool {
        for pattern in patterns {
            if self.simple_pattern_match(file_path, pattern) {
                return true;
            }
        }
        false
    }

    /// Check if text contains any of the keywords
    fn contains_keywords(&self, text: &str, keywords: &[String]) -> bool {
        let text_lower = text.to_lowercase();
        keywords
            .iter()
            .any(|keyword| text_lower.contains(&keyword.to_lowercase()))
    }

    /// Simple pattern matching (supports * wildcards)
    fn simple_pattern_match(&self, text: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            let regex_pattern = pattern.replace('*', ".*");
            if let Ok(regex) = regex::Regex::new(&format!("^{}$", regex_pattern)) {
                regex.is_match(text)
            } else {
                false
            }
        } else {
            text.contains(pattern)
        }
    }

    /// Get filtering statistics
    pub async fn get_statistics(&self) -> Result<FilterStatistics> {
        let db = self.pattern_database.read().await;
        let total_patterns = db.len();
        let total_occurrences: u32 = db.values().map(|stats| stats.occurrences).sum();
        let total_false_positives: u32 = db.values().map(|stats| stats.false_positives).sum();

        Ok(FilterStatistics {
            total_patterns,
            total_occurrences,
            total_false_positives,
            average_false_positive_rate: if total_occurrences > 0 {
                total_false_positives as f64 / total_occurrences as f64
            } else {
                0.0
            },
        })
    }
}

/// Statistics about the filter's performance
#[derive(Debug, Clone)]
pub struct FilterStatistics {
    /// Total number of patterns tracked
    pub total_patterns: usize,
    /// Total occurrences of all patterns
    pub total_occurrences: u32,
    /// Total false positives identified
    pub total_false_positives: u32,
    /// Average false positive rate across all patterns
    pub average_false_positive_rate: f64,
}

impl Default for MLFalsePositiveFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_filter_finding() {
        let filter = MLFalsePositiveFilter::new();

        // Test filtering a finding in a test file
        let result = filter
            .filter_finding(
                "HardcodedSecret",
                "src/test_file.rs",
                "const API_KEY = \"test_key\";",
                0.3,
            )
            .await
            .unwrap();

        assert!(result.should_filter);
        assert!(result.confidence > 0.5);
        assert!(result.reason.contains("test"));
    }

    #[tokio::test]
    async fn test_update_pattern_stats() {
        let filter = MLFalsePositiveFilter::new();

        // Update stats for a pattern
        filter
            .update_pattern_stats(
                "Injection",
                "src/main.rs",
                "sql_query(user_input)",
                true,
                0.8,
            )
            .await
            .unwrap();

        // Check that stats were updated
        let stats = filter.get_statistics().await.unwrap();
        assert_eq!(stats.total_occurrences, 1);
        assert_eq!(stats.total_false_positives, 1);
    }

    #[tokio::test]
    async fn test_pattern_matching() {
        let filter = MLFalsePositiveFilter::new();

        assert!(filter.simple_pattern_match("src/test_file.rs", "*test*.rs"));
        assert!(filter.simple_pattern_match("README.md", "README.md"));
        assert!(!filter.simple_pattern_match("src/main.rs", "*test*.rs"));
    }
}
