//! ML-based False Positive Filter
//!
//! This module provides intelligent filtering of security findings to reduce false positives
//! using machine learning techniques and pattern recognition.

use crate::Result;
use crate::security::deterministic_filter::FilterMode;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

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
                    "fixture".to_string(),
                    "mock".to_string(),
                    "stub".to_string(),
                ],
                file_patterns: vec![
                    "*test*.rs".to_string(),
                    "*spec*.rs".to_string(),
                    "*example*.rs".to_string(),
                    "*demo*.rs".to_string(),
                    "*fixture*.rs".to_string(),
                    "*mock*.rs".to_string(),
                    "tests/*".to_string(),
                    "examples/*".to_string(),
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
                    "guide".to_string(),
                    "tutorial".to_string(),
                    "sample".to_string(),
                ],
                file_patterns: vec![
                    "README.md".to_string(),
                    "docs/*".to_string(),
                    "*.md".to_string(),
                    "CHANGELOG.md".to_string(),
                    "CONTRIBUTING.md".to_string(),
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
                    "env".to_string(),
                    "environment".to_string(),
                    "default".to_string(),
                ],
                file_patterns: vec![
                    "*config*.rs".to_string(),
                    "*settings*.rs".to_string(),
                    "*env*.rs".to_string(),
                    "*constants*.rs".to_string(),
                ],
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
                    "encrypted".to_string(),
                    "hashed".to_string(),
                    "secure".to_string(),
                ],
                file_patterns: vec![],
                probability: 0.6,
                reason: "Code appears to use safe patterns".to_string(),
            },
            FalsePositivePattern {
                name: "Logging Pattern".to_string(),
                keywords: vec![
                    "log".to_string(),
                    "debug".to_string(),
                    "info".to_string(),
                    "warn".to_string(),
                    "error".to_string(),
                    "println".to_string(),
                    "eprintln".to_string(),
                    "trace".to_string(),
                ],
                file_patterns: vec![],
                probability: 0.75,
                reason: "Finding in logging/debugging context".to_string(),
            },
            FalsePositivePattern {
                name: "Placeholder Pattern".to_string(),
                keywords: vec![
                    "placeholder".to_string(),
                    "your_".to_string(),
                    "replace_with".to_string(),
                    "change_me".to_string(),
                    "todo".to_string(),
                    "fixme".to_string(),
                    "xxxxx".to_string(),
                    "*****".to_string(),
                ],
                file_patterns: vec![],
                probability: 0.95,
                reason: "Finding appears to be a placeholder or template value".to_string(),
            },
            FalsePositivePattern {
                name: "Migration/Seed Pattern".to_string(),
                keywords: vec![
                    "migration".to_string(),
                    "seed".to_string(),
                    "fixture".to_string(),
                    "initial".to_string(),
                    "setup".to_string(),
                    "bootstrap".to_string(),
                ],
                file_patterns: vec![
                    "*migration*.rs".to_string(),
                    "*seed*.rs".to_string(),
                    "*fixture*.rs".to_string(),
                ],
                probability: 0.8,
                reason: "Finding in database migration or seed file".to_string(),
            },
            FalsePositivePattern {
                name: "Comment Pattern".to_string(),
                keywords: vec![
                    "//".to_string(),
                    "/*".to_string(),
                    "*/".to_string(),
                    "#".to_string(),
                    "///".to_string(),
                    "//!".to_string(),
                ],
                file_patterns: vec![],
                probability: 0.85,
                reason: "Finding appears to be in a comment".to_string(),
            },
        ];

        Self {
            pattern_database: Arc::new(RwLock::new(HashMap::new())),
            confidence_thresholds,
            false_positive_patterns,
        }
    }

    /// Create a new filter adjusted for a deterministic filter mode
    pub fn with_mode(mode: FilterMode) -> Self {
        let mut f = Self::new();
        f.apply_mode(mode);
        f
    }

    /// Adjust internal thresholds and heuristics for the given mode
    pub fn apply_mode(&mut self, mode: FilterMode) {
        match mode {
            FilterMode::Strict => {
                // Raise thresholds to be more aggressive in filtering
                self.confidence_thresholds.insert("HardcodedSecret".into(), 0.75);
                self.confidence_thresholds.insert("Injection".into(), 0.6);
                self.confidence_thresholds.insert("WeakAuthentication".into(), 0.8);
                self.confidence_thresholds.insert("InsecureDesign".into(), 0.5);
                // Boost probabilities for docs/tests indicators
                for p in &mut self.false_positive_patterns {
                    if p.name.contains("Test") || p.name.contains("Documentation") {
                        p.probability = (p.probability + 0.1).min(0.95);
                    }
                }
            }
            FilterMode::Balanced => {
                // Defaults already tuned for balanced; ensure defaults
                self.confidence_thresholds.insert("HardcodedSecret".into(), 0.6);
                self.confidence_thresholds.insert("Injection".into(), 0.5);
                self.confidence_thresholds.insert("WeakAuthentication".into(), 0.7);
                self.confidence_thresholds.insert("InsecureDesign".into(), 0.4);
            }
            FilterMode::Permissive => {
                // Lower thresholds to keep more findings
                self.confidence_thresholds.insert("HardcodedSecret".into(), 0.45);
                self.confidence_thresholds.insert("Injection".into(), 0.4);
                self.confidence_thresholds.insert("WeakAuthentication".into(), 0.6);
                self.confidence_thresholds.insert("InsecureDesign".into(), 0.3);
                for p in &mut self.false_positive_patterns {
                    // Slightly reduce pattern probability impact
                    p.probability = (p.probability - 0.1).max(0.4);
                }
            }
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

        // Check file-based patterns with higher priority
        for pattern in &self.false_positive_patterns {
            if self.matches_file_pattern(file_path, &pattern.file_patterns) {
                should_filter = true;
                confidence = pattern.probability;
                reason = pattern.reason.clone();
                adjustments.insert("file_pattern_match".to_string(), pattern.probability);
                break;
            }
        }

        // Check keyword-based patterns with context analysis
        if !should_filter {
            for pattern in &self.false_positive_patterns {
                if self.contains_keywords_with_context(code_snippet, &pattern.keywords) {
                    should_filter = true;
                    confidence = pattern.probability;
                    reason = pattern.reason.clone();
                    adjustments.insert("keyword_match".to_string(), pattern.probability);
                    break;
                }
            }
        }

        // Enhanced pattern combination analysis
        if !should_filter {
            let combined_score =
                self.analyze_pattern_combination(finding_type, file_path, code_snippet);
            if combined_score > 0.6 {
                should_filter = true;
                confidence = combined_score;
                reason = "Multiple false positive indicators detected".to_string();
                adjustments.insert("pattern_combination".to_string(), combined_score);
            }
        }

        // Check historical patterns
        let pattern_key = self.generate_pattern_key(finding_type, file_path, code_snippet);
        if let Some(stats) = self.get_pattern_stats(&pattern_key) {
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

        // Apply confidence adjustments based on finding type
        if let Some(base_threshold) = self.confidence_thresholds.get(finding_type) {
            if current_confidence < *base_threshold * 0.8 {
                let adjustment_factor = (1.0 - current_confidence / base_threshold).min(0.5);
                confidence = confidence.max(adjustment_factor);
                if !should_filter && adjustment_factor > 0.3 {
                    should_filter = true;
                    reason = format!("Low confidence finding ({:.2})", current_confidence);
                }
                adjustments.insert("low_confidence_penalty".to_string(), adjustment_factor);
            }
        }

        Ok(FilterResult {
            should_filter,
            confidence,
            reason,
            adjustments,
        })
    }

    /// Analyze combination of patterns for more accurate detection
    fn analyze_pattern_combination(
        &self,
        finding_type: &str,
        file_path: &str,
        code_snippet: &str,
    ) -> f64 {
        let mut score = 0.0;
        let mut indicators = 0;

        // File path indicators
        if file_path.contains("test") || file_path.contains("example") || file_path.contains("demo")
        {
            score += 0.3;
            indicators += 1;
        }

        // Code content indicators
        let snippet_lower = code_snippet.to_lowercase();
        if snippet_lower.contains("example") || snippet_lower.contains("sample") {
            score += 0.25;
            indicators += 1;
        }
        if snippet_lower.contains("your_") || snippet_lower.contains("placeholder") {
            score += 0.4;
            indicators += 1;
        }
        if snippet_lower.contains("todo") || snippet_lower.contains("fixme") {
            score += 0.35;
            indicators += 1;
        }

        // Context-based scoring
        if snippet_lower.contains("config") && snippet_lower.contains("const") {
            score += 0.2;
            indicators += 1;
        }

        // Finding type specific adjustments
        match finding_type {
            "HardcodedSecret" => {
                if snippet_lower.contains("api_key") && snippet_lower.contains("example") {
                    score += 0.5;
                }
            }
            "Injection" => {
                if snippet_lower.contains("test") && snippet_lower.contains("sql") {
                    score += 0.4;
                }
            }
            _ => {}
        }

        if indicators > 0 {
            score / indicators as f64
        } else {
            0.0
        }
    }

    /// Check if keywords are present with better context analysis
    fn contains_keywords_with_context(&self, text: &str, keywords: &[String]) -> bool {
        let text_lower = text.to_lowercase();

        for keyword in keywords {
            if text_lower.contains(&keyword.to_lowercase()) {
                // Check if the keyword appears in a meaningful context
                if self.is_meaningful_context(text, keyword) {
                    return true;
                }
            }
        }

        false
    }

    /// Determine if a keyword appears in a meaningful false positive context
    fn is_meaningful_context(&self, text: &str, keyword: &str) -> bool {
        let text_lower = text.to_lowercase();
        let keyword_lower = keyword.to_lowercase();

        // For logging keywords, check if they're actually used in logging calls
        if keyword_lower.contains("log") || keyword_lower.contains("println") {
            return text_lower.contains("log::")
                || text_lower.contains("println!")
                || text_lower.contains("eprintln!")
                || text_lower.contains("debug!")
                || text_lower.contains("info!");
        }

        // For comment keywords, check if they're in actual comments
        if keyword_lower == "//" || keyword_lower == "/*" || keyword_lower == "*/" {
            return text_lower.contains("//") || text_lower.contains("/*");
        }

        // For placeholder keywords, check for common patterns
        if keyword_lower == "your_" {
            return text_lower.contains("your_api")
                || text_lower.contains("your_secret")
                || text_lower.contains("your_token");
        }

        // Default to true for other keywords
        true
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
        let mut db = self.pattern_database.write().unwrap();

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
    fn get_pattern_stats(&self, pattern_key: &str) -> Option<PatternStats> {
        let db = self.pattern_database.read().unwrap();
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
        let db = self.pattern_database.read().unwrap();
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
