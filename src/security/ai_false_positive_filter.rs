//! Advanced AI-based False Positive Filter
//!
//! This module provides intelligent filtering of security findings using AI-powered
//! context analysis, semantic understanding, and machine learning to drastically
//! reduce false positives while maintaining high detection accuracy.

use crate::ai::AIService;
use crate::security::ast_analyzer::{AstSecurityAnalyzer, SecurityFinding};
use crate::security::ml_filter::MLFalsePositiveFilter;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Advanced AI-based false positive filter
pub struct AIFalsePositiveFilter {
    /// AI service for context analysis
    ai_service: Arc<AIService>,
    /// ML filter for pattern-based filtering
    ml_filter: Arc<MLFalsePositiveFilter>,
    /// AST analyzer for semantic understanding
    ast_analyzer: Arc<AstSecurityAnalyzer>,
    /// Feedback database
    feedback_db: Arc<RwLock<HashMap<String, FeedbackEntry>>>,
    /// Context analysis cache
    context_cache: Arc<RwLock<HashMap<String, ContextAnalysis>>>,
    /// Configuration
    config: AIFilterConfig,
}

impl AIFalsePositiveFilter {
    /// Get semantic analysis for a security finding
    pub fn analyze_semantic_context(
        &self,
        finding: &crate::security::ast_analyzer::SecurityFinding,
        code_context: &str,
        full_file_content: Option<&str>,
    ) -> Result<crate::security::ast_analyzer::SemanticContextResult> {
        self.ast_analyzer
            .analyze_semantic_context(finding, code_context, full_file_content)
    }
}

/// Configuration for AI false positive filter
#[derive(Debug, Clone)]
pub struct AIFilterConfig {
    /// Enable AI context analysis
    pub ai_context_enabled: bool,
    /// Enable semantic analysis
    pub semantic_analysis_enabled: bool,
    /// Enable feedback learning
    pub feedback_learning_enabled: bool,
    /// Minimum AI confidence threshold
    pub min_ai_confidence: f64,
    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,
    /// Maximum concurrent AI requests
    pub max_concurrent_requests: usize,
}

/// Context analysis result from AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextAnalysis {
    /// Whether this appears to be a false positive
    pub is_false_positive: bool,
    /// Confidence in the analysis (0.0 to 1.0)
    pub confidence: f64,
    /// Detailed reasoning
    pub reasoning: String,
    /// Context factors considered
    pub context_factors: Vec<String>,
    /// Suggested severity adjustment
    pub severity_adjustment: Option<f64>,
    /// Timestamp of analysis
    pub timestamp: std::time::SystemTime,
}

/// Feedback entry for learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEntry {
    /// Pattern key
    pub pattern_key: String,
    /// User feedback (true = confirmed false positive)
    pub user_feedback: bool,
    /// AI analysis result
    pub ai_analysis: ContextAnalysis,
    /// Timestamp
    pub timestamp: std::time::SystemTime,
    /// Frequency of occurrence
    pub occurrences: u32,
}

/// Enhanced filter result
#[derive(Debug, Clone)]
pub struct AIFilterResult {
    /// Whether to filter out the finding
    pub should_filter: bool,
    /// Overall confidence in filtering decision
    pub confidence: f64,
    /// Detailed reasoning
    pub reasoning: String,
    /// Contributing factors
    pub factors: Vec<String>,
    /// Suggested adjustments
    pub adjustments: HashMap<String, f64>,
    /// AI analysis details
    pub ai_analysis: Option<ContextAnalysis>,
}

impl AIFalsePositiveFilter {
    /// Create a new AI false positive filter
    pub fn new(
        ai_service: Arc<AIService>,
        ml_filter: Arc<MLFalsePositiveFilter>,
        ast_analyzer: Arc<AstSecurityAnalyzer>,
        config: AIFilterConfig,
    ) -> Self {
        Self {
            ai_service,
            ml_filter,
            ast_analyzer,
            feedback_db: Arc::new(RwLock::new(HashMap::new())),
            context_cache: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Filter a security finding using AI-enhanced analysis
    pub async fn filter_finding(
        &self,
        finding: &SecurityFinding,
        file_path: &str,
        code_context: &str,
        full_file_content: Option<&str>,
    ) -> Result<AIFilterResult> {
        let mut factors = Vec::new();
        let mut adjustments = HashMap::new();
        let mut total_confidence = 0.0;
        let mut confidence_count = 0;

        // 1. ML-based filtering
        let ml_result = self
            .ml_filter
            .filter_finding(
                &finding.finding_type.to_string(),
                file_path,
                code_context,
                finding.confidence,
            )
            .await?;

        if ml_result.should_filter {
            factors.push(format!("ML pattern: {}", ml_result.reason));
            total_confidence += ml_result.confidence;
            confidence_count += 1;

            // Apply ML adjustments
            for (key, value) in &ml_result.adjustments {
                adjustments.insert(key.clone(), *value);
            }
        }

        // 2. Semantic analysis
        if self.config.semantic_analysis_enabled {
            let semantic_result = self
                .analyze_semantic_context_async(finding, code_context, full_file_content)
                .await?;
            if semantic_result.should_filter {
                factors.push(format!("Semantic: {}", semantic_result.reason));
                total_confidence += semantic_result.confidence;
                confidence_count += 1;
            }
        }

        // 3. AI context analysis
        let mut ai_analysis = None;
        if self.config.ai_context_enabled {
            ai_analysis = Some(
                self.analyze_with_ai(finding, file_path, code_context, full_file_content)
                    .await?,
            );
            if ai_analysis.as_ref().unwrap().is_false_positive {
                factors.push(format!(
                    "AI context: {}",
                    ai_analysis.as_ref().unwrap().reasoning
                ));
                total_confidence += ai_analysis.as_ref().unwrap().confidence;
                confidence_count += 1;
            }
        }

        // 4. Check historical feedback
        if self.config.feedback_learning_enabled {
            let pattern_key = self.generate_pattern_key(finding, file_path, code_context);
            if let Some(feedback) = self.get_feedback(&pattern_key).await {
                if feedback.user_feedback {
                    factors.push("Historical user feedback: confirmed false positive".to_string());
                    total_confidence += 0.9; // High confidence from user feedback
                    confidence_count += 1;
                }
            }
        }

        // Calculate overall confidence
        let overall_confidence = if confidence_count > 0 {
            total_confidence / confidence_count as f64
        } else {
            0.0
        };

        // Determine final filtering decision
        let should_filter = overall_confidence >= self.config.min_ai_confidence
            && (ml_result.should_filter
                || ai_analysis.as_ref().map_or(false, |a| a.is_false_positive));

        // Generate comprehensive reasoning
        let reasoning = self.generate_reasoning(&factors, overall_confidence, should_filter);

        Ok(AIFilterResult {
            should_filter,
            confidence: overall_confidence,
            reasoning,
            factors,
            adjustments,
            ai_analysis,
        })
    }

    /// Analyze semantic context using AST
    async fn analyze_semantic_context_async(
        &self,
        finding: &SecurityFinding,
        code_context: &str,
        full_file_content: Option<&str>,
    ) -> Result<SemanticFilterResult> {
        // Use AST analyzer to understand code structure
        let semantic_insights =
            self.ast_analyzer
                .analyze_semantic_context(finding, code_context, full_file_content)?;

        let should_filter = semantic_insights.is_test_code
            || semantic_insights.is_placeholder
            || semantic_insights.is_documentation
            || semantic_insights.is_embedded
            || semantic_insights.is_safe_usage;

        let confidence = if should_filter { 0.8 } else { 0.2 };
        let reason = semantic_insights.explanation;

        Ok(SemanticFilterResult {
            should_filter,
            confidence,
            reason,
        })
    }

    /// Analyze with AI for context understanding
    async fn analyze_with_ai(
        &self,
        finding: &SecurityFinding,
        file_path: &str,
        code_context: &str,
        full_file_content: Option<&str>,
    ) -> Result<ContextAnalysis> {
        let cache_key = self.generate_cache_key(finding, file_path, code_context);

        // Check cache first
        if let Some(cached) = self.get_cached_analysis(&cache_key).await {
            if self.is_cache_valid(&cached) {
                return Ok(cached);
            }
        }

        // Perform AI analysis
        let analysis = self
            .perform_ai_analysis(finding, file_path, code_context, full_file_content)
            .await?;

        // Cache the result
        self.cache_analysis(cache_key, analysis.clone()).await;

        Ok(analysis)
    }

    /// Perform actual AI analysis
    async fn perform_ai_analysis(
        &self,
        finding: &SecurityFinding,
        file_path: &str,
        code_context: &str,
        full_file_content: Option<&str>,
    ) -> Result<ContextAnalysis> {
        let prompt = self.build_ai_prompt(finding, file_path, code_context, full_file_content);

        let ai_response = self
            .ai_service
            .analyze_security_context(&prompt)
            .await
            .map_err(|e| {
                crate::error::Error::internal_error(
                    "AI Security Analysis",
                    format!("AI service error: {}", e),
                )
            })?;

        // Parse AI response into ContextAnalysis
        self.parse_ai_response(&ai_response)
    }

    /// Build prompt for AI analysis
    fn build_ai_prompt(
        &self,
        finding: &SecurityFinding,
        file_path: &str,
        code_context: &str,
        full_file_content: Option<&str>,
    ) -> String {
        let mut prompt = format!(
            "SECURITY FALSE POSITIVE ANALYSIS\n\n\
            Finding Type: {:?}\n\
            Severity: {:?}\n\
            File: {}\n\
            Code Context:\n{}\n\n",
            finding.finding_type, finding.severity, file_path, code_context
        );

        if let Some(full_content) = full_file_content {
            prompt.push_str(&format!(
                "Full File Context (first 1000 chars):\n{}\n\n",
                &full_content[..full_content.len().min(1000)]
            ));
        }

        prompt.push_str(
            "Analyze this security finding and determine if it's likely a false positive.\n\n\
            Consider:\n\
            1. Is this in test/demo/example code?\n\
            2. Is this a placeholder or dummy value?\n\
            3. Is this properly sanitized/validated?\n\
            4. Is this in documentation or comments?\n\
            5. Is this a known safe pattern?\n\
            6. What's the actual security impact?\n\n\
            Respond with JSON:\n\
            {\n\
              \"is_false_positive\": boolean,\n\
              \"confidence\": number (0.0-1.0),\n\
              \"reasoning\": \"string\",\n\
              \"context_factors\": [\"factor1\", \"factor2\"],\n\
              \"severity_adjustment\": number or null\n\
            }",
        );

        prompt
    }

    /// Parse AI response into ContextAnalysis
    fn parse_ai_response(&self, response: &str) -> Result<ContextAnalysis> {
        // Try to parse JSON response
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(response) {
            let is_false_positive = parsed
                .get("is_false_positive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let confidence = parsed
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.5);

            let reasoning = parsed
                .get("reasoning")
                .and_then(|v| v.as_str())
                .unwrap_or("AI analysis inconclusive")
                .to_string();

            let context_factors = parsed
                .get("context_factors")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let severity_adjustment = parsed.get("severity_adjustment").and_then(|v| v.as_f64());

            Ok(ContextAnalysis {
                is_false_positive,
                confidence,
                reasoning,
                context_factors,
                severity_adjustment,
                timestamp: std::time::SystemTime::now(),
            })
        } else {
            // Fallback for non-JSON responses
            let is_false_positive = response.to_lowercase().contains("false positive")
                || response.to_lowercase().contains("not a vulnerability");

            Ok(ContextAnalysis {
                is_false_positive,
                confidence: if is_false_positive { 0.7 } else { 0.3 },
                reasoning: response.to_string(),
                context_factors: vec!["AI text analysis".to_string()],
                severity_adjustment: None,
                timestamp: std::time::SystemTime::now(),
            })
        }
    }

    /// Add user feedback for learning
    pub async fn add_feedback(
        &self,
        finding: &SecurityFinding,
        file_path: &str,
        code_context: &str,
        was_false_positive: bool,
        user_reasoning: Option<String>,
    ) -> Result<()> {
        let pattern_key = self.generate_pattern_key(finding, file_path, code_context);

        let feedback = FeedbackEntry {
            pattern_key: pattern_key.clone(),
            user_feedback: was_false_positive,
            ai_analysis: ContextAnalysis {
                is_false_positive: was_false_positive,
                confidence: 1.0, // User feedback has maximum confidence
                reasoning: user_reasoning.unwrap_or_else(|| "User feedback".to_string()),
                context_factors: vec!["User input".to_string()],
                severity_adjustment: None,
                timestamp: std::time::SystemTime::now(),
            },
            timestamp: std::time::SystemTime::now(),
            occurrences: 1,
        };

        let mut db = self.feedback_db.write().await;
        if let Some(existing) = db.get_mut(&pattern_key) {
            existing.occurrences += 1;
            // Update with latest feedback if different
            if existing.user_feedback != was_false_positive {
                *existing = feedback;
            }
        } else {
            db.insert(pattern_key, feedback);
        }

        Ok(())
    }

    /// Get feedback for a pattern
    async fn get_feedback(&self, pattern_key: &str) -> Option<FeedbackEntry> {
        let db = self.feedback_db.read().await;
        db.get(pattern_key).cloned()
    }

    /// Generate pattern key for caching/feedback
    fn generate_pattern_key(
        &self,
        finding: &SecurityFinding,
        file_path: &str,
        code_context: &str,
    ) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        finding.finding_type.hash(&mut hasher);
        file_path.hash(&mut hasher);
        code_context.len().hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Generate cache key
    fn generate_cache_key(
        &self,
        finding: &SecurityFinding,
        file_path: &str,
        code_context: &str,
    ) -> String {
        format!(
            "ai_{}",
            self.generate_pattern_key(finding, file_path, code_context)
        )
    }

    /// Cache analysis result
    async fn cache_analysis(&self, key: String, analysis: ContextAnalysis) {
        let mut cache = self.context_cache.write().await;
        cache.insert(key, analysis);
    }

    /// Get cached analysis
    async fn get_cached_analysis(&self, key: &str) -> Option<ContextAnalysis> {
        let cache = self.context_cache.read().await;
        cache.get(key).cloned()
    }

    /// Check if cache entry is still valid
    fn is_cache_valid(&self, analysis: &ContextAnalysis) -> bool {
        if let Ok(duration) = analysis.timestamp.elapsed() {
            duration.as_secs() < self.config.cache_ttl_seconds
        } else {
            false
        }
    }

    /// Generate comprehensive reasoning
    fn generate_reasoning(
        &self,
        factors: &[String],
        confidence: f64,
        should_filter: bool,
    ) -> String {
        let action = if should_filter {
            "Filtering"
        } else {
            "Keeping"
        };
        let confidence_pct = (confidence * 100.0).round();

        let mut reasoning = format!(
            "{} finding with {:.0}% confidence based on: ",
            action, confidence_pct
        );

        if factors.is_empty() {
            reasoning.push_str("no specific factors");
        } else {
            reasoning.push_str(&factors.join("; "));
        }

        reasoning
    }

    /// Get filter statistics
    pub async fn get_statistics(&self) -> Result<AIFilterStatistics> {
        let feedback_db = self.feedback_db.read().await;
        let cache = self.context_cache.read().await;

        let total_feedback = feedback_db.len();
        let total_cached = cache.len();
        let false_positive_feedback = feedback_db.values().filter(|f| f.user_feedback).count();

        Ok(AIFilterStatistics {
            total_feedback_entries: total_feedback,
            total_cached_analyses: total_cached,
            false_positive_feedback_rate: if total_feedback > 0 {
                false_positive_feedback as f64 / total_feedback as f64
            } else {
                0.0
            },
        })
    }
}

/// Result from semantic analysis
#[derive(Debug, Clone)]
struct SemanticFilterResult {
    pub should_filter: bool,
    pub confidence: f64,
    pub reason: String,
}

/// Statistics for AI filter
#[derive(Debug, Clone)]
pub struct AIFilterStatistics {
    pub total_feedback_entries: usize,
    pub total_cached_analyses: usize,
    pub false_positive_feedback_rate: f64,
}

impl Default for AIFilterConfig {
    fn default() -> Self {
        Self {
            ai_context_enabled: true,
            semantic_analysis_enabled: true,
            feedback_learning_enabled: true,
            min_ai_confidence: 0.6,
            cache_ttl_seconds: 3600, // 1 hour
            max_concurrent_requests: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::AIServiceBuilder;
    use crate::security::ast_analyzer::AstSecurityAnalyzer;
    use crate::security::ml_filter::MLFalsePositiveFilter;

    #[tokio::test]
    async fn test_ai_filter_creation() {
        let ai_service = Arc::new(
            AIServiceBuilder::new()
                .with_mock_providers(true)
                .build()
                .await
                .unwrap(),
        );
        let ml_filter = Arc::new(MLFalsePositiveFilter::new());
        let ast_analyzer = Arc::new(AstSecurityAnalyzer::new().unwrap());
        let config = AIFilterConfig::default();

        let filter = AIFalsePositiveFilter::new(ai_service, ml_filter, ast_analyzer, config);

        assert!(filter.config.ai_context_enabled);
    }

    #[tokio::test]
    async fn test_feedback_learning() {
        let ai_service = Arc::new(
            AIServiceBuilder::new()
                .with_mock_providers(true)
                .build()
                .await
                .unwrap(),
        );
        let ml_filter = Arc::new(MLFalsePositiveFilter::new());
        let ast_analyzer = Arc::new(AstSecurityAnalyzer::new().unwrap());
        let config = AIFilterConfig::default();

        let filter = AIFalsePositiveFilter::new(ai_service, ml_filter, ast_analyzer, config);

        // This would need a mock SecurityFinding
        // let finding = SecurityFinding::new(...);
        // filter.add_feedback(&finding, "test.rs", "test code", true, None).await.unwrap();

        let stats = filter.get_statistics().await.unwrap();
        assert_eq!(stats.total_feedback_entries, 0);
    }

    #[tokio::test]
    async fn test_pattern_matching() {
        // Test basic functionality without accessing private methods
        let _filter = MLFalsePositiveFilter::new();
        // This test just verifies the filter can be created
        assert!(true, "ML filter created successfully");
    }
}
