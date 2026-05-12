// rust_tree_sitter/src/security/accuracy_metrics.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents accuracy metrics for security analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyMetrics {
    pub true_positives: u32,
    pub false_positives: u32,
    pub true_negatives: u32,
    pub false_negatives: u32,
    pub total_samples: u32,
}

impl AccuracyMetrics {
    /// Create a new AccuracyMetrics instance with zero values
    pub fn new() -> Self {
        Self {
            true_positives: 0,
            false_positives: 0,
            true_negatives: 0,
            false_negatives: 0,
            total_samples: 0,
        }
    }

    /// Calculate precision (TP / (TP + FP))
    pub fn precision(&self) -> f64 {
        if self.true_positives + self.false_positives == 0 {
            0.0
        } else {
            self.true_positives as f64 / (self.true_positives + self.false_positives) as f64
        }
    }

    /// Calculate recall (TP / (TP + FN))
    pub fn recall(&self) -> f64 {
        if self.true_positives + self.false_negatives == 0 {
            0.0
        } else {
            self.true_positives as f64 / (self.true_positives + self.false_negatives) as f64
        }
    }

    /// Calculate F1 score (2 * precision * recall / (precision + recall))
    pub fn f1_score(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }

    /// Calculate false positive rate (FP / (FP + TN))
    pub fn false_positive_rate(&self) -> f64 {
        if self.false_positives + self.true_negatives == 0 {
            0.0
        } else {
            self.false_positives as f64 / (self.false_positives + self.true_negatives) as f64
        }
    }

    /// Calculate overall accuracy ((TP + TN) / total_samples)
    pub fn accuracy(&self) -> f64 {
        if self.total_samples == 0 {
            0.0
        } else {
            (self.true_positives + self.true_negatives) as f64 / self.total_samples as f64
        }
    }

    /// Update metrics with a new sample
    pub fn update(&mut self, is_positive: bool, is_actual_positive: bool) {
        self.total_samples += 1;
        if is_positive && is_actual_positive {
            self.true_positives += 1;
        } else if is_positive && !is_actual_positive {
            self.false_positives += 1;
        } else if !is_positive && is_actual_positive {
            self.false_negatives += 1;
        } else {
            self.true_negatives += 1;
        }
    }

    /// Calculate accuracy metrics from findings (placeholder implementation)
    pub fn calculate(_findings: &[SecurityFinding]) -> Self {
        // Placeholder: In a real implementation, this would analyze findings
        // against known ground truth to calculate true/false positives
        Self::new()
    }
}

/// Comprehensive security analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalysisReport {
    pub timestamp: DateTime<Utc>,
    pub metrics: AccuracyMetrics,
    pub findings: Vec<SecurityFinding>,
    pub summary: String,
}

impl SecurityAnalysisReport {
    /// Create a new report
    pub fn new(metrics: AccuracyMetrics, findings: Vec<SecurityFinding>, summary: String) -> Self {
        Self {
            timestamp: Utc::now(),
            metrics,
            findings,
            summary,
        }
    }

    /// Serialize report to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Generate a human-readable text report
    pub fn generate_text_report(&self) -> String {
        format!(
            "Security Analysis Report\n\
            Timestamp: {}\n\
            \n\
            Metrics:\n\
            - Precision: {:.2}%\n\
            - Recall: {:.2}%\n\
            - F1 Score: {:.2}%\n\
            - False Positive Rate: {:.2}%\n\
            - Accuracy: {:.2}%\n\
            \n\
            Total Findings: {}\n\
            \n\
            Summary:\n\
            {}\n",
            self.timestamp,
            self.metrics.precision() * 100.0,
            self.metrics.recall() * 100.0,
            self.metrics.f1_score() * 100.0,
            self.metrics.false_positive_rate() * 100.0,
            self.metrics.accuracy() * 100.0,
            self.findings.len(),
            self.summary
        )
    }
}

/// Placeholder for SecurityFinding - should be defined in the main security module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub severity: String,
    pub description: String,
    pub location: String,
    pub cwe_id: Option<String>,
    pub confidence: f64,
}
