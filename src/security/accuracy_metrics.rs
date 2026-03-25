use super::ast_analyzer::SecurityFinding;
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

/// Ground-truth sample used for accuracy calculations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ClassificationSample {
    pub detected: bool,
    pub actual_positive: bool,
}

impl Default for AccuracyMetrics {
    fn default() -> Self {
        Self::new()
    }
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

    /// Calculate accuracy metrics from labeled samples.
    pub fn from_classification_samples(samples: &[ClassificationSample]) -> Self {
        let mut metrics = Self::new();
        for sample in samples {
            metrics.update(sample.detected, sample.actual_positive);
        }
        metrics
    }
}

/// Comprehensive security analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalysisReport {
    pub timestamp: String,
    pub metrics: AccuracyMetrics,
    pub findings: Vec<SecurityFinding>,
    pub summary: String,
}

impl SecurityAnalysisReport {
    /// Create a new report
    pub fn new(metrics: AccuracyMetrics, findings: Vec<SecurityFinding>, summary: String) -> Self {
        Self {
            timestamp: crate::current_timestamp_rfc3339(),
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
        if self.metrics.total_samples == 0 {
            return format!(
                "Security Analysis Report\n\
                Timestamp: {}\n\
                \n\
                Metrics:\n\
                - Accuracy metrics unavailable without labeled ground truth samples\n\
                \n\
                Total Findings: {}\n\
                \n\
                Summary:\n\
                {}\n",
                self.timestamp,
                self.findings.len(),
                self.summary
            );
        }

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

#[cfg(test)]
mod tests {
    use super::{AccuracyMetrics, ClassificationSample, SecurityAnalysisReport};

    #[test]
    fn metrics_can_be_built_from_labeled_samples() {
        let samples = [
            ClassificationSample {
                detected: true,
                actual_positive: true,
            },
            ClassificationSample {
                detected: true,
                actual_positive: false,
            },
            ClassificationSample {
                detected: false,
                actual_positive: true,
            },
            ClassificationSample {
                detected: false,
                actual_positive: false,
            },
        ];

        let metrics = AccuracyMetrics::from_classification_samples(&samples);
        assert_eq!(metrics.true_positives, 1);
        assert_eq!(metrics.false_positives, 1);
        assert_eq!(metrics.false_negatives, 1);
        assert_eq!(metrics.true_negatives, 1);
        assert_eq!(metrics.total_samples, 4);
    }

    #[test]
    fn report_text_is_honest_without_labels() {
        let report = SecurityAnalysisReport::new(AccuracyMetrics::new(), Vec::new(), "ok".into());
        let text = report.generate_text_report();
        assert!(text.contains("unavailable without labeled ground truth samples"));
    }
}
