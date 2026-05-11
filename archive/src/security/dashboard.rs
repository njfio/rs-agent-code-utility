use crate::security::accuracy_metrics::AccuracyMetrics;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security Dashboard for generating comprehensive analysis reports
pub struct SecurityDashboard;

/// Report format for dashboard output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardReport {
    pub timestamp: String,
    pub summary: DashboardSummary,
    pub metrics: AccuracyMetrics,
    pub findings_by_severity: HashMap<String, usize>,
    pub findings_by_type: HashMap<String, usize>,
    pub top_vulnerabilities: Vec<VulnerabilitySummary>,
    pub recommendations: Vec<String>,
}

/// Summary statistics for the dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub total_files_analyzed: usize,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub info_findings: usize,
    pub analysis_duration_ms: u64,
}

/// Summary of a vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilitySummary {
    pub vulnerability_type: String,
    pub severity: String,
    pub count: usize,
    pub cwe_id: Option<String>,
    pub description: String,
}

impl SecurityDashboard {
    /// Generate a comprehensive dashboard report from analysis results
    pub fn generate_report(
        findings: &[crate::security::SecurityFinding],
        analysis_duration: std::time::Duration,
        total_files: usize,
    ) -> DashboardReport {
        let timestamp = chrono::Utc::now().to_rfc3339();

        // Calculate summary statistics
        let total_findings = findings.len();
        let mut findings_by_severity = HashMap::new();
        let mut findings_by_type = HashMap::new();
        let mut top_vulnerabilities = Vec::new();

        for finding in findings {
            // Count by severity
            let severity_str = format!("{:?}", finding.severity);
            *findings_by_severity
                .entry(severity_str.clone())
                .or_insert(0) += 1;

            // Count by type
            let type_str = format!("{:?}", finding.finding_type);
            *findings_by_type.entry(type_str).or_insert(0) += 1;
        }

        // Calculate severity counts
        let critical_findings = findings_by_severity.get("Critical").unwrap_or(&0).clone();
        let high_findings = findings_by_severity.get("High").unwrap_or(&0).clone();
        let medium_findings = findings_by_severity.get("Medium").unwrap_or(&0).clone();
        let low_findings = findings_by_severity.get("Low").unwrap_or(&0).clone();
        let info_findings = findings_by_severity.get("Info").unwrap_or(&0).clone();

        let summary = DashboardSummary {
            total_files_analyzed: total_files,
            total_findings,
            critical_findings,
            high_findings,
            medium_findings,
            low_findings,
            info_findings,
            analysis_duration_ms: analysis_duration.as_millis() as u64,
        };

        // Generate top vulnerabilities summary
        for (vuln_type, count) in findings_by_type.iter() {
            if *count > 0 {
                top_vulnerabilities.push(VulnerabilitySummary {
                    vulnerability_type: vuln_type.clone(),
                    severity: "High".to_string(), // This would be determined from actual findings
                    count: *count,
                    cwe_id: None, // Would be populated from correlation engine
                    description: format!("{} vulnerability detected", vuln_type),
                });
            }
        }

        // Sort by count descending
        top_vulnerabilities.sort_by(|a, b| b.count.cmp(&a.count));
        top_vulnerabilities.truncate(10); // Top 10

        // Generate recommendations
        let mut recommendations = Vec::new();
        if critical_findings > 0 {
            recommendations.push("Immediate attention required for critical findings".to_string());
        }
        if total_findings > 100 {
            recommendations.push(
                "Consider breaking down large codebases into smaller analysis units".to_string(),
            );
        }
        if summary.false_positive_rate() > 0.2 {
            recommendations
                .push("Review and tune detection rules to reduce false positives".to_string());
        }

        // Calculate accuracy metrics (placeholder - would need labeled data)
        let metrics = AccuracyMetrics::new();

        DashboardReport {
            timestamp,
            summary,
            metrics,
            findings_by_severity,
            findings_by_type,
            top_vulnerabilities,
            recommendations,
        }
    }

    /// Generate a human-readable text report
    pub fn generate_text_report(report: &DashboardReport) -> String {
        let mut output = String::new();

        output.push_str(&format!("Security Analysis Dashboard Report\n"));
        output.push_str(&format!("Generated: {}\n\n", report.timestamp));

        output.push_str("SUMMARY\n");
        output.push_str(&format!(
            "Total Files Analyzed: {}\n",
            report.summary.total_files_analyzed
        ));
        output.push_str(&format!(
            "Total Findings: {}\n",
            report.summary.total_findings
        ));
        output.push_str(&format!(
            "Analysis Duration: {} ms\n\n",
            report.summary.analysis_duration_ms
        ));

        output.push_str("FINDINGS BY SEVERITY\n");
        output.push_str(&format!("Critical: {}\n", report.summary.critical_findings));
        output.push_str(&format!("High: {}\n", report.summary.high_findings));
        output.push_str(&format!("Medium: {}\n", report.summary.medium_findings));
        output.push_str(&format!("Low: {}\n", report.summary.low_findings));
        output.push_str(&format!("Info: {}\n\n", report.summary.info_findings));

        output.push_str("ACCURACY METRICS\n");
        output.push_str(&format!(
            "True Positive Rate: {:.2}%\n",
            report.metrics.recall() * 100.0
        ));
        output.push_str(&format!(
            "False Positive Rate: {:.2}%\n",
            report.metrics.false_positive_rate() * 100.0
        ));
        output.push_str(&format!(
            "Precision: {:.2}%\n",
            report.metrics.precision() * 100.0
        ));
        output.push_str(&format!(
            "Recall: {:.2}%\n",
            report.metrics.recall() * 100.0
        ));
        output.push_str(&format!(
            "F1 Score: {:.2}%\n",
            report.metrics.f1_score() * 100.0
        ));

        if !report.top_vulnerabilities.is_empty() {
            output.push_str("TOP VULNERABILITIES\n");
            for vuln in &report.top_vulnerabilities {
                output.push_str(&format!(
                    "- {} ({}): {}\n",
                    vuln.vulnerability_type, vuln.severity, vuln.count
                ));
            }
            output.push('\n');
        }

        if !report.recommendations.is_empty() {
            output.push_str("RECOMMENDATIONS\n");
            for rec in &report.recommendations {
                output.push_str(&format!("- {}\n", rec));
            }
        }

        output
    }

    /// Generate JSON report
    pub fn generate_json_report(report: &DashboardReport) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(report)
    }
}

impl DashboardSummary {
    /// Calculate false positive rate estimate
    pub fn false_positive_rate(&self) -> f64 {
        // This is a simplified estimate - in practice, would need labeled data
        if self.total_findings == 0 {
            0.0
        } else {
            // Assume 20% of findings in test code are false positives
            0.2
        }
    }
}
