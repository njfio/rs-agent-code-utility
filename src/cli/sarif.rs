//! SARIF 2.1.0 minimal serializer and converter
//! Pure functions to convert AnalysisResult into SARIF for tool integrations.

use serde::Serialize;

use crate::{AnalysisResult};
use crate::advanced_security::{SecuritySeverity, OwaspCategory};

#[derive(Debug, Clone, Serialize)]
pub struct SarifLog {
    pub version: String,
    pub runs: Vec<Run>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<ResultItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub driver: Driver,
}

#[derive(Debug, Clone, Serialize)]
pub struct Driver {
    pub name: String,
    pub version: Option<String>,
    pub information_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResultItem {
    #[serde(rename = "ruleId")]
    pub rule_id: Option<String>,
    pub level: Option<&'static str>,
    pub message: Message,
    pub locations: Vec<Location>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Location {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
}

#[derive(Debug, Clone, Serialize)]
pub struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    pub region: Option<Region>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Region {
    #[serde(rename = "startLine")]
    pub start_line: u64,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u64>,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u64>,
}

fn map_severity(sev: &SecuritySeverity) -> &'static str {
    match sev {
        SecuritySeverity::Critical | SecuritySeverity::High => "error",
        SecuritySeverity::Medium => "warning",
        SecuritySeverity::Low | SecuritySeverity::Info => "note",
    }
}

fn owasp_to_str(cat: &OwaspCategory) -> &'static str {
    match cat {
        OwaspCategory::BrokenAccessControl => "OWASP:A01:BrokenAccessControl",
        OwaspCategory::CryptographicFailures => "OWASP:A02:CryptographicFailures",
        OwaspCategory::Injection => "OWASP:A03:Injection",
        OwaspCategory::InsecureDesign => "OWASP:A04:InsecureDesign",
        OwaspCategory::SecurityMisconfiguration => "OWASP:A05:SecurityMisconfiguration",
        OwaspCategory::VulnerableComponents => "OWASP:A06:VulnerableComponents",
        OwaspCategory::AuthenticationFailures => "OWASP:A07:AuthenticationFailures",
        OwaspCategory::IntegrityFailures => "OWASP:A08:IntegrityFailures",
        OwaspCategory::LoggingFailures => "OWASP:A09:LoggingFailures",
        OwaspCategory::SSRF => "OWASP:A10:SSRF",
    }
}

/// Convert AnalysisResult to minimal SARIF log
pub fn to_sarif(result: &AnalysisResult) -> SarifLog {
    let tool = Tool {
        driver: Driver {
            name: "rust-tree-sitter".to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            information_uri: Some("https://github.com/".to_string()),
        },
    };

    let mut sarif_results: Vec<ResultItem> = Vec::new();

    for file in &result.files {
        for vuln in &file.security_vulnerabilities {
            let rule_id = vuln.cwe_id.clone().or_else(|| Some(owasp_to_str(&vuln.owasp_category).to_string()));
            let level = Some(map_severity(&vuln.severity));
            let message = Message { text: format!("{}: {}", vuln.title, vuln.description) };
            let uri = file.path.to_string_lossy().to_string();
            let region = Region {
                start_line: vuln.location.start_line as u64,
                end_line: Some(vuln.location.end_line as u64),
                start_column: Some(vuln.location.column as u64),
            };
            let loc = Location { physical_location: PhysicalLocation { artifact_location: ArtifactLocation { uri }, region: Some(region) } };

            sarif_results.push(ResultItem { rule_id, level, message, locations: vec![loc] });
        }
    }

    SarifLog { version: "2.1.0".to_string(), runs: vec![Run { tool, results: sarif_results }] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnalysisResult, AnalysisConfig, FileInfo};
    use crate::advanced_security::{SecurityVulnerability, VulnerabilityLocation, SecuritySeverity, OwaspCategory, SecurityImpact, ImpactLevel, RemediationGuidance, CodeExample, RemediationEffort, ConfidenceLevel};

    #[test]
    fn sarif_conversion_includes_one_result_per_vulnerability() {
        let mut res = AnalysisResult::new();
        res.root_path = std::path::PathBuf::from("/tmp");
        res.config = AnalysisConfig::default();
        let vuln = SecurityVulnerability {
            id: "ID".to_string(),
            title: "Test".to_string(),
            description: "Desc".to_string(),
            severity: SecuritySeverity::Medium,
            owasp_category: OwaspCategory::Injection,
            cwe_id: None,
            location: VulnerabilityLocation { file: std::path::PathBuf::from("a.rs"), function: None, start_line: 1, end_line: 2, column: 0 },
            code_snippet: "".to_string(),
            impact: SecurityImpact { confidentiality: ImpactLevel::Low, integrity: ImpactLevel::Low, availability: ImpactLevel::Low, overall_score: 1.0 },
            remediation: RemediationGuidance { summary: "".to_string(), steps: vec![], code_examples: vec![CodeExample { description: "".to_string(), vulnerable_code: "".to_string(), secure_code: "".to_string(), language: "Rust".to_string() }], references: vec![], effort: RemediationEffort::Low },
            confidence: ConfidenceLevel::Medium,
        };
        let file = FileInfo { path: std::path::PathBuf::from("a.rs"), language: "Rust".to_string(), size: 1, lines: 1, parsed_successfully: true, parse_errors: vec![], symbols: vec![], security_vulnerabilities: vec![vuln] };
        res.files.push(file);

        let sarif = to_sarif(&res);
        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].results.len(), 1);
        assert_eq!(sarif.runs[0].results[0].level, Some("warning"));
    }
}

