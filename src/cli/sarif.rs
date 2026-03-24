//! SARIF 2.1.0 and Code Climate serializers for CLI security integrations.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

use crate::advanced_security::{ConfidenceLevel, OwaspCategory, SecuritySeverity};
use crate::AnalysisResult;

pub const SARIF_SCHEMA_URL: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

#[derive(Debug, Clone, Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<Run>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<ResultItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invocations: Vec<Invocation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Invocation {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub driver: Driver,
}

#[derive(Debug, Clone, Serialize)]
pub struct Driver {
    pub name: String,
    pub version: Option<String>,
    #[serde(rename = "informationUri", skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RuleDescriptor>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleDescriptor {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: Message,
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    pub full_description: Option<Message>,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<RuleProperties>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleProperties {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResultItem {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex", skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<usize>,
    pub level: Option<&'static str>,
    pub message: Message,
    pub locations: Vec<Location>,
    #[serde(rename = "partialFingerprints")]
    pub partial_fingerprints: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ResultProperties>,
    #[serde(rename = "baselineState", skip_serializing_if = "Option::is_none")]
    pub baseline_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressions: Option<Vec<Suppression>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResultProperties {
    #[serde(rename = "security-severity")]
    pub security_severity: String,
    pub confidence: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub remediation: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    pub owasp: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Suppression {
    pub kind: String,
    pub justification: String,
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

#[derive(Debug, Clone, Serialize)]
pub struct CodeClimateIssue {
    #[serde(rename = "type")]
    pub issue_type: String,
    pub check_name: String,
    pub description: String,
    pub categories: Vec<String>,
    pub severity: &'static str,
    pub fingerprint: String,
    pub location: CodeClimateLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<CodeClimateContent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeClimateLocation {
    pub path: String,
    pub lines: CodeClimateLines,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeClimateLines {
    pub begin: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeClimateContent {
    pub body: String,
}

fn map_severity(sev: &SecuritySeverity) -> &'static str {
    match sev {
        SecuritySeverity::Critical | SecuritySeverity::High => "error",
        SecuritySeverity::Medium => "warning",
        SecuritySeverity::Low | SecuritySeverity::Info => "note",
    }
}

fn confidence_label(confidence: &ConfidenceLevel) -> &'static str {
    match confidence {
        ConfidenceLevel::High => "high",
        ConfidenceLevel::Medium => "medium",
        ConfidenceLevel::Low => "low",
    }
}

fn codeclimate_severity(sev: &SecuritySeverity) -> &'static str {
    match sev {
        SecuritySeverity::Critical => "critical",
        SecuritySeverity::High | SecuritySeverity::Medium => "major",
        SecuritySeverity::Low => "minor",
        SecuritySeverity::Info => "info",
    }
}

fn owasp_tag(cat: &OwaspCategory) -> &'static str {
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

fn owasp_help_uri(cat: &OwaspCategory) -> &'static str {
    match cat {
        OwaspCategory::BrokenAccessControl => {
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        }
        OwaspCategory::CryptographicFailures => {
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        }
        OwaspCategory::Injection => "https://owasp.org/Top10/A03_2021-Injection/",
        OwaspCategory::InsecureDesign => "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        OwaspCategory::SecurityMisconfiguration => {
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        }
        OwaspCategory::VulnerableComponents => {
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
        }
        OwaspCategory::AuthenticationFailures => {
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        }
        OwaspCategory::IntegrityFailures => {
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
        }
        OwaspCategory::LoggingFailures => {
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
        }
        OwaspCategory::SSRF => {
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
        }
    }
}

pub fn rule_id(cwe_id: Option<&str>, owasp_category: &OwaspCategory) -> String {
    cwe_id
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| owasp_tag(owasp_category).to_string())
}

pub fn help_uri(cwe_id: Option<&str>, owasp_category: &OwaspCategory) -> String {
    if let Some(cwe) = cwe_id {
        let digits = cwe.trim_start_matches("CWE-");
        return format!("https://cwe.mitre.org/data/definitions/{}.html", digits);
    }

    owasp_help_uri(owasp_category).to_string()
}

pub fn security_severity(score: f64, severity: &SecuritySeverity) -> String {
    let normalized = if score > 0.0 {
        score
    } else {
        match severity {
            SecuritySeverity::Critical => 9.0,
            SecuritySeverity::High => 8.0,
            SecuritySeverity::Medium => 5.0,
            SecuritySeverity::Low => 2.0,
            SecuritySeverity::Info => 0.0,
        }
    };

    format!("{normalized:.1}")
}

pub fn vulnerability_fingerprint(
    path: &str,
    start_line: usize,
    start_column: usize,
    rule_id: &str,
    title: &str,
) -> String {
    format!("{path}:{start_line}:{start_column}:{rule_id}:{title}")
}

pub fn partial_fingerprints(fingerprint: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "primaryLocationLineHash".to_string(),
            fingerprint.to_string(),
        ),
        (
            "primaryLocationStartColumnFingerprint".to_string(),
            fingerprint.to_string(),
        ),
    ])
}

fn information_uri() -> Option<String> {
    option_env!("CARGO_PKG_REPOSITORY")
        .map(ToOwned::to_owned)
        .or_else(|| Some("https://github.com/".to_string()))
}

pub fn to_sarif(result: &AnalysisResult) -> SarifLog {
    let mut rule_indices = HashMap::new();
    let mut rules = Vec::new();
    let mut sarif_results = Vec::new();

    for file in &result.files {
        let path = file.path.to_string_lossy().to_string();

        for vuln in &file.security_vulnerabilities {
            let rule_id = rule_id(vuln.cwe_id.as_deref(), &vuln.owasp_category);
            let rule_index = if let Some(existing) = rule_indices.get(&rule_id) {
                *existing
            } else {
                let new_index = rules.len();
                rule_indices.insert(rule_id.clone(), new_index);
                rules.push(RuleDescriptor {
                    id: rule_id.clone(),
                    name: vuln.title.clone(),
                    short_description: Message {
                        text: vuln.description.clone(),
                    },
                    full_description: Some(Message {
                        text: vuln.description.clone(),
                    }),
                    help_uri: Some(help_uri(vuln.cwe_id.as_deref(), &vuln.owasp_category)),
                    properties: Some(RuleProperties {
                        tags: vec![
                            "security".to_string(),
                            owasp_tag(&vuln.owasp_category).to_string(),
                        ],
                        cwe: vuln.cwe_id.clone(),
                        owasp: Some(owasp_tag(&vuln.owasp_category).to_string()),
                    }),
                });
                new_index
            };

            let fingerprint = vulnerability_fingerprint(
                &path,
                vuln.location.start_line,
                vuln.location.column,
                &rule_id,
                &vuln.title,
            );
            let start_column = (vuln.location.column.max(1)) as u64;

            sarif_results.push(ResultItem {
                rule_id,
                rule_index: Some(rule_index),
                level: Some(map_severity(&vuln.severity)),
                message: Message {
                    text: format!("{}: {}", vuln.title, vuln.description),
                },
                locations: vec![Location {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation { uri: path.clone() },
                        region: Some(Region {
                            start_line: vuln.location.start_line as u64,
                            end_line: Some(vuln.location.end_line as u64),
                            start_column: Some(start_column),
                        }),
                    },
                }],
                partial_fingerprints: partial_fingerprints(&fingerprint),
                properties: Some(ResultProperties {
                    security_severity: security_severity(vuln.impact.overall_score, &vuln.severity),
                    confidence: confidence_label(&vuln.confidence).to_string(),
                    remediation: vuln.remediation.summary.clone(),
                    tags: vec![
                        "security".to_string(),
                        owasp_tag(&vuln.owasp_category).to_string(),
                    ],
                    cwe: vuln.cwe_id.clone(),
                    owasp: owasp_tag(&vuln.owasp_category).to_string(),
                }),
                baseline_state: None,
                suppressions: None,
            });
        }
    }

    SarifLog {
        schema: SARIF_SCHEMA_URL.to_string(),
        version: "2.1.0".to_string(),
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "rust-tree-sitter".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    information_uri: information_uri(),
                    rules,
                },
            },
            results: sarif_results,
            invocations: vec![Invocation {
                execution_successful: true,
            }],
        }],
    }
}

pub fn to_sarif_pretty_json(result: &AnalysisResult) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&to_sarif(result))
}

pub fn to_codeclimate(result: &AnalysisResult) -> Vec<CodeClimateIssue> {
    let mut issues = Vec::new();

    for file in &result.files {
        let path = file.path.to_string_lossy().to_string();

        for vuln in &file.security_vulnerabilities {
            let rule_id = rule_id(vuln.cwe_id.as_deref(), &vuln.owasp_category);
            let fingerprint = vulnerability_fingerprint(
                &path,
                vuln.location.start_line,
                vuln.location.column,
                &rule_id,
                &vuln.title,
            );

            issues.push(CodeClimateIssue {
                issue_type: "issue".to_string(),
                check_name: rule_id,
                description: format!("{}: {}", vuln.title, vuln.description),
                categories: vec!["Security".to_string()],
                severity: codeclimate_severity(&vuln.severity),
                fingerprint,
                location: CodeClimateLocation {
                    path: path.clone(),
                    lines: CodeClimateLines {
                        begin: vuln.location.start_line as u64,
                        end: Some(vuln.location.end_line as u64),
                    },
                },
                content: Some(CodeClimateContent {
                    body: vuln.remediation.summary.clone(),
                }),
            });
        }
    }

    issues
}

pub fn to_codeclimate_pretty_json(result: &AnalysisResult) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&to_codeclimate(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advanced_security::{
        CodeExample, ImpactLevel, RemediationEffort, RemediationGuidance, SecurityImpact,
        SecurityVulnerability, VulnerabilityLocation,
    };
    use crate::{AnalysisConfig, FileInfo};

    fn sample_analysis_result() -> AnalysisResult {
        let mut res = AnalysisResult::new();
        res.root_path = std::path::PathBuf::from("/tmp");
        res.config = AnalysisConfig::default();

        let vuln = SecurityVulnerability {
            id: "ID".to_string(),
            title: "Command Injection".to_string(),
            description: "Untrusted input reaches a shell sink".to_string(),
            severity: SecuritySeverity::High,
            owasp_category: OwaspCategory::Injection,
            cwe_id: Some("CWE-78".to_string()),
            location: VulnerabilityLocation {
                file: std::path::PathBuf::from("src/main.rs"),
                function: None,
                start_line: 10,
                end_line: 12,
                column: 4,
            },
            code_snippet: "".to_string(),
            impact: SecurityImpact {
                confidentiality: ImpactLevel::High,
                integrity: ImpactLevel::High,
                availability: ImpactLevel::Medium,
                overall_score: 8.5,
            },
            remediation: RemediationGuidance {
                summary: "Sanitize input".to_string(),
                steps: vec![],
                code_examples: vec![CodeExample {
                    description: "".to_string(),
                    vulnerable_code: "".to_string(),
                    secure_code: "".to_string(),
                    language: "Rust".to_string(),
                }],
                references: vec![],
                effort: RemediationEffort::Low,
            },
            confidence: ConfidenceLevel::High,
        };
        let file = FileInfo {
            path: std::path::PathBuf::from("src/main.rs"),
            language: "Rust".to_string(),
            size: 1,
            lines: 1,
            parsed_successfully: true,
            parse_errors: vec![],
            symbols: vec![],
            security_vulnerabilities: vec![vuln],
        };
        res.files.push(file);

        res
    }

    #[test]
    fn sarif_conversion_includes_rule_metadata_and_fingerprints() {
        let sarif = to_sarif(&sample_analysis_result());

        assert_eq!(sarif.schema, SARIF_SCHEMA_URL);
        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 1);

        let rule = &sarif.runs[0].tool.driver.rules[0];
        assert_eq!(rule.id, "CWE-78");
        assert!(rule
            .help_uri
            .as_deref()
            .is_some_and(|uri| uri.contains("cwe.mitre.org")));

        let result = &sarif.runs[0].results[0];
        assert_eq!(result.level, Some("error"));
        assert!(result
            .partial_fingerprints
            .contains_key("primaryLocationLineHash"));
        assert_eq!(
            result
                .properties
                .as_ref()
                .and_then(|properties| properties.cwe.as_deref()),
            Some("CWE-78")
        );
        assert_eq!(
            result
                .properties
                .as_ref()
                .map(|properties| properties.security_severity.as_str()),
            Some("8.5")
        );
        assert_eq!(
            result
                .properties
                .as_ref()
                .map(|properties| properties.confidence.as_str()),
            Some("high")
        );
    }

    #[test]
    fn codeclimate_conversion_emits_security_issues() {
        let issues = to_codeclimate(&sample_analysis_result());

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].issue_type, "issue");
        assert_eq!(issues[0].check_name, "CWE-78");
        assert_eq!(issues[0].severity, "major");
        assert_eq!(issues[0].categories, vec!["Security".to_string()]);
        assert_eq!(issues[0].location.path, "src/main.rs");
    }
}
