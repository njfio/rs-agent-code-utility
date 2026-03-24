//! Declarative security rule engine backed by tree-sitter queries.

use crate::error::Error;
use crate::query::Query;
use crate::security::ast_analyzer::{
    CodeContext, SecurityFinding, SecurityFindingType, SecuritySeverity,
};
use crate::tree::SyntaxTree;
use crate::{Language, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Declarative rule engine for loading YAML metadata plus tree-sitter query patterns.
pub struct DeclarativeRuleEngine {
    rules: Vec<LoadedRule>,
    rules_dir: PathBuf,
}

#[derive(Deserialize)]
struct RuleFile {
    id: String,
    title: Option<String>,
    description: String,
    finding_type: String,
    severity: String,
    confidence: f64,
    languages: Vec<String>,
    remediation: String,
    cwe_id: Option<String>,
    pattern: Option<String>,
    pattern_file: Option<PathBuf>,
    taint_requirement: Option<String>,
}

struct LoadedRule {
    id: String,
    title: String,
    description: String,
    finding_type: SecurityFindingType,
    severity: SecuritySeverity,
    confidence: f64,
    remediation: String,
    cwe_id: Option<String>,
    taint_requirement: Option<String>,
    queries: HashMap<Language, Query>,
}

impl DeclarativeRuleEngine {
    /// Load all declarative security rules from a directory.
    pub fn load_from_dir(rules_dir: &Path) -> Result<Self> {
        if !rules_dir.exists() {
            return Err(Error::config_error_with_context(
                format!(
                    "security rules directory does not exist: {}",
                    rules_dir.display()
                ),
                Some(rules_dir.to_path_buf()),
                Some("rules_dir".to_string()),
            ));
        }

        let mut rule_paths = collect_rule_paths(rules_dir)?;
        rule_paths.sort();

        let mut rules = Vec::new();
        for rule_path in rule_paths {
            if let Some(rule) = Self::load_rule_file(&rule_path)? {
                rules.push(rule);
            }
        }

        Ok(Self {
            rules,
            rules_dir: rules_dir.to_path_buf(),
        })
    }

    /// Load the built-in rules shipped with the repository.
    pub fn load_builtin() -> Result<Self> {
        Self::load_from_dir(&default_rules_dir())
    }

    /// Evaluate the loaded rules against one parsed file.
    pub fn evaluate(
        &self,
        tree: &SyntaxTree,
        language: Language,
        file_path: &Path,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for rule in &self.rules {
            let Some(query) = rule.queries.get(&language) else {
                continue;
            };

            for query_match in query.matches(tree)? {
                let capture = query_match
                    .capture_by_name(query, "finding")
                    .or_else(|| query_match.captures().into_iter().next());
                let Some(capture) = capture else {
                    continue;
                };

                let start = capture.start_position();
                let end = capture.end_position();
                let mut description = rule.description.clone();
                if let Some(taint_requirement) = &rule.taint_requirement {
                    description.push_str(" Taint requirement: ");
                    description.push_str(taint_requirement);
                }

                findings.push(SecurityFinding {
                    id: format!("rule_{}_{}_{}", rule.id, start.row + 1, start.column),
                    finding_type: rule.finding_type.clone(),
                    severity: rule.severity.clone(),
                    title: rule.title.clone(),
                    description,
                    file_path: file_path.to_string_lossy().into_owned(),
                    line_number: start.row + 1,
                    column_start: start.column,
                    column_end: end.column,
                    code_snippet: capture.text()?.to_string(),
                    cwe_id: rule.cwe_id.clone(),
                    remediation: rule.remediation.clone(),
                    confidence: rule.confidence,
                    context: CodeContext::default(),
                });
            }
        }

        Ok(findings)
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Directory the engine loaded rules from.
    pub fn rules_dir(&self) -> &Path {
        &self.rules_dir
    }

    fn load_rule_file(rule_path: &Path) -> Result<Option<LoadedRule>> {
        let raw_rule = fs::read_to_string(rule_path)?;
        let rule_file: RuleFile = serde_yaml::from_str(&raw_rule).map_err(|err| {
            Error::config_error_with_context(
                format!(
                    "failed to parse security rule metadata {}",
                    rule_path.display()
                ),
                Some(rule_path.to_path_buf()),
                Some(err.to_string()),
            )
        })?;

        if !(0.0..=1.0).contains(&rule_file.confidence) {
            return Err(Error::invalid_input_error(
                "rule confidence",
                "a floating-point value between 0.0 and 1.0",
                rule_file.confidence.to_string(),
            ));
        }

        let rule_dir = rule_path.parent().unwrap_or_else(|| Path::new("."));
        let pattern = match (&rule_file.pattern, &rule_file.pattern_file) {
            (Some(pattern), None) => pattern.clone(),
            (None, Some(pattern_file)) => fs::read_to_string(rule_dir.join(pattern_file))?,
            (Some(_), Some(_)) => {
                return Err(Error::config_error_with_context(
                    format!(
                        "rule {} defines both pattern and pattern_file",
                        rule_file.id
                    ),
                    Some(rule_path.to_path_buf()),
                    Some("pattern".to_string()),
                ));
            }
            (None, None) => {
                return Err(Error::config_error_with_context(
                    format!("rule {} is missing pattern content", rule_file.id),
                    Some(rule_path.to_path_buf()),
                    Some("pattern".to_string()),
                ));
            }
        };

        let mut queries = HashMap::new();
        for language_name in &rule_file.languages {
            let language = language_name.parse::<Language>()?;
            match Query::new(language, &pattern) {
                Ok(query) => {
                    queries.insert(language, query);
                }
                Err(Error::NotSupported { .. }) => {
                    continue;
                }
                Err(err) => {
                    return Err(Error::config_error_with_context(
                        format!(
                            "failed to compile rule {} for {}",
                            rule_file.id,
                            language.name()
                        ),
                        Some(rule_path.to_path_buf()),
                        Some(err.to_string()),
                    ));
                }
            }
        }

        if queries.is_empty() {
            return Ok(None);
        }

        Ok(Some(LoadedRule {
            id: rule_file.id.clone(),
            title: rule_file
                .title
                .unwrap_or_else(|| rule_file.description.clone()),
            description: rule_file.description,
            finding_type: parse_finding_type(&rule_file.finding_type)?,
            severity: parse_severity(&rule_file.severity)?,
            confidence: rule_file.confidence,
            remediation: rule_file.remediation,
            cwe_id: rule_file.cwe_id,
            taint_requirement: rule_file.taint_requirement,
            queries,
        }))
    }
}

fn collect_rule_paths(rules_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut pending_dirs = vec![rules_dir.to_path_buf()];
    let mut rule_paths = Vec::new();

    while let Some(current_dir) = pending_dirs.pop() {
        for entry in fs::read_dir(&current_dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let path = entry.path();

            if file_type.is_dir() {
                pending_dirs.push(path);
                continue;
            }

            if file_type.is_file()
                && matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("yaml" | "yml")
                )
            {
                rule_paths.push(path);
            }
        }
    }

    Ok(rule_paths)
}

/// Default location of the checked-in security rules.
pub fn default_rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules")
}

fn parse_finding_type(value: &str) -> Result<SecurityFindingType> {
    match value.trim().to_lowercase().as_str() {
        "injection" => Ok(SecurityFindingType::Injection),
        "broken_access_control" | "broken-access-control" => {
            Ok(SecurityFindingType::BrokenAccessControl)
        }
        "cryptographic_failure" | "cryptographic-failure" => {
            Ok(SecurityFindingType::CryptographicFailure)
        }
        "insecure_design" | "insecure-design" => Ok(SecurityFindingType::InsecureDesign),
        "security_misconfiguration" | "security-misconfiguration" => {
            Ok(SecurityFindingType::SecurityMisconfiguration)
        }
        "hardcoded_secret" | "hardcoded-secret" => Ok(SecurityFindingType::HardcodedSecret),
        "weak_authentication" | "weak-authentication" => {
            Ok(SecurityFindingType::WeakAuthentication)
        }
        "information_disclosure" | "information-disclosure" => {
            Ok(SecurityFindingType::InformationDisclosure)
        }
        _ => Err(Error::invalid_input_error(
            "rule finding_type",
            "supported security finding type",
            value,
        )),
    }
}

fn parse_severity(value: &str) -> Result<SecuritySeverity> {
    match value.trim().to_lowercase().as_str() {
        "info" => Ok(SecuritySeverity::Info),
        "low" => Ok(SecuritySeverity::Low),
        "medium" => Ok(SecuritySeverity::Medium),
        "high" => Ok(SecuritySeverity::High),
        "critical" => Ok(SecuritySeverity::Critical),
        _ => Err(Error::invalid_input_error(
            "rule severity",
            "info, low, medium, high, or critical",
            value,
        )),
    }
}
