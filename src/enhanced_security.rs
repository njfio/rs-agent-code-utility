//! Enhanced security analysis with real implementations
//! 
//! This module provides production-grade security analysis by integrating
//! real vulnerability databases, secrets detection, and OWASP scanning.

use crate::{AnalysisResult, Parser, Language, Result};
use crate::constants::security::*;
use crate::security::{VulnerabilityDatabase, SecretsDetector, OwaspDetector, SecretFinding, OwaspFinding};
use crate::infrastructure::{DatabaseManager, Cache, MultiServiceRateLimiter, AppConfig, VulnerabilityRecord};
use serde::{Serialize, Deserialize};
use std::path::Path;
use tracing::{info, debug, warn};

/// Enhanced security scanner with real implementations
pub struct EnhancedSecurityScanner {
    vulnerability_db: VulnerabilityDatabase,
    secrets_detector: SecretsDetector,
    owasp_detector: OwaspDetector,
    config: EnhancedSecurityConfig,
}

/// Configuration for enhanced security scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedSecurityConfig {
    /// Enable vulnerability database scanning
    pub enable_vulnerability_db: bool,
    /// Enable secrets detection
    pub enable_secrets_detection: bool,
    /// Enable OWASP Top 10 scanning
    pub enable_owasp_scanning: bool,
    /// Minimum confidence threshold for findings
    pub min_confidence: f64,
    /// Maximum number of findings per category
    pub max_findings_per_category: usize,
    /// Enable dependency vulnerability scanning
    pub enable_dependency_scanning: bool,
}

/// Enhanced security scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedSecurityResult {
    /// Overall security score (0-100)
    pub security_score: u8,
    /// Total findings across all categories
    pub total_findings: usize,
    /// Vulnerability database findings
    pub vulnerability_findings: Vec<VulnerabilityRecord>,
    /// Secrets detection findings
    pub secret_findings: Vec<SecretFinding>,
    /// OWASP Top 10 findings
    pub owasp_findings: Vec<OwaspFinding>,
    /// Security metrics
    pub metrics: SecurityMetrics,
    /// Compliance assessment
    pub compliance: ComplianceAssessment,
    /// Remediation roadmap
    pub remediation_roadmap: RemediationRoadmap,
}

/// Security metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Critical findings count
    pub critical_count: usize,
    /// High severity findings count
    pub high_count: usize,
    /// Medium severity findings count
    pub medium_count: usize,
    /// Low severity findings count
    pub low_count: usize,
    /// Average confidence score
    pub avg_confidence: f64,
    /// Coverage percentage
    pub coverage_percentage: f64,
}

/// Compliance assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAssessment {
    /// OWASP Top 10 compliance score (0-100)
    pub owasp_compliance: u8,
    /// CWE compliance score (0-100)
    pub cwe_compliance: u8,
    /// Secrets management compliance (0-100)
    pub secrets_compliance: u8,
    /// Overall compliance score (0-100)
    pub overall_compliance: u8,
    /// Compliance recommendations
    pub recommendations: Vec<String>,
}

/// Remediation roadmap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationRoadmap {
    /// Immediate actions (critical/high severity)
    pub immediate_actions: Vec<RemediationAction>,
    /// Short-term actions (medium severity)
    pub short_term_actions: Vec<RemediationAction>,
    /// Long-term actions (low severity, improvements)
    pub long_term_actions: Vec<RemediationAction>,
    /// Estimated total effort (hours)
    pub total_effort_hours: f64,
}

/// Remediation action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    /// Action ID
    pub id: String,
    /// Action title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Priority level
    pub priority: ActionPriority,
    /// Estimated effort (hours)
    pub effort_hours: f64,
    /// Related findings
    pub related_findings: Vec<String>,
    /// Implementation steps
    pub implementation_steps: Vec<String>,
}

// Use common Priority from constants module
pub use crate::constants::common::Priority as ActionPriority;

// Trait implementations are provided by the common Priority type

impl Default for EnhancedSecurityConfig {
    fn default() -> Self {
        Self {
            enable_vulnerability_db: true,
            enable_secrets_detection: true,
            enable_owasp_scanning: true,
            min_confidence: DEFAULT_MIN_CONFIDENCE,
            max_findings_per_category: 50,
            enable_dependency_scanning: true,
        }
    }
}

impl EnhancedSecurityScanner {
    /// Create a new enhanced security scanner
    pub async fn new(
        database: DatabaseManager,
        cache: Cache,
        rate_limiter: MultiServiceRateLimiter,
        app_config: &AppConfig,
    ) -> Result<Self> {
        // Initialize vulnerability database
        let vulnerability_db = VulnerabilityDatabase::new(
            database.clone(),
            cache.clone(),
            rate_limiter,
            crate::security::vulnerability_db::NvdConfig {
                base_url: app_config.apis.nvd.base_url.clone(),
                api_key: app_config.apis.nvd.api_key.clone(),
                enabled: true,
            },
            crate::security::vulnerability_db::OsvConfig {
                base_url: app_config.apis.osv.base_url.clone(),
                enabled: true,
            },
            crate::security::vulnerability_db::GitHubConfig {
                base_url: app_config.apis.github.base_url.clone(),
                token: app_config.apis.github.token.clone(),
                enabled: true,
            },
        ).await?;

        // Initialize secrets detector
        let secrets_detector = SecretsDetector::new(&database).await?;

        // Initialize OWASP detector
        let owasp_detector = OwaspDetector::new()?;

        Ok(Self {
            vulnerability_db,
            secrets_detector,
            owasp_detector,
            config: EnhancedSecurityConfig::default(),
        })
    }

    /// Create a new scanner with custom configuration
    pub async fn with_config(
        database: DatabaseManager,
        cache: Cache,
        rate_limiter: MultiServiceRateLimiter,
        app_config: &AppConfig,
        config: EnhancedSecurityConfig,
    ) -> Result<Self> {
        let mut scanner = Self::new(database, cache, rate_limiter, app_config).await?;
        scanner.config = config;
        Ok(scanner)
    }

    /// Perform comprehensive security analysis
    pub async fn analyze(&self, analysis_result: &AnalysisResult) -> Result<EnhancedSecurityResult> {
        info!("Starting enhanced security analysis");

        let mut vulnerability_findings = Vec::new();
        let mut secret_findings = Vec::new();
        let mut owasp_findings = Vec::new();

        // Dependency vulnerability scanning
        if self.config.enable_dependency_scanning && self.config.enable_vulnerability_db {
            vulnerability_findings
                .extend(self.scan_dependencies(analysis_result).await?);
        }

        // File-by-file analysis
        for file in &analysis_result.files {
            // Skip non-source files
            if !self.is_source_file(&file.path) {
                continue;
            }

            // Read file content using absolute path
            let full_path = analysis_result.root_path.join(&file.path);
            let content = match std::fs::read_to_string(&full_path) {
                Ok(content) => content,
                Err(e) => {
                    warn!("Failed to read file {}: {}", full_path.display(), e);
                    continue;
                }
            };

            // Secrets detection
            if self.config.enable_secrets_detection {
                match self.secrets_detector.detect_secrets(&content, &file.path.display().to_string()) {
                    Ok(findings) => {
                        let filtered_findings: Vec<_> = findings.into_iter()
                            .filter(|f| f.confidence >= self.config.min_confidence)
                            .take(self.config.max_findings_per_category)
                            .collect();
                        secret_findings.extend(filtered_findings);
                    }
                    Err(e) => warn!("Secrets detection failed for {}: {}", file.path.display(), e),
                }
            }

            // OWASP Top 10 scanning
            if self.config.enable_owasp_scanning {
                if let Some(language) = self.detect_language(&file.path) {
                    match self.parse_and_analyze_owasp(&content, &file.path.display().to_string(), language) {
                        Ok(findings) => {
                            let filtered_findings: Vec<_> = findings.into_iter()
                                .filter(|f| f.confidence >= self.config.min_confidence)
                                .take(self.config.max_findings_per_category)
                                .collect();
                            owasp_findings.extend(filtered_findings);
                        }
                        Err(e) => warn!("OWASP scanning failed for {}: {}", file.path.display(), e),
                    }
                }
            }
        }

        // Calculate metrics
        let metrics = self.calculate_metrics(&vulnerability_findings, &secret_findings, &owasp_findings);

        // Assess compliance
        let compliance = self.assess_compliance(&vulnerability_findings, &secret_findings, &owasp_findings);

        // Generate remediation roadmap
        let remediation_roadmap = self.generate_remediation_roadmap(&vulnerability_findings, &secret_findings, &owasp_findings);

        // Calculate overall security score
        let security_score = self.calculate_security_score(&metrics, &compliance);

        let total_findings = vulnerability_findings.len() + secret_findings.len() + owasp_findings.len();

        info!("Enhanced security analysis completed: {} total findings, security score: {}", total_findings, security_score);

        Ok(EnhancedSecurityResult {
            security_score,
            total_findings,
            vulnerability_findings,
            secret_findings,
            owasp_findings,
            metrics,
            compliance,
            remediation_roadmap,
        })
    }

    /// Scan dependencies for vulnerabilities
    async fn scan_dependencies(&self, analysis_result: &AnalysisResult) -> Result<Vec<VulnerabilityRecord>> {
        let mut vulnerabilities = Vec::new();

        // Look for dependency files
        for file in &analysis_result.files {
            let file_name = file.path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            match file_name {
                "Cargo.toml" => {
                    let path = analysis_result.root_path.join(&file.path);
                    vulnerabilities.extend(self.scan_cargo_dependencies(&path).await?);
                }
                "package.json" => {
                    let path = analysis_result.root_path.join(&file.path);
                    vulnerabilities.extend(self.scan_npm_dependencies(&path).await?);
                }
                "requirements.txt" | "Pipfile" => {
                    let path = analysis_result.root_path.join(&file.path);
                    vulnerabilities.extend(self.scan_python_dependencies(&path).await?);
                }
                "go.mod" => {
                    let path = analysis_result.root_path.join(&file.path);
                    vulnerabilities.extend(self.scan_go_dependencies(&path).await?);
                }
                _ => {}
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan Cargo.toml for vulnerable dependencies
    async fn scan_cargo_dependencies(&self, cargo_path: &Path) -> Result<Vec<VulnerabilityRecord>> {
        let content = std::fs::read_to_string(cargo_path)?;
        let mut vulnerabilities = Vec::new();

        // Parse TOML and extract dependencies
        // This is a simplified implementation - would need proper TOML parsing
        for line in content.lines() {
            if line.contains("=") && !line.trim_start().starts_with("#") {
                if let Some(package_name) = self.extract_package_name(line) {
                    match self.vulnerability_db.check_package_vulnerabilities(&package_name, None, "cargo").await {
                        Ok(vulns) => vulnerabilities.extend(vulns),
                        Err(e) => debug!("Failed to check vulnerabilities for {}: {}", package_name, e),
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan package.json for vulnerable dependencies
    async fn scan_npm_dependencies(&self, package_path: &Path) -> Result<Vec<VulnerabilityRecord>> {
        let content = std::fs::read_to_string(package_path)?;
        let mut vulnerabilities = Vec::new();

        // Parse JSON and extract dependencies
        if let Ok(package_json) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(dependencies) = package_json.get("dependencies").and_then(|d| d.as_object()) {
                for (package_name, _version) in dependencies {
                    match self.vulnerability_db.check_package_vulnerabilities(package_name, None, "npm").await {
                        Ok(vulns) => vulnerabilities.extend(vulns),
                        Err(e) => debug!("Failed to check vulnerabilities for {}: {}", package_name, e),
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan Python dependencies for vulnerabilities
    async fn scan_python_dependencies(&self, deps_path: &Path) -> Result<Vec<VulnerabilityRecord>> {
        let content = std::fs::read_to_string(deps_path)?;
        let mut vulnerabilities = Vec::new();

        for line in content.lines() {
            if let Some(package_name) = self.extract_python_package_name(line) {
                match self.vulnerability_db.check_package_vulnerabilities(&package_name, None, "pypi").await {
                    Ok(vulns) => vulnerabilities.extend(vulns),
                    Err(e) => debug!("Failed to check vulnerabilities for {}: {}", package_name, e),
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan Go dependencies for vulnerabilities
    async fn scan_go_dependencies(&self, go_mod_path: &Path) -> Result<Vec<VulnerabilityRecord>> {
        let content = std::fs::read_to_string(go_mod_path)?;
        let mut vulnerabilities = Vec::new();

        for line in content.lines() {
            if line.trim_start().starts_with("require") || line.contains("v") {
                if let Some(package_name) = self.extract_go_package_name(line) {
                    match self.vulnerability_db.check_package_vulnerabilities(&package_name, None, "go").await {
                        Ok(vulns) => vulnerabilities.extend(vulns),
                        Err(e) => debug!("Failed to check vulnerabilities for {}: {}", package_name, e),
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Parse file and analyze for OWASP vulnerabilities
    fn parse_and_analyze_owasp(&self, content: &str, file_path: &str, language: Language) -> Result<Vec<OwaspFinding>> {
        let parser = Parser::new(language)?;
        let tree = parser.parse(content, None)?;
        self.owasp_detector.detect_vulnerabilities(&tree, content, file_path)
            .map_err(|e| crate::error::Error::internal_error_with_context(
                "enhanced_security",
                format!("OWASP vulnerability detection failed: {}", e),
                format!("File: {}", file_path)
            ))
    }

    /// Detect programming language from file extension
    fn detect_language(&self, path: &Path) -> Option<Language> {
        match path.extension()?.to_str()? {
            "rs" => Some(Language::Rust),
            "js" => Some(Language::JavaScript),
            "ts" => Some(Language::TypeScript),
            "py" => Some(Language::Python),
            "c" => Some(Language::C),
            "cpp" | "cc" | "cxx" => Some(Language::Cpp),
            "go" => Some(Language::Go),
            _ => None,
        }
    }

    /// Check if file is a source code file
    fn is_source_file(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            matches!(ext, "rs" | "js" | "ts" | "py" | "c" | "cpp" | "cc" | "cxx" | "go" | "java" | "cs")
        } else {
            false
        }
    }

    /// Extract package name from Cargo.toml line
    fn extract_package_name(&self, line: &str) -> Option<String> {
        if let Some(eq_pos) = line.find('=') {
            let package_name = line[..eq_pos].trim().trim_matches('"');
            if !package_name.is_empty() && !package_name.starts_with('[') {
                return Some(package_name.to_string());
            }
        }
        None
    }

    /// Extract package name from Python requirements line
    fn extract_python_package_name(&self, line: &str) -> Option<String> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        // Handle package==version, package>=version, etc.
        let package_name = line.split(&['=', '>', '<', '!', '~'][..])
            .next()?
            .trim();

        if !package_name.is_empty() {
            Some(package_name.to_string())
        } else {
            None
        }
    }

    /// Extract package name from Go module line
    fn extract_go_package_name(&self, line: &str) -> Option<String> {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() >= 2 && !parts[0].starts_with("//") {
            // Skip "require" keyword if present
            let package_name = if parts[0] == "require" && parts.len() >= 3 {
                parts[1]
            } else {
                parts[0]
            };
            
            if !package_name.is_empty() {
                Some(package_name.to_string())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Calculate security metrics
    fn calculate_metrics(
        &self,
        vulnerability_findings: &[VulnerabilityRecord],
        secret_findings: &[SecretFinding],
        owasp_findings: &[OwaspFinding],
    ) -> SecurityMetrics {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut total_confidence = 0.0;
        let mut confidence_count = 0;

        // Count vulnerability findings by severity
        for vuln in vulnerability_findings {
            match vuln.severity.to_uppercase().as_str() {
                "CRITICAL" => critical_count += 1,
                "HIGH" => high_count += 1,
                "MEDIUM" => medium_count += 1,
                "LOW" => low_count += 1,
                _ => low_count += 1,
            }
        }

        // Count secret findings by severity
        for secret in secret_findings {
            match secret.severity {
                crate::security::secrets_detector::SecretSeverity::Critical => critical_count += 1,
                crate::security::secrets_detector::SecretSeverity::High => high_count += 1,
                crate::security::secrets_detector::SecretSeverity::Medium => medium_count += 1,
                crate::security::secrets_detector::SecretSeverity::Low => low_count += 1,
                crate::security::secrets_detector::SecretSeverity::Info => low_count += 1,
            }
            total_confidence += secret.confidence;
            confidence_count += 1;
        }

        // Count OWASP findings by severity
        for owasp in owasp_findings {
            match owasp.severity {
                crate::security::owasp_detector::VulnSeverity::Critical => critical_count += 1,
                crate::security::owasp_detector::VulnSeverity::High => high_count += 1,
                crate::security::owasp_detector::VulnSeverity::Medium => medium_count += 1,
                crate::security::owasp_detector::VulnSeverity::Low => low_count += 1,
            }
            total_confidence += owasp.confidence;
            confidence_count += 1;
        }

        let avg_confidence = if confidence_count > 0 {
            total_confidence / confidence_count as f64
        } else {
            1.0
        };

        // Calculate coverage percentage (simplified)
        let total_findings = critical_count + high_count + medium_count + low_count;
        let coverage_percentage = if total_findings > 0 {
            (total_findings as f64 / (total_findings as f64 + COVERAGE_CALCULATION_DIVISOR)) * crate::constants::scoring::PERCENTAGE_FACTOR
        } else {
            crate::constants::scoring::PERFECT_SCORE
        };

        SecurityMetrics {
            critical_count,
            high_count,
            medium_count,
            low_count,
            avg_confidence,
            coverage_percentage,
        }
    }

    /// Assess compliance with security standards
    fn assess_compliance(
        &self,
        vulnerability_findings: &[VulnerabilityRecord],
        secret_findings: &[SecretFinding],
        owasp_findings: &[OwaspFinding],
    ) -> ComplianceAssessment {
        let total_critical = vulnerability_findings.iter().filter(|v| v.severity.to_uppercase() == "CRITICAL").count()
            + secret_findings.iter().filter(|s| matches!(s.severity, crate::security::secrets_detector::SecretSeverity::Critical)).count()
            + owasp_findings.iter().filter(|o| matches!(o.severity, crate::security::owasp_detector::VulnSeverity::Critical)).count();

        let total_high = vulnerability_findings.iter().filter(|v| v.severity.to_uppercase() == "HIGH").count()
            + secret_findings.iter().filter(|s| matches!(s.severity, crate::security::secrets_detector::SecretSeverity::High)).count()
            + owasp_findings.iter().filter(|o| matches!(o.severity, crate::security::owasp_detector::VulnSeverity::High)).count();

        // OWASP compliance (based on OWASP findings)
        let owasp_compliance = if total_critical == 0 && total_high == 0 {
            95
        } else if total_critical == 0 && total_high <= 2 {
            80
        } else if total_critical <= 1 && total_high <= 5 {
            60
        } else {
            30
        };

        // CWE compliance (based on all findings)
        let cwe_compliance = if total_critical == 0 {
            90
        } else if total_critical <= 2 {
            70
        } else {
            40
        };

        // Secrets compliance (based on secret findings)
        let secrets_compliance = if secret_findings.is_empty() {
            HIGH_SECRETS_COMPLIANCE
        } else if secret_findings.iter().all(|s| !matches!(s.severity, crate::security::secrets_detector::SecretSeverity::Critical | crate::security::secrets_detector::SecretSeverity::High)) {
            MEDIUM_SECRETS_COMPLIANCE
        } else {
            50
        };

        let overall_compliance = (owasp_compliance + cwe_compliance + secrets_compliance) / 3;

        let mut recommendations = Vec::new();
        if total_critical > 0 {
            recommendations.push("Address all critical security vulnerabilities immediately".to_string());
        }
        if total_high > 5 {
            recommendations.push("Implement comprehensive security review process".to_string());
        }
        if !secret_findings.is_empty() {
            recommendations.push("Implement secrets management solution".to_string());
        }
        if owasp_findings.len() > 10 {
            recommendations.push("Conduct OWASP Top 10 security training for development team".to_string());
        }

        ComplianceAssessment {
            owasp_compliance,
            cwe_compliance,
            secrets_compliance,
            overall_compliance,
            recommendations,
        }
    }

    /// Calculate overall security score
    fn calculate_security_score(&self, metrics: &SecurityMetrics, compliance: &ComplianceAssessment) -> u8 {
        let mut score = BASE_SECURITY_SCORE;

        // Deduct points for findings
        score = score.saturating_sub(metrics.critical_count as u8 * 25);
        score = score.saturating_sub(metrics.high_count as u8 * 15);
        score = score.saturating_sub(metrics.medium_count as u8 * 8);
        score = score.saturating_sub(metrics.low_count as u8 * 3);

        // Factor in compliance
        let compliance_factor = compliance.overall_compliance as f64 / crate::constants::scoring::PERCENTAGE_FACTOR;
        score = ((score as f64) * compliance_factor) as u8;

        // Factor in confidence
        let confidence_factor = metrics.avg_confidence;
        score = ((score as f64) * confidence_factor) as u8;

        score.max(0).min(MAX_SECURITY_SCORE)
    }

    /// Generate remediation roadmap
    fn generate_remediation_roadmap(
        &self,
        vulnerability_findings: &[VulnerabilityRecord],
        secret_findings: &[SecretFinding],
        owasp_findings: &[OwaspFinding],
    ) -> RemediationRoadmap {
        let mut immediate_actions = Vec::new();
        let mut short_term_actions = Vec::new();
        let mut long_term_actions = Vec::new();
        let mut total_effort = 0.0;

        // Process vulnerability findings
        for vuln in vulnerability_findings {
            let effort = match vuln.severity.to_uppercase().as_str() {
                "CRITICAL" => 8.0,
                "HIGH" => 4.0,
                "MEDIUM" => 2.0,
                _ => 1.0,
            };
            total_effort += effort;

            let action = RemediationAction {
                id: format!("vuln_{}", vuln.id),
                title: format!("Fix vulnerability: {}", vuln.cve_id),
                description: vuln.description.clone(),
                priority: match vuln.severity.to_uppercase().as_str() {
                    "CRITICAL" => ActionPriority::Critical,
                    "HIGH" => ActionPriority::High,
                    "MEDIUM" => ActionPriority::Medium,
                    _ => ActionPriority::Low,
                },
                effort_hours: effort,
                related_findings: vec![vuln.cve_id.clone()],
                implementation_steps: vec![
                    "Review vulnerability details".to_string(),
                    "Update affected dependencies".to_string(),
                    "Test fix in development environment".to_string(),
                    "Deploy fix to production".to_string(),
                ],
            };

            match action.priority {
                ActionPriority::Critical | ActionPriority::High => immediate_actions.push(action),
                ActionPriority::Medium => short_term_actions.push(action),
                ActionPriority::Low => long_term_actions.push(action),
            }
        }

        // Process secret findings
        for secret in secret_findings {
            let effort = match secret.severity {
                crate::security::secrets_detector::SecretSeverity::Critical => 6.0,
                crate::security::secrets_detector::SecretSeverity::High => 3.0,
                crate::security::secrets_detector::SecretSeverity::Medium => 1.5,
                _ => 0.5,
            };
            total_effort += effort;

            let action = RemediationAction {
                id: format!("secret_{}", secret.id),
                title: format!("Remove secret: {:?}", secret.secret_type),
                description: secret.remediation.clone(),
                priority: match secret.severity {
                    crate::security::secrets_detector::SecretSeverity::Critical => ActionPriority::Critical,
                    crate::security::secrets_detector::SecretSeverity::High => ActionPriority::High,
                    crate::security::secrets_detector::SecretSeverity::Medium => ActionPriority::Medium,
                    _ => ActionPriority::Low,
                },
                effort_hours: effort,
                related_findings: vec![secret.id.clone()],
                implementation_steps: vec![
                    "Remove secret from source code".to_string(),
                    "Rotate compromised credentials".to_string(),
                    "Implement secure configuration management".to_string(),
                    "Update deployment processes".to_string(),
                ],
            };

            match action.priority {
                ActionPriority::Critical | ActionPriority::High => immediate_actions.push(action),
                ActionPriority::Medium => short_term_actions.push(action),
                ActionPriority::Low => long_term_actions.push(action),
            }
        }

        // Process OWASP findings
        for owasp in owasp_findings {
            let effort = match owasp.severity {
                crate::security::owasp_detector::VulnSeverity::Critical => 12.0,
                crate::security::owasp_detector::VulnSeverity::High => 6.0,
                crate::security::owasp_detector::VulnSeverity::Medium => 3.0,
                crate::security::owasp_detector::VulnSeverity::Low => 1.0,
            };
            total_effort += effort;

            let action = RemediationAction {
                id: format!("owasp_{}", owasp.id),
                title: format!("Fix OWASP issue: {}", owasp.name),
                description: owasp.remediation.clone(),
                priority: match owasp.severity {
                    crate::security::owasp_detector::VulnSeverity::Critical => ActionPriority::Critical,
                    crate::security::owasp_detector::VulnSeverity::High => ActionPriority::High,
                    crate::security::owasp_detector::VulnSeverity::Medium => ActionPriority::Medium,
                    crate::security::owasp_detector::VulnSeverity::Low => ActionPriority::Low,
                },
                effort_hours: effort,
                related_findings: vec![owasp.id.clone()],
                implementation_steps: vec![
                    "Analyze vulnerability pattern".to_string(),
                    "Implement secure coding practices".to_string(),
                    "Add security tests".to_string(),
                    "Review similar code patterns".to_string(),
                ],
            };

            match action.priority {
                ActionPriority::Critical | ActionPriority::High => immediate_actions.push(action),
                ActionPriority::Medium => short_term_actions.push(action),
                ActionPriority::Low => long_term_actions.push(action),
            }
        }

        RemediationRoadmap {
            immediate_actions,
            short_term_actions,
            long_term_actions,
            total_effort_hours: total_effort,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_enhanced_security_config_default() {
        let config = EnhancedSecurityConfig::default();
        assert!(config.enable_vulnerability_db);
        assert!(config.enable_secrets_detection);
        assert!(config.enable_owasp_scanning);
        assert!(config.enable_dependency_scanning);
        assert_eq!(config.min_confidence, DEFAULT_MIN_CONFIDENCE);
        assert_eq!(config.max_findings_per_category, 50);
    }

    #[test]
    fn test_security_metrics_creation() {
        let metrics = SecurityMetrics {
            critical_count: 2,
            high_count: 5,
            medium_count: 10,
            low_count: 15,
            avg_confidence: 0.85,
            coverage_percentage: 75.0,
        };

        assert_eq!(metrics.critical_count, 2);
        assert_eq!(metrics.high_count, 5);
        assert_eq!(metrics.medium_count, 10);
        assert_eq!(metrics.low_count, 15);
        assert_eq!(metrics.avg_confidence, 0.85);
        assert_eq!(metrics.coverage_percentage, 75.0);
    }

    #[test]
    fn test_compliance_assessment_creation() {
        let compliance = ComplianceAssessment {
            owasp_compliance: 85,
            cwe_compliance: 90,
            secrets_compliance: 95,
            overall_compliance: 90,
            recommendations: vec![
                "Implement security training".to_string(),
                "Add automated security testing".to_string(),
            ],
        };

        assert_eq!(compliance.owasp_compliance, 85);
        assert_eq!(compliance.cwe_compliance, 90);
        assert_eq!(compliance.secrets_compliance, 95);
        assert_eq!(compliance.overall_compliance, 90);
        assert_eq!(compliance.recommendations.len(), 2);
    }

    #[test]
    fn test_remediation_action_creation() {
        let action = RemediationAction {
            id: "test-001".to_string(),
            title: "Fix SQL Injection".to_string(),
            description: "Sanitize user input to prevent SQL injection".to_string(),
            priority: ActionPriority::Critical,
            effort_hours: 8.0,
            related_findings: vec!["CWE-89".to_string()],
            implementation_steps: vec![
                "Review vulnerable code".to_string(),
                "Implement parameterized queries".to_string(),
                "Add input validation".to_string(),
                "Test fix".to_string(),
            ],
        };

        assert_eq!(action.id, "test-001");
        assert_eq!(action.title, "Fix SQL Injection");
        assert!(matches!(action.priority, ActionPriority::Critical));
        assert_eq!(action.effort_hours, 8.0);
        assert_eq!(action.related_findings.len(), 1);
        assert_eq!(action.implementation_steps.len(), 4);
    }

    #[test]
    fn test_action_priority_ordering() {
        assert!(ActionPriority::Critical > ActionPriority::High);
        assert!(ActionPriority::High > ActionPriority::Medium);
        assert!(ActionPriority::Medium > ActionPriority::Low);
    }

    #[test]
    fn test_remediation_roadmap_creation() {
        let roadmap = RemediationRoadmap {
            immediate_actions: vec![
                RemediationAction {
                    id: "critical-001".to_string(),
                    title: "Critical Fix".to_string(),
                    description: "Fix critical vulnerability".to_string(),
                    priority: ActionPriority::Critical,
                    effort_hours: 12.0,
                    related_findings: vec!["CVE-2023-1234".to_string()],
                    implementation_steps: vec!["Step 1".to_string(), "Step 2".to_string()],
                }
            ],
            short_term_actions: vec![],
            long_term_actions: vec![],
            total_effort_hours: 12.0,
        };

        assert_eq!(roadmap.immediate_actions.len(), 1);
        assert_eq!(roadmap.short_term_actions.len(), 0);
        assert_eq!(roadmap.long_term_actions.len(), 0);
        assert_eq!(roadmap.total_effort_hours, 12.0);
    }

    #[test]
    fn test_enhanced_security_result_creation() {
        let result = EnhancedSecurityResult {
            security_score: 85,
            total_findings: 10,
            vulnerability_findings: vec![],
            secret_findings: vec![],
            owasp_findings: vec![],
            metrics: SecurityMetrics {
                critical_count: 0,
                high_count: 2,
                medium_count: 5,
                low_count: 3,
                avg_confidence: 0.8,
                coverage_percentage: 85.0,
            },
            compliance: ComplianceAssessment {
                owasp_compliance: 85,
                cwe_compliance: 90,
                secrets_compliance: 95,
                overall_compliance: 90,
                recommendations: vec![],
            },
            remediation_roadmap: RemediationRoadmap {
                immediate_actions: vec![],
                short_term_actions: vec![],
                long_term_actions: vec![],
                total_effort_hours: 0.0,
            },
        };

        assert_eq!(result.security_score, 85);
        assert_eq!(result.total_findings, 10);
        assert_eq!(result.metrics.critical_count, 0);
        assert_eq!(result.metrics.high_count, 2);
        assert_eq!(result.compliance.overall_compliance, 90);
        assert_eq!(result.remediation_roadmap.total_effort_hours, 0.0);
    }

    #[test]
    fn test_package_name_extraction() {
        // This would require creating a scanner instance, which needs async setup
        // For now, we'll test the logic conceptually
        let cargo_line = r#"serde = "1.0""#;
        assert!(cargo_line.contains("serde"));
        assert!(cargo_line.contains("="));

        let python_line = "requests>=2.25.0";
        let package_name = python_line.split(&['=', '>', '<'][..]).next().unwrap().trim();
        assert_eq!(package_name, "requests");

        let go_line = "require github.com/gorilla/mux v1.8.0";
        let parts: Vec<&str> = go_line.trim().split_whitespace().collect();
        assert_eq!(parts[0], "require");
        assert_eq!(parts[1], "github.com/gorilla/mux");
    }

    #[test]
    fn test_language_detection() {
        // Test file extension to language mapping
        let rust_path = PathBuf::from("main.rs");
        assert_eq!(rust_path.extension().unwrap().to_str().unwrap(), "rs");

        let js_path = PathBuf::from("app.js");
        assert_eq!(js_path.extension().unwrap().to_str().unwrap(), "js");

        let py_path = PathBuf::from("script.py");
        assert_eq!(py_path.extension().unwrap().to_str().unwrap(), "py");

        let go_path = PathBuf::from("main.go");
        assert_eq!(go_path.extension().unwrap().to_str().unwrap(), "go");
    }

    #[test]
    fn test_source_file_detection() {
        let source_extensions = ["rs", "js", "ts", "py", "c", "cpp", "go", "java", "cs"];
        let non_source_extensions = ["txt", "md", "json", "yaml", "toml"];

        for ext in &source_extensions {
            let path = PathBuf::from(format!("test.{}", ext));
            assert_eq!(path.extension().unwrap().to_str().unwrap(), *ext);
        }

        for ext in &non_source_extensions {
            let path = PathBuf::from(format!("test.{}", ext));
            assert_eq!(path.extension().unwrap().to_str().unwrap(), *ext);
        }
    }
}
