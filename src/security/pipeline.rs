//! Canonical security-analysis pipeline.
//!
//! This facade keeps the existing detector modules separate while giving callers one place to
//! run parse, taint, AST, OWASP, filtering, and confidence scoring in a stable order.

use crate::error::Result;
use crate::languages::Language;
use crate::parser::Parser;
#[cfg(feature = "net")]
use crate::security::ai_false_positive_filter::AIFalsePositiveFilter;
use crate::security::ast_analyzer::{
    AstSecurityAnalyzer, CodeContext, SecurityFinding, SecurityFindingType, SecuritySeverity,
};
use crate::security::deterministic_filter::FilterMode;
use crate::security::heuristic_filter::HeuristicFindingFilter;
use crate::security::owasp_detector::{
    OwaspCategory as DetectorOwaspCategory, OwaspDetector, OwaspFinding, VulnSeverity,
};
use crate::security::rule_engine::DeclarativeRuleEngine;
use crate::taint_analysis::{TaintAnalyzer, TaintFlow, VulnerabilityType};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

/// Confidence provenance for a scored security finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConfidenceSource {
    /// Confirmed by a taint source-to-sink flow.
    TaintConfirmed,
    /// Produced by AST-level structural analysis.
    AstPattern,
    /// Produced by heuristic detection without structural confirmation.
    Heuristic,
}

/// Normalized finding returned by the canonical security pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredFinding {
    pub id: String,
    pub finding_type: SecurityFindingType,
    pub severity: SecuritySeverity,
    pub title: String,
    pub description: String,
    pub file_path: String,
    pub line_number: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub code_snippet: String,
    pub cwe_id: Option<String>,
    pub remediation: String,
    pub confidence: f64,
    pub context: CodeContext,
    pub confidence_source: ConfidenceSource,
}

impl From<ScoredFinding> for SecurityFinding {
    fn from(value: ScoredFinding) -> Self {
        Self {
            id: value.id,
            finding_type: value.finding_type,
            severity: value.severity,
            title: value.title,
            description: value.description,
            file_path: value.file_path,
            line_number: value.line_number,
            column_start: value.column_start,
            column_end: value.column_end,
            code_snippet: value.code_snippet,
            cwe_id: value.cwe_id,
            remediation: value.remediation,
            confidence: value.confidence,
            context: value.context,
        }
    }
}

impl ScoredFinding {
    fn from_security_finding(
        finding: SecurityFinding,
        confidence_source: ConfidenceSource,
    ) -> Self {
        Self {
            id: finding.id,
            finding_type: finding.finding_type,
            severity: finding.severity,
            title: finding.title,
            description: finding.description,
            file_path: finding.file_path,
            line_number: finding.line_number,
            column_start: finding.column_start,
            column_end: finding.column_end,
            code_snippet: finding.code_snippet,
            cwe_id: finding.cwe_id,
            remediation: finding.remediation,
            confidence: finding.confidence,
            context: finding.context,
            confidence_source,
        }
    }
}

/// Pipeline configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPipelineConfig {
    /// Drop findings below this confidence after scoring and filtering.
    pub min_confidence: f64,
    /// Heuristic filter posture.
    pub filter_mode: FilterMode,
    /// Whether to include OWASP detector results.
    pub enable_owasp: bool,
    /// Whether to include declarative query-backed rules.
    pub enable_rules: bool,
    /// Optional override for the rule directory.
    pub rules_dir: Option<PathBuf>,
}

impl Default for SecurityPipelineConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.5,
            filter_mode: FilterMode::Balanced,
            enable_owasp: true,
            enable_rules: true,
            rules_dir: None,
        }
    }
}

/// Canonical security-analysis entry point.
pub struct SecurityPipeline {
    ast_analyzer: AstSecurityAnalyzer,
    heuristic_filter: HeuristicFindingFilter,
    owasp_detector: OwaspDetector,
    rule_engine: Option<DeclarativeRuleEngine>,
    config: SecurityPipelineConfig,
}

impl SecurityPipeline {
    /// Create the pipeline with default configuration.
    pub fn new() -> Result<Self> {
        Self::with_config(SecurityPipelineConfig::default())
    }

    /// Create the pipeline with custom configuration.
    pub fn with_config(config: SecurityPipelineConfig) -> Result<Self> {
        let rule_engine = if config.enable_rules {
            Some(match &config.rules_dir {
                Some(rules_dir) => DeclarativeRuleEngine::load_from_dir(rules_dir)?,
                None => DeclarativeRuleEngine::load_builtin()?,
            })
        } else {
            None
        };

        Ok(Self {
            ast_analyzer: AstSecurityAnalyzer::new()?,
            heuristic_filter: HeuristicFindingFilter::with_mode(config.filter_mode),
            owasp_detector: OwaspDetector::new()?,
            rule_engine,
            config,
        })
    }

    /// Analyze in-memory code.
    pub fn analyze(&self, source_code: &str, language: Language) -> Result<Vec<ScoredFinding>> {
        self.analyze_with_path(source_code, Path::new("<memory>"), language)
    }

    /// Analyze a file on disk.
    pub fn analyze_file(&self, file_path: &Path, language: Language) -> Result<Vec<ScoredFinding>> {
        let source_code = std::fs::read_to_string(file_path)?;
        self.analyze_with_path(&source_code, file_path, language)
    }

    /// Analyze in-memory code with a concrete file path for context-sensitive filtering.
    pub fn analyze_with_path(
        &self,
        source_code: &str,
        file_path: &Path,
        language: Language,
    ) -> Result<Vec<ScoredFinding>> {
        let parser = Parser::new(language)?;
        let tree = parser.parse(source_code, None)?;

        let mut staged_findings = Vec::new();

        let ast_findings = block_on_immediate(self.ast_analyzer.analyze_source_raw(
            source_code,
            file_path,
            language,
        ))?;
        staged_findings.extend(ast_findings.into_iter().map(|finding| {
            ScoredFinding::from_security_finding(finding, ConfidenceSource::AstPattern)
        }));

        if let Some(rule_engine) = &self.rule_engine {
            let rule_findings = rule_engine.evaluate(&tree, language, file_path)?;
            staged_findings.extend(rule_findings.into_iter().map(|finding| {
                ScoredFinding::from_security_finding(finding, ConfidenceSource::AstPattern)
            }));
        }

        if self.config.enable_owasp {
            let heuristic_findings = self.owasp_detector.detect_vulnerabilities(
                &tree,
                source_code,
                &file_path.to_string_lossy(),
            )?;
            staged_findings.extend(heuristic_findings.into_iter().map(Self::owasp_to_scored));
        }

        let taint_flows = if staged_findings.is_empty() {
            Vec::new()
        } else {
            let mut taint_analyzer = TaintAnalyzer::new(language.name());
            catch_unwind_silently(AssertUnwindSafe(|| {
                taint_analyzer.analyze_with_path(&tree, file_path)
            }))
            .ok()
            .and_then(|result| result.ok())
            .unwrap_or_default()
        };

        let mut findings: Vec<_> = staged_findings
            .into_iter()
            .map(|finding| self.apply_confidence_scoring(finding, &taint_flows))
            .collect();

        findings = self.apply_heuristic_filter(findings)?;
        findings.retain(|finding| finding.confidence >= self.config.min_confidence);
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| {
                    b.confidence
                        .partial_cmp(&a.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.file_path.cmp(&b.file_path))
                .then_with(|| a.line_number.cmp(&b.line_number))
        });

        Ok(findings)
    }

    /// Async variant that runs the same pipeline and then applies the optional AI filter.
    #[cfg(feature = "net")]
    pub async fn analyze_with_ai(
        &self,
        source_code: &str,
        file_path: &Path,
        language: Language,
        ai_filter: &AIFalsePositiveFilter,
    ) -> Result<Vec<ScoredFinding>> {
        let findings = self.analyze_with_path(source_code, file_path, language)?;
        let mut filtered = Vec::new();

        for finding in findings {
            let security_finding: SecurityFinding = finding.clone().into();
            let ai_result = ai_filter
                .filter_finding(
                    &security_finding,
                    &finding.file_path,
                    &finding.code_snippet,
                    Some(source_code),
                )
                .await?;

            if !ai_result.should_filter {
                filtered.push(finding);
            }
        }

        Ok(filtered)
    }

    fn apply_heuristic_filter(&self, findings: Vec<ScoredFinding>) -> Result<Vec<ScoredFinding>> {
        let mut filtered = Vec::new();

        for mut finding in findings {
            let filter_result = block_on_immediate(self.heuristic_filter.filter_finding(
                &finding.finding_type.to_string(),
                &finding.file_path,
                &finding.code_snippet,
                finding.confidence,
            ))?;

            if filter_result.should_filter {
                continue;
            }

            if let Some(delta) = filter_result.adjustments.get("confidence_boost") {
                finding.confidence = (finding.confidence + delta).clamp(0.0, 1.0);
            }

            filtered.push(finding);
        }

        Ok(filtered)
    }

    fn apply_confidence_scoring(
        &self,
        mut finding: ScoredFinding,
        taint_flows: &[TaintFlow],
    ) -> ScoredFinding {
        let taint_confirmed = taint_flows
            .iter()
            .any(|flow| self.flow_confirms_finding(flow, &finding));

        if taint_confirmed {
            finding.confidence = finding.confidence.max(0.85).clamp(0.85, 1.0);
            finding.confidence_source = ConfidenceSource::TaintConfirmed;
            return finding;
        }

        match finding.confidence_source {
            ConfidenceSource::AstPattern => {
                finding.confidence = finding.confidence.clamp(0.5, 0.79);
            }
            ConfidenceSource::Heuristic => {
                finding.confidence = finding.confidence.min(0.45);
            }
            ConfidenceSource::TaintConfirmed => {}
        }

        finding
    }

    fn flow_confirms_finding(&self, flow: &TaintFlow, finding: &ScoredFinding) -> bool {
        if flow.is_sanitized {
            return false;
        }

        if Self::map_vulnerability_type(&flow.sink.vulnerability_type) != finding.finding_type {
            return false;
        }

        let sink_line = flow.sink.location.line;
        if sink_line == 0 || finding.line_number == 0 {
            return true;
        }

        sink_line.abs_diff(finding.line_number) <= 2
    }

    fn owasp_to_scored(finding: OwaspFinding) -> ScoredFinding {
        let detector_confidence = finding.confidence.min(0.45);
        ScoredFinding {
            id: finding.id,
            finding_type: match finding.category {
                DetectorOwaspCategory::A01BrokenAccessControl => {
                    SecurityFindingType::BrokenAccessControl
                }
                DetectorOwaspCategory::A02CryptographicFailures => {
                    SecurityFindingType::CryptographicFailure
                }
                DetectorOwaspCategory::A03Injection => SecurityFindingType::Injection,
                DetectorOwaspCategory::A04InsecureDesign => SecurityFindingType::InsecureDesign,
                DetectorOwaspCategory::A05SecurityMisconfiguration => {
                    SecurityFindingType::SecurityMisconfiguration
                }
            },
            severity: match finding.severity {
                VulnSeverity::Critical => SecuritySeverity::Critical,
                VulnSeverity::High => SecuritySeverity::High,
                VulnSeverity::Medium => SecuritySeverity::Medium,
                VulnSeverity::Low => SecuritySeverity::Low,
            },
            title: finding.name,
            description: finding.description,
            file_path: finding.file_path,
            line_number: finding.line_number,
            column_start: 0,
            column_end: 0,
            code_snippet: finding.code_snippet,
            cwe_id: finding.cwe_id,
            remediation: finding.remediation,
            confidence: detector_confidence,
            context: CodeContext::default(),
            confidence_source: ConfidenceSource::Heuristic,
        }
    }

    fn map_vulnerability_type(vulnerability_type: &VulnerabilityType) -> SecurityFindingType {
        match vulnerability_type {
            VulnerabilityType::SqlInjection
            | VulnerabilityType::CommandInjection
            | VulnerabilityType::CrossSiteScripting => SecurityFindingType::Injection,
            VulnerabilityType::PathTraversal => SecurityFindingType::BrokenAccessControl,
            VulnerabilityType::HeaderInjection => SecurityFindingType::SecurityMisconfiguration,
            VulnerabilityType::LogInjection | VulnerabilityType::DeserializationAttack => {
                SecurityFindingType::InsecureDesign
            }
        }
    }
}

fn block_on_immediate<F>(future: F) -> F::Output
where
    F: Future,
{
    fn raw_waker() -> RawWaker {
        fn clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        fn no_op(_: *const ()) {}

        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(std::ptr::null(), &VTABLE)
    }

    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut future = Pin::from(Box::new(future));
    let mut context = Context::from_waker(&waker);

    loop {
        match Future::poll(future.as_mut(), &mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn catch_unwind_silently<F, R>(closure: F) -> std::thread::Result<R>
where
    F: FnOnce() -> R + std::panic::UnwindSafe,
{
    static PANIC_HOOK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let hook_lock = PANIC_HOOK_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = hook_lock.lock().expect("panic hook mutex poisoned");

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(closure);
    std::panic::set_hook(original_hook);
    result
}
