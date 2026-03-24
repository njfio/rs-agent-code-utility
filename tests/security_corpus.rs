use proptest::prelude::*;
use rust_tree_sitter::advanced_security::{
    AdvancedSecurityAnalyzer, AdvancedSecurityResult, ConfidenceLevel, DetectedSecret,
    SecurityVulnerability,
};
use rust_tree_sitter::analyzer::{AnalysisResult, FileInfo};
use rust_tree_sitter::security::accuracy_metrics::AccuracyMetrics;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[derive(Clone, Copy, Debug)]
enum ExpectedOutcome {
    Vulnerable,
    Safe,
}

#[derive(Clone, Debug)]
struct CorpusCase {
    class: &'static str,
    relative_path: &'static str,
    cwe_id: &'static str,
    expected: ExpectedOutcome,
    min_confidence: ConfidenceLevel,
}

const CORPUS_CASES: &[CorpusCase] = &[
    CorpusCase {
        class: "sql-injection",
        relative_path: "tests/fixtures/security-corpus/sql-injection/rust-positive-format.rs",
        cwe_id: "CWE-89",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Low,
    },
    CorpusCase {
        class: "sql-injection",
        relative_path: "tests/fixtures/security-corpus/sql-injection/javascript-positive-concat.js",
        cwe_id: "CWE-89",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Low,
    },
    CorpusCase {
        class: "sql-injection",
        relative_path:
            "tests/fixtures/security-corpus/sql-injection/javascript-negative-parameterized.js",
        cwe_id: "CWE-89",
        expected: ExpectedOutcome::Safe,
        min_confidence: ConfidenceLevel::Low,
    },
    CorpusCase {
        class: "sql-injection",
        relative_path:
            "tests/fixtures/security-corpus/sql-injection/python-positive-cursor-execute.py",
        cwe_id: "CWE-89",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Low,
    },
    CorpusCase {
        class: "command-injection",
        relative_path: "tests/fixtures/security-corpus/command-injection/rust-positive-shell-c.rs",
        cwe_id: "CWE-78",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Medium,
    },
    CorpusCase {
        class: "command-injection",
        relative_path:
            "tests/fixtures/security-corpus/command-injection/javascript-positive-exec.js",
        cwe_id: "CWE-78",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Medium,
    },
    CorpusCase {
        class: "command-injection",
        relative_path:
            "tests/fixtures/security-corpus/command-injection/javascript-positive-exec-sync.js",
        cwe_id: "CWE-78",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Medium,
    },
    CorpusCase {
        class: "command-injection",
        relative_path:
            "tests/fixtures/security-corpus/command-injection/python-positive-os-system.py",
        cwe_id: "CWE-78",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Medium,
    },
    CorpusCase {
        class: "command-injection",
        relative_path:
            "tests/fixtures/security-corpus/command-injection/rust-negative-safe-args.rs",
        cwe_id: "CWE-78",
        expected: ExpectedOutcome::Safe,
        min_confidence: ConfidenceLevel::Low,
    },
    CorpusCase {
        class: "secrets",
        relative_path: "tests/fixtures/security-corpus/secrets/rust-positive-aws.rs",
        cwe_id: "CWE-798",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Low,
    },
    CorpusCase {
        class: "secrets",
        relative_path: "tests/fixtures/security-corpus/secrets/javascript-positive-aws.js",
        cwe_id: "CWE-798",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Low,
    },
    CorpusCase {
        class: "secrets",
        relative_path: "tests/fixtures/security-corpus/secrets/python-positive-api-token.py",
        cwe_id: "CWE-798",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Low,
    },
    CorpusCase {
        class: "secrets",
        relative_path: "tests/fixtures/security-corpus/secrets/rust-negative-env-token.rs",
        cwe_id: "CWE-798",
        expected: ExpectedOutcome::Safe,
        min_confidence: ConfidenceLevel::Low,
    },
    CorpusCase {
        class: "secrets",
        relative_path: "tests/fixtures/security-corpus/secrets/python-negative-env-token.py",
        cwe_id: "CWE-798",
        expected: ExpectedOutcome::Safe,
        min_confidence: ConfidenceLevel::Low,
    },
    CorpusCase {
        class: "xss",
        relative_path: "tests/fixtures/security-corpus/xss/javascript-positive-innerhtml.js",
        cwe_id: "CWE-79",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Medium,
    },
    CorpusCase {
        class: "xss",
        relative_path: "tests/fixtures/security-corpus/xss/javascript-positive-innerhtml-append.js",
        cwe_id: "CWE-79",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Medium,
    },
    CorpusCase {
        class: "xss",
        relative_path: "tests/fixtures/security-corpus/xss/javascript-positive-document-write.js",
        cwe_id: "CWE-79",
        expected: ExpectedOutcome::Vulnerable,
        min_confidence: ConfidenceLevel::Medium,
    },
    CorpusCase {
        class: "xss",
        relative_path: "tests/fixtures/security-corpus/xss/javascript-negative-textcontent.js",
        cwe_id: "CWE-79",
        expected: ExpectedOutcome::Safe,
        min_confidence: ConfidenceLevel::Low,
    },
];

#[test]
fn security_corpus_meets_detection_thresholds() {
    let analyzer = AdvancedSecurityAnalyzer::new()
        .unwrap_or_else(|err| panic!("failed to create analyzer: {}", err));
    let mut overall_metrics = AccuracyMetrics::new();

    assert!(
        CORPUS_CASES.len() >= 18,
        "expected at least 18 corpus cases, found {}",
        CORPUS_CASES.len()
    );

    for case in CORPUS_CASES {
        let fixture_path = fixture_path(case.relative_path);
        let result = analyze_corpus_fixture(&analyzer, &fixture_path);
        let relevant = relevant_findings(&result.vulnerabilities, case.cwe_id);
        let detected = if case.class == "secrets" {
            secret_detected(&result, &relevant)
        } else {
            !relevant.is_empty()
        };
        let expected_vulnerable = matches!(case.expected, ExpectedOutcome::Vulnerable);

        overall_metrics.update(detected, expected_vulnerable);

        match case.expected {
            ExpectedOutcome::Vulnerable => {
                if case.class == "secrets" {
                    assert_secret_positive(case, &result, &relevant);
                } else {
                    assert!(
                        detected,
                        "expected {} fixture {} to produce {}, but result was {:?}",
                        case.class, case.relative_path, case.cwe_id, result
                    );
                    assert_vulnerabilities_meet_confidence(case, &relevant);
                }
            }
            ExpectedOutcome::Safe => {
                if case.class == "secrets" {
                    assert_secret_negative(case, &result, &relevant);
                } else {
                    assert!(
                        !detected,
                        "expected {} fixture {} to stay clean for {}, but result was {:?}",
                        case.class, case.relative_path, case.cwe_id, result
                    );
                }
            }
        }
    }

    assert!(
        overall_metrics.recall() >= 0.8,
        "security corpus recall regressed below threshold: {:.2}%",
        overall_metrics.recall() * 100.0
    );
    assert!(
        overall_metrics.precision() >= 0.7,
        "security corpus precision regressed below threshold: {:.2}%",
        overall_metrics.precision() * 100.0
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 8,
        .. ProptestConfig::default()
    })]

    #[test]
    fn sql_injection_variants_are_detected(
        table in "[a-z][a-z0-9_]{2,7}",
        field in "[a-z][a-z0-9_]{2,7}",
        user_var in "[a-z][a-z0-9_]{2,7}",
    ) {
        let source = format!(
            "function fetchRecord({user_var}) {{ return execute(\"SELECT * FROM {table} WHERE {field} = '\" + {user_var} + \"'\"); }}",
        );

        let findings = analyze_generated_source(&source, "variant.js");
        prop_assert!(
            has_cwe(&findings, "CWE-89"),
            "expected SQL injection variant to be detected, got {:?}",
            findings
        );
    }

    #[test]
    fn command_injection_variants_are_detected(
        binary in prop::sample::select(vec!["ls", "cat", "grep"]),
        user_var in "[a-z][a-z0-9_]{2,7}",
    ) {
        let source = format!(
            "function run({user_var}) {{ return exec(\"{binary} \" + {user_var}); }}",
        );

        let findings = analyze_generated_source(&source, "variant.js");
        prop_assert!(
            has_cwe(&findings, "CWE-78"),
            "expected command injection variant to be detected, got {:?}",
            findings
        );
    }
}

fn analyze_corpus_fixture(
    analyzer: &AdvancedSecurityAnalyzer,
    path: &Path,
) -> AdvancedSecurityResult {
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {}", path.display(), err));
    let temp_dir = TempDir::new()
        .unwrap_or_else(|err| panic!("failed to create temp dir for {}: {}", path.display(), err));
    let file_name = path
        .file_name()
        .unwrap_or_else(|| panic!("fixture {} has no filename", path.display()));
    let analysis_path = temp_dir.path().join(file_name);
    std::fs::write(&analysis_path, &source).unwrap_or_else(|err| {
        panic!(
            "failed to stage fixture {} for analysis: {}",
            path.display(),
            err
        )
    });

    let mut languages = HashMap::new();
    languages.insert(fixture_language(path).to_string(), 1);

    let file_info = FileInfo {
        path: PathBuf::from(file_name),
        language: fixture_language(path).to_string(),
        size: source.len(),
        lines: source.lines().count(),
        parsed_successfully: true,
        parse_errors: Vec::new(),
        symbols: Vec::new(),
        security_vulnerabilities: Vec::new(),
    };

    let analysis = AnalysisResult {
        root_path: temp_dir.path().to_path_buf(),
        total_files: 1,
        parsed_files: 1,
        error_files: 0,
        total_lines: source.lines().count(),
        languages,
        files: vec![file_info],
        config: Default::default(),
    };

    analyzer
        .analyze(&analysis)
        .unwrap_or_else(|err| panic!("failed to analyze fixture {}: {}", path.display(), err))
}

fn analyze_generated_source(source: &str, file_name: &str) -> Vec<SecurityVulnerability> {
    let temp_dir =
        TempDir::new().unwrap_or_else(|err| panic!("failed to create temp dir: {}", err));
    let path = temp_dir.path().join(file_name);
    std::fs::write(&path, source).unwrap_or_else(|err| {
        panic!(
            "failed to write generated source {}: {}",
            path.display(),
            err
        )
    });

    let analyzer = AdvancedSecurityAnalyzer::new()
        .unwrap_or_else(|err| panic!("failed to create analyzer: {}", err));
    analyze_generated_fixture(&analyzer, &path)
}

fn analyze_generated_fixture(
    analyzer: &AdvancedSecurityAnalyzer,
    path: &Path,
) -> Vec<SecurityVulnerability> {
    let source = std::fs::read_to_string(path).unwrap_or_else(|err| {
        panic!(
            "failed to read generated source {}: {}",
            path.display(),
            err
        )
    });
    let file_info = FileInfo {
        path: path.to_path_buf(),
        language: fixture_language(path).to_string(),
        size: source.len(),
        lines: source.lines().count(),
        parsed_successfully: true,
        parse_errors: Vec::new(),
        symbols: Vec::new(),
        security_vulnerabilities: Vec::new(),
    };

    analyzer
        .detect_owasp_vulnerabilities(&file_info)
        .unwrap_or_else(|err| {
            panic!(
                "failed to analyze generated source {}: {}",
                path.display(),
                err
            )
        })
}

fn relevant_findings<'a>(
    findings: &'a [SecurityVulnerability],
    cwe_id: &str,
) -> Vec<&'a SecurityVulnerability> {
    findings
        .iter()
        .filter(|finding| finding.cwe_id.as_deref() == Some(cwe_id))
        .collect()
}

fn has_cwe(findings: &[SecurityVulnerability], cwe_id: &str) -> bool {
    findings
        .iter()
        .any(|finding| finding.cwe_id.as_deref() == Some(cwe_id))
}

fn assert_vulnerabilities_meet_confidence(case: &CorpusCase, findings: &[&SecurityVulnerability]) {
    assert!(
        findings
            .iter()
            .all(|finding| finding.confidence >= case.min_confidence),
        "expected {} fixture {} findings to have at least {:?} confidence, got {:?}",
        case.class,
        case.relative_path,
        case.min_confidence,
        findings
    );
}

fn assert_secrets_meet_confidence(case: &CorpusCase, secrets: &[DetectedSecret]) {
    assert!(
        secrets
            .iter()
            .all(|secret| secret.confidence >= case.min_confidence),
        "expected {} fixture {} secrets to have at least {:?} confidence, got {:?}",
        case.class,
        case.relative_path,
        case.min_confidence,
        secrets
    );
}

fn secret_detected(result: &AdvancedSecurityResult, relevant: &[&SecurityVulnerability]) -> bool {
    !result.secrets.is_empty() || !relevant.is_empty()
}

fn assert_secret_positive(
    case: &CorpusCase,
    result: &AdvancedSecurityResult,
    relevant: &[&SecurityVulnerability],
) {
    assert!(
        secret_detected(result, relevant),
        "expected {} fixture {} to produce {}, but result was {:?}",
        case.class,
        case.relative_path,
        case.cwe_id,
        result
    );

    if !result.secrets.is_empty() {
        assert_secrets_meet_confidence(case, &result.secrets);
    } else {
        assert_vulnerabilities_meet_confidence(case, relevant);
    }
}

fn assert_secret_negative(
    case: &CorpusCase,
    result: &AdvancedSecurityResult,
    relevant: &[&SecurityVulnerability],
) {
    assert!(
        !secret_detected(result, relevant),
        "expected {} fixture {} to stay clean for {}, but result was {:?}",
        case.class,
        case.relative_path,
        case.cwe_id,
        result
    );
}

fn fixture_path(relative_path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path)
}

fn fixture_language(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("rs") => "rust",
        Some("js") => "javascript",
        Some("py") => "python",
        _ => "unknown",
    }
}
