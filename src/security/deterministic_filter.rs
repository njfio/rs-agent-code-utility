//! Deterministic false-positive filter (no ML/AI, fast and predictable)

use crate::advanced_security::{SecuritySeverity, SecurityVulnerability};

/// Filter mode for deterministic filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    Strict,
    Balanced,
    Permissive,
}

impl FilterMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "strict" => FilterMode::Strict,
            "permissive" => FilterMode::Permissive,
            _ => FilterMode::Balanced,
        }
    }
}

/// Apply deterministic filtering heuristics to reduce false positives.
/// Returns references into the original slice, preserving ordering.
pub fn filter_vulnerabilities<'a>(
    vulns: &'a [SecurityVulnerability],
    mode: FilterMode,
) -> Vec<&'a SecurityVulnerability> {
    vulns
        .iter()
        .filter(|v| keep(v, mode))
        .collect()
}

fn keep(v: &SecurityVulnerability, mode: FilterMode) -> bool {
    let file = v.location.file.to_string_lossy().to_lowercase();
    let code = v.code_snippet.to_lowercase();
    let title = v.title.to_lowercase();

    let is_docs = file.ends_with(".md")
        || file.contains("/docs/")
        || file.contains("\\docs\\")
        || file.contains("readme");
    let is_test = file.contains("/tests/")
        || file.contains("/test/")
        || file.contains("/spec/")
        || file.contains("/specs/")
        || file.ends_with("_test.rs")
        || file.contains("test_");
    let is_example = file.contains("/examples/") || file.contains("/example/") || file.contains("/demo/");
    let is_fixture = file.contains("fixture") || file.contains("mock") || file.contains("stub")
        || file.contains("snapshots") || file.contains("__snapshots__") || file.contains("test_files");

    let looks_like_example = code.contains("example")
        || code.contains("demo")
        || code.contains("sample")
        || code.contains("placeholder")
        || title.contains("example");

    // Heuristic: comment-only or non-executable snippet (documentation lines)
    let trimmed = v.code_snippet.trim_start();
    let comment_only = trimmed.starts_with("//") || trimmed.starts_with("/*");
    let lacks_code_tokens = !v.code_snippet.contains('=')
        && !v.code_snippet.contains('"')
        && !v.code_snippet.contains('\'')
        && !v.code_snippet.contains('(');

    let is_low_sev = matches!(v.severity, SecuritySeverity::Low | SecuritySeverity::Info);
    let is_medium_sev = matches!(v.severity, SecuritySeverity::Medium);

    match mode {
        FilterMode::Strict => {
            if is_docs || is_example || is_fixture || looks_like_example || is_test || comment_only || lacks_code_tokens {
                return false;
            }
            // Also drop low/medium in config/constants files
            if (is_low_sev || is_medium_sev)
                && (file.contains("config") || file.contains("constants") || file.ends_with(".md"))
            {
                return false;
            }
            true
        }
        FilterMode::Balanced => {
            // Default: drop low severities in tests/docs/examples/fixtures
            if is_low_sev && (is_docs || is_example || is_fixture || is_test) {
                return false;
            }
            // Drop any severity if snippet is clearly documentation/comment-only
            if comment_only || (lacks_code_tokens && (is_docs || is_example || is_fixture || is_test)) {
                return false;
            }
            // Drop anything that looks like documentation example regardless of sev if Info
            if looks_like_example && matches!(v.severity, SecuritySeverity::Info) {
                return false;
            }
            true
        }
        FilterMode::Permissive => {
            // Keep almost everything; only drop Info in docs
            if matches!(v.severity, SecuritySeverity::Info) && is_docs {
                return false;
            }
            true
        }
    }
}

// Tests are provided at integration level; unit tests omitted to avoid coupling to evolving types
