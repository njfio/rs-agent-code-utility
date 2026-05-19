//! Multi-line regex compile path for Index.Grep v2 — U3.
//!
//! When `validate()` returns `ValidatedGrepCall::Regex { multiline: true, .. }`,
//! the daemon needs to compile the user's pattern with
//! `dot_matches_new_line(true) + multi_line(true)` flags and *also*
//! constrain the regex compile to an explicit DFA/NFA size budget so
//! adversarial patterns like `(?s).*` over a large file return a
//! structured `REGEX_TOO_COMPLEX` error instead of OOMing the daemon.
//!
//! See `docs/plans/2026-05-18-002-feat-index-grep-v2-plan.md` §U3
//! for the design rationale and budget choices.

use regex::bytes::{Regex, RegexBuilder};

use super::errors::{GrepValidationCode, GrepValidationError};

/// DFA byte budget for compiled multiline regex. Bounded so that
/// `(?s).*` over a 4 MB file cannot expand the DFA without bound.
/// Single-line regex (the v1 path) inherits the regex crate's
/// defaults; this limit applies only when `multiline: true`.
pub const MULTILINE_DFA_SIZE_LIMIT: usize = 32 * 1024 * 1024;

/// NFA byte budget — the upstream `size_limit` knob covers
/// pre-compilation structure size. Same shape as the DFA cap.
pub const MULTILINE_NFA_SIZE_LIMIT: usize = 32 * 1024 * 1024;

/// Compile a regex for the multiline path. Sets `dot_matches_new_line`
/// + `multi_line` flags, applies the DFA/NFA size budgets, and
/// returns a structured `REGEX_TOO_COMPLEX` error envelope on
/// compile failure (whether syntax error or budget breach — the
/// regex crate doesn't separate them in `RegexBuilder::build`'s
/// error type, so we surface both as `REGEX_TOO_COMPLEX` with the
/// upstream error message in `data.error_message`).
pub fn compile_multiline_regex(
    pattern: &str,
    case_insensitive: bool,
) -> Result<Regex, GrepValidationError> {
    compile_multiline_regex_with_limits(
        pattern,
        case_insensitive,
        MULTILINE_DFA_SIZE_LIMIT,
        MULTILINE_NFA_SIZE_LIMIT,
    )
}

/// Internal seam: lets tests force a tiny size limit to provoke the
/// budget-breach error path without needing a real adversarial input
/// large enough to blow the production cap.
pub(crate) fn compile_multiline_regex_with_limits(
    pattern: &str,
    case_insensitive: bool,
    dfa_size_limit: usize,
    nfa_size_limit: usize,
) -> Result<Regex, GrepValidationError> {
    let mut builder = RegexBuilder::new(pattern);
    builder
        .case_insensitive(case_insensitive)
        .dot_matches_new_line(true)
        .multi_line(true)
        .size_limit(nfa_size_limit)
        .dfa_size_limit(dfa_size_limit);
    builder.build().map_err(|e| {
        GrepValidationError::new(
            GrepValidationCode::RegexTooComplex,
            format!("multiline regex failed to compile: {e}"),
        )
        .with_data("error_message", serde_json::Value::String(e.to_string()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_simple_multiline_pattern() {
        let re = compile_multiline_regex(r"fn\s+foo\([^)]*\)", false).expect("compile");
        // Sanity-check the flags actually took effect: `.` matches `\n`.
        let bytes: &[u8] = b"fn foo(\n    arg: u32,\n)";
        assert!(re.is_match(bytes), "multiline regex should span newlines");
    }

    #[test]
    fn adversarial_pattern_under_tiny_budget_returns_regex_too_complex() {
        // 1 KB DFA budget cannot accommodate `(?s).*` over a wide
        // alphabet — the build() call fails with a CompiledTooBig
        // error. We surface it as REGEX_TOO_COMPLEX with the upstream
        // diagnostic in `data.error_message`.
        let err = compile_multiline_regex_with_limits(
            r"(?s).*", false, /* dfa_size_limit = */ 1024, /* nfa_size_limit = */ 1024,
        )
        .expect_err("tiny budget must reject `(?s).*`");
        assert_eq!(err.code, GrepValidationCode::RegexTooComplex);
        assert!(
            err.data.contains_key("error_message"),
            "REGEX_TOO_COMPLEX should carry data.error_message: {:?}",
            err.data
        );
    }

    #[test]
    fn syntax_error_also_renders_as_regex_too_complex_envelope() {
        // The regex crate's `build()` returns the same `Error` type
        // for both syntax errors and size-limit breaches. We map both
        // to REGEX_TOO_COMPLEX (the diagnostic message preserves the
        // distinction for the caller).
        let err =
            compile_multiline_regex(r"(unbalanced", false).expect_err("syntax error must reject");
        assert_eq!(err.code, GrepValidationCode::RegexTooComplex);
    }
}
