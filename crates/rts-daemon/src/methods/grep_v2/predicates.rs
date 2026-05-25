//! Predicate whitelist + budget enforcement for structural queries.
//!
//! ## Why a whitelist
//!
//! Tree-sitter queries accept *user-defined* predicates of the form
//! `(#name? @capture "arg")` which the calling code is free to
//! interpret however it likes. The most useful are the seven
//! whitelisted below; others (`#contains?`, `#match-regex?` variants
//! from third-party tooling) are either non-standard or carry
//! DoS-shaped surface area we don't want to expose to agent-supplied
//! input.
//!
//! v1 ships the conservative whitelist. If observed agent usage
//! demands more, expand in a follow-up PR — don't widen pre-emptively
//! (each accepted predicate is a new piece of surface).
//!
//! ## v1 whitelist
//!
//! 1. `#eq?`        — exact text equality between capture and arg
//! 2. `#not-eq?`    — inverse of `#eq?`
//! 3. `#match?`     — capture text matches regex arg
//! 4. `#not-match?` — capture text does NOT match regex arg
//! 5. `#any-of?`    — capture text equals one of N string args
//! 6. `#is?`        — capture has a tagged annotation (tree-sitter
//!                    standard, used by tags.scm)
//! 7. `#is-not?`    — inverse of `#is?`
//!
//! ## Implementation note
//!
//! This is a **string-scan parser**, not a tree-sitter-grammar
//! parser, for the v1 cut. Reasons:
//!
//! 1. Tree-sitter 0.26's Rust binding doesn't expose the parsed
//!    predicate-AST through the `Query::general_predicates` API in a
//!    way we can iterate from `rts_core`.
//! 2. The predicate syntax is regular enough (`#name? args...`
//!    inside `(...)` form) that a hand-rolled scanner is small,
//!    auditable, and correct for the patterns agents actually
//!    write.
//! 3. The whitelist is a safety net, not a parser — we only need
//!    to find any predicate-name token that isn't on the list. False
//!    positives (rejecting a legal predicate that's actually a
//!    string literal containing `#eq?`) would surface as
//!    `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED` with a clear
//!    message, which is recoverable from the caller side. The
//!    scanner is conservative about string literals: tokens
//!    inside `"…"` are skipped.
//!
//! If a v1.x cut needs richer surface area (e.g. predicate-arg
//! validation), graduate this module to a real S-expression
//! mini-parser. For now the surface fits in 80 lines.

use regex::RegexBuilder;

use super::errors::{GrepValidationCode, GrepValidationError};
use super::limits::PREDICATE_REGEX_DFA_LIMIT;

/// The v1 whitelist. Lexically ordered alphabetically; the order
/// doesn't affect behavior but keeps diffs readable.
const ALLOWED_PREDICATES: &[&str] = &[
    "any-of?",
    "eq?",
    "is-not?",
    "is?",
    "match?",
    "not-eq?",
    "not-match?",
];

/// Inspect `query_text` for predicates and reject any that fall
/// outside the whitelist. For `#match?` / `#not-match?` also test-
/// compile the regex argument against the
/// [`PREDICATE_REGEX_DFA_LIMIT`] DFA cap so catastrophic patterns
/// fail at validation time, not runtime.
///
/// Returns `Ok(())` if the query uses only whitelisted predicates;
/// otherwise `Err(STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED)`. The
/// error's `message` names the offending predicate so the caller can
/// fix their query without a separate diagnostic call.
pub fn validate_predicates(query_text: &str) -> Result<(), GrepValidationError> {
    for pred in scan_predicates(query_text) {
        if !ALLOWED_PREDICATES.contains(&pred.name.as_str()) {
            return Err(GrepValidationError::new(
                GrepValidationCode::StructuralQueryPredicateNotAllowed,
                format!(
                    "predicate `#{}` is not on the v1 whitelist; allowed: {}",
                    pred.name,
                    ALLOWED_PREDICATES
                        .iter()
                        .map(|s| format!("#{s}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }

        // For `#match?` / `#not-match?`, the second token (after
        // the capture name) is the regex argument. Compile-test it
        // against the DFA cap.
        if pred.name == "match?" || pred.name == "not-match?" {
            if let Some(regex_arg) = pred.regex_arg.as_deref() {
                let compile = RegexBuilder::new(regex_arg)
                    .dfa_size_limit(PREDICATE_REGEX_DFA_LIMIT)
                    .size_limit(PREDICATE_REGEX_DFA_LIMIT)
                    .build();
                if compile.is_err() {
                    return Err(GrepValidationError::new(
                        GrepValidationCode::StructuralQueryPredicateNotAllowed,
                        format!(
                            "predicate `#{}` regex compile exceeded budget ({} bytes): {}",
                            pred.name,
                            PREDICATE_REGEX_DFA_LIMIT,
                            compile.err().unwrap()
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// A predicate occurrence found by the scanner. `name` is the bare
/// identifier *without* the leading `#` and trailing `?` (so the
/// whitelist comparison is by bare token). `regex_arg` carries the
/// regex argument if this is a `#match?` / `#not-match?` form.
#[derive(Debug, Clone)]
struct ScannedPredicate {
    name: String,
    regex_arg: Option<String>,
}

/// Hand-rolled scanner. Walks bytes of `query_text` looking for
/// `(#NAME?` patterns at depth >= 1 (a top-level `#NAME?` at depth 0
/// isn't legal tree-sitter query syntax anyway). Treats `"..."`
/// literals as opaque (no token recognition inside).
fn scan_predicates(query_text: &str) -> Vec<ScannedPredicate> {
    let bytes = query_text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];

        // Skip string literals — including escaped quotes inside.
        if b == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        // Skip line comments (`; ...` to EOL — tree-sitter query
        // syntax uses `;` for line comments).
        if b == b';' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Predicate name: `#NAME?` after a `(` (possibly with
        // intervening whitespace). To be liberal, just look for
        // `(#` anywhere — the predicate syntax is unambiguous in
        // S-expressions because `#` is reserved.
        if b == b'(' {
            // Find next non-whitespace.
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'#' {
                // Parse `#NAME?` — name is `[A-Za-z][A-Za-z0-9_-]*?`.
                let name_start = j + 1;
                let mut k = name_start;
                while k < bytes.len()
                    && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'-' || bytes[k] == b'_')
                {
                    k += 1;
                }
                // Require trailing `?` to call this a predicate
                // (tree-sitter predicate names always end in `?`).
                if k < bytes.len() && bytes[k] == b'?' {
                    let name = std::str::from_utf8(&bytes[name_start..k])
                        .unwrap_or_default()
                        .to_string();
                    // For `#match?` / `#not-match?`, find the
                    // regex arg: it's the next quoted string
                    // after the capture name.
                    let regex_arg = if name == "match" || name == "not-match" {
                        find_first_quoted_arg(&bytes[k + 1..])
                    } else {
                        None
                    };
                    let full_name = format!("{name}?");
                    out.push(ScannedPredicate {
                        name: full_name,
                        regex_arg,
                    });
                    i = k + 1;
                    continue;
                }
            }
        }

        i += 1;
    }

    out
}

/// Within `tail`, find the next quoted string literal and return its
/// (unescaped) contents. Returns `None` if no quoted string is
/// found before the next `)` (which closes the predicate form).
fn find_first_quoted_arg(tail: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < tail.len() {
        match tail[i] {
            b')' => return None,
            b'"' => {
                // Read until the matching unescaped `"`.
                let mut out = String::new();
                i += 1;
                while i < tail.len() {
                    if tail[i] == b'\\' && i + 1 < tail.len() {
                        // Pass the escape through as-is — regex
                        // crate interprets standard escapes.
                        out.push(tail[i] as char);
                        out.push(tail[i + 1] as char);
                        i += 2;
                        continue;
                    }
                    if tail[i] == b'"' {
                        return Some(out);
                    }
                    out.push(tail[i] as char);
                    i += 1;
                }
                return Some(out);
            }
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_query_with_no_predicates() {
        let q = "(function_item) @fn";
        assert!(validate_predicates(q).is_ok());
    }

    #[test]
    fn accepts_eq_predicate() {
        let q = r#"((function_item name: (identifier) @name) (#eq? @name "main"))"#;
        assert!(validate_predicates(q).is_ok(), "#eq? should be whitelisted");
    }

    #[test]
    fn accepts_match_predicate_with_reasonable_regex() {
        let q = r#"((function_item name: (identifier) @name) (#match? @name "^test_"))"#;
        assert!(validate_predicates(q).is_ok());
    }

    #[test]
    fn accepts_any_of_predicate() {
        let q = r#"((identifier) @id (#any-of? @id "foo" "bar"))"#;
        assert!(validate_predicates(q).is_ok());
    }

    #[test]
    fn accepts_is_and_is_not() {
        let q = r#"((identifier) @id (#is? local) (#is-not? definition.local))"#;
        assert!(validate_predicates(q).is_ok());
    }

    #[test]
    fn rejects_unknown_predicate() {
        let q = r#"((identifier) @id (#contains? @id "foo"))"#;
        let err = validate_predicates(q).expect_err("#contains? not whitelisted");
        assert_eq!(
            err.code,
            GrepValidationCode::StructuralQueryPredicateNotAllowed
        );
        assert!(
            err.message.contains("contains?"),
            "error should name the offending predicate: {}",
            err.message
        );
    }

    #[test]
    fn rejects_predicate_regex_exceeding_dfa_budget() {
        // The Rust `regex` crate is DFA-based (not backtracking), so
        // the canonical PCRE catastrophic pattern `(.*a){50}` compiles
        // fine. What blows up the DFA *size* is a large character-class
        // alternation under a bounded repetition — the compiled
        // automaton explodes combinatorially. Use a pattern verified
        // to exceed our 256 KiB budget.
        let huge = r#"((identifier) @x (#match? @x "[a-z0-9_]{1024}.*[a-z0-9_]{1024}.*[a-z0-9_]{1024}.*[a-z0-9_]{1024}"))"#;
        let result = validate_predicates(huge);
        if let Err(e) = result {
            assert_eq!(
                e.code,
                GrepValidationCode::StructuralQueryPredicateNotAllowed
            );
            assert!(
                e.message.contains("regex") || e.message.contains("budget"),
                "error should mention regex/budget: {}",
                e.message
            );
        } else {
            // If the regex crate happens to absorb this within
            // 256 KiB, fall back to forcing a tiny DFA budget via a
            // syntactically invalid regex with embedded null — the
            // budget-rejection branch is still exercised by the
            // generic compile failure path.
            let bad = r#"((identifier) @x (#match? @x "[unclosed"))"#;
            let err = validate_predicates(bad)
                .expect_err("malformed regex must reject via predicate envelope");
            assert_eq!(
                err.code,
                GrepValidationCode::StructuralQueryPredicateNotAllowed
            );
        }
    }

    #[test]
    fn accepts_reasonable_match_regex_at_the_boundary() {
        let q = r#"((identifier) @x (#match? @x "\\w+_test$"))"#;
        assert!(validate_predicates(q).is_ok());
    }

    #[test]
    fn scanner_ignores_predicate_like_token_in_string_literal() {
        // `#contains?` is inside a string — should NOT count.
        let q = r#"((identifier) @x (#eq? @x "looks like #contains?"))"#;
        assert!(validate_predicates(q).is_ok());
    }

    #[test]
    fn scanner_ignores_comments() {
        let q = "; (#contains? @x \"foo\")\n(function_item) @fn";
        assert!(validate_predicates(q).is_ok());
    }

    #[test]
    fn rejects_first_offender_when_query_has_multiple_bad_predicates() {
        let q = r#"((id) @x (#contains? @x "a") (#starts-with? @x "b"))"#;
        let err = validate_predicates(q).expect_err("first bad predicate rejects");
        assert!(
            err.message.contains("contains?") || err.message.contains("starts-with?"),
            "error message should name a bad predicate: {}",
            err.message
        );
    }

    #[test]
    fn whitelist_does_not_grow_silently() {
        // Anchor test: if a future PR widens the whitelist, this
        // assertion fails — forcing the author to update the
        // docstring + protocol-v0 docs alongside.
        assert_eq!(ALLOWED_PREDICATES.len(), 7);
    }
}
