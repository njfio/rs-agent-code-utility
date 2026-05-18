//! Composition matrix + validation for `Index.Grep` v2.
//!
//! The matrix has six axes: `text`, `regex`, `multiline`,
//! `structural_query`, `within_symbol`, `language`. Some cells are
//! valid scan modes; others are mutually exclusive and rejected with
//! a structured `INVALID_PARAMS` envelope carrying a stable
//! `data.code` string.
//!
//! ## Matrix (binding contract — see plan U2)
//!
//! | text   | regex   | multiline | structural | within | language | Result                                   |
//! |--------|---------|-----------|------------|--------|----------|------------------------------------------|
//! | Some   | n/false | n/false   | None       | opt    | opt      | `Literal { … }`                          |
//! | Some   | true    | n/false   | None       | opt    | opt      | `Regex { multiline=false }`              |
//! | Some   | true    | true      | None       | opt    | opt      | `Regex { multiline=true }`               |
//! | None   | any     | true      | None       | —      | —        | REJECT `MULTILINE_REQUIRES_REGEX`        |
//! | Some   | n/false | true      | any        | —      | —        | REJECT `MULTILINE_REQUIRES_REGEX`        |
//! | None   | any     | any       | Some       | opt    | req      | `Structural { combine=None }`            |
//! | Some   | n/false | n/false   | Some       | opt    | req      | `Structural { combine=Literal }`         |
//! | Some   | true    | any       | Some       | opt    | req      | `Structural { combine=Regex { ml } }`    |
//! | any    | any     | any       | Some       | —      | None     | REJECT `STRUCTURAL_REQUIRES_LANGUAGE`    |
//! | None   | any     | any       | None       | —      | —        | REJECT `NO_SEARCH_SOURCE_PROVIDED`       |
//! | Some('') | any   | any       | any        | —      | —        | REJECT `INVALID_TEXT_LENGTH`             |
//! | Some(>1024) | any | any      | any        | —      | —        | REJECT `INVALID_TEXT_LENGTH`             |
//!
//! Within_symbol cardinality (`WITHIN_SYMBOL_NOT_FOUND`,
//! `WITHIN_SYMBOL_TOO_MANY_DEFS`) is resolved post-validation in U4
//! because it requires a store lookup; structural-query syntax errors
//! (`STRUCTURAL_QUERY_INVALID`, `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`)
//! land in U5 because they require a `Query::new` call against the
//! grammars. Everything else is pure-input validation and lives here.

use super::errors::{GrepValidationCode, GrepValidationError};

/// Outcome of validating a `GrepParams`. Each variant carries the
/// resolved (param-shape) data the downstream scan path needs; the
/// caller dispatches on this enum rather than re-reading the raw
/// params.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedGrepCall {
    /// Literal substring scan. v1 semantics; reaches the existing
    /// `GrepScanner::Literal` path.
    Literal {
        text: String,
        case_insensitive: bool,
    },
    /// Single-line regex scan. v1 semantics; reaches the existing
    /// `GrepScanner::Regex` path.
    Regex {
        pattern: String,
        case_insensitive: bool,
        multiline: bool,
    },
    /// Structural query scan. U5 implements the actual execution;
    /// validation here only confirms the gate (language present,
    /// structural_query non-empty).
    ///
    /// `combine` describes any literal/regex filter the caller asked
    /// to intersect with the structural matches.
    Structural {
        query: String,
        languages: Vec<String>,
        combine: StructuralCombine,
    },
}

/// When a structural query is composed with a literal/regex filter,
/// this enum carries the additional filter shape. `None` means the
/// structural query alone selects matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuralCombine {
    None,
    Literal {
        text: String,
        case_insensitive: bool,
    },
    Regex {
        pattern: String,
        case_insensitive: bool,
        multiline: bool,
    },
}

/// Shared filters applied across all scan modes. The composition
/// matrix doesn't gate these — every mode honors them when set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedFilters {
    pub limit: u32,
    pub file_glob: Option<String>,
    pub language: Option<Vec<String>>,
    pub within_symbol: Option<String>,
    pub within_symbol_allow_overload: bool,
}

/// Input shape consumed by [`validate`]. Mirrors the deserialized
/// `GrepParams` so the validator stays independent of the handler's
/// internal types (lets us unit-test the matrix without standing up
/// the daemon).
#[derive(Debug, Clone, Default)]
pub struct ValidationInput {
    pub text: Option<String>,
    pub limit: Option<u32>,
    pub case_insensitive: Option<bool>,
    pub regex: Option<bool>,
    pub file_glob: Option<String>,
    pub multiline: Option<bool>,
    pub structural_query: Option<String>,
    pub within_symbol: Option<String>,
    pub within_symbol_allow_overload: Option<bool>,
    pub language: Option<Vec<String>>,
}

/// Default match limit when `params.limit` is unset. Mirrors the v1
/// `DEFAULT_LIMIT` from `methods/index.rs`.
const DEFAULT_LIMIT: u32 = 256;

/// Maximum allowed `text` length (chars). Mirrors v1.
const MAX_TEXT_LEN: usize = 1024;

/// Validate the input against the composition matrix. Returns the
/// resolved scan call + shared filters, or a structured error.
pub fn validate(
    input: &ValidationInput,
) -> Result<(ValidatedGrepCall, SharedFilters), GrepValidationError> {
    let multiline = input.multiline.unwrap_or(false);
    let regex_mode = input.regex.unwrap_or(false);
    let case_insensitive = input.case_insensitive.unwrap_or(true);
    let has_structural = input
        .structural_query
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());

    // 1. Validate `text` shape if present. (Empty / too-long strings
    //    fail regardless of which mode the caller intended.)
    if let Some(text) = &input.text {
        if text.is_empty() {
            return Err(GrepValidationError::new(
                GrepValidationCode::InvalidTextLength,
                "`text` is empty; provide 1..=1024 chars",
            ));
        }
        if text.len() > MAX_TEXT_LEN {
            return Err(GrepValidationError::new(
                GrepValidationCode::InvalidTextLength,
                format!(
                    "`text` is {} chars; maximum is {MAX_TEXT_LEN}",
                    text.len()
                ),
            ));
        }
    }

    // 2. At least one search source required.
    if input.text.is_none() && !has_structural {
        return Err(GrepValidationError::new(
            GrepValidationCode::NoSearchSourceProvided,
            "provide `text` (literal/regex) or `structural_query` (tree-sitter S-expr)",
        ));
    }

    // 3. Structural queries require `language`.
    if has_structural {
        let lang_missing = input
            .language
            .as_ref()
            .is_none_or(|v| v.is_empty());
        if lang_missing {
            return Err(GrepValidationError::new(
                GrepValidationCode::StructuralRequiresLanguage,
                "`structural_query` requires `language` (single id or list, e.g. [\"rust\"])",
            ));
        }
    }

    // 4. `multiline: true` requires the regex path. The literal path
    //    is already byte-wise across newlines; multiline is a regex
    //    flag concept only.
    if multiline && !regex_mode && input.text.is_some() {
        // Literal-path attempt: hard error.
        return Err(GrepValidationError::new(
            GrepValidationCode::MultilineRequiresRegex,
            "`multiline: true` requires `regex: true`; the literal path crosses newlines already",
        ));
    }
    if multiline && input.text.is_none() && !has_structural {
        // Shouldn't reach here — covered by step 2 — but explicit
        // for the matrix.
        return Err(GrepValidationError::new(
            GrepValidationCode::MultilineRequiresRegex,
            "`multiline: true` has no source pattern (provide regex `text` + `regex: true`)",
        ));
    }

    // 5. Resolve which scan mode this maps to.
    let shared = SharedFilters {
        limit: input.limit.unwrap_or(DEFAULT_LIMIT),
        file_glob: input.file_glob.clone(),
        language: input.language.clone(),
        within_symbol: input.within_symbol.clone(),
        within_symbol_allow_overload: input.within_symbol_allow_overload.unwrap_or(false),
    };

    let call = if has_structural {
        // Structural mode (alone or composed with literal/regex).
        let query = input.structural_query.clone().unwrap();
        let languages = input.language.clone().unwrap();
        let combine = match (&input.text, regex_mode) {
            (None, _) => StructuralCombine::None,
            (Some(text), false) => StructuralCombine::Literal {
                text: text.clone(),
                case_insensitive,
            },
            (Some(text), true) => StructuralCombine::Regex {
                pattern: text.clone(),
                case_insensitive,
                multiline,
            },
        };
        ValidatedGrepCall::Structural {
            query,
            languages,
            combine,
        }
    } else if regex_mode {
        ValidatedGrepCall::Regex {
            pattern: input.text.clone().unwrap(),
            case_insensitive,
            multiline,
        }
    } else {
        ValidatedGrepCall::Literal {
            text: input.text.clone().unwrap(),
            case_insensitive,
        }
    };

    Ok((call, shared))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input_text(t: &str) -> ValidationInput {
        ValidationInput {
            text: Some(t.into()),
            ..Default::default()
        }
    }

    // ----- Matrix happy-path cells -----

    #[test]
    fn literal_text_alone_yields_literal_call() {
        let (call, _) = validate(&input_text("hello")).unwrap();
        assert_eq!(
            call,
            ValidatedGrepCall::Literal {
                text: "hello".into(),
                case_insensitive: true,
            }
        );
    }

    #[test]
    fn regex_text_yields_regex_call_with_multiline_false() {
        let input = ValidationInput {
            text: Some("hello.*world".into()),
            regex: Some(true),
            ..Default::default()
        };
        let (call, _) = validate(&input).unwrap();
        assert_eq!(
            call,
            ValidatedGrepCall::Regex {
                pattern: "hello.*world".into(),
                case_insensitive: true,
                multiline: false,
            }
        );
    }

    #[test]
    fn regex_text_with_multiline_yields_regex_call_with_multiline_true() {
        let input = ValidationInput {
            text: Some("hello.*world".into()),
            regex: Some(true),
            multiline: Some(true),
            ..Default::default()
        };
        let (call, _) = validate(&input).unwrap();
        assert_eq!(
            call,
            ValidatedGrepCall::Regex {
                pattern: "hello.*world".into(),
                case_insensitive: true,
                multiline: true,
            }
        );
    }

    #[test]
    fn structural_alone_yields_structural_call_with_combine_none() {
        let input = ValidationInput {
            structural_query: Some("(function_item) @fn".into()),
            language: Some(vec!["rust".into()]),
            ..Default::default()
        };
        let (call, _) = validate(&input).unwrap();
        assert!(matches!(call, ValidatedGrepCall::Structural { ref combine, .. } if combine == &StructuralCombine::None));
    }

    #[test]
    fn structural_plus_text_yields_structural_with_literal_combine() {
        let input = ValidationInput {
            text: Some("unsafe".into()),
            structural_query: Some("(function_item) @fn".into()),
            language: Some(vec!["rust".into()]),
            ..Default::default()
        };
        let (call, _) = validate(&input).unwrap();
        match call {
            ValidatedGrepCall::Structural { combine, .. } => {
                assert!(matches!(combine, StructuralCombine::Literal { ref text, .. } if text == "unsafe"));
            }
            _ => panic!("expected Structural call"),
        }
    }

    #[test]
    fn structural_plus_regex_yields_structural_with_regex_combine() {
        let input = ValidationInput {
            text: Some("unsafe.*fn".into()),
            regex: Some(true),
            structural_query: Some("(impl_item) @impl".into()),
            language: Some(vec!["rust".into()]),
            ..Default::default()
        };
        let (call, _) = validate(&input).unwrap();
        match call {
            ValidatedGrepCall::Structural { combine, .. } => {
                assert!(matches!(combine, StructuralCombine::Regex { ref pattern, multiline: false, .. } if pattern == "unsafe.*fn"));
            }
            _ => panic!("expected Structural call"),
        }
    }

    // ----- Matrix rejection cells -----

    #[test]
    fn empty_text_is_rejected() {
        let err = validate(&input_text("")).unwrap_err();
        assert_eq!(err.code, GrepValidationCode::InvalidTextLength);
    }

    #[test]
    fn oversize_text_is_rejected() {
        let big = "a".repeat(MAX_TEXT_LEN + 1);
        let err = validate(&input_text(&big)).unwrap_err();
        assert_eq!(err.code, GrepValidationCode::InvalidTextLength);
    }

    #[test]
    fn nothing_provided_is_rejected() {
        let err = validate(&ValidationInput::default()).unwrap_err();
        assert_eq!(err.code, GrepValidationCode::NoSearchSourceProvided);
    }

    #[test]
    fn structural_without_language_is_rejected() {
        let input = ValidationInput {
            structural_query: Some("(function_item)".into()),
            ..Default::default()
        };
        let err = validate(&input).unwrap_err();
        assert_eq!(err.code, GrepValidationCode::StructuralRequiresLanguage);
    }

    #[test]
    fn structural_with_empty_language_list_is_rejected() {
        let input = ValidationInput {
            structural_query: Some("(function_item)".into()),
            language: Some(vec![]),
            ..Default::default()
        };
        let err = validate(&input).unwrap_err();
        assert_eq!(err.code, GrepValidationCode::StructuralRequiresLanguage);
    }

    #[test]
    fn multiline_on_literal_path_is_rejected() {
        let input = ValidationInput {
            text: Some("hello".into()),
            multiline: Some(true),
            // regex defaults to false → literal path → multiline forbidden
            ..Default::default()
        };
        let err = validate(&input).unwrap_err();
        assert_eq!(err.code, GrepValidationCode::MultilineRequiresRegex);
    }

    #[test]
    fn multiline_with_explicit_regex_false_is_rejected() {
        let input = ValidationInput {
            text: Some("hello".into()),
            regex: Some(false),
            multiline: Some(true),
            ..Default::default()
        };
        let err = validate(&input).unwrap_err();
        assert_eq!(err.code, GrepValidationCode::MultilineRequiresRegex);
    }

    // ----- Shared-filter passthrough -----

    #[test]
    fn shared_filters_passthrough() {
        let input = ValidationInput {
            text: Some("x".into()),
            limit: Some(42),
            file_glob: Some("*.rs".into()),
            language: Some(vec!["rust".into()]),
            within_symbol: Some("foo".into()),
            within_symbol_allow_overload: Some(true),
            ..Default::default()
        };
        let (_, shared) = validate(&input).unwrap();
        assert_eq!(shared.limit, 42);
        assert_eq!(shared.file_glob.as_deref(), Some("*.rs"));
        assert_eq!(shared.language.as_deref(), Some(&["rust".to_string()][..]));
        assert_eq!(shared.within_symbol.as_deref(), Some("foo"));
        assert!(shared.within_symbol_allow_overload);
    }

    #[test]
    fn default_limit_when_unset() {
        let (_, shared) = validate(&input_text("hello")).unwrap();
        assert_eq!(shared.limit, DEFAULT_LIMIT);
    }

    // ----- Error envelope rendering -----

    #[test]
    fn error_code_appears_in_data_envelope() {
        let err = validate(&ValidationInput::default()).unwrap_err();
        let proto = err.into_protocol_error();
        // ProtocolError isn't itself Serialize, but its `data` field
        // is a JSON Value we can inspect directly. The wire-side
        // shape is exercised in the round-trip integration test.
        let data = proto
            .data
            .as_ref()
            .expect("validation error should carry a `data` envelope");
        assert_eq!(
            data.pointer("/code"),
            Some(&serde_json::Value::String(
                "NO_SEARCH_SOURCE_PROVIDED".into()
            )),
            "expected data.code to be set; got {data}"
        );
    }
}
