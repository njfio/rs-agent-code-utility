//! Structured error codes for the Index.Grep v2 composition matrix.
//!
//! Every error returned from `grep_v2::validate` (and from the
//! downstream U3/U4/U5 implementations) carries a `data.code` string
//! that's stable across patch releases. Callers (agents, agent-bench
//! preflight, doctor) can branch on the code without parsing free-form
//! message strings.

use crate::error::{ErrorCode, ProtocolError};

/// Closed taxonomy of v2 validation error codes. Renders to a string
/// via `Display` for inclusion in the `data.code` field of an
/// `INVALID_PARAMS` envelope. See `docs/plans/2026-05-18-002-feat-index-grep-v2-plan.md`
/// for the full list and per-code semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrepValidationCode {
    /// `text` and `regex: true` mode + `multiline: true` is fine; but
    /// `multiline: true` with the literal (`text` + `regex: false`)
    /// path is rejected — literal substring search is already
    /// byte-wise across newlines.
    MultilineRequiresRegex,
    /// `structural_query` set but `language` missing.
    StructuralRequiresLanguage,
    /// `text` (or `pattern` regex) AND `structural_query` both absent.
    /// At least one source is required.
    NoSearchSourceProvided,
    /// Either the `text` field was empty or its length exceeded the
    /// 1024-char cap. Mirrors v1 semantics.
    InvalidTextLength,
    /// `structural_query` failed `Query::new(language, query_text)`
    /// for *every* requested language — likely a syntax error in the
    /// S-expression. Carries the tree-sitter parser's diagnostic in
    /// `data.error_message`.
    StructuralQueryInvalid,
    /// The S-expression query uses a predicate that's not on the v1
    /// whitelist (`#eq?`, `#not-eq?`, `#match?`, `#not-match?`,
    /// `#any-of?`, `#is?`, `#is-not?`).
    StructuralQueryPredicateNotAllowed,
    /// `within_symbol` name resolved to zero defs in the index.
    WithinSymbolNotFound,
    /// `within_symbol` resolved to more than `WITHIN_SYMBOL_MAX_DEFS`
    /// (16) defs, and `within_symbol_allow_overload: true` was not
    /// set. Returned with a `data.def_count` field so the caller can
    /// decide whether to retry with the opt-in flag.
    WithinSymbolTooManyDefs,
    /// Regex compile exceeded the configured DFA/NFA size limit
    /// (`MULTILINE_DFA_SIZE_LIMIT` for the multiline path, regex
    /// crate defaults otherwise). Bounded against adversarial
    /// patterns like `(?s).*` over very large files.
    RegexTooComplex,
    /// Structural query scan exceeded `STRUCTURAL_WALL_CLOCK_MS`
    /// (5 seconds default) across the file set.
    StructuralQueryTimeout,
    /// `language` contains an identifier the daemon doesn't know how
    /// to index (e.g. a typo, or a language we don't yet ship).
    UnknownLanguage,
}

impl GrepValidationCode {
    pub fn as_str(self) -> &'static str {
        match self {
            GrepValidationCode::MultilineRequiresRegex => "MULTILINE_REQUIRES_REGEX",
            GrepValidationCode::StructuralRequiresLanguage => "STRUCTURAL_REQUIRES_LANGUAGE",
            GrepValidationCode::NoSearchSourceProvided => "NO_SEARCH_SOURCE_PROVIDED",
            GrepValidationCode::InvalidTextLength => "INVALID_TEXT_LENGTH",
            GrepValidationCode::StructuralQueryInvalid => "STRUCTURAL_QUERY_INVALID",
            GrepValidationCode::StructuralQueryPredicateNotAllowed => {
                "STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED"
            }
            GrepValidationCode::WithinSymbolNotFound => "WITHIN_SYMBOL_NOT_FOUND",
            GrepValidationCode::WithinSymbolTooManyDefs => "WITHIN_SYMBOL_TOO_MANY_DEFS",
            GrepValidationCode::RegexTooComplex => "REGEX_TOO_COMPLEX",
            GrepValidationCode::StructuralQueryTimeout => "STRUCTURAL_QUERY_TIMEOUT",
            GrepValidationCode::UnknownLanguage => "UNKNOWN_LANGUAGE",
        }
    }
}

/// Validation-time error carrying a stable code + a human-readable
/// message + optional structured data fields. Renders to a
/// protocol-v0 `INVALID_PARAMS` envelope via [`Self::into_protocol_error`].
#[derive(Debug, Clone)]
pub struct GrepValidationError {
    pub code: GrepValidationCode,
    pub message: String,
    /// Extra structured payload merged into `data` alongside `code`.
    /// Used for e.g. `WITHIN_SYMBOL_TOO_MANY_DEFS` to carry the
    /// observed `def_count`, or `STRUCTURAL_QUERY_INVALID` to carry
    /// the tree-sitter parser diagnostic.
    pub data: serde_json::Map<String, serde_json::Value>,
}

impl GrepValidationError {
    pub fn new(code: GrepValidationCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: serde_json::Map::new(),
        }
    }

    pub fn with_data(mut self, key: &str, value: serde_json::Value) -> Self {
        self.data.insert(key.to_string(), value);
        self
    }

    /// Render as an `INVALID_PARAMS` envelope with the documented
    /// `data.code` field. The free-form `message` becomes the
    /// envelope's `message`; any extra `data` keys are merged in
    /// alongside `code`.
    pub fn into_protocol_error(self) -> ProtocolError {
        let mut data = self.data;
        data.insert(
            "code".to_string(),
            serde_json::Value::String(self.code.as_str().to_string()),
        );
        ProtocolError::new(ErrorCode::InvalidParams, self.message)
            .with_data(serde_json::Value::Object(data))
    }
}
