//! Index.Grep v2 — composition matrix, validation, and supporting
//! modules. See `docs/plans/2026-05-18-002-feat-index-grep-v2-plan.md`
//! for the design rationale and the binding matrix table.
//!
//! Entry point: [`validate`] takes the deserialized `GrepParams` and
//! returns a [`ValidatedGrepCall`] enum describing which matrix cell
//! should execute. Errors carry a stable `data.code` string for
//! programmatic dispatch by callers; the wire shape mirrors the
//! existing `INVALID_PARAMS` envelope.
//!
//! This module is the *gate* between request deserialization and the
//! actual scan paths. The scan paths themselves (multiline regex,
//! structural query execution, within_symbol filtering) live in
//! their respective sub-modules and are dispatched from
//! `crates/rts-daemon/src/methods/index.rs::grep`.

pub mod compose;
pub mod errors;
pub mod limits;
pub mod multiline;
pub mod predicates;
pub mod query_cache;
pub mod structural;
pub mod within_symbol;

pub use compose::{ValidatedGrepCall, validate};
pub use errors::{GrepValidationCode, GrepValidationError};
pub use predicates::validate_predicates;
pub use query_cache::QueryCache;
pub use within_symbol::{
    MatchRange as WithinSymbolMatchRange, WITHIN_SYMBOL_MAX_DEFS,
    filter_matches_by_defs as filter_matches_by_within_symbol_defs,
    resolve_and_filter as resolve_and_filter_within_symbol,
};
