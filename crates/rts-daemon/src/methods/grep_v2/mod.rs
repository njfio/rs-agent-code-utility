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

pub use compose::{ValidatedGrepCall, validate};
pub use errors::{GrepValidationError, GrepValidationCode};
