//! Shared primitives for the verification layer (Phase F).
//!
//! Pure-ish library building blocks consumed by later phases (daemon
//! methods, metrics). Nothing here does I/O beyond tree-sitter parsing.
//!
//! - [`resolution`] — the resolution-outcome model ([`Resolution`],
//!   [`IndeterminateReason`]). Wire strings are frozen.

pub mod resolution;

pub use resolution::{IndeterminateReason, Resolution};
