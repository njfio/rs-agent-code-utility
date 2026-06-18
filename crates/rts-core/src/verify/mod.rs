//! Shared primitives for the verification layer (Phase F).
//!
//! Pure-ish library building blocks consumed by later phases (daemon
//! methods, metrics). Nothing here does I/O beyond tree-sitter parsing.
//!
//! - [`resolution`] — the resolution-outcome model ([`Resolution`],
//!   [`IndeterminateReason`]). Wire strings are frozen.
//! - [`candidates`] — fuzzy "did you mean" ranking ([`Candidate`],
//!   [`rank_candidates`]) over a pool of qualified names.

pub mod candidates;
pub mod resolution;

pub use candidates::{Candidate, rank_candidates};
pub use resolution::{IndeterminateReason, Resolution};
