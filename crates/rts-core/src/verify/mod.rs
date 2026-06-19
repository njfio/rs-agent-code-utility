//! Shared primitives for the verification layer (Phase F).
//!
//! Pure-ish library building blocks consumed by later phases (daemon
//! methods, metrics). Nothing here does I/O beyond tree-sitter parsing.
//!
//! - [`resolution`] — the resolution-outcome model ([`Resolution`],
//!   [`IndeterminateReason`]). Wire strings are frozen.
//! - [`candidates`] — fuzzy "did you mean" ranking ([`Candidate`],
//!   [`rank_candidates`]) over a pool of qualified names.
//! - [`references`] — use-site extraction ([`Reference`], [`RefKind`],
//!   [`extract_references`]); the inverse of definition extraction.
//! - [`signature_shape`] — arity/param/return shape of a definition node
//!   ([`SignatureShape`], [`signature_shape`]).

pub mod candidates;
pub mod references;
pub mod resolution;
pub mod signature_shape;

pub use candidates::{Candidate, rank_candidates};
pub use references::{RefKind, Reference, extract_references, supports_references};
pub use resolution::{IndeterminateReason, Resolution};
pub use signature_shape::{SignatureShape, signature_shape};
