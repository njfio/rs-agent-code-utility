//! Resolution outcome model for the verification layer (Phase F, F1).
//!
//! A [`Resolution`] records whether a reference was conclusively matched
//! to a definition ([`Resolution::Exact`]), conclusively absent
//! ([`Resolution::NotFound`]), or *unknowable* with the static
//! information available ([`Resolution::Indeterminate`]).
//!
//! ## Invariant — never upgrade `Indeterminate` to `NotFound`
//!
//! When a reference can't be resolved because of dynamic dispatch,
//! macro-generated code, FFI, reflection, an unresolved import, or an
//! ambiguous overload, the honest answer is [`Resolution::Indeterminate`]
//! — *not* [`Resolution::NotFound`]. A `NotFound` is a claim that the
//! symbol provably does not exist; an `Indeterminate` is an admission
//! that we cannot tell. Callers MUST NOT collapse `Indeterminate` into
//! `NotFound`: doing so would manufacture false negatives (telling an
//! agent a symbol is missing when the analysis simply couldn't see it).
//! The reverse — refusing to claim `NotFound` when in doubt — is the
//! whole point of carrying an [`IndeterminateReason`].

use serde::{Deserialize, Serialize};

/// Outcome of attempting to resolve a reference to a definition.
///
/// Wire strings (frozen): `"exact"`, `"not_found"`, `"indeterminate"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// The reference resolved to exactly one definition.
    Exact,
    /// The reference provably has no matching definition.
    NotFound,
    /// Resolution could not be decided from static information; the
    /// reason is carried alongside as an [`IndeterminateReason`].
    Indeterminate,
}

/// Why a [`Resolution::Indeterminate`] outcome could not be decided.
///
/// Wire strings (frozen): `"dynamic_dispatch"`, `"macro_generated"`,
/// `"ffi"`, `"unresolved_ref"`, `"reflection"`, `"ambiguous_overload"`,
/// `"undecidable_signature"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndeterminateReason {
    /// Call goes through a trait object / virtual method / function
    /// pointer — the concrete target is chosen at runtime.
    DynamicDispatch,
    /// The definition or reference is produced by a macro and isn't
    /// present in the surface syntax we can walk.
    MacroGenerated,
    /// The symbol crosses a foreign-function-interface boundary
    /// (`extern`, native bindings) where the target isn't in-tree.
    Ffi,
    /// An import / path the reference depends on could not be resolved.
    UnresolvedRef,
    /// The target is selected via reflection / dynamic lookup
    /// (`getattr`, `Type::class.method`, string-keyed dispatch).
    Reflection,
    /// Multiple definitions match and we cannot pick one statically.
    AmbiguousOverload,
    /// The definition's signature shape can't be decided statically —
    /// variadics (`...`, `*args`, `**kwargs`, `...rest`) or a language
    /// whose signature extraction isn't yet supported. Distinct from
    /// [`Ffi`](Self::Ffi), which is specifically a foreign boundary.
    UndecidableSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(value: impl Serialize) -> String {
        serde_json::to_string(&value).expect("serialize")
    }

    #[test]
    fn resolution_serializes_to_frozen_wire_strings() {
        assert_eq!(json(Resolution::Exact), "\"exact\"");
        assert_eq!(json(Resolution::NotFound), "\"not_found\"");
        assert_eq!(json(Resolution::Indeterminate), "\"indeterminate\"");
    }

    #[test]
    fn resolution_round_trips() {
        for variant in [
            Resolution::Exact,
            Resolution::NotFound,
            Resolution::Indeterminate,
        ] {
            let wire = json(variant);
            let back: Resolution = serde_json::from_str(&wire).expect("deserialize");
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn reason_serializes_to_frozen_wire_strings() {
        assert_eq!(
            json(IndeterminateReason::DynamicDispatch),
            "\"dynamic_dispatch\""
        );
        assert_eq!(
            json(IndeterminateReason::MacroGenerated),
            "\"macro_generated\""
        );
        assert_eq!(json(IndeterminateReason::Ffi), "\"ffi\"");
        assert_eq!(
            json(IndeterminateReason::UnresolvedRef),
            "\"unresolved_ref\""
        );
        assert_eq!(json(IndeterminateReason::Reflection), "\"reflection\"");
        assert_eq!(
            json(IndeterminateReason::AmbiguousOverload),
            "\"ambiguous_overload\""
        );
        assert_eq!(
            json(IndeterminateReason::UndecidableSignature),
            "\"undecidable_signature\""
        );
    }

    #[test]
    fn reason_round_trips() {
        for variant in [
            IndeterminateReason::DynamicDispatch,
            IndeterminateReason::MacroGenerated,
            IndeterminateReason::Ffi,
            IndeterminateReason::UnresolvedRef,
            IndeterminateReason::Reflection,
            IndeterminateReason::AmbiguousOverload,
            IndeterminateReason::UndecidableSignature,
        ] {
            let wire = json(variant);
            let back: IndeterminateReason = serde_json::from_str(&wire).expect("deserialize");
            assert_eq!(back, variant);
        }
    }
}
