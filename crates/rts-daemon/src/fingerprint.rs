//! Composite workspace fingerprint for the persisted-cold-mount
//! pathway (v0.6+, capability `daemon_stats_v2`'s `mount_source`
//! field).
//!
//! The fingerprint is the load-bearing invariant: it tells the daemon
//! at mount time whether the existing on-disk redb state still
//! describes the current code + grammars + ignore rules, or whether
//! it needs to be wiped and rebuilt. A fingerprint is "fresh" iff
//! every part round-trips identically across runs.
//!
//! Parts (each tested in isolation; combined into `Fingerprint`):
//!
//! 1. **Schema version** — `crate::store::SCHEMA_VERSION`, the redb
//!    table layout version. Bumped manually when tables change shape
//!    (e.g. #103 added UNRESOLVED_REFS / FID_UNRESOLVED).
//! 2. **Daemon binary version** — `env!("CARGO_PKG_VERSION")`. Patch
//!    bumps invalidate; the conservative choice avoids subtle issues
//!    where a bugfix only takes effect on re-indexed content.
//! 3. **Grammar versions** — every linked `tree-sitter-*` crate's
//!    `Cargo.toml` version, baked into the binary at build time by
//!    `crates/rts-daemon/build.rs` and exposed via the
//!    `RTS_GRAMMAR_VERSIONS` env var. See [`grammar_versions`].
//! 4. **gitignore content hash** — blake3 of the effective gitignore
//!    byte stream (workspace `.gitignore`, parent ancestors, global,
//!    fallbacks). Lives in [`crate::gitignore_hash`].
//!
//! The `combined` field is `blake3(part1 ‖ part2 ‖ part3 ‖ part4)`
//! truncated to 16 bytes (32 hex chars). It's the fast-path comparison
//! key; per-part fields exist for diagnostic invalidation reasons
//! (e.g. `cold_walk_after_invalidation:grammar:rust:0.23→0.24`).

#![allow(dead_code)] // U3 wires this into the store; U5 wires the mount decision.

/// Returns the linked tree-sitter grammar crate versions as a sorted
/// list of `(crate_name, version_string)` pairs. The list is built
/// at compile time by `build.rs` from `rts-core/Cargo.toml`, so a
/// dependency bump rebuilds and re-bakes the list automatically.
///
/// Returns an empty list if the build script didn't run for some
/// reason (which would be a build-system bug; this never happens
/// in practice). Tests rely on the at-least-12-entries invariant.
pub fn grammar_versions() -> Vec<(String, String)> {
    let raw = env!("RTS_GRAMMAR_VERSIONS");
    // The build script encodes the pairs as `[[name, version], ...]`.
    // Parse without pulling serde_json into rts-daemon's build-time
    // closure for build.rs (we do use serde_json at runtime; that's
    // fine since it's already a daemon dep for protocol-v0).
    serde_json::from_str::<Vec<(String, String)>>(raw).unwrap_or_default()
}

/// Stable string representation of [`grammar_versions`] for inclusion
/// in the composite fingerprint. Format: `"name=ver,name=ver,..."`,
/// joined by commas, sorted by name. The sort is enforced by the
/// build script so this function's output is deterministic.
pub fn grammar_versions_fingerprint() -> String {
    grammar_versions()
        .into_iter()
        .map(|(name, ver)| format!("{name}={ver}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar_versions_returns_known_crates() {
        let versions = grammar_versions();
        let names: Vec<&str> = versions.iter().map(|(n, _)| n.as_str()).collect();
        // Spot-check: the build script should always surface at least
        // the canonical 12-grammar list pinned in rts-core's Cargo.toml.
        // We assert presence rather than exact membership so adding
        // a new grammar doesn't break this test.
        for expected in [
            "tree-sitter",
            "tree-sitter-rust",
            "tree-sitter-javascript",
            "tree-sitter-python",
            "tree-sitter-c",
            "tree-sitter-cpp",
            "tree-sitter-go",
            "tree-sitter-java",
            "tree-sitter-ruby",
        ] {
            assert!(
                names.contains(&expected),
                "expected `{expected}` in grammar_versions(); got {names:?}"
            );
        }
    }

    #[test]
    fn grammar_versions_are_sorted_by_name() {
        let versions = grammar_versions();
        let names: Vec<&str> = versions.iter().map(|(n, _)| n.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(
            names, sorted,
            "build.rs should emit grammar versions sorted by name; got {names:?}"
        );
    }

    #[test]
    fn grammar_versions_have_non_empty_version_strings() {
        for (name, ver) in grammar_versions() {
            assert!(!ver.is_empty(), "`{name}` should have a non-empty version");
        }
    }

    #[test]
    fn fingerprint_string_is_stable() {
        // Two consecutive calls return byte-identical strings.
        let a = grammar_versions_fingerprint();
        let b = grammar_versions_fingerprint();
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_string_includes_every_grammar() {
        let fp = grammar_versions_fingerprint();
        for (name, ver) in grammar_versions() {
            assert!(
                fp.contains(&format!("{name}={ver}")),
                "fingerprint missing entry `{name}={ver}`; got `{fp}`"
            );
        }
    }
}
