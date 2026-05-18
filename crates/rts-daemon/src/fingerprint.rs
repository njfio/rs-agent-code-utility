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

#![allow(dead_code)] // U5 wires the mount decision; U6 surfaces via Daemon.Stats.

use std::collections::BTreeMap;
use std::path::Path;

use blake3::Hasher;

use crate::gitignore_hash::effective_gitignore_hash;

/// Composite workspace fingerprint. Each field is one part of the
/// invalidation invariant; `combined` is `blake3(schema_version ‖
/// daemon_binary_version ‖ grammar_versions ‖ gitignore_hash)`
/// truncated to 16 bytes (32 hex). Per-part fields stay alongside
/// `combined` so the diff function can name the specific part that
/// drifted, feeding diagnostic `cold_walk_after_invalidation:<reason>`
/// strings into `mount_source` telemetry (U6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub schema_version: u32,
    pub daemon_binary_version: String,
    /// Sorted `name=ver,name=ver,...` string of every linked
    /// tree-sitter grammar crate version.
    pub grammar_versions: String,
    /// 32 hex chars from `gitignore_hash::effective_gitignore_hash`.
    pub gitignore_hash: String,
    /// 32 hex chars from blake3 of all parts joined by a sentinel.
    pub combined: String,
}

impl Fingerprint {
    /// Compute the current fingerprint from runtime + filesystem state.
    /// Caller supplies the workspace root (needed for the gitignore
    /// hash). The schema_version comes from the daemon binary at
    /// compile time; the daemon_binary_version is `CARGO_PKG_VERSION`;
    /// grammar_versions come from `build.rs` injection.
    pub fn current(workspace_root: &Path) -> Self {
        let schema_version = crate::store::SCHEMA_VERSION;
        let daemon_binary_version = env!("CARGO_PKG_VERSION").to_string();
        let grammar_versions = grammar_versions_fingerprint();
        let gitignore_hash = effective_gitignore_hash(workspace_root);
        let combined = compute_combined(
            schema_version,
            &daemon_binary_version,
            &grammar_versions,
            &gitignore_hash,
        );
        Self {
            schema_version,
            daemon_binary_version,
            grammar_versions,
            gitignore_hash,
            combined,
        }
    }

    /// Diff two fingerprints. Returns `None` when they're identical;
    /// otherwise returns the *first* part that drifted in this order:
    /// schema_version, daemon_binary_version, grammar_versions,
    /// gitignore_hash. The ordering matters for the mount_source
    /// telemetry: a schema bump is the most consequential signal
    /// (forces rebuild of every table), so it wins.
    pub fn diff(stored: &Self, current: &Self) -> Option<InvalidationReason> {
        if stored.schema_version != current.schema_version {
            return Some(InvalidationReason::SchemaVersion {
                old: stored.schema_version,
                new: current.schema_version,
            });
        }
        if stored.daemon_binary_version != current.daemon_binary_version {
            return Some(InvalidationReason::DaemonBinaryVersion {
                old: stored.daemon_binary_version.clone(),
                new: current.daemon_binary_version.clone(),
            });
        }
        if stored.grammar_versions != current.grammar_versions {
            // Narrow to the first language that differs so the
            // mount_source label can name it (e.g.
            // `cold_walk_after_invalidation:grammar:rust:0.23→0.24`).
            return Some(InvalidationReason::GrammarVersion(
                first_grammar_diff(&stored.grammar_versions, &current.grammar_versions),
            ));
        }
        if stored.gitignore_hash != current.gitignore_hash {
            return Some(InvalidationReason::Gitignore);
        }
        None
    }
}

/// The reason the stored fingerprint doesn't match the current one.
/// Renders to a stable label via [`Self::as_label`] for inclusion in
/// `mount_source = "cold_walk_after_invalidation:<label>"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidationReason {
    SchemaVersion {
        old: u32,
        new: u32,
    },
    DaemonBinaryVersion {
        old: String,
        new: String,
    },
    GrammarVersion(GrammarDiff),
    Gitignore,
    /// Stored fingerprint is missing some required META keys; treat
    /// as "we don't trust any of the existing data."
    EmptyOrMissingFingerprint,
}

impl InvalidationReason {
    /// Stable label for inclusion in the `mount_source` telemetry
    /// string. Examples:
    /// - `"schema:3→4"`
    /// - `"binary:0.5.5→0.6.0"`
    /// - `"grammar:tree-sitter-rust:0.23→0.24"`
    /// - `"gitignore"`
    /// - `"empty_or_missing_fingerprint"`
    pub fn as_label(&self) -> String {
        match self {
            InvalidationReason::SchemaVersion { old, new } => format!("schema:{old}→{new}"),
            InvalidationReason::DaemonBinaryVersion { old, new } => {
                format!("binary:{old}→{new}")
            }
            InvalidationReason::GrammarVersion(diff) => match diff {
                GrammarDiff::Changed { name, old, new } => {
                    format!("grammar:{name}:{old}→{new}")
                }
                GrammarDiff::Added { name, new } => format!("grammar:{name}:added@{new}"),
                GrammarDiff::Removed { name, old } => format!("grammar:{name}:removed@{old}"),
                GrammarDiff::OpaqueShapeChange => "grammar:opaque".into(),
            },
            InvalidationReason::Gitignore => "gitignore".into(),
            InvalidationReason::EmptyOrMissingFingerprint => {
                "empty_or_missing_fingerprint".into()
            }
        }
    }
}

/// Fine-grained reason for a grammar-versions mismatch. Surfaced
/// inside `InvalidationReason::GrammarVersion` so the telemetry
/// label can name the offending crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrammarDiff {
    Changed {
        name: String,
        old: String,
        new: String,
    },
    Added {
        name: String,
        new: String,
    },
    Removed {
        name: String,
        old: String,
    },
    /// Falls back when both strings have the same set of names with
    /// the same per-name versions but the overall strings differ
    /// (shouldn't happen given the sort in `build.rs`, but the
    /// fallback exists for forward-compatibility).
    OpaqueShapeChange,
}

/// Find the first crate that differs between two
/// `name=ver,name=ver,...` strings (already sorted by name). Returns
/// `Changed` for crates present on both sides with different versions,
/// `Added`/`Removed` when one side lacks the crate.
fn first_grammar_diff(stored: &str, current: &str) -> GrammarDiff {
    let stored_map = parse_grammar_string(stored);
    let current_map = parse_grammar_string(current);
    // First name in either map (BTreeMap keeps sorted order).
    for name in stored_map.keys().chain(current_map.keys()) {
        match (stored_map.get(name), current_map.get(name)) {
            (Some(old), Some(new)) if old != new => {
                return GrammarDiff::Changed {
                    name: name.clone(),
                    old: old.clone(),
                    new: new.clone(),
                };
            }
            (Some(old), None) => {
                return GrammarDiff::Removed {
                    name: name.clone(),
                    old: old.clone(),
                };
            }
            (None, Some(new)) => {
                return GrammarDiff::Added {
                    name: name.clone(),
                    new: new.clone(),
                };
            }
            _ => continue,
        }
    }
    GrammarDiff::OpaqueShapeChange
}

fn parse_grammar_string(s: &str) -> BTreeMap<String, String> {
    s.split(',')
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.split_once('='))
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

/// Hash all parts into a stable 32-char hex digest. The leading 16
/// bytes match the existing `WorkspaceFingerprint::id_str()`
/// truncation pattern.
fn compute_combined(
    schema_version: u32,
    daemon_binary_version: &str,
    grammar_versions: &str,
    gitignore_hash: &str,
) -> String {
    let mut h = Hasher::new();
    h.update(b"rts-fingerprint-v1");
    h.update(&schema_version.to_le_bytes());
    h.update(b"\0bin\0");
    h.update(daemon_binary_version.as_bytes());
    h.update(b"\0gram\0");
    h.update(grammar_versions.as_bytes());
    h.update(b"\0gi\0");
    h.update(gitignore_hash.as_bytes());
    let digest = h.finalize();
    let bytes = digest.as_bytes();
    let mut out = String::with_capacity(32);
    for b in &bytes[..16] {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

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

    // ----- Fingerprint::diff -----

    fn fp(schema: u32, bin: &str, gram: &str, gi: &str) -> Fingerprint {
        Fingerprint {
            schema_version: schema,
            daemon_binary_version: bin.into(),
            grammar_versions: gram.into(),
            gitignore_hash: gi.into(),
            combined: compute_combined(schema, bin, gram, gi),
        }
    }

    #[test]
    fn identical_fingerprints_diff_to_none() {
        let a = fp(3, "0.6.0", "rust=0.23", "deadbeef");
        let b = fp(3, "0.6.0", "rust=0.23", "deadbeef");
        assert_eq!(Fingerprint::diff(&a, &b), None);
    }

    #[test]
    fn schema_bump_takes_priority() {
        let stored = fp(3, "0.6.0", "rust=0.23", "deadbeef");
        let current = fp(4, "0.7.0", "rust=0.24", "cafebabe");
        let reason = Fingerprint::diff(&stored, &current).unwrap();
        assert!(matches!(
            reason,
            InvalidationReason::SchemaVersion { old: 3, new: 4 }
        ));
    }

    #[test]
    fn binary_drift_below_schema() {
        let stored = fp(3, "0.5.5", "rust=0.23", "deadbeef");
        let current = fp(3, "0.6.0", "rust=0.23", "deadbeef");
        let reason = Fingerprint::diff(&stored, &current).unwrap();
        match reason {
            InvalidationReason::DaemonBinaryVersion { old, new } => {
                assert_eq!(old, "0.5.5");
                assert_eq!(new, "0.6.0");
            }
            other => panic!("expected DaemonBinaryVersion; got {other:?}"),
        }
    }

    #[test]
    fn grammar_drift_names_the_changed_crate() {
        let stored = fp(3, "0.6.0", "rust=0.23,ts=0.23", "deadbeef");
        let current = fp(3, "0.6.0", "rust=0.24,ts=0.23", "deadbeef");
        let reason = Fingerprint::diff(&stored, &current).unwrap();
        match reason {
            InvalidationReason::GrammarVersion(GrammarDiff::Changed { name, old, new }) => {
                assert_eq!(name, "rust");
                assert_eq!(old, "0.23");
                assert_eq!(new, "0.24");
            }
            other => panic!("expected GrammarDiff::Changed; got {other:?}"),
        }
    }

    #[test]
    fn grammar_added_is_named() {
        let stored = fp(3, "0.6.0", "rust=0.23", "deadbeef");
        let current = fp(3, "0.6.0", "rust=0.23,ts=0.23", "deadbeef");
        let reason = Fingerprint::diff(&stored, &current).unwrap();
        assert!(matches!(
            reason,
            InvalidationReason::GrammarVersion(GrammarDiff::Added { ref name, .. }) if name == "ts"
        ));
    }

    #[test]
    fn gitignore_drift_below_grammar() {
        let stored = fp(3, "0.6.0", "rust=0.23", "deadbeef");
        let current = fp(3, "0.6.0", "rust=0.23", "cafebabe");
        let reason = Fingerprint::diff(&stored, &current).unwrap();
        assert_eq!(reason, InvalidationReason::Gitignore);
    }

    #[test]
    fn label_strings_are_stable() {
        assert_eq!(
            InvalidationReason::SchemaVersion { old: 3, new: 4 }.as_label(),
            "schema:3→4"
        );
        assert_eq!(
            InvalidationReason::DaemonBinaryVersion {
                old: "0.5.5".into(),
                new: "0.6.0".into(),
            }
            .as_label(),
            "binary:0.5.5→0.6.0"
        );
        assert_eq!(
            InvalidationReason::GrammarVersion(GrammarDiff::Changed {
                name: "tree-sitter-rust".into(),
                old: "0.23".into(),
                new: "0.24".into(),
            })
            .as_label(),
            "grammar:tree-sitter-rust:0.23→0.24"
        );
        assert_eq!(InvalidationReason::Gitignore.as_label(), "gitignore");
        assert_eq!(
            InvalidationReason::EmptyOrMissingFingerprint.as_label(),
            "empty_or_missing_fingerprint"
        );
    }

    #[test]
    fn combined_hash_is_deterministic() {
        let a = compute_combined(3, "0.6.0", "rust=0.23", "deadbeef");
        let b = compute_combined(3, "0.6.0", "rust=0.23", "deadbeef");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn combined_hash_changes_when_any_part_changes() {
        let base = compute_combined(3, "0.6.0", "rust=0.23", "deadbeef");
        assert_ne!(base, compute_combined(4, "0.6.0", "rust=0.23", "deadbeef"));
        assert_ne!(base, compute_combined(3, "0.7.0", "rust=0.23", "deadbeef"));
        assert_ne!(base, compute_combined(3, "0.6.0", "rust=0.24", "deadbeef"));
        assert_ne!(base, compute_combined(3, "0.6.0", "rust=0.23", "cafebabe"));
    }
}
