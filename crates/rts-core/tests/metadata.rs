//! Drift-defense for root `Cargo.toml` workspace metadata.
//!
//! The workspace ships `[workspace.package]` placeholder identity for
//! `authors` and `repository` in early development states. A `cargo
//! publish` against those placeholders would send junk identity to
//! crates.io. This test locks in real values once they're correct and
//! fails CI if any future edit reintroduces a placeholder string or a
//! malformed repository URL.
//!
//! Parsing approach: `toml = "0.8"` (already a workspace dependency)
//! instead of regex. The workspace-inheritance pattern means crate
//! manifests carry `authors.workspace = true` rather than literal
//! strings; a regex over those manifests would silently false-pass.
//! Parsing reaches the resolved values via the workspace table.
//!
//! Pattern mirrors `crates/rts-daemon/tests/protocol_schemas.rs` —
//! `env!("CARGO_MANIFEST_DIR")` + relative path traversal to reach
//! the repo root.

use std::path::PathBuf;

/// Substrings that, if present in any author entry, indicate
/// placeholder identity rather than a real maintainer. Each one
/// individually flags the value as bogus.
const PLACEHOLDER_AUTHOR_FRAGMENTS: &[&str] = &[
    "Your Name",
    "your.email@example.com",
    "example.com",
];

fn workspace_root_cargo_toml() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `crates/rts-core/`. The workspace root
    // Cargo.toml is two `..` segments up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("Cargo.toml")
}

fn workspace_package_table() -> toml::Table {
    let path = workspace_root_cargo_toml();
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let parsed: toml::Table = toml::from_str(&contents)
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    parsed
        .get("workspace")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("package"))
        .and_then(|v| v.as_table())
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "{} missing [workspace.package] table",
                path.display()
            )
        })
}

#[test]
fn workspace_authors_contains_no_placeholders() {
    let table = workspace_package_table();
    let authors = table
        .get("authors")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("[workspace.package].authors missing or not an array"));

    assert!(
        !authors.is_empty(),
        "[workspace.package].authors must list at least one maintainer"
    );

    for entry in authors {
        let s = entry
            .as_str()
            .unwrap_or_else(|| panic!("author entry is not a string: {entry:?}"));
        for fragment in PLACEHOLDER_AUTHOR_FRAGMENTS {
            assert!(
                !s.contains(fragment),
                "[workspace.package].authors entry {s:?} contains placeholder fragment {fragment:?}; \
                 set a real maintainer identity in root Cargo.toml"
            );
        }
    }
}

#[test]
fn workspace_repository_is_a_valid_github_url() {
    let table = workspace_package_table();
    let repo = table
        .get("repository")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("[workspace.package].repository missing or not a string"));

    // Anchored validity check: `https://github.com/<owner>/<name>` with
    // an optional trailing slash. Owner + name are restricted to the
    // GitHub-permitted character classes. Rejects placeholder URLs
    // like `github.com/yourusername/...` because `yourusername` is not
    // a real owner — that check is via the placeholder-fragment list.
    let valid_shape = repo
        .strip_prefix("https://github.com/")
        .and_then(|tail| {
            let trimmed = tail.strip_suffix('/').unwrap_or(tail);
            let mut parts = trimmed.split('/');
            let owner = parts.next()?;
            let name = parts.next()?;
            if parts.next().is_some() {
                return None;
            }
            if owner.is_empty() || name.is_empty() {
                return None;
            }
            let owner_ok = owner
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
            let name_ok = name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
            (owner_ok && name_ok).then_some(())
        })
        .is_some();

    assert!(
        valid_shape,
        "[workspace.package].repository {repo:?} is not a well-formed \
         https://github.com/<owner>/<name> URL"
    );

    // Belt-and-suspenders: reject the original placeholder owner. A
    // shape-only check would pass `https://github.com/yourusername/...`.
    assert!(
        !repo.contains("yourusername"),
        "[workspace.package].repository {repo:?} still references the \
         placeholder owner 'yourusername'; set the real repo URL"
    );
}
