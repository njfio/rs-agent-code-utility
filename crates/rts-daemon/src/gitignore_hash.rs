//! Effective-gitignore content hasher for the persisted-cold-mount
//! fingerprint (v0.6+, capability `daemon_stats_v2`'s `mount_source`
//! field).
//!
//! The fingerprint needs to invalidate the cached redb whenever the
//! files the indexer *would* consider change. The walker
//! (`crates/rts-daemon/src/watcher.rs:299-307`) honors:
//!
//!   1. workspace `.gitignore` (top-of-repo)
//!   2. `.git/info/exclude`
//!   3. workspace `.rtsignore` (rts-specific overlay)
//!   4. ancestor `.gitignore` files walked upward toward `/`
//!   5. global gitignore (`~/.config/git/ignore` or
//!      `${XDG_CONFIG_HOME}/git/ignore`)
//!   6. hardcoded fallbacks compiled into the binary
//!      (`target/`, `node_modules/`, `.git/`, `.hg/`, `.svn/`,
//!      `build/`, `dist/`, `.next/`, `.cache/`)
//!
//! This module hashes that effective byte stream. Each segment is
//! length-prefixed with `(u32 len, ASCII name, content_bytes)` so
//! two distinct ignore stacks can never collide via concatenation.
//!
//! Byte-equal semantics only — a whitespace-only edit of `.gitignore`
//! invalidates the snapshot. Semantic normalization is documented as a
//! deliberate v1 non-goal in the plan.
//!
//! Returns a 32-char lowercase hex string (the leading 16 bytes of
//! blake3) so it composes with the existing `WorkspaceFingerprint`
//! truncation pattern.

use std::path::{Path, PathBuf};

use blake3::Hasher;

/// Hardcoded fallback gitignore content baked into the binary. Mirrors
/// `crates/rts-daemon/src/filter.rs:205-216` (`PrebuiltGitignore::build`).
/// Joined with newlines so the byte representation is stable across
/// builds.
const FALLBACK_IGNORES: &[&str] = &[
    "target/",
    "node_modules/",
    ".git/",
    ".hg/",
    ".svn/",
    "build/",
    "dist/",
    ".next/",
    ".cache/",
];

/// Computes a stable byte-content hash of the effective gitignore
/// stack for `workspace_root`. Returns 32 hex chars (16 bytes of
/// blake3 truncated).
///
/// `workspace_root` should be the canonicalized workspace path the
/// daemon mounts; ancestor traversal walks upward from there until
/// the filesystem root (each segment present prepended to the stream
/// in walked order, so the order in the hashed stream matches the
/// walker's precedence).
pub fn effective_gitignore_hash(workspace_root: &Path) -> String {
    let mut hasher = Hasher::new();

    // 1. workspace `.gitignore`
    hash_optional_file(&mut hasher, "workspace-gitignore", &workspace_root.join(".gitignore"));

    // 2. `.git/info/exclude`
    hash_optional_file(
        &mut hasher,
        "git-info-exclude",
        &workspace_root.join(".git").join("info").join("exclude"),
    );

    // 3. workspace `.rtsignore`
    hash_optional_file(&mut hasher, "workspace-rtsignore", &workspace_root.join(".rtsignore"));

    // 4. ancestor `.gitignore`s — walk upward from the parent of the
    //    workspace toward `/`. Walked-order is innermost-first so the
    //    fingerprint reflects how the `ignore::WalkBuilder` would
    //    actually layer them.
    let mut current = workspace_root.parent();
    while let Some(dir) = current {
        hash_optional_file(&mut hasher, "ancestor-gitignore", &dir.join(".gitignore"));
        current = dir.parent();
    }

    // 5. global gitignore. Look at `${XDG_CONFIG_HOME}/git/ignore`
    //    first (matches `git`'s own resolution order), then
    //    `~/.config/git/ignore`.
    if let Some(path) = global_gitignore_path() {
        hash_optional_file(&mut hasher, "global-gitignore", &path);
    }

    // 6. Hardcoded fallbacks. These are baked into the binary so a
    //    daemon version bump (which already invalidates the
    //    fingerprint via the binary-version part) handles any future
    //    change here. We include them anyway so two daemons with the
    //    same binary version but somehow-different fallbacks would
    //    still be detected — defense in depth.
    hash_segment(&mut hasher, "fallbacks", FALLBACK_IGNORES.join("\n").as_bytes());

    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    let mut out = String::with_capacity(32);
    for b in &bytes[..16] {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Returns the resolved global gitignore path, honoring
/// `XDG_CONFIG_HOME` on Linux/macOS. Returns `None` when neither the
/// XDG path nor `~/.config/git/ignore` resolves; the hasher treats
/// `None` as "no global gitignore present" (no segment hashed).
fn global_gitignore_path() -> Option<PathBuf> {
    // Honor `XDG_CONFIG_HOME` first per the freedesktop spec.
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let path = PathBuf::from(xdg).join("git").join("ignore");
        if path.exists() {
            return Some(path);
        }
    }
    // Fall back to `~/.config/git/ignore`.
    if let Some(home) = dirs::home_dir() {
        let path = home.join(".config").join("git").join("ignore");
        if path.exists() {
            return Some(path);
        }
    }
    None
}

/// Hash a segment by streaming `(name_len_u32_le, name, content_len_u32_le, content)`.
/// The length prefix is what makes the concatenation unambiguous —
/// two streams that produce the same byte sequence under naive
/// concatenation will produce different hashes here because their
/// segment boundaries differ.
fn hash_segment(hasher: &mut Hasher, name: &str, content: &[u8]) {
    let name_bytes = name.as_bytes();
    hasher.update(&(name_bytes.len() as u32).to_le_bytes());
    hasher.update(name_bytes);
    hasher.update(&(content.len() as u32).to_le_bytes());
    hasher.update(content);
}

/// Hash a file's bytes if it exists; emit an "absent" sentinel if it
/// doesn't. The sentinel is important because "no `.gitignore`" and
/// "empty `.gitignore`" produce different walker behavior (well,
/// they don't in practice, but the fingerprint should distinguish
/// them so adding an empty file later triggers an invalidation).
fn hash_optional_file(hasher: &mut Hasher, name: &str, path: &Path) {
    match std::fs::read(path) {
        Ok(bytes) => hash_segment(hasher, name, &bytes),
        Err(_) => hash_segment(hasher, name, b"<absent>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn empty_workspace_returns_stable_hash() {
        let tmp = TempDir::new().unwrap();
        let a = effective_gitignore_hash(tmp.path());
        let b = effective_gitignore_hash(tmp.path());
        assert_eq!(a, b, "two calls on the same state should match");
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn editing_workspace_gitignore_changes_hash() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(".gitignore"), "*.log\n").unwrap();
        let before = effective_gitignore_hash(tmp.path());
        std::fs::write(tmp.path().join(".gitignore"), "*.tmp\n").unwrap();
        let after = effective_gitignore_hash(tmp.path());
        assert_ne!(before, after);
    }

    #[test]
    fn adding_gitignore_changes_hash() {
        let tmp = TempDir::new().unwrap();
        let absent = effective_gitignore_hash(tmp.path());
        std::fs::write(tmp.path().join(".gitignore"), "*.log\n").unwrap();
        let present = effective_gitignore_hash(tmp.path());
        assert_ne!(absent, present);
    }

    #[test]
    fn adding_rtsignore_changes_hash() {
        let tmp = TempDir::new().unwrap();
        let absent = effective_gitignore_hash(tmp.path());
        std::fs::write(tmp.path().join(".rtsignore"), "scratch/\n").unwrap();
        let present = effective_gitignore_hash(tmp.path());
        assert_ne!(absent, present);
    }

    #[test]
    fn adding_git_info_exclude_changes_hash() {
        let tmp = TempDir::new().unwrap();
        let absent = effective_gitignore_hash(tmp.path());
        std::fs::create_dir_all(tmp.path().join(".git").join("info")).unwrap();
        std::fs::write(
            tmp.path().join(".git").join("info").join("exclude"),
            "private/\n",
        )
        .unwrap();
        let present = effective_gitignore_hash(tmp.path());
        assert_ne!(absent, present);
    }

    #[test]
    fn whitespace_only_edit_changes_hash() {
        // Documented limitation: byte-equal semantics.
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(".gitignore"), "*.log\n").unwrap();
        let before = effective_gitignore_hash(tmp.path());
        std::fs::write(tmp.path().join(".gitignore"), "*.log\n\n").unwrap();
        let after = effective_gitignore_hash(tmp.path());
        assert_ne!(
            before, after,
            "v1 hashes byte-equal content; whitespace edits should invalidate"
        );
    }

    #[test]
    fn segment_lengths_disambiguate_boundaries() {
        // Two streams that would naively concatenate to the same
        // bytes ("ab" alone vs "a" + "b") must produce different
        // hashes because of the length prefix.
        let mut h1 = Hasher::new();
        hash_segment(&mut h1, "x", b"ab");

        let mut h2 = Hasher::new();
        hash_segment(&mut h2, "x", b"a");
        hash_segment(&mut h2, "x", b"b");

        assert_ne!(h1.finalize(), h2.finalize());
    }
}
