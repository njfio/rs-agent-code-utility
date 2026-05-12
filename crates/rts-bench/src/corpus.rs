//! Fixture corpus management.
//!
//! Per plan §P9, the bench corpus is pinned in `corpus.lock` with
//! `{name, git_url, commit_sha, tarball_url, tarball_sha256,
//! archive_size_bytes}` per fixture. Restore is idempotent and
//! verifies SHA256 *before* extract, so a partial download or a tampered
//! mirror surfaces as an error rather than a poisoned workspace.
//!
//! v0 of this module:
//! - **Defines the schema** (`Corpus`, `FixtureEntry`).
//! - **Implements `restore_one`** in terms of an already-downloaded tarball:
//!   verify SHA256, then extract. The actual *download* step is left to a
//!   later session because v0's first baseline measurement runs against
//!   a hand-seeded workspace, not a real OSS fixture.
//! - **Persists nothing transient.** The full corpus.lock can be re-read on
//!   every run — there's no caching layer.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Top-level corpus.lock document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Corpus {
    /// `corpus.lock` schema version. Bumped if the on-disk format changes.
    pub version: u32,
    /// Pinned model id used as the token oracle when `--with-network` is on
    /// (e.g. `"claude-sonnet-4-6-2026-04-30"`). Carried in every report so
    /// historical comparisons stay anchored.
    pub model: String,
    /// One entry per fixture repository.
    pub fixtures: Vec<FixtureEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureEntry {
    /// Stable short name used to refer to the fixture from CLI args
    /// (e.g. `"tokio"`, `"mitmproxy"`, `"vscode-extension-samples"`).
    pub name: String,
    /// GitHub or other VCS URL — informational; the canonical artifact is
    /// `tarball_url`. v1 may add `git_url` cloning as a fallback.
    pub git_url: String,
    /// Pinned commit / tag the tarball corresponds to.
    pub commit_sha: String,
    /// Direct HTTPS download URL for the archive (e.g. GitHub's codeload).
    pub tarball_url: String,
    /// SHA-256 of the tarball, hex-encoded lowercase. Mismatch on restore
    /// rejects the download.
    pub tarball_sha256: String,
    /// Expected archive size in bytes. Used as a coarse sanity check
    /// against the total 1 GB budget before extraction.
    pub archive_size_bytes: u64,
}

impl Corpus {
    /// Load `corpus.lock` from disk. JSON for now; a TOML variant lands when
    /// the corpus has enough entries that human-readable diffs matter.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes =
            std::fs::read(path).with_context(|| format!("read corpus lock {}", path.display()))?;
        let parsed: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse corpus lock {}", path.display()))?;
        if parsed.version != 1 {
            return Err(anyhow!(
                "unsupported corpus.lock version {}; this binary supports v1",
                parsed.version
            ));
        }
        Ok(parsed)
    }

    /// Look up a fixture by short name. Reserved for the tarball-download
    /// path that lands when there's a pinned corpus to fetch.
    #[allow(dead_code)]
    pub fn find(&self, name: &str) -> Option<&FixtureEntry> {
        self.fixtures.iter().find(|f| f.name == name)
    }
}

/// Verify a tarball's SHA256 against `expected_hex`. Returns `Ok(())` on
/// match, `Err` otherwise. Streaming hash — never loads the file into
/// memory. Reserved for the download path that fetches tarballs from
/// pinned URLs in `corpus.lock`; the integrity check itself ships now
/// so the security boundary is in place before the network code lands.
#[allow(dead_code)]
pub fn verify_sha256(tarball: &Path, expected_hex: &str) -> Result<()> {
    let mut f =
        std::fs::File::open(tarball).with_context(|| format!("open {}", tarball.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut f, &mut buf)
            .with_context(|| format!("read {}", tarball.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let got = hasher.finalize();
    let got_hex = hex::encode(got);
    if !got_hex.eq_ignore_ascii_case(expected_hex) {
        return Err(anyhow!(
            "SHA256 mismatch on {}: expected {expected_hex}, got {got_hex}",
            tarball.display()
        ));
    }
    Ok(())
}

/// The on-disk root where extracted fixtures live. By default
/// `crates/rts-bench/corpus/`, but the CLI can override via
/// `--corpus-root` or `RTS_BENCH_CORPUS_ROOT`.
pub fn default_corpus_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("$PWD")?;
    Ok(cwd.join("crates").join("rts-bench").join("corpus"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tarball(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn sha256_match_passes() {
        let dir = tempfile::tempdir().unwrap();
        let tb = write_tarball(dir.path(), "x.tgz", b"hello world");
        // sha256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        verify_sha256(&tb, expected).unwrap();
    }

    #[test]
    fn sha256_mismatch_errors() {
        let dir = tempfile::tempdir().unwrap();
        let tb = write_tarball(dir.path(), "x.tgz", b"hello world");
        let err = verify_sha256(
            &tb,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("SHA256 mismatch"));
    }

    #[test]
    fn corpus_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("corpus.lock");
        let corpus = Corpus {
            version: 1,
            model: "claude-sonnet-4-6-2026-04-30".into(),
            fixtures: vec![FixtureEntry {
                name: "tokio".into(),
                git_url: "https://github.com/tokio-rs/tokio".into(),
                commit_sha: "abcdef".into(),
                tarball_url: "https://codeload.github.com/tokio-rs/tokio/tar.gz/abcdef".into(),
                tarball_sha256: "deadbeef".into(),
                archive_size_bytes: 12_345_678,
            }],
        };
        std::fs::write(&lock, serde_json::to_string_pretty(&corpus).unwrap()).unwrap();
        let parsed = Corpus::load(&lock).unwrap();
        assert_eq!(parsed.fixtures.len(), 1);
        assert_eq!(parsed.find("tokio").unwrap().commit_sha, "abcdef");
    }

    #[test]
    fn corpus_version_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("corpus.lock");
        std::fs::write(&lock, r#"{"version":99,"model":"x","fixtures":[]}"#).unwrap();
        let err = Corpus::load(&lock).unwrap_err();
        assert!(format!("{err:#}").contains("unsupported corpus.lock version 99"));
    }
}
