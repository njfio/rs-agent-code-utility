//! TOML config for the real-repo bench. See `repos.toml` for the v1
//! default set.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One pinned upstream repo. `git_ref` may be a tag (`v1.10.0`),
/// branch, or full SHA — the cloner tries `--branch <ref>` first and
/// falls back to a full clone + `git checkout` when that fails (the
/// SHA case).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repo {
    pub name: String,
    pub url: String,
    /// Serialized as `ref` to match the operator-facing TOML key.
    #[serde(rename = "ref")]
    pub git_ref: String,
    #[serde(default)]
    pub description: String,
}

/// The full set of repos for one bench invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSet {
    #[serde(rename = "repo")]
    pub repos: Vec<Repo>,
}

impl RepoSet {
    /// Parse a TOML string into a `RepoSet`. Used by both the embedded
    /// `REPOS_TOML` and any custom config the maintainer points at via
    /// `--config-toml`.
    pub fn from_toml(s: &str) -> Result<Self> {
        toml::from_str::<RepoSet>(s).context("parse real-repos TOML")
    }

    /// Parse the embedded v1 set. Returns the same content as reading
    /// `crates/rts-bench/src/real_repos/repos.toml` from the source
    /// tree, but baked in at compile time so the released binary
    /// works without the source.
    pub fn default_v1() -> Result<Self> {
        Self::from_toml(super::REPOS_TOML)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_toml_parses_minimal() {
        let toml_str = r#"
            [[repo]]
            name = "x"
            url = "https://example.invalid/x"
            ref = "v0.0.1"

            [[repo]]
            name = "y"
            url = "https://example.invalid/y"
            ref = "main"
            description = "demo"
        "#;
        let set = RepoSet::from_toml(toml_str).expect("parse");
        assert_eq!(set.repos.len(), 2);
        assert_eq!(set.repos[0].name, "x");
        assert_eq!(set.repos[0].git_ref, "v0.0.1");
        assert_eq!(set.repos[0].description, "");
        assert_eq!(set.repos[1].description, "demo");
    }

    #[test]
    fn from_toml_rejects_missing_required_fields() {
        // Missing `url`.
        let bad = r#"
            [[repo]]
            name = "x"
            ref = "main"
        "#;
        assert!(RepoSet::from_toml(bad).is_err());
    }

    #[test]
    fn default_v1_has_expected_repos() {
        let set = RepoSet::default_v1().expect("default v1 set");
        let names: Vec<&str> = set.repos.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"tokio"), "expected tokio in v1: {names:?}");
        assert!(names.contains(&"flask"), "expected flask in v1: {names:?}");
        assert!(names.contains(&"gin"), "expected gin in v1: {names:?}");
    }
}
