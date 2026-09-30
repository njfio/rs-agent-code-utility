//! Multi-root routing for the MCP shim.
//!
//! One `rts-mcp` process can serve several workspace roots out of **one**
//! daemon: the root it was started with plus any extras it was told about
//! (`--workspace` repeated, or `RTS_MCP_ROOTS`). The daemon mounts each root
//! separately (its own index, watcher, writer) and addresses them by
//! `workspace_id`.
//!
//! The model never names a root — that is the whole point. The shim infers
//! which root a tool call concerns from the call's *own* path-shaped
//! arguments (a `file`, a `path`, a `file_glob`, an `edits[].file`, …) and
//! names it on the wire (`workspace_id` in the request envelope).
//!
//! ## Resolution rules
//!
//! Arguments are tried in the order the tool passes them (most specific
//! first — an explicit `file` before a `glob`). For each argument:
//!
//! 1. **Absolute** path (or glob): the mounted root that is a path-prefix of
//!    it wins; the longest match wins, so a worktree nested inside the repo
//!    root routes to the worktree. Component-wise (`Path::starts_with`), so
//!    `/a/b` never matches root `/a/bc`.
//! 2. **Relative** path: the root under which it actually exists wins —
//!    *only* when exactly one mounted root has it. A relative path that
//!    exists under several roots (the normal case for a worktree: it is a
//!    checkout of the same repo) carries no information, so it is ignored.
//! 3. **Glob**: rules 1–2 applied to the literal prefix before the first
//!    wildcard (`src/**/*.rs` → `src/`); a glob whose prefix is empty or is
//!    just `.` carries no information.
//!
//! If the arguments that *do* resolve agree on one root, that root serves the
//! call ([`RouteKind::PathMatch`]). If none resolve, or if they disagree, the
//! call is served by the start-up root ([`RouteKind::Default`] /
//! [`RouteKind::Ambiguous`]) and the tool response says so in `_root` — a
//! visible default, never a silent guess.
//!
//! ## Addressing a worktree
//!
//! Because of rule 2, the way to address a worktree is an **absolute** path
//! (`/repo/.wt/alpha/crates/x.rs`), which rule 1 routes to `/repo/.wt/alpha`.
//! A bare `crates/x.rs` exists under every root and is therefore served by
//! the start-up root; the `_root` block on the response names that root and
//! `resolved_by: "default"`, so an agent that sees the wrong tree learns
//! exactly what to pass instead.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// The roots this shim may route to, start-up root first.
#[derive(Debug, Clone)]
pub struct RootSet {
    start_up: PathBuf,
    roots: Vec<PathBuf>,
}

/// How a call's root was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// A path-shaped argument named the root.
    PathMatch,
    /// No argument resolved; the start-up root serves the call.
    Default,
    /// Arguments resolved to *different* roots; the start-up root serves the
    /// call so the answer stays coherent (a single call cannot span roots).
    Ambiguous,
}

impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::PathMatch => "path_match",
            RouteKind::Default => "default",
            RouteKind::Ambiguous => "ambiguous",
        }
    }
}

/// The chosen root plus why.
#[derive(Debug, Clone)]
pub struct Route {
    pub root: PathBuf,
    pub kind: RouteKind,
    /// The argument that decided it (or the first conflicting argument).
    pub evidence: Option<String>,
}

impl Route {
    /// The `_root` block the tool layer attaches to a response. `workspace_id`
    /// is the daemon's mount id for this root, which the model can quote back
    /// in a bug report; `path` + `resolved_by` are what it acts on.
    pub fn to_wire(&self, workspace_id: &str) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("workspace_id".into(), json!(workspace_id));
        obj.insert("path".into(), json!(self.root.to_string_lossy()));
        obj.insert("resolved_by".into(), json!(self.kind.as_str()));
        if let Some(ev) = self.evidence.as_deref() {
            obj.insert("matched_arg".into(), json!(ev));
        }
        let note = match self.kind {
            RouteKind::PathMatch => None,
            RouteKind::Default => Some(format!(
                "no mounted root matched this call's paths; served by the start-up root {}. \
                 Pass an absolute path (e.g. {}/…) to target another root.",
                self.root.display(),
                self.root.display()
            )),
            RouteKind::Ambiguous => Some(format!(
                "this call's paths span more than one mounted root ({}); served by the \
                 start-up root {}. Split the call per root, or pass absolute paths.",
                self.evidence.as_deref().unwrap_or("multiple"),
                self.root.display()
            )),
        };
        if let Some(note) = note {
            obj.insert("note".into(), json!(note));
        }
        Value::Object(obj)
    }
}

impl RootSet {
    /// Build a root set. `start_up` is the root the shim was started for (the
    /// one the daemon socket is keyed on); `extras` are additional roots,
    /// mounted lazily on first use. Duplicates are dropped, order preserved.
    pub fn new(start_up: PathBuf, extras: Vec<PathBuf>) -> Self {
        let mut roots = vec![start_up.clone()];
        for extra in extras {
            if !roots.contains(&extra) {
                roots.push(extra);
            }
        }
        Self { start_up, roots }
    }

    pub fn start_up(&self) -> &Path {
        &self.start_up
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Route a call by its path-shaped arguments, most specific first.
    pub fn resolve<'a>(&self, candidates: impl IntoIterator<Item = Option<&'a str>>) -> Route {
        let mut matched: Option<(PathBuf, String)> = None;
        let mut conflicting: Option<String> = None;
        for candidate in candidates.into_iter().flatten() {
            let candidate = candidate.trim();
            if candidate.is_empty() {
                continue;
            }
            let Some(root) = self.match_one(candidate) else {
                continue;
            };
            match &matched {
                None => matched = Some((root, candidate.to_string())),
                Some((previous, _)) if *previous == root => {}
                Some(_) => conflicting = Some(candidate.to_string()),
            }
        }
        match (matched, conflicting) {
            (Some((root, evidence)), None) => Route {
                root,
                kind: RouteKind::PathMatch,
                evidence: Some(evidence),
            },
            (Some(_), Some(conflict)) => Route {
                root: self.start_up.clone(),
                kind: RouteKind::Ambiguous,
                evidence: Some(conflict),
            },
            (None, _) => Route {
                root: self.start_up.clone(),
                kind: RouteKind::Default,
                evidence: None,
            },
        }
    }

    /// Which mounted root (if exactly one) a single argument names.
    fn match_one(&self, candidate: &str) -> Option<PathBuf> {
        let literal = literal_prefix(candidate);
        if literal.is_empty() {
            return None;
        }
        let path = Path::new(literal);
        if path.is_absolute() {
            // Longest matching root wins: `/repo/.wt/alpha/…` must route to
            // the worktree, not to `/repo`.
            return self
                .roots
                .iter()
                .filter(|root| path.starts_with(root))
                .max_by_key(|root| root.components().count())
                .cloned();
        }
        // Relative: only a path that exists under exactly one root is
        // evidence. Existence under several roots is the worktree case and
        // says nothing about which tree the caller meant.
        let hits: Vec<&PathBuf> = self
            .roots
            .iter()
            .filter(|root| root.join(path).exists())
            .collect();
        match hits.as_slice() {
            [only] => Some((*only).clone()),
            _ => None,
        }
    }
}

/// The literal (wildcard-free) prefix of a glob or path argument.
///
/// `src/**/*.rs` → `src/`, `/repo/.wt/a/src/*.rs` → `/repo/.wt/a/src/`,
/// `*.rs` → `""`. Trailing separators are kept so a bare directory prefix
/// still `Path::starts_with`-matches.
fn literal_prefix(candidate: &str) -> &str {
    let end = candidate
        .find(['*', '?', '[', '{'])
        .unwrap_or(candidate.len());
    &candidate[..end]
}

/// Rewrite the absolute path arguments in a tool call into the selected
/// root's coordinate system, in place. Returns how many were rewritten.
///
/// The daemon's path-taking arguments (`file`, `glob`, `file_glob`,
/// `edits[].file`, `claims[].file`) are **workspace-relative** — `file` is
/// compared for exact equality against the indexed path, and a glob is matched
/// against it. An absolute path is therefore the right thing to *route* on and
/// the wrong thing to *send*. So once a route is chosen, an absolute argument
/// under that root is handed over relative to it; anything else (relative
/// already, or absolute but outside the root) is passed through untouched and
/// the daemon answers honestly.
///
/// Only call this for a [`RouteKind::PathMatch`] route: with no match the
/// argument is not known to belong to the routed root.
pub fn relativize_params(params: &mut Value, root: &Path) -> usize {
    let Some(obj) = params.as_object_mut() else {
        return 0;
    };
    let mut rewritten = 0;
    for key in ["file", "glob", "file_glob"] {
        if let Some(slot) = obj.get_mut(key) {
            if let Some(rel) = strip_root(slot, root) {
                *slot = json!(rel);
                rewritten += 1;
            }
        }
    }
    for key in ["edits", "claims"] {
        if let Some(Value::Array(items)) = obj.get_mut(key) {
            for item in items.iter_mut() {
                let Some(map) = item.as_object_mut() else {
                    continue;
                };
                if let Some(slot) = map.get_mut("file") {
                    if let Some(rel) = strip_root(slot, root) {
                        *slot = json!(rel);
                        rewritten += 1;
                    }
                }
            }
        }
    }
    rewritten
}

/// `"/root/src/a.rs"` under root `"/root"` → `"src/a.rs"`. `None` when the
/// value isn't an absolute path under `root` (relative already, outside the
/// root, or the root itself).
fn strip_root(value: &Value, root: &Path) -> Option<String> {
    let raw = value.as_str()?;
    let path = Path::new(raw);
    if !path.is_absolute() {
        return None;
    }
    let rel = path.strip_prefix(root).ok()?;
    let rel = rel.to_string_lossy();
    if rel.is_empty() {
        return None;
    }
    Some(rel.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> RootSet {
        RootSet::new(
            PathBuf::from("/repo"),
            vec![
                PathBuf::from("/repo/.wt/alpha"),
                PathBuf::from("/repo/.wt/beta"),
            ],
        )
    }

    #[test]
    fn keeps_start_up_first_and_drops_duplicates() {
        let set = RootSet::new(
            PathBuf::from("/repo"),
            vec![PathBuf::from("/repo/.wt/a"), PathBuf::from("/repo")],
        );
        assert_eq!(set.roots().len(), 2);
        assert_eq!(set.start_up(), Path::new("/repo"));
        assert_eq!(set.roots()[0], PathBuf::from("/repo"));
        assert_eq!(set.roots()[1], PathBuf::from("/repo/.wt/a"));
    }

    #[test]
    fn absolute_path_routes_to_the_deepest_matching_root() {
        let route = roots().resolve([Some("/repo/.wt/alpha/crates/x/src/lib.rs")]);
        assert_eq!(route.kind, RouteKind::PathMatch);
        assert_eq!(route.root, PathBuf::from("/repo/.wt/alpha"));
    }

    #[test]
    fn absolute_path_only_under_the_start_up_root_routes_there() {
        let route = roots().resolve([Some("/repo/crates/rts-core/src/lib.rs")]);
        assert_eq!(route.kind, RouteKind::PathMatch);
        assert_eq!(route.root, PathBuf::from("/repo"));
    }

    #[test]
    fn absolute_path_prefix_must_end_on_a_component_boundary() {
        // `/repo2/...` must not match the `/repo` root.
        let route = roots().resolve([Some("/repo2/src/lib.rs")]);
        assert_eq!(route.kind, RouteKind::Default);
        assert_eq!(route.root, PathBuf::from("/repo"));
    }

    #[test]
    fn absolute_path_outside_every_root_is_a_visible_default() {
        let route = roots().resolve([Some("/elsewhere/src/lib.rs")]);
        assert_eq!(route.kind, RouteKind::Default);
        assert_eq!(route.root, PathBuf::from("/repo"));
        let wire = route.to_wire("aabbccddeeff0011");
        assert_eq!(wire["resolved_by"], "default");
        assert_eq!(wire["workspace_id"], "aabbccddeeff0011");
        assert!(
            wire["note"].as_str().unwrap().contains("start-up root"),
            "the default must be stated in the response: {wire:?}"
        );
    }

    #[test]
    fn no_path_arguments_at_all_is_a_visible_default() {
        let route = roots().resolve([]);
        assert_eq!(route.kind, RouteKind::Default);
        assert_eq!(route.root, PathBuf::from("/repo"));
    }

    #[test]
    fn glob_routes_by_its_literal_prefix() {
        let route = roots().resolve([Some("/repo/.wt/beta/crates/**/*.rs")]);
        assert_eq!(route.kind, RouteKind::PathMatch);
        assert_eq!(route.root, PathBuf::from("/repo/.wt/beta"));
    }

    #[test]
    fn glob_without_a_literal_prefix_carries_no_information() {
        let route = roots().resolve([Some("**/*.rs")]);
        assert_eq!(route.kind, RouteKind::Default);
        assert_eq!(route.evidence, None);
    }

    #[test]
    fn arguments_that_disagree_are_ambiguous_and_fall_back() {
        let route = roots().resolve([
            Some("/repo/.wt/alpha/src/a.rs"),
            Some("/repo/.wt/beta/src/b.rs"),
        ]);
        assert_eq!(route.kind, RouteKind::Ambiguous);
        assert_eq!(route.root, PathBuf::from("/repo"));
        assert_eq!(route.evidence.as_deref(), Some("/repo/.wt/beta/src/b.rs"));
    }

    #[test]
    fn arguments_that_agree_on_one_root_route_there() {
        let route = roots().resolve([
            Some("/repo/.wt/alpha/src/a.rs"),
            Some("/repo/.wt/alpha/src/b.rs"),
        ]);
        assert_eq!(route.kind, RouteKind::PathMatch);
        assert_eq!(route.root, PathBuf::from("/repo/.wt/alpha"));
    }

    #[test]
    fn later_arguments_do_not_override_an_earlier_unresolved_one() {
        let route = roots().resolve([Some("src/**/*.rs"), Some("/repo/.wt/beta/src/a.rs")]);
        assert_eq!(route.kind, RouteKind::PathMatch);
        assert_eq!(route.root, PathBuf::from("/repo/.wt/beta"));
    }

    #[test]
    fn blank_arguments_are_ignored() {
        let route = roots().resolve([Some("   "), None, Some("/repo/.wt/alpha/src/a.rs")]);
        assert_eq!(route.kind, RouteKind::PathMatch);
        assert_eq!(route.root, PathBuf::from("/repo/.wt/alpha"));
    }

    #[test]
    fn relative_path_existing_under_exactly_one_root_routes_there() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(a.path().join("src")).unwrap();
        std::fs::write(a.path().join("src/only_here.rs"), "fn a() {}\n").unwrap();
        std::fs::create_dir_all(b.path().join("src")).unwrap();
        std::fs::write(b.path().join("src/other.rs"), "fn b() {}\n").unwrap();

        let set = RootSet::new(a.path().to_path_buf(), vec![b.path().to_path_buf()]);
        let route = set.resolve([Some("src/only_here.rs")]);
        assert_eq!(route.kind, RouteKind::PathMatch);
        // `RootSet` keeps the roots it was handed verbatim (the shim
        // canonicalises before constructing it), so compare against that path —
        // tempdirs live behind macOS's `/var` → `/private/var` symlink.
        assert_eq!(route.root, a.path());
    }

    #[test]
    fn relative_path_present_under_every_root_is_a_visible_default() {
        // The worktree case: a checkout of the same repo has the same
        // relative paths, so a bare relative path cannot pick a tree.
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        for dir in [a.path(), b.path()] {
            std::fs::create_dir_all(dir.join("src")).unwrap();
            std::fs::write(dir.join("src/lib.rs"), "fn shared() {}\n").unwrap();
        }
        let set = RootSet::new(a.path().to_path_buf(), vec![b.path().to_path_buf()]);
        let route = set.resolve([Some("src/lib.rs")]);
        assert_eq!(route.kind, RouteKind::Default);
        assert_eq!(route.root, a.path());
    }

    #[test]
    fn relative_path_that_exists_nowhere_is_a_visible_default() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let set = RootSet::new(a.path().to_path_buf(), vec![b.path().to_path_buf()]);
        let route = set.resolve([Some("src/nope.rs")]);
        assert_eq!(route.kind, RouteKind::Default);
    }

    #[test]
    fn literal_prefix_stops_at_the_first_wildcard() {
        assert_eq!(literal_prefix("/repo/a/**/*.rs"), "/repo/a/");
        assert_eq!(literal_prefix("src/lib.rs"), "src/lib.rs");
        assert_eq!(literal_prefix("*.rs"), "");
        assert_eq!(literal_prefix("{a,b}/x"), "");
    }

    #[test]
    fn relativize_rewrites_absolute_paths_under_the_root() {
        let mut params = json!({
            "name": "answer",
            "file": "/repo/.wt/a/src/lib.rs",
            "file_glob": "/repo/.wt/a/src/**/*.rs",
        });
        assert_eq!(relativize_params(&mut params, Path::new("/repo/.wt/a")), 2);
        assert_eq!(params["file"], "src/lib.rs");
        assert_eq!(params["file_glob"], "src/**/*.rs");
    }

    #[test]
    fn relativize_leaves_relative_and_foreign_paths_alone() {
        let mut params = json!({
            "file": "src/lib.rs",
            "glob": "/elsewhere/src/**",
        });
        assert_eq!(relativize_params(&mut params, Path::new("/repo")), 0);
        assert_eq!(params["file"], "src/lib.rs");
        assert_eq!(params["glob"], "/elsewhere/src/**");
    }

    #[test]
    fn relativize_handles_nested_edits_and_claims() {
        let mut params = json!({
            "edits": [{"file": "/repo/.wt/a/src/a.rs", "content": "x"}],
            "claims": [
                {"type": "location", "file": "/repo/.wt/a/src/b.rs", "line": 3},
                {"type": "symbol", "name": "answer"}
            ],
        });
        assert_eq!(relativize_params(&mut params, Path::new("/repo/.wt/a")), 2);
        assert_eq!(params["edits"][0]["file"], "src/a.rs");
        assert_eq!(params["claims"][0]["file"], "src/b.rs");
        assert!(params["claims"][1].get("file").is_none());
    }

    #[test]
    fn relativize_ignores_the_root_itself() {
        let mut params = json!({ "file": "/repo" });
        assert_eq!(relativize_params(&mut params, Path::new("/repo")), 0);
        assert_eq!(params["file"], "/repo");
    }
}
