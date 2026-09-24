//! Tool-surface profiles.
//!
//! Every tool declaration is paid for on every request: `tools/list` is part of the context an
//! agent sends with each turn. All sixteen tools with their pinned descriptions come to about
//! 11 KB, roughly 2,800 tokens per call — which is more than some harnesses budget for their
//! *entire* tool surface, and they will filter us down anyway if we do not offer a smaller
//! surface ourselves.
//!
//! A profile is a named subset, advertised with one-line descriptions instead of the pinned
//! paragraphs. The long descriptions exist to steer a model that can see everything; when the
//! surface *is* the steer — eight tools, each named for its job — the paragraphs are overhead.
//! `--tools core` is that surface: about 120 tokens instead of 2,800.
//!
//! The subset is a policy, not an advertisement: a tool outside the surface is disabled in the
//! router, so calling it fails the same way an unknown tool does rather than succeeding
//! quietly.

/// A named subset, or `None` for every tool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Surface {
    keep: Option<Vec<String>>,
}

/// Lookup: where things are, what they look like, and what calls them.
///
/// The surface for an agent that reads and reasons — scouts, reviewers, a planner.
pub const CORE: &[&str] = &[
    "outline_workspace",
    "find_symbol",
    "read_symbol",
    "read_symbol_at",
    "read_range",
    "find_callers",
    "impact_of",
    "grep",
];

/// Lookup plus the gates: everything an agent that *edits* code needs to check its work.
///
/// The four `verify_*` lookups are cheap and factual (does this symbol, signature or import
/// exist); `verify_impact` and `verify_edit` are the expensive gates that walk the call graph.
pub const VERIFY: &[&str] = &[
    "outline_workspace",
    "find_symbol",
    "read_symbol",
    "read_symbol_at",
    "read_range",
    "find_callers",
    "impact_of",
    "grep",
    "verify_symbol",
    "verify_signature",
    "verify_import",
    "verify_claims",
    "verify_impact",
    "verify_edit",
];

/// One line per tool, for profiles that are small enough to carry the instruction themselves.
///
/// Each still says *when* to reach for the tool, which is the part that changes behaviour; what
/// they drop is the comparison against the shell command they replace.
const SHORT: &[(&str, &str)] = &[
    (
        "outline_workspace",
        "Ranked map of the workspace: files with their most important symbols and signatures. Use to orient before reading.",
    ),
    (
        "find_symbol",
        "Where a symbol is defined: AST-precise, ranked, with kind and signature. Use instead of grep for identifiers.",
    ),
    (
        "read_symbol",
        "Read one symbol's body, optionally with its dependencies or its callers. Use instead of reading the whole file.",
    ),
    (
        "read_symbol_at",
        "Read the symbol enclosing a file:line. Use for compiler errors and stack traces.",
    ),
    (
        "read_range",
        "Read an explicit line range: diff hunks, stack frames, log excerpts.",
    ),
    (
        "find_callers",
        "Direct callers of a symbol, AST-precise. Use before changing or deleting it.",
    ),
    (
        "impact_of",
        "Transitive callers of a symbol — the refactor blast radius — bounded by depth.",
    ),
    (
        "grep",
        "Literal, regex or structural search, each match labelled with the symbol that encloses it.",
    ),
    (
        "verify_symbol",
        "Check that a symbol exists before you call or import it; a miss lists ranked candidates.",
    ),
    (
        "verify_signature",
        "Check a call against the symbol's real arity and parameters before you write it.",
    ),
    (
        "verify_import",
        "Check that an import path's final segment resolves to a real symbol.",
    ),
    (
        "verify_claims",
        "Fact-check a batch of symbol, signature, import or location claims against the AST.",
    ),
    (
        "verify_impact",
        "Declare a signature change, rename or removal and get its blast radius as pass or fail.",
    ),
    (
        "verify_edit",
        "Gate a proposed multi-file patch: broken callers, signature breaks, dangling references.",
    ),
];

impl Surface {
    /// Every tool: the default, and what every existing wiring already gets.
    pub fn all() -> Self {
        Self { keep: None }
    }

    /// Resolves `--tools`/`RTS_MCP_TOOLS`: a profile name, a comma-separated list of tool names,
    /// or `all`. An unknown name is an error rather than a silently smaller surface — the one
    /// failure mode that would look like it worked.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(
                "tool surface must not be empty (use `all`, `core`, `verify`, or a list)"
                    .to_string(),
            );
        }
        let names: Vec<String> = match spec.to_ascii_lowercase().as_str() {
            "all" | "*" => return Ok(Self::all()),
            "core" => CORE.iter().map(|name| (*name).to_string()).collect(),
            "verify" => VERIFY.iter().map(|name| (*name).to_string()).collect(),
            _ => spec
                .split(',')
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty())
                .collect(),
        };
        if names.is_empty() {
            return Err("tool surface is empty after parsing".to_string());
        }
        let known = SHORT.iter().map(|(name, _)| *name).collect::<Vec<_>>();
        let unknown = names
            .iter()
            .filter(|name| {
                !known.contains(&name.as_str())
                    && !matches!(name.as_str(), "daemon_stats" | "daemon_telemetry")
            })
            .cloned()
            .collect::<Vec<_>>();
        if !unknown.is_empty() {
            return Err(format!(
                "unknown tool(s) in surface: {}. Known: {}",
                unknown.join(", "),
                known.join(", ")
            ));
        }
        Ok(Self { keep: Some(names) })
    }

    /// Whether the tool is inside the surface.
    pub fn keeps(&self, name: &str) -> bool {
        match &self.keep {
            None => true,
            Some(names) => names.iter().any(|kept| kept == name),
        }
    }

    /// Whether this surface is a subset (and therefore uses the short descriptions).
    pub fn is_subset(&self) -> bool {
        self.keep.is_some()
    }

    /// The one-line description to advertise for `name`, under a subset surface only.
    ///
    /// `None` means "leave the pinned description alone": either the surface is `all`, or the
    /// tool has no one-liner and its paragraph is what it has.
    pub fn short(&self, name: &str) -> Option<&'static str> {
        if !self.is_subset() {
            return None;
        }
        SHORT
            .iter()
            .find(|(tool, _)| *tool == name)
            .map(|(_, short)| *short)
    }

    /// The names outside the surface, given the tools that exist.
    ///
    /// Deliberately takes names rather than a router: naming `rmcp`'s router type here would
    /// make rmcp part of this library's public API, and its blanket impls come with it — the
    /// public-API snapshot grew eighteen unrelated `DynClone` lines the first time. The caller
    /// that already depends on rmcp disables what this returns.
    pub fn disabled(&self, tools: impl IntoIterator<Item = String>) -> Vec<String> {
        let Some(keep) = &self.keep else {
            return Vec::new();
        };
        tools
            .into_iter()
            .filter(|name| !keep.iter().any(|kept| kept == name))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of the profiles: a small surface, and every tool in it has a one-liner.
    #[test]
    fn a_profile_is_a_subset_with_a_short_description_for_each_tool() {
        for (profile, names) in [("core", CORE), ("verify", VERIFY)] {
            let surface = Surface::parse(profile).expect("profile");
            assert!(surface.is_subset(), "{profile} is a subset");
            assert!(!names.is_empty(), "{profile} is not empty");
            for name in names {
                assert!(surface.keeps(name), "{profile} keeps {name}");
                assert!(
                    surface.short(name).is_some_and(|d| d.len() < 200),
                    "{name} needs a one-line description under {profile}"
                );
            }
        }
        // Every name in a profile exists in the short table or is an observability tool:
        // a profile that lists a tool which cannot be described is a stale profile.
        for name in CORE.iter().chain(VERIFY.iter()) {
            assert!(
                SHORT.iter().any(|(tool, _)| tool == name),
                "{name} has no short description"
            );
        }
    }

    /// `all` is the default and leaves the pinned descriptions alone.
    #[test]
    fn all_keeps_every_tool_and_its_pinned_description() {
        let surface = Surface::parse("all").expect("all");
        assert!(!surface.is_subset());
        assert!(surface.keeps("daemon_telemetry"));
        assert_eq!(surface.short("find_symbol"), None, "no rewriting under all");
    }

    /// A list names exactly what it says, and an unknown name is an error: a typo must not
    /// read as "that tool is not available for you".
    #[test]
    fn a_named_list_is_exact_and_an_unknown_name_is_an_error() {
        let surface = Surface::parse("find_symbol, read_symbol").expect("list");
        assert!(surface.keeps("find_symbol") && surface.keeps("read_symbol"));
        assert!(!surface.keeps("grep"), "a list keeps only what it names");

        let err = Surface::parse("find_symbols").expect_err("typo");
        assert!(err.contains("unknown tool"), "{err}");
        assert!(
            err.contains("find_symbol"),
            "the error lists what exists: {err}"
        );
        assert!(
            Surface::parse("").is_err(),
            "empty is refused, not treated as all"
        );
    }
}
