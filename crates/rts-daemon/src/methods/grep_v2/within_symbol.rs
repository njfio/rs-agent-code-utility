//! `within_symbol` post-filter for `Index.Grep` v2 (U4).
//!
//! When `shared_filters.within_symbol` is set the grep handler runs
//! its full match collection, then hands the resulting match vec to
//! [`resolve_and_filter`]. That function:
//!
//! 1. Resolves the qualified name via [`Store::find_symbol`].
//! 2. Classifies the resolution cardinality:
//!    - **0 defs** → returns [`GrepValidationCode::WithinSymbolNotFound`].
//!    - **> [`WITHIN_SYMBOL_MAX_DEFS`] defs** AND
//!      `within_symbol_allow_overload != true` →
//!      [`GrepValidationCode::WithinSymbolTooManyDefs`] with a
//!      `data.def_count` field so the caller can decide whether to
//!      retry with the opt-in flag.
//!    - **1..=16 defs OR allow_overload=true** → proceed to filter.
//! 3. Filters the matches using strict byte-range containment against
//!    the union of resolved def ranges: a match `m` is kept iff
//!    `m.file == def.file && m.start_byte >= def.start_byte && m.end_byte <= def.end_byte`
//!    for some resolved def. Matches in files that don't host any
//!    resolved def are necessarily dropped (a def lives in exactly
//!    one file).
//!
//! Strict containment is chosen over lenient overlap — see plan
//! Key Decisions §5 — so a match starting before a def and bleeding
//! into it (or trailing past the closing brace) is excluded. The
//! comparison is *inclusive on the closing edge*: a match whose
//! `end_byte == def.end_byte` is still considered "inside". Per the
//! plan, "strict containment" means the match range is a (possibly
//! coincident) sub-range of the def range; only matches strictly
//! protruding past the def boundary are excluded.
//!
//! ## Pure-filter split
//!
//! The cardinality classification + `find_symbol` lookup is wrapped
//! in [`resolve_and_filter`]; the byte-range filter half is split
//! out as [`filter_matches_by_defs`] so it can be unit-tested in
//! isolation against synthetic match/def vectors without standing
//! up a real `Store`. The store-touching half is covered by the
//! integration test under
//! `crates/rts-daemon/tests/grep_within_symbol_round_trip.rs`.

use crate::store::{FoundSymbol, Store};

use super::errors::{GrepValidationCode, GrepValidationError};

/// Maximum number of resolved defs `within_symbol` may unify over
/// without the caller opting in via `within_symbol_allow_overload:
/// true`. Mirrors the constant documented in
/// `docs/plans/2026-05-18-002-feat-index-grep-v2-plan.md` §"Resource
/// budgets".
pub const WITHIN_SYMBOL_MAX_DEFS: usize = 16;

/// Minimal shape of a collected match that the within_symbol filter
/// needs to make a keep/drop decision. The real grep handler uses
/// `serde_json::Value` records; rather than pass those through here
/// (and re-parse byte offsets out of the wire shape), the handler
/// extracts each match's `(file, start_byte, end_byte)` into a
/// `MatchRange` keyed by the original record's index, runs
/// [`filter_matches_by_defs`], and rebuilds the surviving record
/// list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchRange {
    pub file: String,
    pub start_byte: u32,
    pub end_byte: u32,
}

/// Predicate: is the match strictly contained in *any* of the
/// resolved defs? Closing-edge coincidence (`m.end_byte ==
/// def.end_byte`) is allowed; protruding past it is not.
fn match_inside_any(m: &MatchRange, defs: &[FoundSymbol]) -> bool {
    defs.iter()
        .any(|d| m.file == d.file && m.start_byte >= d.start_byte && m.end_byte <= d.end_byte)
}

/// Pure half of the within_symbol post-filter: given a vec of
/// matches and a vec of resolved defs, return the matches that lie
/// strictly inside any def's byte range.
///
/// Splits out from [`resolve_and_filter`] so the byte-range logic
/// can be unit-tested with synthetic inputs (no `Store` required).
pub fn filter_matches_by_defs(matches: Vec<MatchRange>, defs: &[FoundSymbol]) -> Vec<MatchRange> {
    matches
        .into_iter()
        .filter(|m| match_inside_any(m, defs))
        .collect()
}

/// Resolve `name` via the store, classify the cardinality, and
/// filter `matches` to those contained in any resolved def. See
/// module docs for the policy.
///
/// `allow_overload=true` lifts the [`WITHIN_SYMBOL_MAX_DEFS`] cap;
/// the filter then unions all defs regardless of how many there are.
/// (Reasonable callers still observe an upper bound implicitly via
/// the store's natural distribution; the daemon does not impose a
/// hard ceiling above the opt-in threshold.)
pub fn resolve_and_filter(
    store: &Store,
    name: &str,
    allow_overload: bool,
    matches: Vec<MatchRange>,
) -> Result<Vec<MatchRange>, GrepValidationError> {
    let defs = store.find_symbol(name).map_err(|e| {
        // Storage errors are not validation errors per se, but the
        // within_symbol surface is best served by a structured
        // envelope rather than bubbling an opaque `InternalError`.
        // Treat as "not found" with the underlying error preserved
        // in `message` — the caller can distinguish via the code.
        // (An alternative shape — a dedicated WithinSymbolStoreError
        // — was rejected as overkill for the v1 surface; if storage
        // errors here become observable in practice, revisit.)
        GrepValidationError::new(
            GrepValidationCode::WithinSymbolNotFound,
            format!("`within_symbol` lookup failed: {e}"),
        )
    })?;

    if defs.is_empty() {
        return Err(GrepValidationError::new(
            GrepValidationCode::WithinSymbolNotFound,
            format!("`within_symbol`: no defs found for `{name}`"),
        ));
    }

    if defs.len() > WITHIN_SYMBOL_MAX_DEFS && !allow_overload {
        return Err(GrepValidationError::new(
            GrepValidationCode::WithinSymbolTooManyDefs,
            format!(
                "`within_symbol`: `{name}` resolves to {} defs (max {} without `within_symbol_allow_overload: true`)",
                defs.len(),
                WITHIN_SYMBOL_MAX_DEFS,
            ),
        )
        .with_data(
            "def_count",
            serde_json::Value::Number(serde_json::Number::from(defs.len())),
        ));
    }

    Ok(filter_matches_by_defs(matches, &defs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SymbolKind;
    use crate::store::schema::Visibility;

    // ----- helpers -----

    fn def(name: &str, file: &str, start_byte: u32, end_byte: u32) -> FoundSymbol {
        FoundSymbol {
            name: name.to_string(),
            kind: SymbolKind::Function,
            file: file.to_string(),
            fid: 1,
            sid: 0,
            start_byte,
            end_byte,
            start_line: 1,
            end_line: 1,
            visibility: Visibility::Public,
        }
    }

    fn m(file: &str, start_byte: u32, end_byte: u32) -> MatchRange {
        MatchRange {
            file: file.to_string(),
            start_byte,
            end_byte,
        }
    }

    // ----- filter_matches_by_defs (pure) -----

    #[test]
    fn resolve_and_filter_keeps_match_inside_def() {
        let defs = vec![def("foo", "src/lib.rs", 100, 200)];
        let matches = vec![m("src/lib.rs", 110, 120)];
        let kept = filter_matches_by_defs(matches, &defs);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].start_byte, 110);
    }

    #[test]
    fn resolve_and_filter_drops_match_outside_def() {
        let defs = vec![def("foo", "src/lib.rs", 100, 200)];
        // entirely before the def
        let before = m("src/lib.rs", 10, 20);
        // entirely after the def
        let after = m("src/lib.rs", 250, 300);
        // overlaps the start (protrudes before def.start)
        let straddle_start = m("src/lib.rs", 90, 110);
        // overlaps the end (protrudes after def.end)
        let straddle_end = m("src/lib.rs", 190, 210);
        let kept = filter_matches_by_defs(vec![before, after, straddle_start, straddle_end], &defs);
        assert!(kept.is_empty(), "no match strictly inside; got {kept:?}");
    }

    #[test]
    fn resolve_and_filter_drops_match_in_different_file() {
        let defs = vec![def("foo", "src/lib.rs", 100, 200)];
        // byte range would be "inside" if file matched, but file differs
        let matches = vec![m("src/other.rs", 110, 120)];
        let kept = filter_matches_by_defs(matches, &defs);
        assert!(kept.is_empty(), "cross-file match must be dropped");
    }

    #[test]
    fn resolve_and_filter_excludes_match_at_closing_brace() {
        // The doc comment in the plan: "match.end_byte == def.end_byte
        // should be allowed; match.end_byte > def.end_byte excluded".
        let defs = vec![def("foo", "src/lib.rs", 100, 200)];
        // Exactly coincident with the def's closing edge — kept.
        let edge_inclusive = m("src/lib.rs", 195, 200);
        // One byte past the closing edge — excluded.
        let edge_protruding = m("src/lib.rs", 195, 201);
        let kept = filter_matches_by_defs(vec![edge_inclusive, edge_protruding], &defs);
        assert_eq!(kept.len(), 1, "coincident edge kept, protruding dropped");
        assert_eq!(kept[0].end_byte, 200);
    }

    #[test]
    fn filter_unions_multiple_defs() {
        // Two defs in different files; matches in each kept; match
        // in a third file dropped.
        let defs = vec![
            def("foo", "src/a.rs", 100, 200),
            def("foo", "src/b.rs", 300, 400),
        ];
        let matches = vec![
            m("src/a.rs", 150, 160), // inside def #1
            m("src/b.rs", 350, 360), // inside def #2
            m("src/c.rs", 100, 200), // wrong file
            m("src/a.rs", 250, 260), // right file, outside def
        ];
        let kept = filter_matches_by_defs(matches, &defs);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().any(|m| m.file == "src/a.rs"));
        assert!(kept.iter().any(|m| m.file == "src/b.rs"));
    }

    #[test]
    fn filter_match_inside_one_of_overloaded_defs_in_same_file() {
        // Same name, two defs in one file (e.g. two `impl` blocks
        // implementing a method named `new`).
        let defs = vec![
            def("new", "src/lib.rs", 100, 200),
            def("new", "src/lib.rs", 500, 600),
        ];
        let matches = vec![
            m("src/lib.rs", 150, 160), // inside def #1
            m("src/lib.rs", 550, 560), // inside def #2
            m("src/lib.rs", 300, 310), // between defs — dropped
        ];
        let kept = filter_matches_by_defs(matches, &defs);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn filter_match_exactly_coincident_with_def() {
        // Match start == def start AND match end == def end — kept
        // (strict containment is `>=` and `<=`).
        let defs = vec![def("foo", "src/lib.rs", 100, 200)];
        let matches = vec![m("src/lib.rs", 100, 200)];
        let kept = filter_matches_by_defs(matches, &defs);
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn filter_empty_matches_returns_empty() {
        let defs = vec![def("foo", "src/lib.rs", 100, 200)];
        let kept = filter_matches_by_defs(Vec::new(), &defs);
        assert!(kept.is_empty());
    }

    #[test]
    fn filter_empty_defs_drops_everything() {
        // If somehow `filter_matches_by_defs` is called with no defs
        // (shouldn't happen via `resolve_and_filter` — zero defs is
        // a hard error there — but the pure half must still be
        // safe), every match is dropped.
        let kept = filter_matches_by_defs(vec![m("src/lib.rs", 1, 2)], &[]);
        assert!(kept.is_empty());
    }

    // ----- cardinality cap (resolve_and_filter, exercising the
    // policy logic against a hand-rolled defs vec). The store-touching
    // half (zero-def lookup, real find_symbol) is covered by the
    // integration test. Here we drive the cap policy through a
    // separate helper that mirrors resolve_and_filter's classification
    // but skips the store call so we can unit-test 16 vs 17 defs
    // without seeding a real workspace.
    //
    // The helper below is the same code path resolve_and_filter
    // takes once it has `defs` in hand.

    fn classify_and_filter(
        defs: Vec<FoundSymbol>,
        allow_overload: bool,
        matches: Vec<MatchRange>,
    ) -> Result<Vec<MatchRange>, GrepValidationError> {
        if defs.is_empty() {
            return Err(GrepValidationError::new(
                GrepValidationCode::WithinSymbolNotFound,
                "no defs",
            ));
        }
        if defs.len() > WITHIN_SYMBOL_MAX_DEFS && !allow_overload {
            return Err(GrepValidationError::new(
                GrepValidationCode::WithinSymbolTooManyDefs,
                format!("{} defs", defs.len()),
            )
            .with_data(
                "def_count",
                serde_json::Value::Number(serde_json::Number::from(defs.len())),
            ));
        }
        Ok(filter_matches_by_defs(matches, &defs))
    }

    #[test]
    fn resolve_and_filter_returns_not_found_when_no_defs() {
        let err = classify_and_filter(Vec::new(), false, vec![m("src/lib.rs", 1, 2)]).unwrap_err();
        assert_eq!(err.code, GrepValidationCode::WithinSymbolNotFound);
    }

    #[test]
    fn resolve_and_filter_returns_too_many_defs_without_opt_in() {
        // 17 defs, no opt-in → reject with def_count: 17.
        let defs: Vec<FoundSymbol> = (0..17)
            .map(|i| def("new", "src/lib.rs", i * 100, i * 100 + 50))
            .collect();
        let err = classify_and_filter(defs, false, vec![m("src/lib.rs", 1, 2)]).unwrap_err();
        assert_eq!(err.code, GrepValidationCode::WithinSymbolTooManyDefs);
        assert_eq!(
            err.data.get("def_count"),
            Some(&serde_json::Value::Number(serde_json::Number::from(17))),
            "expected def_count in data; got {:?}",
            err.data
        );
    }

    #[test]
    fn resolve_and_filter_allows_overload_when_opt_in() {
        // 17 defs WITH opt-in → no error; matches filtered by union.
        let defs: Vec<FoundSymbol> = (0..17)
            .map(|i| def("new", "src/lib.rs", i * 100, i * 100 + 50))
            .collect();
        // Match inside def #5's range.
        let matches = vec![m("src/lib.rs", 510, 540), m("src/lib.rs", 9999, 10000)];
        let kept = classify_and_filter(defs, true, matches).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].start_byte, 510);
    }

    #[test]
    fn resolve_and_filter_exactly_at_cap_is_accepted_without_opt_in() {
        // Exactly WITHIN_SYMBOL_MAX_DEFS defs (16) → no error.
        let defs: Vec<FoundSymbol> = (0..WITHIN_SYMBOL_MAX_DEFS as u32)
            .map(|i| def("new", "src/lib.rs", i * 100, i * 100 + 50))
            .collect();
        let kept = classify_and_filter(defs, false, Vec::new()).unwrap();
        assert!(kept.is_empty());
    }

    #[test]
    fn too_many_defs_error_renders_with_code_and_def_count() {
        // Spot-check the wire envelope: code + def_count both present.
        let defs: Vec<FoundSymbol> = (0..20)
            .map(|i| def("new", "src/lib.rs", i * 100, i * 100 + 50))
            .collect();
        let err = classify_and_filter(defs, false, Vec::new()).unwrap_err();
        let proto = err.into_protocol_error();
        let data = proto.data.expect("data envelope present");
        assert_eq!(
            data.pointer("/code"),
            Some(&serde_json::Value::String(
                "WITHIN_SYMBOL_TOO_MANY_DEFS".into()
            ))
        );
        assert_eq!(
            data.pointer("/def_count"),
            Some(&serde_json::Value::Number(serde_json::Number::from(20)))
        );
    }
}
