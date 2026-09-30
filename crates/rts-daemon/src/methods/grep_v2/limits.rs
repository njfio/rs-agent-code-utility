//! Resource budgets for the structural query execution path.
//!
//! These constants are the binding numeric contract called out in the
//! `docs/plans/2026-05-18-002-feat-index-grep-v2-plan.md` "Resource
//! budgets" subsection. Copying them verbatim into the runtime keeps
//! the plan and the implementation in one place; if a number changes,
//! grep both modules and the docs at once.
//!
//! ## Why these numbers
//!
//! * `STRUCTURAL_WALL_CLOCK_MS = 5_000` — agents tolerate ~5s pauses
//!   before they retry/abandon; this matches the `Index.FindCallers`
//!   p99 ceiling and the broader "interactive" budget the daemon
//!   commits to.
//! * `STRUCTURAL_MAX_ROWS = 4_096` — mirrors the existing
//!   `MAX_LIMIT` for literal/regex grep so callers don't need a
//!   different mental model for the structural path.
//! * `STRUCTURAL_MAX_CAPTURE_BYTES = 8 KiB` — long enough to cover
//!   a full mid-size function body's signature/comment but short
//!   enough that ten captures per match still fits in the JSON
//!   envelope's 1 MiB soft ceiling.
//! * `STRUCTURAL_MAX_CAPTURES_PER_MATCH = 64` — guards against
//!   pathological queries that capture every token; 64 covers every
//!   non-pathological tags.scm-style query we ship.
//! * `PREDICATE_REGEX_DFA_LIMIT = 256 KiB` — the regex crate's
//!   `dfa_size_limit` knob. Catastrophic patterns like
//!   `(.*a){50}` exceed this immediately; well-formed patterns
//!   stay well under.
//! * `QUERY_CACHE_CAPACITY = 64` — the LRU's bound. 64 is more
//!   than the number of distinct structural queries a single agent
//!   session has been observed to issue (the dogfood traces top out
//!   at ~12 unique queries per workspace per session); evictions
//!   should be rare.

/// Maximum wall-clock time, in milliseconds, that a single
/// `Index.Grep` structural call may spend across all in-scope files.
/// The budget is checked at file boundaries, not mid-file — a single
/// pathological file can overshoot by its own parse time, but the
/// per-file cost is bounded by `MAX_FILE_BYTES` upstream.
pub const STRUCTURAL_WALL_CLOCK_MS: u64 = 5_000;

/// Hard cap on returned match rows. Matches the v1 literal/regex
/// `MAX_LIMIT` so callers see a consistent "agent context budget".
pub const STRUCTURAL_MAX_ROWS: usize = 4_096;

/// Per-capture text truncation cap (bytes). Captures whose text
/// exceeds this are truncated and the capture object gains
/// `"truncated": true`.
pub const STRUCTURAL_MAX_CAPTURE_BYTES: usize = 8 * 1024;

/// Maximum number of captures attached to a single match record.
/// Captures beyond this are dropped (with `truncated: true` set on
/// the response envelope).
pub const STRUCTURAL_MAX_CAPTURES_PER_MATCH: usize = 64;

/// Per-`#match?` / `#not-match?` predicate regex DFA size limit
/// (bytes). Compile-tested at predicate-whitelist time; over-limit
/// patterns are rejected as `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`.
pub const PREDICATE_REGEX_DFA_LIMIT: usize = 256 * 1024;

/// Capacity of the per-daemon compiled-`Query` LRU. Keyed on
/// `(Language, query_text)`; eviction is recency-ordered.
pub const QUERY_CACHE_CAPACITY: usize = 64;

/// Default RESPONSE budget when `params.limit` is unset for the RANKED
/// text path (literal / regex): how many ranked matches a bare grep
/// returns. The handler still collects a larger ranking pool
/// (`RANK_POOL` in the grep handler) to rank FROM, so the top-40 is
/// drawn from a real candidate population rather than the first 40 in
/// scan order.
///
/// Single source of truth — referenced from both the compose validator
/// (as `u32`) and the grep handler (cast `as usize`).
pub(crate) const GREP_DEFAULT_BUDGET: u32 = 40;
