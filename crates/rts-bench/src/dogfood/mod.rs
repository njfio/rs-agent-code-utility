//! Self-dogfood telemetry harness — `rts-bench dogfood`.
//!
//! Ingests a Claude Code session JSONL transcript and reports how
//! often the agent reached for `Bash(grep|rg|find|cat|ls)` when an
//! `mcp__rts__*` tool would have been a better fit. The goal is to
//! close the evidence loop on PR #121 (the tool-description audit):
//! without a way to count tool-selection outcomes, "did the audit
//! help?" stays a vibe rather than a number.
//!
//! Scope:
//! - **Client-side only.** Reads JSONL files already on disk under
//!   `~/.claude/projects/<encoded-cwd>/<uuid>.jsonl`. No network. No
//!   daemon counters. No opt-in pings — that's PR #115's surface.
//! - **Manual, post-hoc analysis.** Not wired into CI; the maintainer
//!   runs the harness on their own sessions.
//! - **Tool SELECTION, not performance.** Counts which tool an agent
//!   chose; does NOT claim rts would have been faster.
//!
//! Heuristic, by design — false positives are fine. The framing is
//! "candidate fall-throughs" (calls that *could* have used rts), not
//! "definitive wrong-tool" claims. The classifier in `classify.rs`
//! documents each pattern it catches and each it deliberately doesn't.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

mod classify;
mod parse;

pub use classify::{BashCandidate, classify_bash_command};
pub use parse::{ToolUseEvent, parse_session};

/// Output format for `rts-bench dogfood`. Mirrors
/// `real_repos::ReportFormat` so the surface looks consistent.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum ReportFormat {
    /// Pretty JSON. Stable shape (`schema_version: "dogfood-v0"`) for
    /// post-hoc analysis pipelines.
    Json,
    /// Human-readable terminal output with section headings.
    Text,
}

/// Top-level dogfood report. Wire-stable; the `schema_version` field
/// pins the JSON shape so downstream consumers can detect upgrades.
#[derive(Debug, Clone, Serialize)]
pub struct DogfoodReport {
    pub schema_version: &'static str,
    pub session_path: String,
    /// Wall-clock span between first and last event with a parseable
    /// timestamp. `None` when fewer than 2 timestamps are recoverable.
    pub duration_ms: Option<u64>,
    pub total_tool_calls: u64,
    /// Map: tool name (or `mcp__rts__*` aggregate) → call count.
    /// `IndexMap`-ordered isn't worth the dep here; `BTreeMap` gives
    /// deterministic JSON without extra noise.
    pub by_source: std::collections::BTreeMap<String, u64>,
    /// Count of `Bash` calls that could have used an rts tool, broken
    /// out by category. Filtered by `rts_mounted_only` when set.
    pub bash_candidate_fallthroughs: FallthroughCounts,
    /// rts wins ÷ (rts wins + candidate Bash fall-throughs).
    /// `None` when the denominator is zero (no rts use + no Bash
    /// candidates → no signal).
    pub rts_vs_bash_ratio_in_navigation_contexts: Option<f64>,
    /// Per-candidate detail, capped at `MAX_CANDIDATE_DETAIL` to keep
    /// the JSON bounded. Each entry carries the original command for
    /// triage.
    pub candidate_bash_commands: Vec<CandidateDetail>,
    /// Whether the `--rts-mounted-only` filter dropped any calls.
    pub rts_mounted_only: bool,
    pub events_dropped_filter: u64,
}

/// Per-category Bash fall-through counts. Mirrors the four classifier
/// categories one-for-one so JSON consumers can index by name without
/// regex.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FallthroughCounts {
    pub grep_or_rg: u64,
    pub find: u64,
    pub cat_file: u64,
    pub ls_workspace: u64,
    pub total: u64,
}

/// One entry per classified Bash call. Captured in order of
/// appearance in the JSONL.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateDetail {
    /// ISO-8601 timestamp from the JSONL line, when present.
    pub ts: Option<String>,
    pub command: String,
    /// `"mcp__rts__grep"`, `"mcp__rts__find_symbol"`, etc.
    pub would_prefer: &'static str,
}

/// Cap on `candidate_bash_commands` length. The aggregate counts in
/// `bash_candidate_fallthroughs` are NOT capped — only the per-call
/// detail vector. 500 entries is enough for a multi-hour session
/// without blowing JSON size; the maintainer who needs more can
/// re-run with the parser directly.
pub const MAX_CANDIDATE_DETAIL: usize = 500;

/// Schema-version constant for `DogfoodReport.schema_version`. Bumped
/// on wire-shape changes; reserialize current shape unchanged.
pub const SCHEMA_VERSION: &str = "dogfood-v0";

/// Arguments shared across `analyze_path` and `analyze_reader`.
#[derive(Debug, Clone, Copy)]
pub struct AnalyzeOpts {
    /// When true, restrict candidate counting to intervals where rts
    /// appears to be mounted. See `is_session_rts_mounted`. Default
    /// behavior at the CLI layer is `true`; set `false` here to count
    /// every `Bash` call regardless of session context.
    pub rts_mounted_only: bool,
}

impl Default for AnalyzeOpts {
    fn default() -> Self {
        Self {
            rts_mounted_only: true,
        }
    }
}

/// Read a session JSONL file from disk and return a `DogfoodReport`.
/// The path is recorded verbatim in `report.session_path` (no
/// canonicalization — callers may want the path shape they typed).
pub fn analyze_path(path: &Path, opts: AnalyzeOpts) -> Result<DogfoodReport> {
    let file =
        std::fs::File::open(path).with_context(|| format!("opening session JSONL: {path:?}"))?;
    let reader = BufReader::new(file);
    analyze_reader(reader, path.display().to_string(), opts)
}

/// Read a session JSONL from any `BufRead`. Used by stdin (`-`) and
/// by the in-test fixture path. The `session_path_label` is what gets
/// written into the report for display — typically a path string,
/// but `<stdin>` for the stdin case.
pub fn analyze_reader<R: BufRead>(
    reader: R,
    session_path_label: String,
    opts: AnalyzeOpts,
) -> Result<DogfoodReport> {
    let events = parse_session(reader)?;
    Ok(build_report(events, session_path_label, opts))
}

/// Roll up a parsed event stream into a `DogfoodReport`. Pure
/// function so tests can construct synthetic event lists without
/// touching the parser.
pub fn build_report(
    events: Vec<ToolUseEvent>,
    session_path_label: String,
    opts: AnalyzeOpts,
) -> DogfoodReport {
    // First pass: detect whether this session has ever exhibited an
    // rts mount signal. `--rts-mounted-only` is a session-level
    // filter today; we don't try to bracket "rts was mounted between
    // event N and M" because the JSONL doesn't reliably carry
    // unmount events (Claude Code doesn't emit a `Workspace.Unmount`
    // tool_result line on session end). Future work if needed.
    let rts_mounted = is_session_rts_mounted(&events);
    let filter_active = opts.rts_mounted_only && !rts_mounted;

    let mut total_tool_calls: u64 = 0;
    let mut by_source: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut counts = FallthroughCounts::default();
    let mut details: Vec<CandidateDetail> = Vec::new();
    let mut rts_call_count: u64 = 0;
    let mut events_dropped_filter: u64 = 0;

    for evt in &events {
        total_tool_calls += 1;
        let bucket = bucket_for(&evt.name);
        *by_source.entry(bucket.to_string()).or_insert(0) += 1;

        if evt.name.starts_with("mcp__rts__") {
            rts_call_count += 1;
        }

        if filter_active {
            // Skip Bash classification entirely when the user asked
            // to filter to rts-mounted sessions and we can't confirm
            // rts was ever mounted. Still counted in totals — the
            // surface is "here's a session; rts wasn't mounted, so
            // no candidates" rather than "session is empty".
            if evt.name == "Bash" {
                events_dropped_filter += 1;
            }
            continue;
        }

        if evt.name != "Bash" {
            continue;
        }
        let Some(command) = evt.command() else {
            continue;
        };

        if let Some(cand) = classify_bash_command(command) {
            match cand {
                BashCandidate::GrepOrRg => counts.grep_or_rg += 1,
                BashCandidate::Find => counts.find += 1,
                BashCandidate::CatFile => counts.cat_file += 1,
                BashCandidate::LsWorkspace => counts.ls_workspace += 1,
            }
            counts.total += 1;
            if details.len() < MAX_CANDIDATE_DETAIL {
                details.push(CandidateDetail {
                    ts: evt.timestamp.clone(),
                    command: command.to_string(),
                    would_prefer: cand.would_prefer(),
                });
            }
        }
    }

    let ratio = {
        let denom = rts_call_count + counts.total;
        if denom == 0 {
            None
        } else {
            Some((rts_call_count as f64) / (denom as f64))
        }
    };

    DogfoodReport {
        schema_version: SCHEMA_VERSION,
        session_path: session_path_label,
        duration_ms: duration_ms(&events),
        total_tool_calls,
        by_source,
        bash_candidate_fallthroughs: counts,
        rts_vs_bash_ratio_in_navigation_contexts: ratio,
        candidate_bash_commands: details,
        rts_mounted_only: opts.rts_mounted_only,
        events_dropped_filter,
    }
}

/// Group tools into a small set of buckets so the `by_source` table
/// stays legible. The aggregate `mcp__rts__*` bucket is the one the
/// harness actually cares about; everything else is identity-mapped
/// to the tool name so unfamiliar surfaces (e.g. `mcp__muonry__edit`)
/// still appear distinctly in the report.
fn bucket_for(tool_name: &str) -> &str {
    if let Some(_rest) = tool_name.strip_prefix("mcp__rts__") {
        "mcp__rts__*"
    } else {
        tool_name
    }
}

/// Decide whether rts was ever mounted in this session.
///
/// Two signals, any one is sufficient:
/// 1. An `mcp__rts__*` tool_use appears anywhere in the transcript
///    (the agent could only call those if rts was loaded).
/// 2. The session's `cwd` (when present) points at a directory whose
///    parent layout looks like an rts-indexable workspace AND a
///    `Workspace.Mount`-shaped MCP call appears. Today only signal
///    (1) is exercised — signal (2) is documented for the case where
///    we later want to detect "rts was AVAILABLE but unused", but
///    that's a different question.
///
/// Returns true when we have positive evidence of rts mount activity.
/// On uncertainty (e.g. tiny session, no MCP traffic at all), returns
/// false; the caller decides what `--rts-mounted-only` means in that
/// gray zone (we treat it as "filter active" so the user gets the
/// conservative interpretation).
fn is_session_rts_mounted(events: &[ToolUseEvent]) -> bool {
    events.iter().any(|e| e.name.starts_with("mcp__rts__"))
}

/// Span between the earliest and latest event timestamp. None when
/// fewer than two timestamps parse.
fn duration_ms(events: &[ToolUseEvent]) -> Option<u64> {
    let mut min: Option<i64> = None;
    let mut max: Option<i64> = None;
    for e in events {
        let Some(ts) = e.timestamp.as_deref() else {
            continue;
        };
        let Some(ms) = parse_iso8601_to_ms(ts) else {
            continue;
        };
        min = Some(min.map_or(ms, |m| m.min(ms)));
        max = Some(max.map_or(ms, |m| m.max(ms)));
    }
    match (min, max) {
        (Some(lo), Some(hi)) if hi >= lo => Some((hi - lo) as u64),
        _ => None,
    }
}

/// Parse an ISO-8601 UTC timestamp like `"2026-05-19T14:32:11.123Z"`
/// into epoch milliseconds. Hand-rolled rather than pulling in
/// `chrono`/`time` because the format is fixed (Claude Code always
/// emits UTC with `Z` and millisecond precision) and the cost of a
/// 200KB dep for one timestamp shape isn't justified per Rule 2.
///
/// Returns `None` on any parse failure — callers degrade to
/// `duration_ms = None` rather than failing the whole report.
fn parse_iso8601_to_ms(s: &str) -> Option<i64> {
    // Expected shape: YYYY-MM-DDTHH:MM:SS[.fff]Z
    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let year: i32 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;

    // Optional fractional seconds. Strip "Z" if present.
    let (frac_ms, _tail) = if let Some(dot_pos) = s[19..].find('.') {
        let rest = &s[19 + dot_pos + 1..];
        let z_pos = rest.find('Z').unwrap_or(rest.len());
        let frac = &rest[..z_pos];
        // Take up to 3 digits as ms; pad/truncate as needed.
        let mut ms = 0i64;
        for (i, c) in frac.chars().enumerate() {
            if i >= 3 {
                break;
            }
            let d = c.to_digit(10)? as i64;
            ms = ms * 10 + d;
        }
        for _ in frac.chars().take(3).count()..3 {
            ms *= 10;
        }
        (ms, &rest[z_pos..])
    } else {
        (0, &s[19..])
    };

    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    Some(secs * 1_000 + frac_ms)
}

/// Howard Hinnant's days_from_civil; converts (Y, M, D) Gregorian to
/// days since 1970-01-01. Public-domain algorithm.
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400) as i64;
    let yoe = y.rem_euclid(400) as i64;
    let m = m as i64;
    let d = d as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Render a `DogfoodReport` as JSON (pretty-printed). The serde
/// derive gives byte-stable ordering for `BTreeMap`s; field order
/// within structs follows source-declaration order.
pub fn render_json(report: &DogfoodReport) -> Result<String> {
    serde_json::to_string_pretty(report).context("serializing dogfood report")
}

/// Render a `DogfoodReport` as the human-readable terminal output
/// described in the plan. Keeps section headings stable so smoke
/// tests can pattern-match them.
pub fn render_text(report: &DogfoodReport) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "Session: {}", report.session_path);
    if let Some(ms) = report.duration_ms {
        let _ = writeln!(out, "Duration: {}", fmt_duration(ms));
    } else {
        let _ = writeln!(out, "Duration: (insufficient timestamps)");
    }
    let _ = writeln!(out, "Tool calls: {} total", report.total_tool_calls);
    let _ = writeln!(out);

    let _ = writeln!(out, "By tool source:");
    // Sort by descending count, then name asc, so the most-used tools
    // surface first. Stable order makes diffing two reports tractable.
    let mut pairs: Vec<(&String, &u64)> = report.by_source.iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let total = report.total_tool_calls.max(1) as f64;
    for (name, count) in pairs {
        let pct = (*count as f64) / total * 100.0;
        let _ = writeln!(out, "  {:<24} {:>5}  ({:>5.1}%)", name, count, pct);
    }
    let _ = writeln!(out);

    let counts = &report.bash_candidate_fallthroughs;
    if report.rts_mounted_only && report.events_dropped_filter > 0 && counts.total == 0 {
        let _ = writeln!(
            out,
            "Bash calls that may have preferred rts: (skipped — \
             rts mount not detected; {} Bash call(s) not classified, \
             pass --no-rts-mounted-only to score regardless)",
            report.events_dropped_filter,
        );
    } else {
        let _ = writeln!(
            out,
            "Bash calls that may have preferred rts (counted within rts-mounted intervals):"
        );
        let _ = writeln!(out, "  grep / rg     : {} calls", counts.grep_or_rg);
        let _ = writeln!(out, "  find          : {} calls", counts.find);
        let _ = writeln!(
            out,
            "  cat (file)    : {} calls   (Read tool would have been better even ignoring rts)",
            counts.cat_file
        );
        let _ = writeln!(out, "  ls (workspace): {} calls", counts.ls_workspace);
        let _ = writeln!(out, "  Total candidate fall-throughs: {}", counts.total);
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "Rts-vs-Bash ratio in code-navigation contexts:");
    let rts_calls = report.by_source.get("mcp__rts__*").copied().unwrap_or(0);
    match report.rts_vs_bash_ratio_in_navigation_contexts {
        Some(r) => {
            let _ = writeln!(
                out,
                "  rts wins: {} / ({} + {}) = {:.1}%",
                rts_calls,
                rts_calls,
                counts.total,
                r * 100.0,
            );
        }
        None => {
            let _ = writeln!(out, "  rts wins: 0 / 0 (no signal in this session)");
        }
    }
    out
}

fn fmt_duration(ms: u64) -> String {
    let secs = ms / 1000;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// CLI args, parsed in `main.rs` and threaded here. Kept as a
/// separate struct so the dispatcher doesn't have to inline the
/// parameter list (matches the `doctor::DoctorArgs` pattern).
#[derive(Debug)]
pub struct DogfoodArgs {
    /// Path to the session JSONL, or `-` for stdin.
    pub session: PathBuf,
    pub report: ReportFormat,
    pub rts_mounted_only: bool,
}

/// Entry point invoked from `main.rs`'s dispatcher. Reads the
/// transcript, builds the report, prints it in the requested format,
/// and returns success. Exits with a non-zero anyhow error on parse
/// failure (the JSONL is malformed or the file is unreadable).
pub fn run(args: DogfoodArgs) -> Result<()> {
    let opts = AnalyzeOpts {
        rts_mounted_only: args.rts_mounted_only,
    };
    let report = if args.session.as_os_str() == "-" {
        let stdin = std::io::stdin();
        let lock = stdin.lock();
        analyze_reader(lock, "<stdin>".to_string(), opts)?
    } else {
        analyze_path(&args.session, opts)?
    };

    match args.report {
        ReportFormat::Json => {
            println!("{}", render_json(&report)?);
        }
        ReportFormat::Text => {
            print!("{}", render_text(&report));
        }
    }
    Ok(())
}
