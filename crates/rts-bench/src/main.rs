//! `rts-bench` — only operator-facing surface in the v0.2 stack.
//!
//! ```text
//! rts-bench task run <id> --workspace PATH --symbol NAME [--out FILE]
//! rts-bench task list
//! rts-bench fixture restore --corpus-lock PATH [--corpus-root DIR]
//! ```
//!
//! v0 wires task `locate_def` end-to-end; the other four tasks are
//! scaffolded but return `NotImplemented`. `fixture restore` validates a
//! corpus.lock today; the download step lands when there's a real corpus
//! to point at.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;

mod baseline;
mod corpus;
mod doctor;
mod dogfood;
mod footprint;
mod footprint_helpers;
mod latency;
mod mcp_runner;
mod real_repos;
mod report;
mod semantic;
mod tasks;
mod token;
mod verify_metrics;

use mcp_runner::resolve_bin;
use report::BenchReport;
use tasks::{TaskContext, TaskOutcome, run_task};

#[derive(Parser, Debug)]
#[command(
    name = "rts-bench",
    version, // clap reads CARGO_PKG_VERSION; wires up `--version`/`-V`
    about = "Bench harness for the rts-mcp stack"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Task subcommands — run or list the §P9 baseline tasks.
    Task {
        #[command(subcommand)]
        sub: TaskCmd,
    },
    /// Fixture-corpus subcommands — restore tarballs into `corpus/`.
    Fixture {
        #[command(subcommand)]
        sub: FixtureCmd,
    },
    /// Latency benchmark (S1): synth fixture + p50/p95/p99 over a
    /// query mix.
    Latency {
        /// Real workspace path to bench against. Mutually exclusive
        /// with `--synth-loc`. The bench mounts this workspace, waits
        /// for the cold-walk to settle, then enumerates indexable
        /// symbols via `find_symbol(pattern="*")` (top-N by rank,
        /// capped at the daemon's MAX_MATCHES = 256). Use this when
        /// the synth fixture's tiny function bodies aren't
        /// representative of the real workload — closure-walker p95
        /// is the canonical case: alpha.30's body-parse cost grows
        /// linearly in body size while v0.3's stays constant, so the
        /// structural win shows on real Rust function lengths (20–50
        /// lines) but vanishes on the synth's 3-line bodies. Required
        /// for the G5 spec ("real Rust workspace") per the v0.3 plan.
        #[arg(long, conflicts_with = "synth_loc")]
        workspace: Option<PathBuf>,
        /// Total lines of synthetic Rust source to generate. Defaults
        /// to 100,000 per plan §P9. Mutually exclusive with
        /// `--workspace`.
        #[arg(long, default_value_t = 100_000)]
        synth_loc: usize,
        /// Number of queries to run. Defaults to 1000.
        #[arg(long, default_value_t = 1000)]
        queries: u32,
        /// Cold-warm split — first N queries treated as cold-cache
        /// warmup. Defaults to 100.
        #[arg(long, default_value_t = 100)]
        cold_count: u32,
        /// PRNG seed for query selection. Stable runs use the same
        /// seed.
        #[arg(long, default_value_t = 0xC0FFEE_u64)]
        seed: u64,
        /// Exercise the v0.3 U3 closure walker in the 30% read_symbol
        /// bucket — sends `shape=body, include_dependencies=true`
        /// instead of `shape=signature`. Required for the G5 spec
        /// (closure-walker p95 ≥ 50 % faster than alpha.30); off by
        /// default to preserve historical mix.
        #[arg(long)]
        deps: bool,
        /// Where to write the JSON report.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Skip writing the report.
        #[arg(long)]
        dry_run: bool,
    },
    /// Footprint benchmark (S3): build time, peak RSS, on-disk index
    /// size on a synthetic workspace. Companion to `latency` for the
    /// "is this production-ready?" question.
    Footprint {
        /// Total lines of synthetic Rust source to generate. Defaults
        /// to 100,000 per plan §P9.
        #[arg(long, default_value_t = footprint::DEFAULT_TARGET_LOC)]
        synth_loc: usize,
        /// Where to write the JSON report.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Skip writing the report.
        #[arg(long)]
        dry_run: bool,
    },
    /// One-shot daemon queries from the shell. Spawns rts-mcp + the
    /// daemon, runs the requested tool, prints the JSON response to
    /// stdout, exits. Useful for: dogfooding the daemon from Bash
    /// pipelines, `jq`-driven scripts, or any non-MCP-aware caller
    /// (including this very Claude Code session, which can't easily
    /// re-configure its MCP server list mid-conversation).
    Query {
        /// Output format. `json` (default) prints the daemon's full
        /// response. `lines` prints rg-shaped `path:line:content` so
        /// queries compose into bash pipelines (`| head`, `| sort`,
        /// `| xargs sed -i`). Lines mode is the v0.5.6+ answer to
        /// "why does the agent always reach for grep instead of
        /// `query grep`" — it strips the JSON-skim friction without
        /// losing the AST-precise data the daemon returns. Available
        /// for `find-symbol`, `find-callers`, `grep`, `impact-of`,
        /// `outline`. Other subcommands ignore this flag.
        #[arg(long, value_enum, default_value_t = QueryOutput::Json, global = true)]
        output: QueryOutput,
        #[command(subcommand)]
        sub: QueryCmd,
    },
    /// Semantic-search evaluation harness. Runs a TOML corpus of
    /// labelled queries against a workspace, reports precision@10 +
    /// MRR + coverage of a graph-only baseline ranker. The deliverable
    /// is a measurable comparison point for ANY future ranker
    /// (embedding-based, LLM-routed, hybrid) — without this, every
    /// claim about "semantic search would help" is speculation.
    ///
    /// Corpus format: see `corpus/semantic-eval-rts-core.toml` for an
    /// example. Each query has `text` (the natural-language query)
    /// and `expected_top_k` (hand-graded list of symbol names that
    /// should appear in the top-K results).
    /// Read-only first-run health check. Inspects rts install state
    /// (binary version, daemon reachability, MCP registration in 5
    /// agent hosts, hook file presence) and per-workspace index state
    /// (daemon PID, pinned-workspace path, index generation, cold-walk
    /// completion). Prints an OK/WARN/FAIL checklist with copy-pasteable
    /// fix snippets for every failing row.
    ///
    /// Exit codes are a documented public API:
    /// - 0 — no FAIL rows (any WARN allowed)
    /// - 1 — at least one FAIL row
    /// - 2 — doctor itself failed (panic, unreadable own binary)
    ///
    /// Plan: docs/plans/2026-05-18-001-feat-rts-bench-doctor-plan.md
    Doctor {
        /// Output format. `human` (default) renders a checklist with
        /// inline fix snippets and ANSI when stdout is a TTY and
        /// `NO_COLOR` is unset. `json` produces a machine-readable
        /// document with `schema_version: "doctor-v0"` for agent
        /// consumption (e.g. agent-bench preflight).
        #[arg(long, value_enum, default_value_t = doctor::DoctorOutput::Human)]
        output: doctor::DoctorOutput,
        /// Disable ANSI color even on a TTY. `NO_COLOR=1` env var has
        /// the same effect.
        #[arg(long)]
        no_color: bool,
        /// Workspace path to inspect. Defaults to the current directory.
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// Real-repo CI fixture (v1): clone tokio/flask/gin at pinned
    /// refs, index each, capture core metrics, compare against the
    /// committed baseline. See `docs/plans/` for the rationale —
    /// surfaces latent extractor bugs and cancel-test flakes that
    /// synthetic fixtures historically missed.
    ///
    /// Subcommands:
    ///   run      — clone + index + emit JSON report to stdout
    ///   baseline — same as `run`, but write the report to --baseline
    ///   compare  — read --baseline + run fresh; exit 1 on regression
    RealRepos {
        #[command(subcommand)]
        sub: RealReposCmd,
    },
    Semantic {
        /// Path to a TOML corpus file.
        #[arg(long)]
        corpus: PathBuf,
        /// Workspace to evaluate against. Must be canonicalized;
        /// the bench mounts it and runs the baseline ranker against
        /// the live daemon index.
        #[arg(long)]
        workspace: PathBuf,
        /// Top-K cutoff for precision scoring. Default 10.
        #[arg(long, default_value_t = 10)]
        top_k: usize,
        /// Where to write the JSON report.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Skip writing the report.
        #[arg(long)]
        dry_run: bool,
        /// Regression guard: fail the process with exit code 2 if
        /// `answerable_coverage` falls below this threshold (e.g.
        /// `0.90` for 90%). Use in CI to catch ranker regressions.
        /// Default: no check, exits 0 regardless of metrics.
        #[arg(long)]
        check_coverage: Option<f64>,
    },
    /// Hallucination-metric harness (verify-v0 P1.U5). Parses a corpus of
    /// agent-emitted code snippets with rts's own tree-sitter extractor
    /// (F3), checks every referenced symbol / import / call-arity against
    /// the live index via the verify tools, and reports SHR / IHR / SMR
    /// with honest denominators (indeterminate references excluded from
    /// every rate, counted separately). No LLM in the loop — the metric is
    /// fully deterministic.
    ///
    /// Corpus format: see `corpus/verify-eval-rts-core.toml`. Each
    /// `[[snippet]]` carries `lang` + `code`.
    Verify {
        /// Path to a TOML verify-eval corpus file.
        #[arg(long)]
        corpus: PathBuf,
        /// Workspace to check references against. Mounted + indexed via
        /// the same rts-mcp + daemon path the other benches use.
        #[arg(long)]
        workspace: PathBuf,
        /// Where to write the JSON `HallucinationReport`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Skip writing the report to disk (it's still printed to stdout).
        #[arg(long)]
        dry_run: bool,
    },
    /// Self-dogfood telemetry harness. Ingests a Claude Code session
    /// JSONL transcript and reports how often the agent reached for
    /// `Bash(grep|rg|find|cat|ls)` when an `mcp__rts__*` tool would
    /// have served the same intent. Closes the evidence loop on
    /// PR #121's tool-description audit: lets the maintainer measure
    /// whether discoverability changes actually move the rts-vs-Bash
    /// ratio in real sessions, instead of relying on vibes. Client-
    /// side only — reads JSONL files already on disk; no daemon
    /// counters; no opt-in telemetry pipeline (that's PR #115).
    Dogfood {
        /// Path to the Claude Code session JSONL (typically
        /// `~/.claude/projects/<encoded-cwd>/<uuid>.jsonl`), or `-`
        /// to read from stdin.
        session: PathBuf,
        /// Output format. `text` (default) renders a human checklist
        /// with section headings the smoke tests pattern-match on;
        /// `json` emits a schema-pinned report
        /// (`schema_version: "dogfood-v0"`) for post-hoc pipelines.
        #[arg(long, value_enum, default_value_t = dogfood::ReportFormat::Text)]
        report: dogfood::ReportFormat,
        /// Restrict candidate counting to sessions where rts appears
        /// mounted (a `mcp__rts__*` tool_use appeared anywhere in the
        /// transcript). Default: true — the "did the audit help?"
        /// question is only meaningful when rts was actually available.
        /// Pass `--rts-mounted-only=false` to score every Bash call
        /// regardless of session context.
        #[arg(
            long,
            default_value_t = true,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            default_missing_value = "true"
        )]
        rts_mounted_only: bool,
    },
}

/// Output format for `rts-bench query …`. See the `--output` doc on
/// `Cmd::Query` for the rationale.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum QueryOutput {
    /// Pretty JSON to stdout. Matches the daemon's wire shape exactly.
    Json,
    /// rg-shaped `path:line:content` lines. Composable with `| head`,
    /// `| sort`, `| xargs`, etc.
    Lines,
}

#[derive(Subcommand, Debug)]
enum QueryCmd {
    /// `find_symbol` — exact name or glob pattern. Mutually exclusive.
    FindSymbol {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Exact symbol name.
        #[arg(long, conflicts_with = "pattern")]
        name: Option<String>,
        /// Glob pattern (`*` / `?` wildcards). E.g. `make_*`.
        #[arg(long, conflicts_with = "name")]
        pattern: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        file: Option<String>,
        /// Max number of results. Defaults to 256 (the agent default);
        /// up to 4096 supported by daemons advertising
        /// `find_symbol_limit_param`. Useful for dumping the full
        /// ranked symbol set when validating the semantic eval.
        #[arg(long)]
        limit: Option<u32>,
        /// Filter matches by case-insensitive substring against the
        /// doc-comment text. Requires daemon capability
        /// `find_symbol_doc_filter` (v0.5.2+). Useful for behavior-
        /// shaped queries: `--doc-contains retry` returns documented
        /// symbols whose comments mention retry, regardless of name.
        #[arg(long)]
        doc_contains: Option<String>,
        /// Populate each match's `signature` field via rts-core's
        /// per-language SignatureRenderer. Default off (preserves
        /// pre-v0.5.3 wire shape). Useful for outline-style lookups
        /// where you want signatures without paying for `read_symbol`
        /// per match. Capability: `find_symbol_signature_field`.
        #[arg(long, default_value_t = false)]
        include_signature: bool,
    },
    /// `read_symbol` — read by name, optional shape + closure walk + callers.
    ReadSymbol {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        /// `body` (default), `signature`, or `both`.
        #[arg(long)]
        shape: Option<String>,
        #[arg(long)]
        token_budget: Option<u64>,
        /// Walk the symbol's referenced-symbol closure (depth 1).
        #[arg(long)]
        deps: bool,
        /// Include direct callers (v0.3 U2'). Same shape as
        /// `query find-callers.callers[]`. Token budget shared with
        /// body + deps; body wins first, deps fill the remainder,
        /// callers fill what's left.
        #[arg(long)]
        callers: bool,
    },
    /// `read_symbol_at` — read by `(file, line)`; line-anchored lookup.
    /// The compiler-error flow: take `error[E0308] --> src/lib.rs:42:18`
    /// and one call returns the containing fn body + dep closure.
    ReadSymbolAt {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        file: String,
        #[arg(long)]
        line: u32,
        #[arg(long)]
        column: Option<u32>,
        #[arg(long)]
        shape: Option<String>,
        #[arg(long)]
        token_budget: Option<u64>,
        #[arg(long)]
        deps: bool,
        /// Include direct callers (v0.3 U2').
        #[arg(long)]
        callers: bool,
    },
    /// `find_callers` — direct callers of a symbol (v0.3 U2'). One redb
    /// lookup; returns the call sites + each caller's enclosing fn name.
    /// AST-precise; avoids ripgrep false positives. Distinct from the
    /// legacy `task find_callers` (now removed) — this is a one-shot
    /// query, not a baseline-bench scenario task.
    FindCallers {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        name: String,
        /// Filter callers by the enclosing def's kind (fn/method/etc).
        #[arg(long)]
        kind: Option<String>,
        /// Filter callers to a single workspace-relative file.
        #[arg(long)]
        file: Option<String>,
    },
    /// `impact_of` — transitive caller closure (v0.3 U5). BFS over
    /// reverse refs with depth + node-count + token + wall-clock
    /// bounds. Use for refactor blast radius queries.
    ImpactOf {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        name: String,
        /// BFS depth cap. Default 2 (server-side); hard max 4.
        #[arg(long)]
        depth: Option<u32>,
        /// Token budget. Default 4096 (server-side).
        #[arg(long)]
        token_budget: Option<u64>,
        /// Max distinct caller entries. Default 200 (server-side).
        #[arg(long)]
        max_nodes: Option<u32>,
        /// Pass `--include-tests` to disable the default test-path filter.
        #[arg(long)]
        include_tests: bool,
    },
    /// `outline_workspace` — token-budgeted structural map. Use first
    /// when orienting in an unfamiliar repo.
    Outline {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Optional glob to restrict the outline (e.g. `src/**`).
        #[arg(long)]
        glob: Option<String>,
        #[arg(long)]
        token_budget: Option<u64>,
    },
    /// `read_range` — explicit `[start_line, end_line]` slice. For
    /// stack-trace frames + diff hunks where you already have the
    /// exact location.
    ReadRange {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        file: String,
        #[arg(long)]
        start_line: u32,
        #[arg(long)]
        end_line: u32,
        #[arg(long)]
        token_budget: Option<u64>,
    },
    /// `grep` — literal-substring search across indexed file bytes.
    /// Closes the gap `find_symbol` can't reach: error messages,
    /// version strings, log literals, config values, anything that
    /// isn't a symbol name or a doc-comment. Capability:
    /// `index_grep` (v0.5.4+).
    Grep {
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Literal substring to search for. 1..=1024 characters.
        #[arg(long)]
        text: String,
        /// Max results. Default 256, range 1..=4096.
        #[arg(long)]
        limit: Option<u32>,
        /// Case-sensitive matching (default is case-insensitive).
        /// Pass `--case-sensitive` to opt into exact case.
        #[arg(long)]
        case_sensitive: bool,
    },
    /// `Daemon.Stats` — per-session RPC call counters (v0.5.7+).
    /// Answers "am I actually using the rts surface, or reaching for
    /// `grep`/`Read`?" with real numbers instead of vibes. Counters
    /// reset on every daemon restart — they describe THIS process's
    /// served traffic.
    DaemonStats {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum RealReposCmd {
    /// Clone (shallow, pinned) each repo in the v1 set, index it with
    /// rts, capture metrics, and emit a JSON or text report to stdout.
    /// Use this for ad-hoc local checks; CI runs `compare`.
    Run {
        /// Pool directory the bench clones repos into. Reused across
        /// invocations — first run pays the network cost, subsequent
        /// runs reuse the worktrees. Default: `/tmp/rts-real-repos`.
        #[arg(long, default_value = "/tmp/rts-real-repos")]
        workspace_pool: PathBuf,
        /// Output format. `json` (default) is the nightly-workflow
        /// shape; `text` is one summary line per repo.
        #[arg(long, value_enum, default_value_t = real_repos::ReportFormat::Json)]
        report: real_repos::ReportFormat,
    },
    /// Same wall-clock work as `run`, but write the JSON report to
    /// the path given by `--baseline`. Used by the maintainer after
    /// an intentional daemon change: `rts-bench real-repos baseline
    /// --baseline .github/baselines/rts-bench-real-repos.json`, then
    /// commit the result.
    Baseline {
        #[arg(long, default_value = "/tmp/rts-real-repos")]
        workspace_pool: PathBuf,
        /// Where to write the baseline JSON.
        #[arg(long)]
        baseline: PathBuf,
    },
    /// Read the committed baseline + run fresh; emit a structured
    /// diff. Exit 0 if all metrics within tolerance; exit 1 if any
    /// metric exceeds tolerance. The nightly CI workflow invokes
    /// this and surfaces regressions as failed workflow runs.
    Compare {
        #[arg(long, default_value = "/tmp/rts-real-repos")]
        workspace_pool: PathBuf,
        /// Path to the committed baseline JSON.
        #[arg(long)]
        baseline: PathBuf,
        /// Output format. `json` for CI consumption; `text` for human
        /// triage of a failed compare.
        #[arg(long, value_enum, default_value_t = real_repos::ReportFormat::Json)]
        report: real_repos::ReportFormat,
    },
}

#[derive(Subcommand, Debug)]
enum TaskCmd {
    /// List the five baseline tasks (running them is `task run <id>`).
    List,
    /// Run one task end-to-end. Writes `<out>` (default `bench-<sha>.json`).
    Run {
        /// Task id. One of: locate_def, get_body, find_callers,
        /// summarize_module, fix_imports, scenario_compiler_fix,
        /// scenario_refactor_impact.
        id: String,
        /// Workspace root to bench against.
        #[arg(long)]
        workspace: PathBuf,
        /// Symbol name to look up (locate_def, get_body,
        /// scenario_refactor_impact's target).
        #[arg(long)]
        symbol: Option<String>,
        /// Workspace-relative file path (summarize_module, fix_imports,
        /// scenario_compiler_fix).
        #[arg(long)]
        file: Option<String>,
        /// Line number for `scenario_compiler_fix` (1-indexed).
        #[arg(long)]
        line: Option<u32>,
        /// Referenced symbol to follow up on in `scenario_compiler_fix`.
        #[arg(long)]
        referenced_symbol: Option<String>,
        /// Comma-separated direct-caller names for
        /// `scenario_refactor_impact`'s baseline L2 grep. Real agents
        /// discover these from the L1 grep; the bench takes them as
        /// input so both paths measure the same workload.
        #[arg(long, value_delimiter = ',')]
        direct_callers: Option<Vec<String>>,
        /// Line budget for the summary head (summarize_module). Defaults
        /// to 50.
        #[arg(long)]
        line_budget: Option<u32>,
        /// Where to write the JSON report. Defaults to
        /// `crates/rts-bench/bench-<short-sha>.json` next to the binary.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Skip writing the report — useful for ad-hoc runs.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand, Debug)]
enum FixtureCmd {
    /// Parse and validate a corpus.lock. Today this *only* loads + lists;
    /// the tarball-download step lands when there's a pinned corpus.
    Restore {
        #[arg(long, default_value = "crates/rts-bench/corpus.lock")]
        corpus_lock: PathBuf,
        #[arg(long)]
        corpus_root: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RTS_BENCH_LOG")
                .or_else(|_| tracing_subscriber::EnvFilter::try_from_default_env())
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("rts_bench=info,warn")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Task { sub: TaskCmd::List } => {
            println!("Available tasks (plan §P9):");
            for id in tasks::TASK_IDS {
                println!("  {id}");
            }
            Ok(())
        }
        Cmd::Task {
            sub:
                TaskCmd::Run {
                    id,
                    workspace,
                    symbol,
                    file,
                    line,
                    referenced_symbol,
                    direct_callers,
                    line_budget,
                    out,
                    dry_run,
                },
        } => {
            run_one(
                id,
                workspace,
                symbol,
                file,
                line,
                referenced_symbol,
                direct_callers,
                line_budget,
                out,
                dry_run,
            )
            .await
        }
        Cmd::Fixture {
            sub:
                FixtureCmd::Restore {
                    corpus_lock,
                    corpus_root,
                },
        } => restore_fixtures(corpus_lock, corpus_root).await,
        Cmd::Latency {
            workspace,
            synth_loc,
            queries,
            cold_count,
            seed,
            deps,
            out,
            dry_run,
        } => {
            run_latency(
                workspace, synth_loc, queries, cold_count, seed, deps, out, dry_run,
            )
            .await
        }
        Cmd::Footprint {
            synth_loc,
            out,
            dry_run,
        } => run_footprint(synth_loc, out, dry_run).await,
        Cmd::Query { output, sub } => run_query(sub, output).await,
        Cmd::Doctor {
            output,
            no_color,
            workspace,
        } => {
            // doctor::run returns the process exit code (0/1/2 per the
            // documented contract); we plumb it through std::process::exit
            // because anyhow::Result<()> from main only gives us 0/1.
            let code = doctor::run(doctor::DoctorArgs {
                output,
                no_color,
                workspace,
            })
            .await;
            std::process::exit(code);
        }
        Cmd::Semantic {
            corpus,
            workspace,
            top_k,
            out,
            dry_run,
            check_coverage,
        } => run_semantic(corpus, workspace, top_k, out, dry_run, check_coverage).await,
        Cmd::Verify {
            corpus,
            workspace,
            out,
            dry_run,
        } => run_verify(corpus, workspace, out, dry_run).await,
        Cmd::RealRepos { sub } => run_real_repos(sub).await,
        Cmd::Dogfood {
            session,
            report,
            rts_mounted_only,
        } => {
            // Dogfood is a pure CPU/file-IO operation — no daemon, no
            // network, no tokio handles. Block on the synchronous
            // implementation rather than spawning anything.
            dogfood::run(dogfood::DogfoodArgs {
                session,
                report,
                rts_mounted_only,
            })
        }
    }
}

/// `rts-bench real-repos` dispatcher.
///
/// All three subcommands share the same measurement pipeline (clone
/// → mount → cold-walk-gate → telemetry capture). The differences:
/// - `Run`      prints the report to stdout.
/// - `Baseline` writes the report to a path on disk.
/// - `Compare`  reads a baseline + measures + diffs; exits 1 on regression.
async fn run_real_repos(cmd: RealReposCmd) -> Result<()> {
    let repos = real_repos::RepoSet::default_v1()?;

    match cmd {
        RealReposCmd::Run {
            workspace_pool,
            report,
        } => {
            let rts_mcp_bin = resolve_bin("rts-mcp")?;
            let rts_daemon_bin = resolve_bin("rts-daemon")?;
            let bench =
                real_repos::run_all(&repos, &workspace_pool, &rts_mcp_bin, &rts_daemon_bin).await?;
            real_repos::print_report(&bench, report)?;
            Ok(())
        }
        RealReposCmd::Baseline {
            workspace_pool,
            baseline,
        } => {
            let rts_mcp_bin = resolve_bin("rts-mcp")?;
            let rts_daemon_bin = resolve_bin("rts-daemon")?;
            let bench =
                real_repos::run_all(&repos, &workspace_pool, &rts_mcp_bin, &rts_daemon_bin).await?;
            real_repos::write_report_json(&baseline, &bench)?;
            eprintln!("wrote baseline {}", baseline.display());
            // Also echo the JSON to stdout so the operator running the
            // command from a terminal can see what got written.
            real_repos::print_report(&bench, real_repos::ReportFormat::Json)?;
            Ok(())
        }
        RealReposCmd::Compare {
            workspace_pool,
            baseline,
            report,
        } => {
            // Read the baseline FIRST so a missing/malformed file
            // fails clean with a baseline-related error message
            // before we touch the daemon binary resolution.
            let baseline_report = real_repos::read_report_json(&baseline)?;
            let rts_mcp_bin = resolve_bin("rts-mcp")?;
            let rts_daemon_bin = resolve_bin("rts-daemon")?;
            let current =
                real_repos::run_all(&repos, &workspace_pool, &rts_mcp_bin, &rts_daemon_bin).await?;
            let policy = real_repos::TolerancePolicy::default();
            let cmp = real_repos::diff::compare(&baseline_report, &current, &policy);
            match report {
                real_repos::ReportFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&cmp)?);
                }
                real_repos::ReportFormat::Text => {
                    print!("{}", real_repos::diff::render_compare_text(&cmp));
                }
            }
            if !cmp.regressions.is_empty() {
                eprintln!(
                    "real-repos: {} regression(s) — see report above",
                    cmp.regressions.len()
                );
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

async fn run_semantic(
    corpus_path: PathBuf,
    workspace: PathBuf,
    top_k: usize,
    out: Option<PathBuf>,
    dry_run: bool,
    check_coverage: Option<f64>,
) -> Result<()> {
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("canonicalize {}", workspace.display()))?;
    let corpus = semantic::load_corpus(&corpus_path)
        .with_context(|| format!("load corpus {}", corpus_path.display()))?;
    println!(
        "semantic: workspace={} corpus={} queries={} top_k={}",
        workspace.display(),
        corpus_path.display(),
        corpus.queries.len(),
        top_k,
    );

    let rts_mcp_bin = resolve_bin("rts-mcp")?;
    let rts_daemon_bin = resolve_bin("rts-daemon")?;
    let mut session =
        mcp_runner::McpSession::spawn(&rts_mcp_bin, &rts_daemon_bin, &workspace, &[]).await?;

    // Probe to make sure the index is hot before we start scoring;
    // share the bench's INDEX_NOT_READY-retry budget so cold mounts
    // don't muddy the eval results.
    let _ = session
        .tools_call("find_symbol", json!({ "pattern": "*" }), 30)
        .await?;

    let results = semantic::run(&mut session, &corpus, top_k).await?;
    session.close().await?;

    let report = semantic::build_report(&workspace, &corpus_path, top_k, results);
    println!(
        "semantic: mrr={:.3} coverage={:.1}% answerable_coverage={:.1}% precision@{}={:.3}",
        report.mrr,
        report.coverage * 100.0,
        report.answerable_coverage * 100.0,
        report.top_k,
        report.mean_precision_at_k,
    );
    // Per-query lines for quick scan; full report goes to JSON.
    for q in &report.queries {
        let mark = match q.first_hit_rank {
            Some(0) => "✅".to_string(),
            Some(r) => format!("rank {}", r + 1),
            None => "❌ miss".to_string(),
        };
        println!(
            "  [{mark:>8}] {} → top1={:?}",
            q.query,
            q.returned_top_k.first().cloned().unwrap_or_default()
        );
    }

    if !dry_run {
        let out_path = out.unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(format!("bench-semantic-{}.json", git_short_sha()))
        });
        semantic::write_report(&out_path, &report)?;
        println!("wrote {}", out_path.display());
    }

    // Regression guard: after writing the report, gate on coverage.
    // Print on its own line so CI failure logs make the threshold
    // and observed value easy to spot.
    if let Some(min) = check_coverage {
        if report.answerable_coverage + f64::EPSILON < min {
            eprintln!(
                "regression: answerable_coverage {:.3} < required {:.3}",
                report.answerable_coverage, min
            );
            std::process::exit(2);
        } else {
            println!(
                "check: answerable_coverage {:.3} ≥ required {:.3} ✓",
                report.answerable_coverage, min
            );
        }
    }
    Ok(())
}

/// `rts-bench verify` — hallucination-metric harness (verify-v0 P1.U5).
///
/// Mounts the workspace via the same rts-mcp + daemon path the other
/// benches use, parses each corpus snippet with rts's tree-sitter
/// extractor, checks every reference against the live index via the
/// verify tools, and prints the JSON `HallucinationReport`.
async fn run_verify(
    corpus_path: PathBuf,
    workspace: PathBuf,
    out: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("canonicalize {}", workspace.display()))?;
    let corpus = verify_metrics::load_corpus(&corpus_path)
        .with_context(|| format!("load corpus {}", corpus_path.display()))?;
    println!(
        "verify: workspace={} corpus={} snippets={}",
        workspace.display(),
        corpus_path.display(),
        corpus.snippets.len(),
    );

    let rts_mcp_bin = resolve_bin("rts-mcp")?;
    let rts_daemon_bin = resolve_bin("rts-daemon")?;
    let mut session =
        mcp_runner::McpSession::spawn(&rts_mcp_bin, &rts_daemon_bin, &workspace, &[]).await?;

    // Warm the index before we start verifying so cold-mount
    // INDEX_NOT_READY churn doesn't masquerade as `indeterminate`.
    let _ = session
        .tools_call("find_symbol", json!({ "pattern": "*" }), 30)
        .await?;

    let acc = {
        let mut oracle = verify_metrics::SessionOracle::new(&mut session);
        verify_metrics::run_corpus(&mut oracle, &corpus).await?
    };
    session.close().await?;

    let report = verify_metrics::report_from_resolutions(
        env!("CARGO_PKG_VERSION"),
        &workspace.display().to_string(),
        &corpus_path.display().to_string(),
        corpus.snippets.len(),
        acc,
    );

    // One-line human summary; the full report is the JSON below.
    let fmt_rate = |m: &verify_metrics::Metric| match m.rate {
        Some(r) => format!("{:.3} ({}/{}", r, m.numerator, m.denominator),
        None => "null (0/0".to_string(),
    };
    println!(
        "verify: SHR={}; ind={}) IHR={}; ind={}) SMR={}; ind={}) unsupported_refs={}",
        fmt_rate(&report.shr),
        report.shr.indeterminate_excluded,
        fmt_rate(&report.ihr),
        report.ihr.indeterminate_excluded,
        fmt_rate(&report.smr),
        report.smr.indeterminate_excluded,
        report.unsupported_language_refs,
    );

    let json = serde_json::to_string_pretty(&report).context("encode hallucination report")?;
    println!("{json}");

    if !dry_run {
        let out_path = out.unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(format!("bench-verify-{}.json", git_short_sha()))
        });
        std::fs::write(&out_path, &json)
            .with_context(|| format!("write {}", out_path.display()))?;
        println!("wrote {}", out_path.display());
    }
    Ok(())
}

/// One-shot query against the daemon. Spawns rts-mcp + the daemon,
/// calls the requested tool, prints the JSON response to stdout.
///
/// Exit codes:
///   0 — tool returned a non-error response
///   1 — tool returned `is_error=true` (daemon-level error; the body
///       JSON describes which error code fired)
///   2 — subprocess / JSON-decode failure
///
/// Output: pretty JSON to stdout. The `result_body` from McpCall is
/// what gets printed — the daemon's structured response, not the MCP
/// envelope. For raw envelope debugging, set `RTS_BENCH_LOG=debug`.
async fn run_query(cmd: QueryCmd, output: QueryOutput) -> Result<()> {
    let rts_mcp_bin = resolve_bin("rts-mcp")?;
    let rts_daemon_bin = resolve_bin("rts-daemon")?;

    // Each variant carries an optional workspace; default to $PWD.
    // We canonicalise so the daemon's mount check accepts the path.
    let (workspace, tool, args) = build_query(&cmd)?;
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("canonicalize workspace {}", workspace.display()))?;

    let mut session =
        crate::mcp_runner::McpSession::spawn(&rts_mcp_bin, &rts_daemon_bin, &workspace, &[])
            .await?;

    // 30 retries × 120ms = up to ~3.6s for INDEX_NOT_READY. Real
    // workspaces with thousands of files may need longer; for now
    // matching the bench/runner default.
    let call = session.tools_call(tool, args, 30).await?;
    session.close().await?;

    let body = call
        .result_body
        .clone()
        .unwrap_or_else(|| serde_json::json!({"is_error": call.is_error, "raw": null}));

    // Lines mode: render rg-shaped output for bash pipelines. Falls
    // back to JSON for tools where line-shape doesn't make sense
    // (read_symbol body, read_range) or for error envelopes — the
    // agent needs the full diagnostic in those cases.
    match output {
        QueryOutput::Json => {
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        QueryOutput::Lines => match render_lines(tool, &body) {
            Some(s) if !s.is_empty() => print!("{s}"),
            Some(_) => {
                // Tool returned an empty result set. Emit nothing —
                // `rts-bench query grep --output lines | wc -l` then
                // returns 0, matching `rg`'s no-match semantics.
            }
            None => {
                // Tool doesn't have a line shape (read_symbol body,
                // read_range). Fall back to JSON so the user still
                // gets a useful result rather than silence.
                println!("{}", serde_json::to_string_pretty(&body)?);
            }
        },
    }

    if call.is_error {
        // Body already carries the error code; agents pipe to `jq`
        // for details. We just need the exit code so shell scripts
        // can branch.
        std::process::exit(1);
    }
    Ok(())
}

/// Render an MCP tool response as `rg`-shaped `path:line:content` lines.
///
/// Returns `Some("")` when the tool has a defined line shape but the
/// response is empty (no matches / no callers); the caller emits
/// nothing in that case so `wc -l` / `| head` match `rg`'s semantics.
///
/// Returns `None` for tools that don't have a useful line shape
/// (`read_symbol`, `read_symbol_at`, `read_range` return file bodies,
/// not match lists). The caller falls back to JSON in that case so
/// the user still sees the result.
///
/// Wire-shape coupling: this function reads optional fields like
/// `enclosing_qualified_name` (v0.5.5+) and `rank_score`. Older
/// daemons that don't populate them produce slightly thinner output
/// — by design, so the same CLI binary works against a mixed
/// daemon-version fleet.
fn render_lines(tool: &str, body: &serde_json::Value) -> Option<String> {
    use std::fmt::Write;
    let mut out = String::new();
    match tool {
        // find_symbol: one line per match, `path:line:qualified_name (kind)`.
        // Rank when present (≥1e-6) appended as `[rank=…]`. Wire field
        // names match protocol-v0 §7.6: `qualified_name`, `range.start_line`.
        "find_symbol" => {
            let matches = body["matches"].as_array()?;
            for m in matches {
                let file = m["file"].as_str().unwrap_or("?");
                let line = m["range"]["start_line"].as_u64().unwrap_or(0);
                let name = m["qualified_name"].as_str().unwrap_or("?");
                let kind = m["kind"].as_str().unwrap_or("?");
                let _ = write!(out, "{file}:{line}:{name} ({kind})");
                if let Some(r) = m["rank_score"].as_f64() {
                    if r > 1e-6 {
                        let _ = write!(out, " [rank={r:.3e}]");
                    }
                }
                out.push('\n');
            }
            Some(out)
        }
        // find_callers: one line per caller, `path:line:enclosing_qualified_name (kind)`.
        // Mirrors the find_symbol shape so a refactor can chain
        // `find_callers ... | awk -F: '{print $1}' | sort -u`.
        "find_callers" => {
            let callers = body["callers"].as_array()?;
            for c in callers {
                let file = c["file"].as_str().unwrap_or("?");
                let line = c["range"]["start_line"].as_u64().unwrap_or(0);
                let enc = c["enclosing_qualified_name"]
                    .as_str()
                    .unwrap_or("<file-scope>");
                let kind = c["kind"].as_str().unwrap_or("?");
                let _ = writeln!(out, "{file}:{line}:{enc} ({kind})");
            }
            Some(out)
        }
        // grep: `path:line:[enclosing] line_text`. The bracketed
        // enclosing is v0.5.5+ — older daemons omit it and we just
        // print `path:line:line_text`, matching pre-v0.5.5 rg shape.
        "grep" => {
            let matches = body["matches"].as_array()?;
            for m in matches {
                let file = m["file"].as_str().unwrap_or("?");
                let line = m["range"]["start_line"].as_u64().unwrap_or(0);
                let text = m["line_text"].as_str().unwrap_or("").trim_end();
                let enc = m["enclosing_qualified_name"].as_str();
                match enc {
                    Some(e) if !e.is_empty() => {
                        let _ = writeln!(out, "{file}:{line}:[{e}] {text}");
                    }
                    _ => {
                        let _ = writeln!(out, "{file}:{line}:{text}");
                    }
                }
            }
            Some(out)
        }
        // impact_of: `[depth=N] path:line:qualified_name (kind) [rank=…]`.
        // Depth-prefix lets a refactor scan see direct callers first
        // by `sort` order without re-implementing the daemon's depth-asc
        // tie-break.
        "impact_of" => {
            let impact = body["impact"].as_array()?;
            for e in impact {
                let depth = e["depth"].as_u64().unwrap_or(0);
                let file = e["file"].as_str().unwrap_or("?");
                let line = e["range"]["start_line"].as_u64().unwrap_or(0);
                let name = e["qualified_name"].as_str().unwrap_or("?");
                let kind = e["kind"].as_str().unwrap_or("?");
                let _ = write!(out, "[depth={depth}] {file}:{line}:{name} ({kind})");
                if let Some(r) = e["rank_score"].as_f64() {
                    if r > 1e-6 {
                        let _ = write!(out, " [rank={r:.3e}]");
                    }
                }
                out.push('\n');
            }
            Some(out)
        }
        // outline_workspace: the daemon already returns a dotted plain-text
        // outline in `outline_text` (protocol-v0 §7.5). Pass through
        // verbatim so `--output lines` is consistent with the rest of
        // the suite (one item per line).
        "outline_workspace" => {
            let text = body["outline_text"].as_str()?;
            if !text.is_empty() {
                out.push_str(text);
                if !text.ends_with('\n') {
                    out.push('\n');
                }
            }
            Some(out)
        }
        // daemon_stats: one line per method, `<method>: <count>`,
        // sorted by count descending so the most-called methods
        // surface first. Zero-count methods are still emitted (the
        // dogfood signal "what AREN'T you using?" is just as
        // important as "what are you using?"). Header lines for
        // uptime + total are printed first, prefixed with `#` so
        // `grep -v ^#` strips the meta and gives you pure
        // method-count pairs for `sort` / `awk`.
        "daemon_stats" => {
            let uptime_ms = body["uptime_ms"].as_u64().unwrap_or(0);
            let total = body["total_calls"].as_u64().unwrap_or(0);
            let version = body["version"].as_str().unwrap_or("?");
            let _ = writeln!(out, "# daemon-version: {version}");
            let _ = writeln!(out, "# uptime-ms: {uptime_ms}");
            let _ = writeln!(out, "# total-calls: {total}");
            let calls = body["calls"].as_object()?;
            // Stable sort: count descending, then method-name asc
            // for deterministic output when counts tie. The agent's
            // typical first read of stats has every counter at 0;
            // the lex tiebreaker keeps that output reproducible.
            let mut pairs: Vec<(&String, u64)> = calls
                .iter()
                .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            for (method, count) in pairs {
                let _ = writeln!(out, "{method}: {count}");
            }
            Some(out)
        }
        // read_symbol / read_symbol_at / read_range return file bodies,
        // not match lists. Lines mode doesn't help here — caller falls
        // back to JSON.
        _ => None,
    }
}

/// Lower the typed `QueryCmd` into `(workspace, tool_name, args_json)`.
/// Keeps the network shape colocated with the CLI surface for easy
/// review when adding new tools.
/// Resolve the workspace path for a `query` invocation.
///
/// - When `--workspace PATH` is passed: use it verbatim.
/// - Otherwise: walk upward from `start` looking for any of the
///   marker files below; first hit wins. This lets agents run
///   `rts-bench query find-symbol --name foo` from anywhere
///   inside a project tree without re-typing the workspace path.
///
/// Markers cover all 12 in-tree languages plus `.git` as a
/// universal fallback. `Cargo.toml` is checked first since
/// `rts-bench` is itself a Rust binary and Rust workspaces are
/// the most common dogfood target.
///
/// If no marker is found, falls back to `start` itself (matches the
/// pre-v0.5.3 behavior, so this change is strictly additive).
///
/// `start` is `$PWD` in production; tests pass a tempdir.
fn detect_workspace_from(start: &std::path::Path) -> PathBuf {
    // Ordered by frequency / specificity; first-match wins per
    // directory level. `.git` is last so a Cargo.toml inside a
    // git repo wins for its sub-crate over the repo root.
    const MARKERS: &[&str] = &[
        "Cargo.toml",       // Rust
        "package.json",     // JS / TS
        "go.mod",           // Go
        "pyproject.toml",   // Python (modern)
        "setup.py",         // Python (legacy)
        "pom.xml",          // Java / Maven
        "build.gradle",     // Java / Kotlin (Gradle Groovy DSL)
        "build.gradle.kts", // Kotlin (Gradle KTS)
        "Gemfile",          // Ruby
        "composer.json",    // PHP
        "Package.swift",    // Swift
        ".git",             // generic VCS fallback
    ];
    let mut dir: Option<&std::path::Path> = Some(start);
    while let Some(d) = dir {
        for marker in MARKERS {
            if d.join(marker).exists() {
                return d.to_path_buf();
            }
        }
        dir = d.parent();
    }
    // No marker anywhere up to /: just use the start path.
    start.to_path_buf()
}

fn build_query(cmd: &QueryCmd) -> Result<(PathBuf, &'static str, serde_json::Value)> {
    fn default_workspace(ws: &Option<PathBuf>) -> Result<PathBuf> {
        if let Some(p) = ws {
            return Ok(p.clone());
        }
        let cwd = std::env::current_dir().context("$PWD lookup")?;
        Ok(detect_workspace_from(&cwd))
    }
    fn opt_str(
        o: &Option<String>,
        args: &mut serde_json::Map<String, serde_json::Value>,
        key: &str,
    ) {
        if let Some(v) = o {
            args.insert(key.into(), serde_json::Value::String(v.clone()));
        }
    }
    fn opt_num(o: Option<u64>, args: &mut serde_json::Map<String, serde_json::Value>, key: &str) {
        if let Some(v) = o {
            args.insert(key.into(), serde_json::Value::Number(v.into()));
        }
    }
    match cmd {
        QueryCmd::FindSymbol {
            workspace,
            name,
            pattern,
            kind,
            file,
            limit,
            doc_contains,
            include_signature,
        } => {
            if name.is_none() && pattern.is_none() {
                return Err(anyhow!(
                    "query find_symbol requires either --name or --pattern"
                ));
            }
            let mut a = serde_json::Map::new();
            opt_str(name, &mut a, "name");
            opt_str(pattern, &mut a, "pattern");
            opt_str(kind, &mut a, "kind");
            opt_str(file, &mut a, "file");
            if let Some(n) = limit {
                a.insert("limit".into(), serde_json::Value::Number((*n).into()));
            }
            opt_str(doc_contains, &mut a, "doc_contains");
            if *include_signature {
                a.insert("include_signature".into(), serde_json::Value::Bool(true));
            }
            Ok((
                default_workspace(workspace)?,
                "find_symbol",
                serde_json::Value::Object(a),
            ))
        }
        QueryCmd::ReadSymbol {
            workspace,
            name,
            file,
            kind,
            shape,
            token_budget,
            deps,
            callers,
        } => {
            let mut a = serde_json::Map::new();
            a.insert("name".into(), serde_json::Value::String(name.clone()));
            opt_str(file, &mut a, "file");
            opt_str(kind, &mut a, "kind");
            opt_str(shape, &mut a, "shape");
            opt_num(*token_budget, &mut a, "token_budget");
            if *deps {
                a.insert("include_dependencies".into(), serde_json::Value::Bool(true));
            }
            if *callers {
                a.insert("include_callers".into(), serde_json::Value::Bool(true));
            }
            Ok((
                default_workspace(workspace)?,
                "read_symbol",
                serde_json::Value::Object(a),
            ))
        }
        QueryCmd::ReadSymbolAt {
            workspace,
            file,
            line,
            column,
            shape,
            token_budget,
            deps,
            callers,
        } => {
            let mut a = serde_json::Map::new();
            a.insert("file".into(), serde_json::Value::String(file.clone()));
            a.insert("line".into(), serde_json::Value::Number((*line).into()));
            if let Some(c) = column {
                a.insert("column".into(), serde_json::Value::Number((*c).into()));
            }
            opt_str(shape, &mut a, "shape");
            opt_num(*token_budget, &mut a, "token_budget");
            if *deps {
                a.insert("include_dependencies".into(), serde_json::Value::Bool(true));
            }
            if *callers {
                a.insert("include_callers".into(), serde_json::Value::Bool(true));
            }
            Ok((
                default_workspace(workspace)?,
                "read_symbol_at",
                serde_json::Value::Object(a),
            ))
        }
        QueryCmd::FindCallers {
            workspace,
            name,
            kind,
            file,
        } => {
            let mut a = serde_json::Map::new();
            a.insert("name".into(), serde_json::Value::String(name.clone()));
            opt_str(kind, &mut a, "kind");
            opt_str(file, &mut a, "file");
            Ok((
                default_workspace(workspace)?,
                "find_callers",
                serde_json::Value::Object(a),
            ))
        }
        QueryCmd::ImpactOf {
            workspace,
            name,
            depth,
            token_budget,
            max_nodes,
            include_tests,
        } => {
            let mut a = serde_json::Map::new();
            a.insert("name".into(), serde_json::Value::String(name.clone()));
            if let Some(d) = depth {
                a.insert("depth".into(), serde_json::Value::Number((*d).into()));
            }
            opt_num(*token_budget, &mut a, "token_budget");
            if let Some(m) = max_nodes {
                a.insert("max_nodes".into(), serde_json::Value::Number((*m).into()));
            }
            // `--include-tests` disables the default test-path filter.
            if *include_tests {
                a.insert("exclude_test_paths".into(), serde_json::Value::Bool(false));
            }
            Ok((
                default_workspace(workspace)?,
                "impact_of",
                serde_json::Value::Object(a),
            ))
        }
        QueryCmd::Outline {
            workspace,
            glob,
            token_budget,
        } => {
            let mut a = serde_json::Map::new();
            opt_str(glob, &mut a, "glob");
            opt_num(*token_budget, &mut a, "token_budget");
            Ok((
                default_workspace(workspace)?,
                "outline_workspace",
                serde_json::Value::Object(a),
            ))
        }
        QueryCmd::ReadRange {
            workspace,
            file,
            start_line,
            end_line,
            token_budget,
        } => {
            let mut a = serde_json::Map::new();
            a.insert("file".into(), serde_json::Value::String(file.clone()));
            a.insert(
                "start_line".into(),
                serde_json::Value::Number((*start_line).into()),
            );
            a.insert(
                "end_line".into(),
                serde_json::Value::Number((*end_line).into()),
            );
            opt_num(*token_budget, &mut a, "token_budget");
            Ok((
                default_workspace(workspace)?,
                "read_range",
                serde_json::Value::Object(a),
            ))
        }
        QueryCmd::Grep {
            workspace,
            text,
            limit,
            case_sensitive,
        } => {
            let mut a = serde_json::Map::new();
            a.insert("text".into(), serde_json::Value::String(text.clone()));
            if let Some(n) = limit {
                a.insert("limit".into(), serde_json::Value::Number((*n).into()));
            }
            // CLI exposes `--case-sensitive` (opt-in) so the
            // default invocation matches the daemon default
            // (`case_insensitive=true`).
            if *case_sensitive {
                a.insert("case_insensitive".into(), serde_json::Value::Bool(false));
            }
            Ok((
                default_workspace(workspace)?,
                "grep",
                serde_json::Value::Object(a),
            ))
        }
        QueryCmd::DaemonStats { workspace } => Ok((
            default_workspace(workspace)?,
            "daemon_stats",
            serde_json::Value::Object(serde_json::Map::new()),
        )),
    }
}

async fn run_footprint(synth_loc: usize, out: Option<PathBuf>, dry_run: bool) -> Result<()> {
    let rts_mcp_bin = resolve_bin("rts-mcp")?;
    let rts_daemon_bin = resolve_bin("rts-daemon")?;

    // Workspace-scoped tmpdir for both the synth fixture and the
    // daemon's runtime/state dirs — matches the latency bench so a
    // local `footprint` and `latency` run don't share state.
    let tmp_root = tempfile::tempdir().context("tempdir for footprint run")?;
    let report = footprint::run(&rts_mcp_bin, &rts_daemon_bin, synth_loc, tmp_root.path()).await?;

    println!(
        "footprint: workspace={} files={} symbols={}",
        report.workspace_path, report.files, report.symbols,
    );
    println!(
        "  build_time={}ms full_index={}ms peak_rss={} index_size={} bytes/symbol={}",
        report.build_time_ms,
        report.full_index_time_ms,
        human_bytes(report.peak_rss_bytes),
        human_bytes(report.index_size_bytes),
        report.bytes_per_symbol,
    );

    if dry_run {
        return Ok(());
    }
    let out_path = out.unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(format!("bench-footprint-{}.json", git_short_sha()))
    });
    footprint::write_report(&out_path, &report)?;
    println!("wrote {}", out_path.display());
    Ok(())
}

/// Compact "1.2 MiB" style for the bench summary line. Operator-facing
/// only; the JSON report keeps raw bytes for downstream dashboards.
fn human_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_latency(
    workspace_arg: Option<PathBuf>,
    synth_loc: usize,
    queries: u32,
    cold_count: u32,
    seed: u64,
    deps: bool,
    out: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let read_symbol_mode = if deps {
        latency::ReadSymbolMode::BodyWithDeps
    } else {
        latency::ReadSymbolMode::Signature
    };
    let rts_mcp_bin = resolve_bin("rts-mcp")?;
    let rts_daemon_bin = resolve_bin("rts-daemon")?;

    // Use a workspace-scoped tmpdir for both the synth fixture and the
    // daemon's runtime/state dirs so concurrent latency runs on the
    // same machine don't fight over /tmp's default socket.
    let tmp_root = tempfile::tempdir().context("tempdir for latency run")?;
    // `--workspace <path>` and `--synth-loc <N>` are mutually exclusive
    // at the clap layer. Pick the right `prepare_workspace` arm based
    // on which is set. For real workspaces, `synth_loc` is recorded in
    // the report as 0 to flag "not synthetic".
    let (workspace, mut symbols, files) = match workspace_arg.as_ref() {
        Some(path) => latency::prepare_workspace(Some(path), None, tmp_root.path())?,
        None => latency::prepare_workspace(None, Some(synth_loc), tmp_root.path())?,
    };
    let synth_loc_for_report = if workspace_arg.is_some() {
        0
    } else {
        synth_loc
    };
    let runtime_dir = tmp_root.path().join("runtime");
    let state_dir = tmp_root.path().join("state");
    std::fs::create_dir_all(&runtime_dir)?;
    std::fs::create_dir_all(&state_dir)?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700));

    let extra_env: Vec<(&str, &str)> = vec![
        ("XDG_RUNTIME_DIR", runtime_dir.to_str().unwrap_or("")),
        ("XDG_STATE_HOME", state_dir.to_str().unwrap_or("")),
        ("HOME", tmp_root.path().to_str().unwrap_or("")),
        ("RTS_IDLE_SHUTDOWN_SECS", "300"),
    ];
    let mut session =
        crate::mcp_runner::McpSession::spawn(&rts_mcp_bin, &rts_daemon_bin, &workspace, &extra_env)
            .await?;

    // Cold gate: wait until the writer's initial walk plateaus on
    // `outline_workspace.files_considered`. Matches the signal
    // `rts-bench footprint` uses for `full_index_time_ms`. The
    // previous single-symbol probe only proved ONE symbol was
    // indexed; subsequent random warm picks could (and did) hit
    // `SYMBOL_NOT_FOUND` and silently drag the measured p95 downward.
    // See CHANGELOG `[Unreleased]` for the discovery writeup.
    cold_gate_wait_for_walk_settled(&mut session).await?;

    // For real workspaces, `prepare_workspace` returned an empty
    // symbols Vec — the bench needs names from the actual index, not
    // from a generator. Pull the top-K by rank via
    // `find_symbol(pattern="*")` post-cold-gate. The daemon caps that
    // response at 256 names (MAX_MATCHES); for the bench's random-pick
    // loop, 256 is more than enough to avoid degenerate repetition
    // even at --queries 5000.
    if symbols.is_empty() {
        let call = session
            .tools_call("find_symbol", serde_json::json!({ "pattern": "*" }), 5)
            .await?;
        if call.is_error {
            anyhow::bail!(
                "find_symbol(pattern='*') failed after cold gate — the workspace \
                 is mounted but no symbols are indexed. Either the workspace has \
                 no Rust/JS/Python/etc files, or the writer panicked. Re-run with \
                 RTS_LOG=debug for daemon-side diagnostics."
            );
        }
        if let Some(body) = call.result_body.as_ref() {
            if let Some(matches) = body.get("matches").and_then(|m| m.as_array()) {
                symbols = matches
                    .iter()
                    .filter_map(|m| m.get("qualified_name").and_then(|n| n.as_str()))
                    .map(|s| s.to_string())
                    .collect();
            }
        }
        anyhow::ensure!(
            !symbols.is_empty(),
            "find_symbol(pattern='*') returned no matches on real workspace {} — \
             the workspace may not contain any indexable source files",
            workspace.display(),
        );
        // Normalize ordering. `find_symbol` returns up to 256 results
        // sorted by rank_score descending; v0.3's PageRank rank differs
        // from alpha.30's 0.0-placeholder rank, so the same call against
        // each daemon picks a different top-K subset. For an
        // apples-to-apples bench comparison, sort + dedup lexically so
        // both daemons end up driving the bench against the same name
        // set (modulo the symbol-table contents the daemons agree on).
        symbols.sort();
        symbols.dedup();
        eprintln!(
            "discovered {} symbols from real workspace {} (sorted lexically \
             for cross-daemon stability)",
            symbols.len(),
            workspace.display()
        );
    }

    println!(
        "latency: workspace={} files={} symbols={} queries={} cold_count={} read_symbol_mode={}",
        workspace.display(),
        files.len(),
        symbols.len(),
        queries,
        cold_count,
        read_symbol_mode.as_str(),
    );

    let samples = latency::run(
        &mut session,
        &symbols,
        &files,
        queries,
        seed,
        read_symbol_mode,
    )
    .await?;
    session.close().await?;

    let report = latency::build_report(
        &workspace,
        synth_loc_for_report,
        seed,
        cold_count,
        read_symbol_mode,
        &samples,
    );
    println!(
        "warm p50={}µs p95={}µs p99={}µs max={}µs (n={})",
        report.warm_all.p50_micros,
        report.warm_all.p95_micros,
        report.warm_all.p99_micros,
        report.warm_all.max_micros,
        report.warm_all.count,
    );
    for (kind, s) in &report.warm {
        println!(
            "  {kind:>16}: p50={:>5}µs p95={:>5}µs p99={:>5}µs (n={})",
            s.p50_micros, s.p95_micros, s.p99_micros, s.count
        );
    }

    if dry_run {
        return Ok(());
    }

    let out_path = out.unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(format!("bench-latency-{}.json", git_short_sha()))
    });
    latency::write_report(&out_path, &report)?;
    println!("wrote {}", out_path.display());
    Ok(())
}

/// Poll interval for the cold gate. Indexing is bursty (writer drains
/// in 200 ms batches per protocol-v0 §15.6), so polling tighter than
/// this wastes daemon CPU on hot-loop calls.
const COLD_GATE_POLL_MS: u64 = 200;

/// Hard ceiling on the cold-gate wait. Indexing 100k LOC finishes
/// in ~1.4 s per `rts-bench footprint`, so 60 s is ample headroom.
const COLD_GATE_TIMEOUT_SECS: u64 = 60;

/// Wait for the writer to settle on its initial walk. Uses the same
/// stability signal as `rts-bench footprint`: poll
/// `outline_workspace.files_considered` every 200 ms and return when
/// two consecutive rounds report the same non-zero count.
///
/// **Why this matters for measurement validity.** The pre-existing
/// single-symbol cold probe at this site (find_symbol on
/// `symbols[0]`) only proved that ONE symbol was indexed — the
/// walker could still be mid-walk when warm queries began, and
/// subsequent random picks would hit `SYMBOL_NOT_FOUND` (a
/// microsecond-fast error response) that silently dragged the
/// measured p50/p95 downward. The session-2026-05-14 dogfooding
/// writeup in the CHANGELOG documents the discovery.
///
/// The matching change in `latency::build_report` computes
/// percentiles over `.ok` samples only, so even if the writer races
/// the bench on a pathological workspace, the latency stats reported
/// describe real responses rather than a mix of real responses + fast
/// errors.
/// Number of consecutive identical readings that count as "settled".
/// Footprint historically used 1 (one stable poll), but the writer
/// flushes in bursts and the count can plateau within a single
/// parse-commit cycle (200 ms poll falls inside one batch) before
/// jumping again. 3 consecutive matches means ~600 ms of true
/// stability is required — catches inter-batch lulls without an
/// excessive pre-roll.
const COLD_GATE_STABLE_ROUNDS: u32 = 3;

async fn cold_gate_wait_for_walk_settled(
    session: &mut crate::mcp_runner::McpSession,
) -> Result<()> {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(COLD_GATE_TIMEOUT_SECS);
    let mut last_seen: i64 = -1;
    let mut stable_streak: u32 = 0;
    let mut round = 0u32;
    loop {
        round += 1;
        let call = session
            .tools_call(
                "outline_workspace",
                serde_json::json!({ "token_budget": 256 }),
                30,
            )
            .await?;
        let files_considered = if call.is_error {
            -1
        } else {
            call.result_body
                .as_ref()
                .and_then(|v| v.get("files_considered").and_then(|x| x.as_i64()))
                .unwrap_or(-1)
        };
        if files_considered > 0 && files_considered == last_seen {
            stable_streak += 1;
            if stable_streak >= COLD_GATE_STABLE_ROUNDS {
                eprintln!(
                    "cold gate: walk settled at {files_considered} files \
                     (round {round}, {stable_streak} consecutive stable polls)"
                );
                return Ok(());
            }
        } else {
            stable_streak = 0;
        }
        last_seen = files_considered;
        if std::time::Instant::now() >= deadline {
            eprintln!(
                "cold gate: timed out at {COLD_GATE_TIMEOUT_SECS}s, last \
                 files_considered={files_considered}. Continuing anyway — the \
                 latency report's per-bucket `.ok` count will show whether \
                 the warm queries hit real symbols."
            );
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(COLD_GATE_POLL_MS)).await;
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
async fn run_one(
    id: String,
    workspace: PathBuf,
    symbol: Option<String>,
    file: Option<String>,
    line: Option<u32>,
    referenced_symbol: Option<String>,
    direct_callers: Option<Vec<String>>,
    line_budget: Option<u32>,
    out: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let workspace = std::fs::canonicalize(&workspace)
        .with_context(|| format!("canonicalize {}", workspace.display()))?;
    let rts_mcp_bin = resolve_bin("rts-mcp")?;
    let rts_daemon_bin = resolve_bin("rts-daemon")?;

    let inputs = build_task_inputs(
        &id,
        symbol.as_deref(),
        file.as_deref(),
        line,
        referenced_symbol.as_deref(),
        direct_callers.as_deref(),
        line_budget,
    )?;

    let ctx = TaskContext {
        workspace: &workspace,
        rts_mcp_bin: &rts_mcp_bin,
        rts_daemon_bin: &rts_daemon_bin,
        task_inputs: inputs.clone(),
    };

    let outcome = run_task(&id, &ctx).await?;
    let mut report = BenchReport::new();
    match outcome {
        TaskOutcome::Ran {
            baseline,
            mcp,
            inputs,
            description,
        } => {
            report.add_task(&id, &description, inputs, &baseline, &mcp);
            println!(
                "task {id}: baseline={} tokens, mcp={} tokens, reduction={:.1}%",
                baseline.tokens,
                mcp.tokens,
                report::pct_reduction(baseline.tokens, mcp.tokens),
            );
        }
        TaskOutcome::NotImplemented { reason } => {
            println!("task {id}: not implemented — {reason}");
            return Ok(());
        }
    }

    if dry_run {
        return Ok(());
    }

    let out_path = out.unwrap_or_else(|| {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        cwd.join("crates")
            .join("rts-bench")
            .join(format!("bench-{}.json", git_short_sha()))
    });
    report.write_to(&out_path)?;
    println!("wrote {}", out_path.display());
    Ok(())
}

async fn restore_fixtures(corpus_lock: PathBuf, corpus_root: Option<PathBuf>) -> Result<()> {
    let lock = corpus::Corpus::load(&corpus_lock)?;
    let root = match corpus_root {
        Some(p) => p,
        None => corpus::default_corpus_root()?,
    };
    println!("corpus.lock v{} model={}", lock.version, lock.model);
    println!("corpus root: {}", root.display());
    for f in &lock.fixtures {
        println!(
            "  {name} @ {sha} (~{mb:.1} MiB)",
            name = f.name,
            sha = &f.commit_sha,
            mb = f.archive_size_bytes as f64 / (1024.0 * 1024.0)
        );
    }
    println!();
    println!(
        "Note: tarball download is intentionally not wired in this build — see plan §P9 \
         'Fixture corpus'. The schema + SHA256 verification + extraction layout are ready; the \
         remaining piece is the HTTPS fetch + extract pipeline, scheduled for a later bench slice."
    );
    Ok(())
}

/// Validate + assemble the per-task `task_inputs` JSON. Per-task required
/// args are checked here so the CLI fails fast with a clear message before
/// any subprocess is spawned.
#[allow(clippy::too_many_arguments)]
fn build_task_inputs(
    id: &str,
    symbol: Option<&str>,
    file: Option<&str>,
    line: Option<u32>,
    referenced_symbol: Option<&str>,
    direct_callers: Option<&[String]>,
    line_budget: Option<u32>,
) -> Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();
    if let Some(s) = symbol {
        obj.insert("symbol_name".into(), json!(s));
    }
    if let Some(f) = file {
        obj.insert("file".into(), json!(f));
    }
    if let Some(l) = line {
        obj.insert("line".into(), json!(l));
    }
    if let Some(r) = referenced_symbol {
        obj.insert("referenced_symbol".into(), json!(r));
    }
    if let Some(cs) = direct_callers {
        obj.insert("direct_callers".into(), json!(cs));
    }
    if let Some(n) = line_budget {
        obj.insert("line_budget".into(), json!(n));
    }
    match id {
        "locate_def" | "get_body" => {
            if symbol.is_none() {
                return Err(anyhow!(
                    "task `{id}` requires --symbol; pick a function in the workspace"
                ));
            }
        }
        "summarize_module" => {
            if file.is_none() {
                return Err(anyhow!(
                    "task `summarize_module` requires --file (workspace-relative path)"
                ));
            }
        }
        "scenario_compiler_fix" => {
            if file.is_none() || line.is_none() || referenced_symbol.is_none() {
                return Err(anyhow!(
                    "task `scenario_compiler_fix` requires --file, --line, and \
                     --referenced-symbol (the symbol an agent would follow up on \
                     from the closure walk)"
                ));
            }
        }
        "scenario_refactor_impact" => {
            if symbol.is_none() {
                return Err(anyhow!(
                    "task `scenario_refactor_impact` requires --symbol (the target \
                     fn being refactored). Optionally pass --direct-callers \
                     <name,name,...> to drive the baseline L2 grep — without it, \
                     the baseline is L1-only and underestimates the wins."
                ));
            }
        }
        "find_callers" | "fix_imports" => {
            // Not implemented this slice; tasks::run_task returns
            // NotImplemented with a pointer to the later P9 slice. We
            // accept the args (so callers can be future-compatible) and
            // let the dispatcher emit the explanatory message.
        }
        _ => {} // Unknown ids fall through to the dispatcher's error.
    }
    Ok(serde_json::Value::Object(obj))
}

/// Best-effort short SHA for the bench report filename. Defaults to
/// `nogit` when not in a git checkout.
fn git_short_sha() -> String {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "nogit".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Auto-detect should find the workspace root even from a deep
    /// subdirectory, matching the marker (Cargo.toml here).
    #[test]
    fn detect_walks_upward_to_cargo_toml() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        let deep = root.join("crates").join("a").join("src");
        std::fs::create_dir_all(&deep).unwrap();

        let resolved = detect_workspace_from(&deep);
        // Canonicalise both sides — tempdir on macOS may give
        // /var/... while canonicalize returns /private/var/...
        assert_eq!(
            resolved.canonicalize().unwrap(),
            root.canonicalize().unwrap(),
            "should walk up to the Cargo.toml dir",
        );
    }

    /// First-marker-wins: a nested Cargo.toml beats the outer one.
    /// Matches Cargo's own behavior — `cargo build` inside a member
    /// crate operates on that member, not the workspace root.
    #[test]
    fn detect_prefers_nearest_marker() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let outer = tmp.path();
        std::fs::write(outer.join("Cargo.toml"), "[workspace]\n").unwrap();
        let inner = outer.join("crates").join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("Cargo.toml"), "[package]\nname = \"inner\"\n").unwrap();
        let deep = inner.join("src");
        std::fs::create_dir_all(&deep).unwrap();

        let resolved = detect_workspace_from(&deep);
        assert_eq!(
            resolved.canonicalize().unwrap(),
            inner.canonicalize().unwrap(),
            "nearest Cargo.toml wins over outer workspace root",
        );
    }

    /// When no marker exists anywhere, fall back to the start path
    /// (matches pre-v0.5.3 behavior — strictly additive change).
    #[test]
    fn detect_falls_back_to_start_when_no_marker() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // No marker files; just a bare directory.
        let resolved = detect_workspace_from(tmp.path());
        assert_eq!(
            resolved.canonicalize().unwrap(),
            tmp.path().canonicalize().unwrap(),
        );
    }

    /// `.git` is the universal fallback when no language-specific
    /// marker is present (e.g. checkout of a polyglot repo whose
    /// roots aren't recognised by their per-language marker).
    #[test]
    fn detect_git_fallback() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir(root.join(".git")).unwrap();
        let deep = root.join("nested").join("dir");
        std::fs::create_dir_all(&deep).unwrap();

        let resolved = detect_workspace_from(&deep);
        assert_eq!(
            resolved.canonicalize().unwrap(),
            root.canonicalize().unwrap(),
        );
    }
}
