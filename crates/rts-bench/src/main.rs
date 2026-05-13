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
use clap::{Parser, Subcommand};
use serde_json::json;

mod baseline;
mod corpus;
mod footprint;
mod latency;
mod mcp_runner;
mod report;
mod tasks;
mod token;

use mcp_runner::resolve_bin;
use report::BenchReport;
use tasks::{TaskContext, TaskOutcome, run_task};

#[derive(Parser, Debug)]
#[command(name = "rts-bench", about = "Bench harness for the rts-mcp stack")]
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
        /// Total lines of synthetic Rust source to generate. Defaults
        /// to 100,000 per plan §P9.
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
}

#[derive(Subcommand, Debug)]
enum TaskCmd {
    /// List the five baseline tasks (running them is `task run <id>`).
    List,
    /// Run one task end-to-end. Writes `<out>` (default `bench-<sha>.json`).
    Run {
        /// Task id. One of: locate_def, get_body, find_callers,
        /// summarize_module, fix_imports.
        id: String,
        /// Workspace root to bench against.
        #[arg(long)]
        workspace: PathBuf,
        /// Symbol name to look up (locate_def, get_body).
        #[arg(long)]
        symbol: Option<String>,
        /// Workspace-relative file path (summarize_module, fix_imports).
        #[arg(long)]
        file: Option<String>,
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
                    line_budget,
                    out,
                    dry_run,
                },
        } => run_one(id, workspace, symbol, file, line_budget, out, dry_run).await,
        Cmd::Fixture {
            sub:
                FixtureCmd::Restore {
                    corpus_lock,
                    corpus_root,
                },
        } => restore_fixtures(corpus_lock, corpus_root).await,
        Cmd::Latency {
            synth_loc,
            queries,
            cold_count,
            seed,
            out,
            dry_run,
        } => run_latency(synth_loc, queries, cold_count, seed, out, dry_run).await,
        Cmd::Footprint {
            synth_loc,
            out,
            dry_run,
        } => run_footprint(synth_loc, out, dry_run).await,
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

async fn run_latency(
    synth_loc: usize,
    queries: u32,
    cold_count: u32,
    seed: u64,
    out: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let rts_mcp_bin = resolve_bin("rts-mcp")?;
    let rts_daemon_bin = resolve_bin("rts-daemon")?;

    // Use a workspace-scoped tmpdir for both the synth fixture and the
    // daemon's runtime/state dirs so concurrent latency runs on the
    // same machine don't fight over /tmp's default socket.
    let tmp_root = tempfile::tempdir().context("tempdir for latency run")?;
    let (workspace, symbols, files) =
        latency::prepare_workspace(None, Some(synth_loc), tmp_root.path())?;
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

    // Wait for the writer to commit at least one symbol (initial walk
    // completed). `tools_call`'s retry loop handles INDEX_NOT_READY,
    // so a single call here is enough — when it returns the index is
    // hot enough to query.
    let probe = &symbols[0];
    let _ = session
        .tools_call("find_symbol", serde_json::json!({ "name": probe }), 30)
        .await?;

    println!(
        "latency: workspace={} files={} symbols={} queries={} cold_count={}",
        workspace.display(),
        files.len(),
        symbols.len(),
        queries,
        cold_count,
    );

    let samples = latency::run(&mut session, &symbols, &files, queries, seed).await?;
    session.close().await?;

    let report = latency::build_report(&workspace, synth_loc, seed, cold_count, &samples);
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

async fn run_one(
    id: String,
    workspace: PathBuf,
    symbol: Option<String>,
    file: Option<String>,
    line_budget: Option<u32>,
    out: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let workspace = std::fs::canonicalize(&workspace)
        .with_context(|| format!("canonicalize {}", workspace.display()))?;
    let rts_mcp_bin = resolve_bin("rts-mcp")?;
    let rts_daemon_bin = resolve_bin("rts-daemon")?;

    let inputs = build_task_inputs(&id, symbol.as_deref(), file.as_deref(), line_budget)?;

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
fn build_task_inputs(
    id: &str,
    symbol: Option<&str>,
    file: Option<&str>,
    line_budget: Option<u32>,
) -> Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();
    if let Some(s) = symbol {
        obj.insert("symbol_name".into(), json!(s));
    }
    if let Some(f) = file {
        obj.insert("file".into(), json!(f));
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
