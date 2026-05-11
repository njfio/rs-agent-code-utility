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
        /// Symbol name the task should look up (most tasks need this).
        #[arg(long)]
        symbol: Option<String>,
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
                    out,
                    dry_run,
                },
        } => run_one(id, workspace, symbol, out, dry_run).await,
        Cmd::Fixture {
            sub:
                FixtureCmd::Restore {
                    corpus_lock,
                    corpus_root,
                },
        } => restore_fixtures(corpus_lock, corpus_root).await,
    }
}

async fn run_one(
    id: String,
    workspace: PathBuf,
    symbol: Option<String>,
    out: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let workspace = std::fs::canonicalize(&workspace)
        .with_context(|| format!("canonicalize {}", workspace.display()))?;
    let rts_mcp_bin = resolve_bin("rts-mcp")?;
    let rts_daemon_bin = resolve_bin("rts-daemon")?;

    let inputs = match (id.as_str(), symbol.as_deref()) {
        (_, Some(s)) => json!({ "symbol_name": s }),
        ("locate_def", None) => {
            return Err(anyhow!(
                "task locate_def requires --symbol; pick a function in the workspace"
            ));
        }
        (_, None) => json!({}),
    };

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
