//! Real-repo CI fixture for `rts-bench`.
//!
//! Clones a hardcoded set of representative OSS repos at pinned refs,
//! indexes each with the rts daemon, captures core indexer metrics,
//! and compares against a committed baseline. The goal is to surface
//! latent bugs that synthetic fixtures miss — e.g. extractor gaps
//! observable only against real codebases, or flakes that only
//! appear when full-workspace test runs touch the cancellation code.
//!
//! Surface (subcommands of `rts-bench real-repos`):
//!
//! - `run`      — clone (shallow, pinned ref), index, emit a JSON
//!                report to stdout (or `--out`).
//! - `baseline` — same as `run`, but write the report to the path
//!                given by `--baseline`. The maintainer runs this
//!                after intentionally changing a daemon metric and
//!                commits the resulting JSON.
//! - `compare`  — read the committed baseline + run fresh; emit a
//!                structured diff. Exit 0 if all metrics within
//!                tolerance; exit 1 if any metric exceeds tolerance.
//!
//! Metrics come from what's reachable through the rts-mcp tool
//! surface today: `daemon_stats` (cold-walk-completion timestamp,
//! reconciliation, cache counters), `outline_workspace.files_considered`,
//! and a `find_symbol(pattern="*")` count probe. `Daemon.Telemetry`
//! exposes more (per-method latency p50/p99, language set) on the
//! daemon's JSON-RPC wire but isn't routed through the MCP tool
//! surface — adding that route is out-of-scope for this PR. See
//! the `TODO(post-G)` fields on `RepoMetrics` for what lights up
//! when it does.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::mcp_runner::McpSession;

mod config;
pub mod diff;

pub use config::{Repo, RepoSet};
pub use diff::TolerancePolicy;

/// The hardcoded v1 repo set, embedded at compile time. The TOML is
/// the source of truth — `RepoSet::default_v1()` parses this string.
/// Updates land via PR (edit the TOML, regen the baseline, commit).
pub const REPOS_TOML: &str = include_str!("repos.toml");

/// Wire-stable per-repo metrics. One of these per `[[repo]]` entry,
/// captured by `run_one_repo` and rolled up into a `BenchReport`.
///
/// The field set is bounded by what's reachable via MCP today —
/// `Daemon.Stats`, `outline_workspace.files_considered`, and the
/// `find_symbol(pattern="*")` count probe. Fields that the daemon
/// computes internally but doesn't yet route through the MCP tool
/// surface (per-method latencies, language set) carry a TODO(post-G)
/// in the source and stay `None`. Per the v1 plan, we don't add new
/// MCP tools in this PR — the regression check focuses on metrics
/// that already had a wire path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoMetrics {
    pub name: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// `outline_workspace.files_considered` post-cold-walk. The
    /// total number of source files the daemon considered for
    /// indexing in the workspace (matches the language allowlist).
    pub files_indexed: u64,
    /// Wall-clock from `Workspace.Mount` to first `Daemon.Stats`
    /// response with `cold_walk_completed_at_ms != null`. Polled at
    /// 200ms intervals; precision is bounded by that cadence.
    pub cold_walk_ms: u64,
    /// Count of matches from `find_symbol(pattern="*", limit=4096)`.
    /// When `symbol_count_truncated` is true the value is the cap
    /// (4096) rather than the true total — the regression check
    /// still gates on exact match, so a truncated baseline + a
    /// truncated current both at 4096 compare equal. Distinct
    /// values mean either the underlying total changed or one of
    /// the two crossed the truncation boundary. This is the
    /// primary regression signal for extractor changes — the
    /// motivation for this whole bench (PR #116 PHP
    /// `method_declaration` gap would have shifted symbol_count
    /// on the Symfony fixture; #117 cancel flake would have
    /// surfaced as a `compare` failure on the cancellations
    /// counter, but that's a follow-up — see below).
    pub symbol_count: u64,
    /// True when the `find_symbol(pattern="*")` probe was truncated
    /// at the 4096 cap. Surfaced so a baseline-regen step knows it's
    /// looking at a capped number rather than the true symbol count.
    pub symbol_count_truncated: bool,
    /// Peak RSS of the `rts-daemon` child sampled at 25ms across the
    /// cold-mount → settled window. Reuses `footprint.rs`'s sampler;
    /// 0 when `pgrep` is unavailable or the daemon can't be resolved.
    pub memory_peak_rss_kb: u64,
    /// TODO(post-G): no daemon-side surface for unresolved-ref count
    /// yet (`Daemon.Stats` exposes `reconciliation` + cache counters
    /// but not call-graph gap metrics). When that lands, populate
    /// from the new field. Until then, this stays `None` and the
    /// regression check skips it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unresolved_refs_count: Option<u64>,
    /// TODO(post-G): `Daemon.Telemetry` exposes `languages_indexed`
    /// but that RPC isn't yet routed through the rts-mcp tool
    /// surface — only `daemon_stats` is. Adding a `daemon_telemetry`
    /// MCP tool is a one-line addition to `crates/rts-mcp/src/server.rs`
    /// but is out-of-scope for this PR per the v1 plan ("don't add
    /// new daemon-side counters; use what's wire-reachable today").
    /// When that tool lands, populate this from
    /// `daemon_telemetry.languages_indexed` and tighten the diff
    /// machinery to gate on exact set match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub languages_indexed: Option<Vec<String>>,
    /// TODO(post-G): per-method latency p50/p99 are tracked
    /// daemon-side (`MethodLatencyHistograms`) and surfaced via
    /// `Daemon.Telemetry` — but, like `languages_indexed`, that RPC
    /// isn't routed through the MCP tool surface today. Same
    /// out-of-scope rationale; same one-line follow-up to populate
    /// these from `method_latency_p50_ms` / `method_latency_p99_ms`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub find_symbol_latency_p50_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub find_symbol_latency_p99_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grep_latency_p50_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grep_latency_p99_ms: Option<u64>,
}

/// Top-level report: one envelope, N `RepoMetrics`. Stable wire shape;
/// the CI workflow reads this verbatim and humans pipe it through `jq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub version: u32,
    pub rts_bench_version: String,
    /// Unix epoch seconds when the run started — useful in long-lived
    /// nightly logs to spot which run produced which numbers.
    pub generated_at_unix_secs: u64,
    pub repos: Vec<RepoMetrics>,
}

/// Output report format selector for `run` / `baseline`.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum ReportFormat {
    /// Pretty JSON. The CI workflow reads this; `jq` consumes it cleanly.
    Json,
    /// One human-readable summary line per repo. Useful for ad-hoc shell runs.
    Text,
}

/// Per-repo measurement entry-point. Spawns rts-mcp + rts-daemon
/// against the repo's worktree, waits for the cold walk to settle,
/// captures every metric, then closes the session.
///
/// Wall-clock budget: ~30s per repo on first clone, <10s on warm
/// re-runs (the worktree is reused across invocations). The CI
/// workflow caches `~/.cargo` and the workspace pool directory, so
/// nightly runs land in the warm regime.
pub async fn run_one_repo(
    repo: &Repo,
    workspace_pool: &Path,
    rts_mcp_bin: &Path,
    rts_daemon_bin: &Path,
) -> Result<RepoMetrics> {
    let repo_path = ensure_cloned(repo, workspace_pool)?;

    // Per-repo workspace-scoped tmpdir for daemon runtime + state, so
    // concurrent or repeated runs don't fight over /tmp's default
    // socket and state path. Matches the pattern from latency.rs /
    // footprint.rs.
    let tmp_root = tempfile::tempdir().context("tempdir for real-repo run")?;
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

    let mount_t0 = Instant::now();
    let mut session =
        McpSession::spawn(rts_mcp_bin, rts_daemon_bin, &repo_path, &extra_env).await?;

    // Start the peak-RSS sampler against the daemon child. Mirrors
    // `footprint.rs::sample_rss_loop`. If pgrep is unavailable peak
    // stays 0 — see footprint.rs's same fallback.
    let daemon_pid = session
        .child_pid()
        .and_then(|pid| crate::footprint_helpers::find_child_pid(pid, "rts-daemon"));
    let peak_rss_bytes = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicU64::new(0));
    let sampler = if let Some(pid) = daemon_pid {
        let peak_clone = peak_rss_bytes.clone();
        let stop_clone = stop.clone();
        Some(tokio::spawn(async move {
            crate::footprint_helpers::sample_rss_loop(pid, peak_clone, stop_clone).await;
        }))
    } else {
        None
    };

    // Cold gate: poll Daemon.Stats until `cold_walk_completed_at_ms`
    // flips from null → a real timestamp. The handler emits null
    // until the writer's ColdWalkComplete flush commits. 120s ceiling
    // is enough for tokio (~70k LOC) on a CI runner; smaller repos
    // settle in seconds.
    let cold_walk_at_ms = wait_for_cold_walk(&mut session, mount_t0).await?;
    let cold_walk_ms = cold_walk_at_ms.unwrap_or_else(|| mount_t0.elapsed().as_millis() as u64);

    // Stop the sampler. Even if the daemon is still doing background
    // work (e.g. PageRank ranking), the cold-walk has committed and
    // the peak we care about is bounded by this window.
    stop.store(1, Ordering::Relaxed);
    if let Some(handle) = sampler {
        let _ = tokio::time::timeout(Duration::from_millis(200), handle).await;
    }
    // On Linux, prefer the kernel-tracked HWM when available — same
    // logic as footprint.rs.
    if let Some(pid) = daemon_pid {
        if let Some(hwm) = crate::footprint_helpers::linux_vm_hwm_bytes(pid) {
            let current = peak_rss_bytes.load(Ordering::Relaxed);
            if hwm > current {
                peak_rss_bytes.store(hwm, Ordering::Relaxed);
            }
        }
    }
    let memory_peak_rss_kb = peak_rss_bytes.load(Ordering::Relaxed) / 1024;

    // files_indexed: `outline_workspace.files_considered` post-cold-walk
    // is the file count that survived the daemon's language allowlist +
    // filter pipeline. Pulled via MCP since `daemon_telemetry` isn't
    // routed through the MCP tool surface (see RepoMetrics TODOs).
    let outline = session
        .tools_call("outline_workspace", json!({ "token_budget": 256 }), 5)
        .await?;
    let files_indexed = outline
        .result_body
        .as_ref()
        .and_then(|v| v["files_considered"].as_u64())
        .unwrap_or(0);

    // Symbol-count probe. `find_symbol(pattern="*", limit=4096)`
    // returns up to 4096 matches with a `truncated` flag. We expose
    // both: a baseline regen will record (4096, truncated=true) if
    // the repo exceeds the cap, and the regression check still gates
    // on exact match — a transition across the boundary moves either
    // the count or the truncation flag.
    let symbol_probe = session
        .tools_call("find_symbol", json!({ "pattern": "*", "limit": 4096 }), 5)
        .await?;
    let probe_body = symbol_probe
        .result_body
        .clone()
        .unwrap_or_else(|| json!({}));
    let symbol_count = probe_body["matches"]
        .as_array()
        .map(|a| a.len() as u64)
        .unwrap_or(0);
    let symbol_count_truncated = probe_body["truncated"].as_bool().unwrap_or(false);

    session.close().await?;

    Ok(RepoMetrics {
        name: repo.name.clone(),
        git_ref: repo.git_ref.clone(),
        files_indexed,
        cold_walk_ms,
        symbol_count,
        symbol_count_truncated,
        memory_peak_rss_kb,
        // TODO(post-G): see field-level docs on `RepoMetrics`.
        unresolved_refs_count: None,
        languages_indexed: None,
        find_symbol_latency_p50_ms: None,
        find_symbol_latency_p99_ms: None,
        grep_latency_p50_ms: None,
        grep_latency_p99_ms: None,
    })
}

/// Run the bench against the full repo set. Each repo is measured
/// sequentially (the daemon is single-workspace-pinned, so parallelism
/// across repos would require N daemons + N tmpdirs and isn't worth
/// the complexity for a 3-repo nightly).
pub async fn run_all(
    repos: &RepoSet,
    workspace_pool: &Path,
    rts_mcp_bin: &Path,
    rts_daemon_bin: &Path,
) -> Result<BenchReport> {
    std::fs::create_dir_all(workspace_pool)
        .with_context(|| format!("create workspace pool {}", workspace_pool.display()))?;

    let mut out = Vec::with_capacity(repos.repos.len());
    for repo in &repos.repos {
        eprintln!("real-repos: measuring {} @ {}", repo.name, repo.git_ref);
        let m = run_one_repo(repo, workspace_pool, rts_mcp_bin, rts_daemon_bin).await?;
        eprintln!(
            "real-repos:   files={} symbols={}{} cold_walk_ms={} rss_kb={}",
            m.files_indexed,
            m.symbol_count,
            if m.symbol_count_truncated {
                " (truncated)"
            } else {
                ""
            },
            m.cold_walk_ms,
            m.memory_peak_rss_kb
        );
        out.push(m);
    }

    let generated_at_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(BenchReport {
        version: 1,
        rts_bench_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at_unix_secs,
        repos: out,
    })
}

/// Poll `Daemon.Stats` every 200ms until `cold_walk_completed_at_ms`
/// is no longer null. The handler sets that field when the writer
/// commits its ColdWalkComplete flush.
///
/// Returns `Some(observed_ms)` — the elapsed wall-clock from
/// `mount_t0` to the first non-null observation — or `None` on
/// timeout. The 120s ceiling is comfortable for the v1 repo set
/// (largest is tokio @ ~70k LOC, which settles in 5-15s on CI).
async fn wait_for_cold_walk(session: &mut McpSession, mount_t0: Instant) -> Result<Option<u64>> {
    const POLL: Duration = Duration::from_millis(200);
    const TIMEOUT: Duration = Duration::from_secs(120);
    loop {
        let call = session.tools_call("daemon_stats", json!({}), 5).await?;
        if !call.is_error {
            if let Some(body) = call.result_body.as_ref() {
                if body["cold_walk_completed_at_ms"].is_number() {
                    return Ok(Some(mount_t0.elapsed().as_millis() as u64));
                }
            }
        }
        if mount_t0.elapsed() >= TIMEOUT {
            eprintln!(
                "real-repos: cold-walk timed out at {}s; recording elapsed anyway",
                TIMEOUT.as_secs()
            );
            return Ok(None);
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Ensure the repo is cloned at `workspace_pool/<name>` and checked
/// out at the pinned ref. Idempotent: a subsequent invocation that
/// finds an existing worktree at the right SHA is a no-op.
///
/// Uses shallow clone (`--depth 1`) for first-clone speed; refs are
/// fetched explicitly when the worktree exists but the ref is missing.
fn ensure_cloned(repo: &Repo, workspace_pool: &Path) -> Result<PathBuf> {
    let dest = workspace_pool.join(&repo.name);
    if dest.join(".git").exists() {
        // Existing checkout — make sure the ref is present + checked
        // out. We don't try to be clever about fetching only the
        // delta; a full fetch is bounded and the workspace pool is
        // cached across runs.
        run_git(
            &dest,
            &["fetch", "--tags", "--force", "origin", &repo.git_ref],
        )
        .or_else(|_| run_git(&dest, &["fetch", "--tags", "origin"]))?;
        run_git(&dest, &["checkout", "--detach", &repo.git_ref])
            .with_context(|| format!("git checkout {} in {}", repo.git_ref, dest.display()))?;
        return Ok(dest);
    }
    // Fresh clone. `--depth 1` with `--branch` works for both tags
    // and branches; if the ref happens to be a bare SHA this falls
    // back to a full clone + checkout.
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow!("workspace_pool has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let status = std::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            "--branch",
            &repo.git_ref,
            &repo.url,
            dest.to_str().ok_or_else(|| anyhow!("non-utf8 dest path"))?,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .with_context(|| format!("git clone {} → {}", repo.url, dest.display()))?;
    if !status.success() {
        // Branch/tag form failed (maybe it's a SHA, or the ref isn't
        // reachable from a depth-1 clone). Try a full clone + checkout.
        let _ = std::fs::remove_dir_all(&dest);
        let status2 = std::process::Command::new("git")
            .args([
                "clone",
                &repo.url,
                dest.to_str().ok_or_else(|| anyhow!("non-utf8 dest path"))?,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .with_context(|| format!("git clone (full) {} → {}", repo.url, dest.display()))?;
        anyhow::ensure!(
            status2.success(),
            "git clone failed for {} (both shallow and full)",
            repo.url
        );
        run_git(&dest, &["checkout", "--detach", &repo.git_ref])?;
    }
    Ok(dest)
}

fn run_git(cwd: &Path, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .with_context(|| format!("spawn git {args:?} in {}", cwd.display()))?;
    anyhow::ensure!(status.success(), "git {args:?} failed in {}", cwd.display());
    Ok(())
}

/// Render a brief human-readable summary of a `BenchReport`. Used by
/// `run` when `--report text` is selected.
pub fn render_text(report: &BenchReport) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "real-repos report v{} (rts-bench {}, n={} repos)",
        report.version,
        report.rts_bench_version,
        report.repos.len()
    );
    for r in &report.repos {
        let _ = writeln!(
            s,
            "  {} @ {}: files={} symbols={}{} cold_walk_ms={} rss_kb={}",
            r.name,
            r.git_ref,
            r.files_indexed,
            r.symbol_count,
            if r.symbol_count_truncated {
                " (cap)"
            } else {
                ""
            },
            r.cold_walk_ms,
            r.memory_peak_rss_kb
        );
    }
    s
}

/// Print a `BenchReport` to `stdout` in the requested format.
pub fn print_report(report: &BenchReport, fmt: ReportFormat) -> Result<()> {
    match fmt {
        ReportFormat::Json => {
            println!("{}", serde_json::to_string_pretty(report)?);
        }
        ReportFormat::Text => {
            print!("{}", render_text(report));
        }
    }
    Ok(())
}

/// Write a `BenchReport` to a JSON file (used by `baseline`).
pub fn write_report_json(path: &Path, report: &BenchReport) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report).context("encode real-repos report")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, &bytes).with_context(|| format!("write {}", path.display()))?;
    // Trailing newline so the file is well-formed under POSIX `cat`.
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(b"\n")
        })
        .ok();
    Ok(())
}

/// Read a baseline report from disk.
pub fn read_report_json(path: &Path) -> Result<BenchReport> {
    let bytes = std::fs::read(path).with_context(|| format!("read baseline {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("decode baseline {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_toml_parses() {
        let set = RepoSet::from_toml(REPOS_TOML).expect("parse embedded repos.toml");
        assert!(
            set.repos.len() >= 3,
            "expected >=3 repos in v1; got {}",
            set.repos.len()
        );
        let names: Vec<&str> = set.repos.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"tokio"));
        assert!(names.contains(&"flask"));
        assert!(names.contains(&"gin"));
    }

    fn sample(name: &str, files: u64, symbols: u64) -> RepoMetrics {
        RepoMetrics {
            name: name.into(),
            git_ref: "v1".into(),
            files_indexed: files,
            cold_walk_ms: 1500,
            symbol_count: symbols,
            symbol_count_truncated: false,
            memory_peak_rss_kb: 100_000,
            unresolved_refs_count: None,
            languages_indexed: None,
            find_symbol_latency_p50_ms: None,
            find_symbol_latency_p99_ms: None,
            grep_latency_p50_ms: None,
            grep_latency_p99_ms: None,
        }
    }

    #[test]
    fn render_text_includes_every_repo_name() {
        let report = BenchReport {
            version: 1,
            rts_bench_version: "0.0.0-test".into(),
            generated_at_unix_secs: 0,
            repos: vec![sample("tokio", 123, 8000), sample("flask", 50, 1200)],
        };
        let text = render_text(&report);
        assert!(text.contains("tokio @ v1"));
        assert!(text.contains("flask @ v1"));
        assert!(text.contains("files=123"));
        assert!(text.contains("files=50"));
    }

    #[test]
    fn report_roundtrips_through_json() {
        let mut m = sample("tokio", 123, 4096);
        m.git_ref = "tokio-1.47.0".into();
        m.symbol_count_truncated = true;
        m.unresolved_refs_count = Some(7);
        m.languages_indexed = Some(vec!["rust".into(), "markdown".into()]);
        m.find_symbol_latency_p50_ms = Some(2);
        let report = BenchReport {
            version: 1,
            rts_bench_version: "0.0.0-test".into(),
            generated_at_unix_secs: 42,
            repos: vec![m],
        };
        let s = serde_json::to_string(&report).unwrap();
        let back: BenchReport = serde_json::from_str(&s).unwrap();
        assert_eq!(back.repos[0].name, "tokio");
        assert_eq!(back.repos[0].git_ref, "tokio-1.47.0");
        assert_eq!(back.repos[0].symbol_count, 4096);
        assert!(back.repos[0].symbol_count_truncated);
        assert_eq!(back.repos[0].unresolved_refs_count, Some(7));
        assert_eq!(
            back.repos[0].languages_indexed,
            Some(vec!["rust".into(), "markdown".into()])
        );
        assert_eq!(back.repos[0].find_symbol_latency_p50_ms, Some(2));
        // Field uses `ref` as the wire name — confirm we don't double-escape.
        assert!(s.contains("\"ref\":\"tokio-1.47.0\""));
    }

    #[test]
    fn optional_fields_omitted_when_none() {
        let report = BenchReport {
            version: 1,
            rts_bench_version: "0.0.0-test".into(),
            generated_at_unix_secs: 0,
            repos: vec![sample("tokio", 0, 0)],
        };
        let s = serde_json::to_string(&report).unwrap();
        for omitted in [
            "unresolved_refs_count",
            "languages_indexed",
            "find_symbol_latency_p50_ms",
            "find_symbol_latency_p99_ms",
            "grep_latency_p50_ms",
            "grep_latency_p99_ms",
        ] {
            assert!(
                !s.contains(omitted),
                "field `{omitted}` should be skipped when None: {s}"
            );
        }
    }
}
