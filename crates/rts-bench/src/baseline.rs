//! Baseline retrieval runner: subprocess `rg` + simulated `read_file`.
//!
//! Models what an agent currently has to do *without* `rts-mcp`:
//!
//!   1. Shell out to ripgrep for a pattern.
//!   2. Read the candidate files in full to extract the symbol body.
//!   3. Feed the total of (rg output + file bodies) to the LLM as context.
//!
//! Step 1+2 are what consumes the agent's token budget. We capture both
//! pieces, then call `token::approx_tokens_total` to land on a single
//! "baseline tokens" number that's comparable to the MCP runner's
//! `tokens_returned` sum.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use tokio::process::Command;

use crate::token;

/// Result of running the baseline path on one task. The fields are wire-stable
/// so the bench report can decode this verbatim into `baseline.*`.
#[derive(Debug, Clone)]
pub struct BaselineRun {
    /// Total approximate tokens the agent would have paid for, summing the
    /// `rg` stdout and every read file.
    pub tokens: u64,
    /// `rg` matches' stdout, raw bytes — counted as tokens the agent would
    /// have to read through.
    pub rg_stdout_bytes: usize,
    /// Total bytes of file content the agent would have had to read.
    pub file_bytes_read: usize,
    /// Files actually opened by the simulated `read_file` step.
    pub files_read: Vec<PathBuf>,
    /// Wall-clock duration of the baseline run, in milliseconds. Bench
    /// reports surface this for the latency-band tracker.
    pub elapsed_ms: u128,
}

/// Probe whether `rg` is on `PATH`. Skipped-test signal for CI on machines
/// without ripgrep installed.
pub async fn rg_available() -> bool {
    Command::new("rg")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run `rg -n --color=never <pattern>` inside `workspace_root`. Returns the
/// raw stdout. Errors only on subprocess spawn / I/O failures — a 0-match
/// `rg` (exit code 1) is normalised to an empty `Vec<u8>`.
pub async fn rg_search(workspace_root: &Path, pattern: &str) -> Result<Vec<u8>> {
    let output = Command::new("rg")
        .arg("-n")
        .arg("--color=never")
        .arg("--no-heading")
        .arg(pattern)
        .arg(workspace_root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .with_context(|| format!("spawn rg {pattern} {}", workspace_root.display()))?;

    match output.status.code() {
        Some(0) | Some(1) => Ok(output.stdout),
        Some(other) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow!("rg exited with status {other}: {stderr}"))
        }
        None => Err(anyhow!("rg killed by signal")),
    }
}

/// Parse `rg -n` output into a deduplicated list of file paths. Each line
/// is `path:line:content` (or `path` for `--files-with-matches` mode — we
/// don't use that path here). Returns paths in the order they first appear.
pub fn parse_rg_paths(rg_stdout: &[u8]) -> Vec<PathBuf> {
    let text = match std::str::from_utf8(rg_stdout) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut seen: std::collections::BTreeSet<PathBuf> = Default::default();
    let mut ordered: Vec<PathBuf> = Vec::new();
    for line in text.lines() {
        if let Some((path, _rest)) = line.split_once(':') {
            let p = PathBuf::from(path);
            if seen.insert(p.clone()) {
                ordered.push(p);
            }
        }
    }
    ordered
}

/// Run the full baseline path for "locate-then-read":
/// 1. `rg -n <pattern>` for the symbol name.
/// 2. Read every candidate file in full (`simulated read_file`).
/// 3. Return totals.
pub async fn locate_and_read(
    workspace_root: &Path,
    pattern: &str,
    max_files: usize,
) -> Result<BaselineRun> {
    let start = std::time::Instant::now();
    let stdout = rg_search(workspace_root, pattern).await?;
    let mut paths = parse_rg_paths(&stdout);
    paths.truncate(max_files);

    let mut total_file_bytes = 0usize;
    let mut bodies: Vec<Vec<u8>> = Vec::with_capacity(paths.len());
    for p in &paths {
        match tokio::fs::read(p).await {
            Ok(b) => {
                total_file_bytes += b.len();
                bodies.push(b);
            }
            Err(e) => {
                tracing::warn!(target: "rts_bench::baseline", "read {} failed: {e}", p.display());
            }
        }
    }

    let mut iters: Vec<&[u8]> = Vec::with_capacity(bodies.len() + 1);
    iters.push(stdout.as_slice());
    for b in &bodies {
        iters.push(b.as_slice());
    }
    let tokens = token::approx_tokens_total(iters);

    Ok(BaselineRun {
        tokens,
        rg_stdout_bytes: stdout.len(),
        file_bytes_read: total_file_bytes,
        files_read: paths,
        elapsed_ms: start.elapsed().as_millis(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rg_paths_dedupes_in_first_seen_order() {
        let raw = b"\
src/lib.rs:10:pub fn alpha() {
src/lib.rs:42:    alpha();
src/mod.rs:7:use crate::alpha;
src/lib.rs:99:    let _ = alpha;
";
        let paths = parse_rg_paths(raw);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], PathBuf::from("src/lib.rs"));
        assert_eq!(paths[1], PathBuf::from("src/mod.rs"));
    }

    #[test]
    fn parse_rg_paths_empty_input() {
        assert!(parse_rg_paths(b"").is_empty());
    }
}
