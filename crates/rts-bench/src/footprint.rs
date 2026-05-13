//! Footprint benchmark (S3) for the rts-mcp stack.
//!
//! Companion to S1 latency (`latency.rs`). Measures the *cost*
//! dimensions of running an indexed daemon against a real-sized
//! workspace:
//!
//! - **`build_time_ms`** — wall-clock from `Workspace.Mount` until the
//!   first `Index.FindSymbol` for a known synth symbol returns OK. This
//!   is the time an agent waits before the daemon stops returning
//!   `INDEX_NOT_READY`.
//! - **`peak_rss_bytes`** — high-water-mark resident set size of the
//!   `rts-daemon` child during the build window, sampled at 25ms
//!   intervals via `ps -o rss=`. On Linux we also read
//!   `/proc/<pid>/status:VmHWM` once at the end and take the larger
//!   of the two — kernel-tracked HWM is more accurate than sampling.
//! - **`index_size_bytes`** — on-disk size of the daemon's redb file
//!   (`${XDG_STATE_HOME}/rts/<workspace_id>/db.redb`), measured after
//!   the index is ready.
//!
//! These are the three numbers an operator needs to answer "is this
//! daemon production-ready for my repo size?". The plan's targets are:
//!
//! | metric          | target (100k LOC)        |
//! |-----------------|--------------------------|
//! | build_time_ms   | < 30 000 (30 s)          |
//! | peak_rss_bytes  | < 1 000 000 000 (1 GiB)  |
//! | index_size_bytes| < 200 000 000 (200 MiB)  |
//!
//! v0 ships the harness. Footprint under churn (re-indexing after
//! `git checkout` of a different ref) is a v1.1 surface.

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::mcp_runner::McpSession;

/// Wire-stable footprint report. One run produces one of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FootprintReport {
    pub version: u32,
    pub rts_bench_version: String,
    pub workspace_path: String,
    pub synth_loc: usize,
    pub files: u32,
    pub symbols: u32,
    /// Wall-clock from `Workspace.Mount` to first non-INDEX_NOT_READY
    /// response for a known synth symbol. This is "time until the
    /// daemon answers", which agents care about for their startup
    /// latency — separate from full-index time below.
    pub build_time_ms: u128,
    /// Wall-clock from `Workspace.Mount` to the full index settling
    /// (no new files appearing in `outline_workspace.files_considered`
    /// across two consecutive 200ms polls). On a healthy run this is
    /// 2× to 10× build_time_ms because the writer keeps indexing in
    /// the background after the first symbol is queryable.
    pub full_index_time_ms: u128,
    /// High-water-mark RSS of the daemon child observed across the
    /// *full* index window (mount → settled). Sampled at 25ms
    /// intervals via `ps -o rss=`; on Linux we also consult
    /// `/proc/<pid>/status:VmHWM` and take the max.
    pub peak_rss_bytes: u64,
    /// Size of `db.redb` on disk after the index has fully settled.
    pub index_size_bytes: u64,
    /// Derived ratio: `index_size_bytes / symbols`. Useful for sizing
    /// expectations on bigger repos. Zero when symbols is 0.
    pub bytes_per_symbol: u64,
}

/// Run the footprint benchmark.
///
/// Steps:
/// 1. Generate (or use the cached) synth workspace at `target_loc` LOC.
/// 2. Launch `rts-mcp` (which spawns `rts-daemon`) and grab the daemon's
///    PID via `ps` walking back from the mcp child.
/// 3. Poll RSS at 25ms intervals while waiting for `find_symbol` to
///    return OK on a known synth symbol. Record build_time when it does.
/// 4. Walk the state dir to find `db.redb` and stat it.
/// 5. Compose the report.
pub async fn run(
    rts_mcp_bin: &Path,
    rts_daemon_bin: &Path,
    target_loc: usize,
    tmp_root: &Path,
) -> Result<FootprintReport> {
    let (workspace, symbols, files) =
        crate::latency::prepare_workspace(None, Some(target_loc), tmp_root)?;
    let runtime_dir = tmp_root.join("runtime");
    let state_dir = tmp_root.join("state");
    std::fs::create_dir_all(&runtime_dir)?;
    std::fs::create_dir_all(&state_dir)?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700));

    let extra_env: Vec<(&str, &str)> = vec![
        ("XDG_RUNTIME_DIR", runtime_dir.to_str().unwrap_or("")),
        ("XDG_STATE_HOME", state_dir.to_str().unwrap_or("")),
        ("HOME", tmp_root.to_str().unwrap_or("")),
        ("RTS_IDLE_SHUTDOWN_SECS", "300"),
    ];

    let probe = symbols
        .first()
        .ok_or_else(|| anyhow::anyhow!("synth workspace produced no symbols"))?
        .clone();

    // Mount handshake happens inside `McpSession::spawn`. We treat
    // *that* moment as t0 — it's when the daemon receives the mount
    // and starts its initial walk.
    let mount_t0 = Instant::now();
    let mut session =
        McpSession::spawn(rts_mcp_bin, rts_daemon_bin, &workspace, &extra_env).await?;

    // Resolve the daemon PID. The mcp child forks rts-daemon as a
    // grandchild; we walk `pgrep -P <mcp_pid>` to find it. If pgrep is
    // unavailable or we can't find the daemon, peak RSS is reported as
    // 0 and the rest of the metrics still ship.
    let daemon_pid = session
        .child_pid()
        .and_then(|mcp_pid| find_child_pid(mcp_pid, "rts-daemon"));

    // Start the peak-RSS sampler. The sampler runs until we drop the
    // sentinel `Arc` — done via the `stop` flag and joining the task.
    let peak_rss = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicU64::new(0));
    let sampler = if let Some(pid) = daemon_pid {
        let peak_clone = peak_rss.clone();
        let stop_clone = stop.clone();
        Some(tokio::spawn(async move {
            sample_rss_loop(pid, peak_clone, stop_clone).await;
        }))
    } else {
        None
    };

    // Wait for the first non-INDEX_NOT_READY response. The mcp_runner
    // retries internally on INDEX_NOT_READY, so a 60-retry budget gives
    // us up to ~7s of slack at the default 120ms backoff.
    let probe_call = session
        .tools_call("find_symbol", json!({ "name": probe }), 60)
        .await
        .context("probe find_symbol")?;
    anyhow::ensure!(
        !probe_call.is_error,
        "probe `find_symbol({})` errored after retries",
        probe
    );
    let build_time = mount_t0.elapsed();

    // Now wait for the *full* index to settle. The writer keeps
    // ingesting files after the first symbol is queryable, so
    // build_time only answers "can the agent start using us?".
    // For peak RSS and final index size we need to keep sampling
    // until the index stops growing. The signal we use is
    // `outline_workspace.files_considered` — when two consecutive
    // 200ms polls return the same number, the writer is done with
    // the initial walk. Bounded by a 60s ceiling so a broken writer
    // can't hang the bench forever.
    let full_index_time = wait_for_index_settled(&mut session, mount_t0).await;

    // Tell the sampler to stop, give it a beat to wind down, and pull
    // the peak. The sampler ran across the full mount → settled
    // window, so peak_rss now reflects the high-water mark of the
    // entire build (not just the time-to-first-query).
    stop.store(1, Ordering::Relaxed);
    if let Some(handle) = sampler {
        let _ = tokio::time::timeout(Duration::from_millis(200), handle).await;
    }
    // On Linux, prefer the kernel-tracked HWM when available — it
    // catches transient peaks that the 25ms sampler may have missed.
    if let Some(pid) = daemon_pid {
        if let Some(hwm) = linux_vm_hwm_bytes(pid) {
            let current = peak_rss.load(Ordering::Relaxed);
            if hwm > current {
                peak_rss.store(hwm, Ordering::Relaxed);
            }
        }
    }

    // Walk the state dir to find db.redb. The path is
    // `<state>/rts/<workspace_id>/db.redb`; we don't know the
    // workspace_id (it's a hash) so we scan one level deep under
    // `<state>/rts/`.
    let index_size = locate_index_size(&state_dir).unwrap_or(0);

    session.close().await?;

    let symbols_count = symbols.len() as u32;
    let index_size_bytes = index_size;
    let bytes_per_symbol = if symbols_count > 0 {
        index_size_bytes / symbols_count as u64
    } else {
        0
    };
    Ok(FootprintReport {
        version: 1,
        rts_bench_version: env!("CARGO_PKG_VERSION").to_string(),
        workspace_path: workspace.display().to_string(),
        synth_loc: target_loc,
        files: files.len() as u32,
        symbols: symbols_count,
        build_time_ms: build_time.as_millis(),
        full_index_time_ms: full_index_time.as_millis(),
        peak_rss_bytes: peak_rss.load(Ordering::Relaxed),
        index_size_bytes,
        bytes_per_symbol,
    })
}

/// Poll `outline_workspace` until `files_considered` stops growing
/// across two consecutive 200ms checks (the writer is done with the
/// initial walk), or until a 60s hard deadline elapses.
///
/// Returns elapsed wall-clock from `mount_t0` to settle. The bench
/// continues even if we time out — the report will carry the elapsed
/// number as-is, which is itself useful signal ("this workspace size
/// did not settle in 60s").
async fn wait_for_index_settled(session: &mut McpSession, mount_t0: Instant) -> Duration {
    const POLL_INTERVAL: Duration = Duration::from_millis(200);
    const DEADLINE: Duration = Duration::from_secs(60);
    let mut last_seen: i64 = -1;
    loop {
        let call = session
            .tools_call("outline_workspace", json!({ "token_budget": 256 }), 0)
            .await;
        let files_considered = match call {
            Ok(c) if !c.is_error => extract_files_considered(&c).unwrap_or(-1),
            _ => -1,
        };
        if files_considered >= 0 && files_considered == last_seen && files_considered > 0 {
            return mount_t0.elapsed();
        }
        last_seen = files_considered;
        if mount_t0.elapsed() >= DEADLINE {
            return mount_t0.elapsed();
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Pull `outline_workspace.files_considered` out of an `McpCall`. The
/// daemon returns this as a top-level integer in the JSON body of the
/// first content item. Returns `None` if the response wasn't JSON, the
/// field is missing, or it isn't an integer.
fn extract_files_considered(call: &crate::mcp_runner::McpCall) -> Option<i64> {
    call.result_body
        .as_ref()
        .and_then(|v| v["files_considered"].as_i64())
}

/// Write a report to disk as pretty JSON.
pub fn write_report(path: &Path, report: &FootprintReport) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report).context("encode footprint report")?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Best-effort: find the first child process of `parent_pid` whose
/// executable name contains `needle`. Uses `pgrep -P <pid>` then `ps -o
/// comm=` for each candidate. Returns `None` if pgrep is missing,
/// returns no rows, or no candidate matches.
fn find_child_pid(parent_pid: u32, needle: &str) -> Option<u32> {
    // Retry briefly — the daemon child may take a few ms to appear
    // after the mcp handshake returns.
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        if let Some(pid) = pgrep_first_match(parent_pid, needle) {
            return Some(pid);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

fn pgrep_first_match(parent_pid: u32, needle: &str) -> Option<u32> {
    let out = std::process::Command::new("pgrep")
        .arg("-P")
        .arg(parent_pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let pid: u32 = match line.trim().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Some(comm) = ps_comm(pid) {
            if comm.contains(needle) {
                return Some(pid);
            }
        }
    }
    None
}

fn ps_comm(pid: u32) -> Option<String> {
    let out = std::process::Command::new("ps")
        .args(["-o", "comm=", "-p"])
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Sample RSS at 25ms cadence until `stop` is set.
async fn sample_rss_loop(pid: u32, peak: Arc<AtomicU64>, stop: Arc<AtomicU64>) {
    while stop.load(Ordering::Relaxed) == 0 {
        if let Some(rss) = ps_rss_bytes(pid) {
            let cur = peak.load(Ordering::Relaxed);
            if rss > cur {
                peak.store(rss, Ordering::Relaxed);
            }
        } else {
            // Daemon went away; stop sampling.
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// `ps -o rss= -p <pid>` returns RSS in kilobytes on both macOS and
/// Linux. Convert to bytes. Returns `None` when the process is gone
/// or `ps` is unavailable.
fn ps_rss_bytes(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p"])
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let kib: u64 = s.trim().parse().ok()?;
    Some(kib.saturating_mul(1024))
}

/// On Linux, parse `/proc/<pid>/status:VmHWM` (kilobytes). Returns
/// `None` on macOS / when /proc is unavailable.
fn linux_vm_hwm_bytes(pid: u32) -> Option<u64> {
    let path = format!("/proc/{pid}/status");
    let content = std::fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kib: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kib.saturating_mul(1024));
        }
    }
    None
}

/// Walk `<state>/rts/<workspace_id>/db.redb` for the first match.
/// Returns the file size in bytes, or `None` if no db.redb is found.
fn locate_index_size(state_dir: &Path) -> Option<u64> {
    let rts_dir = state_dir.join("rts");
    let entries = std::fs::read_dir(&rts_dir).ok()?;
    for e in entries.flatten() {
        let candidate = e.path().join("db.redb");
        if let Ok(meta) = candidate.metadata() {
            if meta.is_file() {
                return Some(meta.len());
            }
        }
    }
    None
}

/// Default target LOC for the footprint bench.
pub const DEFAULT_TARGET_LOC: usize = 100_000;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn ps_rss_for_current_process_is_nonzero() {
        // `std::process::id()` returns the test process's PID. ps must
        // be on PATH on Unix CI runners (it is on both macOS and
        // ubuntu-latest).
        let pid = std::process::id();
        let rss = ps_rss_bytes(pid).expect("ps -o rss= should work for current pid");
        assert!(
            rss > 0,
            "expected nonzero RSS for current process; got {rss}"
        );
        // Sanity: tests don't usually exceed 4 GiB.
        assert!(rss < 4u64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn locate_index_size_finds_db_redb() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("rts").join("ws-abc123");
        fs::create_dir_all(&nested).unwrap();
        let db = nested.join("db.redb");
        fs::write(&db, vec![0u8; 4096]).unwrap();
        let sz = locate_index_size(tmp.path()).expect("should find db.redb");
        assert_eq!(sz, 4096);
    }

    #[test]
    fn locate_index_size_returns_none_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(locate_index_size(tmp.path()).is_none());
        // Even if rts/ exists but no db.redb inside.
        fs::create_dir_all(tmp.path().join("rts").join("ws-empty")).unwrap();
        assert!(locate_index_size(tmp.path()).is_none());
    }

    #[test]
    fn report_serializes_with_stable_field_names() {
        let r = FootprintReport {
            version: 1,
            rts_bench_version: "0.0.0-test".into(),
            workspace_path: "/tmp/ws".into(),
            synth_loc: 1000,
            files: 17,
            symbols: 170,
            build_time_ms: 1234,
            full_index_time_ms: 5678,
            peak_rss_bytes: 50_000_000,
            index_size_bytes: 1_000_000,
            bytes_per_symbol: 5_882,
        };
        let json = serde_json::to_string(&r).unwrap();
        // The names below are the wire contract that operators write
        // dashboards against — keep them stable across bench-tool
        // versions.
        for needle in [
            "\"version\":1",
            "\"workspace_path\":",
            "\"build_time_ms\":1234",
            "\"full_index_time_ms\":5678",
            "\"peak_rss_bytes\":50000000",
            "\"index_size_bytes\":1000000",
            "\"bytes_per_symbol\":5882",
            "\"files\":17",
            "\"symbols\":170",
        ] {
            assert!(json.contains(needle), "missing `{needle}` in {json}");
        }
    }

    #[test]
    fn linux_vm_hwm_is_optional() {
        // On macOS this returns None and that's expected. On Linux
        // it should return Some for the current pid. Either way, the
        // call must not panic — that's all we assert.
        let pid = std::process::id();
        let _ = linux_vm_hwm_bytes(pid);
    }

    #[test]
    fn extract_files_considered_reads_field() {
        use crate::mcp_runner::McpCall;
        let call = McpCall {
            tokens: 0,
            content_items: 1,
            response_text_len: 0,
            elapsed_ms: 0,
            is_error: false,
            result_body: Some(serde_json::json!({
                "outline_text": "...",
                "files_considered": 42
            })),
        };
        assert_eq!(extract_files_considered(&call), Some(42));
    }

    #[test]
    fn extract_files_considered_returns_none_when_missing() {
        use crate::mcp_runner::McpCall;
        let call = McpCall {
            tokens: 0,
            content_items: 0,
            response_text_len: 0,
            elapsed_ms: 0,
            is_error: false,
            result_body: None,
        };
        assert!(extract_files_considered(&call).is_none());

        let call2 = McpCall {
            tokens: 0,
            content_items: 0,
            response_text_len: 0,
            elapsed_ms: 0,
            is_error: false,
            result_body: Some(serde_json::json!({ "other": "value" })),
        };
        assert!(extract_files_considered(&call2).is_none());
    }
}
