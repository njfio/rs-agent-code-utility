//! Integration test for `rts-bench task run get_body`.
//!
//! Seeds a long-ish module (~50 lines) where the target function is a
//! small fraction of total content. Baseline reads the whole file;
//! MCP returns just the function bytes. Reduction should be > 50%.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::process::Command;

fn rts_bench_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-bench"))
}

fn sibling(name: &str) -> PathBuf {
    let me = rts_bench_bin();
    me.parent().expect("CARGO_BIN_EXE has parent").join(name)
}

const MODULE_SOURCE: &str = "\
//! A small but realistic module with some prelude noise around the
//! target function. The baseline path reads the entire file in full;
//! the MCP path returns only `target_fn`'s byte slice.

use std::collections::HashMap;
use std::path::PathBuf;

/// A type the agent doesn't actually need.
pub struct Decoy {
    pub name: String,
    pub kind: u32,
    pub values: HashMap<String, PathBuf>,
}

impl Decoy {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: 0,
            values: HashMap::new(),
        }
    }

    pub fn with_kind(mut self, kind: u32) -> Self {
        self.kind = kind;
        self
    }

    pub fn push_value(&mut self, k: impl Into<String>, v: PathBuf) {
        self.values.insert(k.into(), v);
    }
}

/// Documentation block for `target_fn`. The agent wants only this fn.
pub fn target_fn(x: u32, y: u32) -> u32 {
    let sum = x.saturating_add(y);
    let doubled = sum.saturating_mul(2);
    doubled.saturating_sub(1)
}

/// Another decoy after the target.
pub fn unrelated_after(input: &str) -> String {
    input.chars().rev().collect()
}

pub const PADDING_A: u32 = 42;
pub const PADDING_B: u32 = 1337;
";

async fn rg_available() -> bool {
    Command::new("rg")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_body_end_to_end() -> Result<()> {
    if !rg_available().await {
        eprintln!("ripgrep (`rg`) not on PATH; skipping get_body");
        return Ok(());
    }

    let workspace = tempfile::tempdir()?;
    let runtime = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let home = tempfile::tempdir()?;
    let out_dir = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700));
    std::fs::write(workspace.path().join("module.rs"), MODULE_SOURCE)?;

    let rts_mcp_bin = sibling("rts-mcp");
    let rts_daemon_bin = sibling("rts-daemon");
    assert!(rts_mcp_bin.is_file(), "missing {}", rts_mcp_bin.display());
    assert!(
        rts_daemon_bin.is_file(),
        "missing {}",
        rts_daemon_bin.display()
    );

    let report_path = out_dir.path().join("bench-test.json");
    let status = Command::new(rts_bench_bin())
        .arg("task")
        .arg("run")
        .arg("get_body")
        .arg("--workspace")
        .arg(workspace.path())
        .arg("--symbol")
        .arg("target_fn")
        .arg("--out")
        .arg(&report_path)
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_STATE_HOME", state.path())
        .env("HOME", home.path())
        .env("RTS_MCP_BIN", &rts_mcp_bin)
        .env("RTS_DAEMON_BIN", &rts_daemon_bin)
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("spawn rts-bench")?;
    let stdout = String::from_utf8_lossy(&status.stdout);
    let stderr = String::from_utf8_lossy(&status.stderr);
    assert!(
        status.status.success(),
        "rts-bench task run get_body failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    let bytes = tokio::time::timeout(Duration::from_secs(2), tokio::fs::read(&report_path))
        .await
        .context("timeout waiting for bench report")??;
    let report: Value = serde_json::from_slice(&bytes)?;

    let task = &report["tasks"]["get_body"];
    let baseline = task["baseline"]["tokens"].as_u64().unwrap_or(0);
    let mcp = task["mcp"]["tokens"].as_u64().unwrap_or(0);
    let reduction = task["reduction_pct"].as_f64().unwrap_or(0.0);

    assert!(baseline > 0, "baseline tokens should be > 0; got {task}");
    assert!(mcp > 0, "mcp tokens should be > 0; got {task}");
    assert!(
        reduction > 50.0,
        "expected >50% reduction (target_fn is small fraction of file); got {reduction:.1}% on {task}"
    );
    Ok(())
}
