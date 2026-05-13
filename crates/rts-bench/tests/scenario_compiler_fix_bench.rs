//! Integration test for `rts-bench task run scenario_compiler_fix`.
//!
//! Models the agent flow that responds to a compiler error at a specific
//! `file:line` and follows one referenced symbol. The baseline reads
//! whole files; MCP makes 2 targeted calls (read_symbol_at + read_symbol).
//! With a hub-spoke fixture where the enclosing fn is small relative to
//! the file, the reduction should be substantial.

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

const ENCLOSING_MODULE: &str = "\
//! Module with several functions; only one is the agent's target.
use std::collections::HashMap;

pub struct Padding { a: u32, b: u32, c: HashMap<String, u32> }

impl Padding {
    pub fn new() -> Self { Self { a: 0, b: 0, c: HashMap::new() } }
    pub fn bump(&mut self) { self.a += 1; self.b += 1; }
    pub fn dump(&self) -> String { format!(\"{} {}\", self.a, self.b) }
}

pub fn unrelated_one(x: u32) -> u32 { x.saturating_add(1) }
pub fn unrelated_two(y: u32) -> u32 { y.saturating_mul(2) }

/// The function the bench scenario anchors on. The line of `target_helper`
/// inside this body is what `--line` points at — read_symbol_at returns
/// just this fn, while the baseline reads the whole module.
pub fn enclosing_fn(input: u32) -> u32 {
    let stepped = target_helper(input);
    let doubled = stepped.saturating_mul(2);
    doubled.saturating_sub(1)
}

pub fn trailing_one(x: u32) -> u32 { x.saturating_add(7) }
pub fn trailing_two(x: u32) -> u32 { x.saturating_add(11) }
";

const HELPER_MODULE: &str = "\
//! Where `target_helper` lives.
pub fn target_helper(x: u32) -> u32 {
    x.saturating_add(1)
}
pub fn other_helper(x: u32) -> u32 {
    x.saturating_add(2)
}
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
async fn scenario_compiler_fix_end_to_end() -> Result<()> {
    if !rg_available().await {
        eprintln!("ripgrep (`rg`) not on PATH; skipping scenario_compiler_fix");
        return Ok(());
    }

    let workspace = tempfile::tempdir()?;
    let runtime = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let home = tempfile::tempdir()?;
    let out_dir = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700));
    std::fs::write(workspace.path().join("module.rs"), ENCLOSING_MODULE)?;
    std::fs::write(workspace.path().join("helper.rs"), HELPER_MODULE)?;

    let rts_mcp_bin = sibling("rts-mcp");
    let rts_daemon_bin = sibling("rts-daemon");
    assert!(rts_mcp_bin.is_file(), "missing {}", rts_mcp_bin.display());
    assert!(
        rts_daemon_bin.is_file(),
        "missing {}",
        rts_daemon_bin.display()
    );

    // The `target_helper(input)` call lives on line 21 of ENCLOSING_MODULE
    // (1-indexed). Counting:
    //   1: //! Module with several functions; only one is the agent's target.
    //   2: use std::collections::HashMap;
    //   3: (blank)
    //   4: pub struct Padding { a: u32, b: u32, c: HashMap<String, u32> }
    //   5: (blank)
    //   6: impl Padding {
    //   7:     pub fn new() ...
    //   8:     pub fn bump ...
    //   9:     pub fn dump ...
    //  10: }
    //  11: (blank)
    //  12: pub fn unrelated_one(x: u32) -> u32 { x.saturating_add(1) }
    //  13: pub fn unrelated_two(y: u32) -> u32 { y.saturating_mul(2) }
    //  14: (blank)
    //  15: /// The function the bench scenario anchors on. The line of `target_helper`
    //  16: /// inside this body is what `--line` points at — read_symbol_at returns
    //  17: /// just this fn, while the baseline reads the whole module.
    //  18: pub fn enclosing_fn(input: u32) -> u32 {
    //  19:     let stepped = target_helper(input);
    //  20:     let doubled = stepped.saturating_mul(2);
    //  21:     doubled.saturating_sub(1)
    //  22: }
    //
    // Any line in 18..=22 (the enclosing fn) works. Pick 19 — the line
    // that calls target_helper, the most realistic compiler-error site.
    let report_path = out_dir.path().join("bench-test.json");
    let status = Command::new(rts_bench_bin())
        .arg("task")
        .arg("run")
        .arg("scenario_compiler_fix")
        .arg("--workspace")
        .arg(workspace.path())
        .arg("--file")
        .arg("module.rs")
        .arg("--line")
        .arg("19")
        .arg("--referenced-symbol")
        .arg("target_helper")
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
        "rts-bench task run scenario_compiler_fix failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    let bytes = tokio::time::timeout(Duration::from_secs(2), tokio::fs::read(&report_path))
        .await
        .context("timeout waiting for bench report")??;
    let report: Value = serde_json::from_slice(&bytes)?;

    let task = &report["tasks"]["scenario_compiler_fix"];
    let baseline = task["baseline"]["tokens"].as_u64().unwrap_or(0);
    let mcp = task["mcp"]["tokens"].as_u64().unwrap_or(0);
    let reduction = task["reduction_pct"].as_f64().unwrap_or(0.0);

    assert!(baseline > 0, "baseline tokens should be > 0; got {task}");
    assert!(mcp > 0, "mcp tokens should be > 0; got {task}");
    // The baseline reads two full files (module.rs is ~25 lines + 6
    // unrelated symbols, helper.rs is ~7 lines with one extra fn).
    // MCP returns just the enclosing fn body + one signature. Real
    // reduction should be substantial — set the floor at 25% so this
    // test catches regressions without being flakey on small fixtures.
    assert!(
        reduction > 25.0,
        "expected >25% reduction on scenario_compiler_fix; got {reduction:.1}% \
         (baseline={baseline}, mcp={mcp}, task={task})"
    );
    Ok(())
}
