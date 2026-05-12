//! Integration test for `rts-bench task run summarize_module`.
//!
//! Seeds a ~150-line module with imports + many decoy symbols. Baseline
//! reads the whole file (≈ 150 lines / 3 tokens ≈ a lot); MCP returns
//! only the first `line_budget` lines (where the imports + top-level
//! signatures live).

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

/// Build a long module deterministically — header with imports/public
/// signatures (the "summary"), then a tail of decoy functions filling
/// out lines so the whole-file baseline pays the full cost.
fn synth_module(target_lines: usize) -> String {
    let mut s = String::new();
    s.push_str("//! A module with a clear public surface at the top.\n");
    s.push_str("//!\n");
    s.push_str("//! The first ~30 lines tell a reader what this module exposes; the rest is\n");
    s.push_str("//! private implementation detail that an `outline_workspace` agent doesn't\n");
    s.push_str("//! need to fetch.\n");
    s.push('\n');
    s.push_str("use std::collections::HashMap;\n");
    s.push_str("use std::path::PathBuf;\n");
    s.push('\n');
    s.push_str("pub struct Public {\n");
    s.push_str("    pub name: String,\n");
    s.push_str("    pub value: u32,\n");
    s.push_str("}\n");
    s.push('\n');
    s.push_str("pub trait PublicTrait {\n");
    s.push_str("    fn handle(&self, input: &str) -> String;\n");
    s.push_str("}\n");
    s.push('\n');
    s.push_str("pub fn entry_a(x: u32) -> u32 { x.saturating_add(1) }\n");
    s.push_str("pub fn entry_b(x: u32) -> u32 { x.saturating_mul(2) }\n");
    s.push('\n');
    let header_lines = s.lines().count();
    let mut i: usize = 0;
    while s.lines().count() < target_lines.max(header_lines + 1) {
        s.push_str(&format!(
            "fn private_decoy_{i}() -> &'static str {{ \"decoy_{i}\" }}\n"
        ));
        i += 1;
        // Hard safety cap; never loop more than 10k times.
        if i > 10_000 {
            break;
        }
    }
    s
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn summarize_module_end_to_end() -> Result<()> {
    let workspace = tempfile::tempdir()?;
    let runtime = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let home = tempfile::tempdir()?;
    let out_dir = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700));

    let source = synth_module(150);
    std::fs::write(workspace.path().join("module.rs"), &source)?;
    assert!(
        source.lines().count() >= 150,
        "synth produced {} lines",
        source.lines().count()
    );

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
        .arg("summarize_module")
        .arg("--workspace")
        .arg(workspace.path())
        .arg("--file")
        .arg("module.rs")
        .arg("--line-budget")
        .arg("30")
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
        "rts-bench task run summarize_module failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    let bytes = tokio::time::timeout(Duration::from_secs(2), tokio::fs::read(&report_path))
        .await
        .context("timeout waiting for bench report")??;
    let report: Value = serde_json::from_slice(&bytes)?;

    let task = &report["tasks"]["summarize_module"];
    let baseline = task["baseline"]["tokens"].as_u64().unwrap_or(0);
    let mcp = task["mcp"]["tokens"].as_u64().unwrap_or(0);
    let reduction = task["reduction_pct"].as_f64().unwrap_or(0.0);

    assert!(baseline > 0, "baseline tokens should be > 0; got {task}");
    assert!(mcp > 0, "mcp tokens should be > 0; got {task}");
    // Synth file is ~150 lines; budget is 30. Naive ratio is 30/150 = 20%
    // (so 80% reduction). The bench also adds JSON envelope overhead;
    // require strictly > 50% to leave a comfortable margin.
    assert!(
        reduction > 50.0,
        "expected >50% reduction; got {reduction:.1}% on {task}"
    );

    Ok(())
}
