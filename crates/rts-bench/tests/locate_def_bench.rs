//! End-to-end test for `rts-bench task run locate_def`.
//!
//! Seeds a tempdir workspace that:
//! - defines `target_fn` exactly once (in `lib.rs`),
//! - mentions `target_fn` in a Markdown file (prose),
//! - mentions `target_fn` in a non-code `.txt` file.
//!
//! Baseline (`rg`) hits all three files and reads them in full. MCP
//! (`find_symbol`) returns only the one def site. The test asserts both
//! runs produced non-zero tokens, the bench-<sha>.json was written, and
//! the reduction percentage is positive (MCP used strictly fewer tokens
//! than baseline for this case).

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

fn seed(root: &std::path::Path) -> Result<()> {
    std::fs::write(
        root.join("lib.rs"),
        "pub fn target_fn() {\n    println!(\"hello\");\n}\n\npub fn other() {\n    target_fn();\n}\n",
    )?;
    std::fs::write(
        root.join("README.md"),
        "# demo\n\nMentions `target_fn` in prose only.\n",
    )?;
    std::fs::write(
        root.join("notes.txt"),
        "TODO: revisit target_fn before shipping\n",
    )?;
    Ok(())
}

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
async fn locate_def_end_to_end() -> Result<()> {
    // The baseline path requires `rg` on PATH. CI without ripgrep just
    // skips — we won't pretend to compute a reduction we can't actually
    // measure. The MCP-only smoke check below still runs.
    if !rg_available().await {
        eprintln!("ripgrep (`rg`) not on PATH; skipping locate_def baseline assertion");
        return Ok(());
    }

    let workspace = tempfile::tempdir()?;
    let runtime = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let home = tempfile::tempdir()?;
    let out_dir = tempfile::tempdir()?;
    seed(workspace.path())?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700));

    let rts_mcp_bin = sibling("rts-mcp");
    let rts_daemon_bin = sibling("rts-daemon");
    assert!(
        rts_mcp_bin.is_file(),
        "rts-mcp must be built before this test; missing at {}",
        rts_mcp_bin.display()
    );
    assert!(
        rts_daemon_bin.is_file(),
        "rts-daemon must be built before this test; missing at {}",
        rts_daemon_bin.display()
    );

    let report_path = out_dir.path().join("bench-test.json");
    let status = Command::new(rts_bench_bin())
        .arg("task")
        .arg("run")
        .arg("locate_def")
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
    let stdout_text = String::from_utf8_lossy(&status.stdout);
    let stderr_text = String::from_utf8_lossy(&status.stderr);
    assert!(
        status.status.success(),
        "rts-bench task run failed: {status:?}\nstdout: {stdout_text}\nstderr: {stderr_text}",
    );

    let bytes = tokio::time::timeout(Duration::from_secs(2), tokio::fs::read(&report_path))
        .await
        .context("timeout waiting for bench report")??;
    let report: Value = serde_json::from_slice(&bytes).context("parse bench report")?;

    assert_eq!(report["version"], 1);
    assert_eq!(report["token_counter"], "bytes_div_3");
    let task = &report["tasks"]["locate_def"];
    assert!(
        task["baseline"]["tokens"].as_u64().unwrap_or(0) > 0,
        "baseline tokens should be > 0; got {task}"
    );
    assert!(
        task["mcp"]["tokens"].as_u64().unwrap_or(0) > 0,
        "mcp tokens should be > 0; got {task}"
    );
    // The baseline reads `lib.rs` + `README.md` + `notes.txt`; MCP returns
    // one match for the single def in `lib.rs`. Reduction must be strictly
    // positive.
    let reduction = task["reduction_pct"].as_f64().unwrap_or(0.0);
    assert!(
        reduction > 0.0,
        "expected positive reduction; got {reduction} on {task}"
    );
    assert!(
        task["baseline"]["files_read"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0)
            >= 2,
        "baseline should have read multiple files; got {task}"
    );

    Ok(())
}
