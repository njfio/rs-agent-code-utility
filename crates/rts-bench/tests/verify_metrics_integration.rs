//! Integration test for `rts-bench verify` (verify-v0 P1.U5).
//!
//! Runs the REAL `verify` subcommand — spawning rts-mcp + the daemon and
//! mounting a tiny seeded workspace — against the committed
//! self-validation fixture (`corpus/verify-eval-selftest.toml`) and
//! asserts the KNOWN Symbol Hallucination Rate.
//!
//! The fixture references 3 symbols that exist in the seeded workspace, 2
//! invented names, and 1 ambiguous (double-defined) name. That gives a
//! provable SHR = not_found / decidable = 2 / (3 + 2) = 0.4 with the
//! ambiguous reference excluded as `indeterminate`. If this number drifts,
//! either the F3 extractor or the verify resolution changed.
//!
//! Kept fast: the workspace is three tiny files, so the cold walk settles
//! in well under a second.

use std::path::PathBuf;
use std::process::Stdio;

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

/// Locate the committed corpus relative to this crate's manifest dir
/// (`crates/rts-bench`) → repo-root `corpus/`.
fn selftest_corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("verify-eval-selftest.toml")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verify_selftest_fixture_reports_known_shr() -> Result<()> {
    let workspace = tempfile::tempdir()?;
    let runtime = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let home = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700));

    // Seed the workspace to match the self-validation fixture's
    // expectations:
    //   - make_widget / make_circle / format_widget: one def each → exact
    //   - dup_helper: TWO defs across two files → ambiguous → indeterminate
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn make_widget(id: u32) -> u32 { id + 1 }\n\
         pub fn make_circle(r: u32) -> u32 { r * 2 }\n\
         pub fn format_widget(w: u32) -> String { format!(\"w#{w}\") }\n",
    )?;
    std::fs::write(
        workspace.path().join("dup_a.rs"),
        "pub fn dup_helper(x: u32) -> u32 { x }\n",
    )?;
    std::fs::write(
        workspace.path().join("dup_b.rs"),
        "pub fn dup_helper(x: u32, y: u32) -> u32 { x + y }\n",
    )?;

    let corpus = selftest_corpus();
    assert!(corpus.is_file(), "missing fixture {}", corpus.display());

    let rts_mcp_bin = sibling("rts-mcp");
    let rts_daemon_bin = sibling("rts-daemon");
    assert!(rts_mcp_bin.is_file(), "missing {}", rts_mcp_bin.display());
    assert!(
        rts_daemon_bin.is_file(),
        "missing {}",
        rts_daemon_bin.display()
    );

    let mut cmd = Command::new(rts_bench_bin());
    cmd.arg("verify")
        .arg("--corpus")
        .arg(&corpus)
        .arg("--workspace")
        .arg(workspace.path())
        .arg("--dry-run")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_STATE_HOME", state.path())
        .env("HOME", home.path())
        .env("RTS_MCP_BIN", &rts_mcp_bin)
        .env("RTS_DAEMON_BIN", &rts_daemon_bin)
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().await.context("spawn rts-bench verify")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "rts-bench verify failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The command prints a human summary line then the JSON report. Find
    // the JSON object (starts at the first '{').
    let json_start = stdout.find('{').context("no JSON in verify output")?;
    let report: Value =
        serde_json::from_str(&stdout[json_start..]).context("parse HallucinationReport JSON")?;

    // The self-validation fixture's known answer: SHR = 2/5 = 0.4 with
    // one indeterminate (the ambiguous dup_helper) excluded.
    assert_eq!(report["version"], 1);
    assert_eq!(
        report["shr"]["numerator"], 2,
        "expected 2 hallucinated symbols; got {report}"
    );
    assert_eq!(
        report["shr"]["denominator"], 5,
        "expected 5 decidable symbols; got {report}"
    );
    assert_eq!(
        report["shr"]["indeterminate_excluded"], 1,
        "expected 1 indeterminate (ambiguous dup_helper) excluded; got {report}"
    );
    let shr = report["shr"]["rate"].as_f64().context("shr.rate")?;
    assert!(
        (shr - 0.4).abs() < 1e-9,
        "expected SHR 0.4; got {shr} ({report})"
    );
    // RGR = 1 − SHR = 0.6.
    let rgr = report["rgr"].as_f64().context("rgr")?;
    assert!((rgr - 0.6).abs() < 1e-9, "expected RGR 0.6; got {rgr}");

    // Rust was the only contributing language.
    let langs: Vec<&str> = report["languages_covered"]
        .as_array()
        .context("languages_covered")?
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(langs, vec!["rust"], "expected rust coverage; got {langs:?}");

    Ok(())
}
