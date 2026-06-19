//! Integration test for `rts-bench verify-edit` (verify-v0 P3.U2).
//!
//! Runs the REAL `verify-edit` subcommand — spawning rts-mcp + the daemon
//! and mounting a tiny seeded workspace — against the committed
//! self-validation fixture (`corpus/verify-edit-eval-selftest.toml`) and
//! asserts the KNOWN EVR / BCIR.
//!
//! The fixture has three edit-sets over a workspace where `hub.rs` defines
//! `target(x)` (arity 1) and `caller_a.rs` calls it:
//!   1. remove `target`          → fail + broken_caller   (counts toward BCIR)
//!   2. add a fn, keep `target`  → pass + new_symbol
//!   3. arity-preserving edit    → pass
//!
//! So EVR = 2/3 and BCIR = 1/3. If these drift, either `Index.VerifyEdit`
//! or the extractor changed — investigate before re-baselining.

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
        .join("verify-edit-eval-selftest.toml")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verify_edit_selftest_fixture_reports_known_evr_bcir() -> Result<()> {
    let workspace = tempfile::tempdir()?;
    let runtime = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let home = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700));

    // Seed the workspace to match the fixture's expectations:
    //   hub.rs      defines `target(x)` (arity 1)
    //   caller_a.rs calls `target(1)`
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn target(x: u32) -> u32 { x + 1 }\n",
    )?;
    std::fs::write(
        workspace.path().join("caller_a.rs"),
        "use crate::target;\npub fn caller_a() { let _ = target(1); }\n",
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
    cmd.arg("verify-edit")
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
    let out = cmd.output().await.context("spawn rts-bench verify-edit")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "rts-bench verify-edit failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The command prints a human summary then the JSON report. Find the
    // JSON object (starts at the first '{').
    let json_start = stdout.find('{').context("no JSON in verify-edit output")?;
    let report: Value =
        serde_json::from_str(&stdout[json_start..]).context("parse EditQualityReport JSON")?;

    assert_eq!(report["version"], 1);
    assert_eq!(
        report["edit_set_count"], 3,
        "fixture has 3 edit-sets; got {report}"
    );

    // EVR = passes / total = 2 / 3.
    assert_eq!(
        report["evr"]["numerator"], 2,
        "expected 2 passing edit-sets; got {report}"
    );
    assert_eq!(report["evr"]["denominator"], 3, "got {report}");
    let evr = report["evr"]["rate"].as_f64().context("evr.rate")?;
    assert!(
        (evr - 2.0 / 3.0).abs() < 1e-9,
        "expected EVR 2/3; got {evr} ({report})"
    );

    // BCIR = caller-breaking / total = 1 / 3 (the remove edit-set).
    assert_eq!(
        report["bcir"]["numerator"], 1,
        "expected 1 caller-breaking edit-set; got {report}"
    );
    assert_eq!(report["bcir"]["denominator"], 3, "got {report}");
    let bcir = report["bcir"]["rate"].as_f64().context("bcir.rate")?;
    assert!(
        (bcir - 1.0 / 3.0).abs() < 1e-9,
        "expected BCIR 1/3; got {bcir} ({report})"
    );

    Ok(())
}
