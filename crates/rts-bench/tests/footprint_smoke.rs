//! Smoke test for `rts-bench footprint`. Runs the harness end-to-end
//! on a tiny synth fixture and verifies the report shape. Not a
//! footprint test — actual RSS/index-size numbers are
//! workload-dependent and not asserted beyond "nonzero where the
//! sampler had a chance to fire".

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn footprint_report_has_expected_shape() -> Result<()> {
    let out_dir = tempfile::tempdir()?;
    let report_path = out_dir.path().join("bench-footprint-test.json");

    let rts_mcp_bin = sibling("rts-mcp");
    let rts_daemon_bin = sibling("rts-daemon");
    assert!(rts_mcp_bin.is_file(), "missing {}", rts_mcp_bin.display());
    assert!(
        rts_daemon_bin.is_file(),
        "missing {}",
        rts_daemon_bin.display()
    );

    let status = Command::new(rts_bench_bin())
        .arg("footprint")
        .arg("--synth-loc")
        .arg("1000")
        .arg("--out")
        .arg(&report_path)
        .env("RTS_MCP_BIN", &rts_mcp_bin)
        .env("RTS_DAEMON_BIN", &rts_daemon_bin)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("spawn rts-bench footprint")?;
    let stdout = String::from_utf8_lossy(&status.stdout);
    let stderr = String::from_utf8_lossy(&status.stderr);
    assert!(
        status.status.success(),
        "rts-bench footprint failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    let bytes = tokio::time::timeout(Duration::from_secs(2), tokio::fs::read(&report_path))
        .await
        .context("timeout waiting for report")??;
    let report: Value = serde_json::from_slice(&bytes)?;

    // Wire-stable scalar fields.
    assert_eq!(report["version"], 1, "report version");
    assert_eq!(report["synth_loc"], 1000);
    assert!(report["workspace_path"].is_string());
    assert!(report["rts_bench_version"].is_string());

    // File / symbol counts must be positive — the synth fixture
    // generates at least one file with at least one symbol.
    let files = report["files"].as_u64().expect("files should be a u64");
    let symbols = report["symbols"].as_u64().expect("symbols should be a u64");
    assert!(files >= 2, "expected at least 2 synth files; got {files}");
    assert!(symbols >= 10, "expected many synth symbols; got {symbols}");

    // build_time_ms is set on every run (the probe call is the
    // gating signal).
    let build = report["build_time_ms"]
        .as_u64()
        .expect("build_time_ms should be a u64");
    // No upper bound — slow CI runners are real — but it should be
    // observable.
    assert!(build < 60_000, "build_time_ms = {build} suggests a hang");

    // full_index_time_ms should be >= build_time_ms; the writer keeps
    // ingesting files after the first symbol becomes queryable.
    let full = report["full_index_time_ms"]
        .as_u64()
        .expect("full_index_time_ms should be a u64");
    assert!(
        full >= build,
        "full_index_time_ms ({full}) should be >= build_time_ms ({build})"
    );
    assert!(
        full < 120_000,
        "full_index_time_ms = {full} suggests a hang"
    );

    // index_size_bytes should be nonzero once the writer commits the
    // initial walk. The probe call only returns OK after that commit.
    let idx = report["index_size_bytes"]
        .as_u64()
        .expect("index_size_bytes should be a u64");
    assert!(
        idx > 0,
        "index_size_bytes should be nonzero after writer commits; got {idx}"
    );

    // peak_rss_bytes is best-effort. On CI the pgrep-driven walk can
    // miss the daemon PID if process trees flap; treat zero as
    // acceptable, but if it *did* sample, it must look plausible
    // (≥ 1 MiB, < 4 GiB).
    let rss = report["peak_rss_bytes"]
        .as_u64()
        .expect("peak_rss_bytes should be a u64");
    if rss > 0 {
        assert!(
            (1 << 20..4u64 << 30).contains(&rss),
            "peak_rss_bytes = {rss} looks implausible"
        );
    }

    // Derived ratio matches the raw numbers (off-by-one OK because of
    // integer division).
    let bps = report["bytes_per_symbol"]
        .as_u64()
        .expect("bytes_per_symbol should be a u64");
    if symbols > 0 {
        let expected = idx / symbols;
        assert_eq!(
            bps, expected,
            "bytes_per_symbol = {bps}, expected {expected} ({idx} / {symbols})"
        );
    }

    Ok(())
}
