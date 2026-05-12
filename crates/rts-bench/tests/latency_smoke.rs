//! Smoke test for `rts-bench latency`. Runs a tiny synthetic fixture
//! through the harness end-to-end and asserts the report file has the
//! expected shape. Not a perf test — actual latencies are
//! machine-dependent and not asserted.

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
async fn latency_report_has_expected_shape() -> Result<()> {
    let out_dir = tempfile::tempdir()?;
    let report_path = out_dir.path().join("bench-latency-test.json");

    let rts_mcp_bin = sibling("rts-mcp");
    let rts_daemon_bin = sibling("rts-daemon");
    assert!(rts_mcp_bin.is_file(), "missing {}", rts_mcp_bin.display());
    assert!(
        rts_daemon_bin.is_file(),
        "missing {}",
        rts_daemon_bin.display()
    );

    // Tiny fixture, few queries — just enough to exercise the
    // pipeline. The smoke test is about shape, not perf.
    let status = Command::new(rts_bench_bin())
        .arg("latency")
        .arg("--synth-loc")
        .arg("1000")
        .arg("--queries")
        .arg("20")
        .arg("--cold-count")
        .arg("5")
        .arg("--out")
        .arg(&report_path)
        .env("RTS_MCP_BIN", &rts_mcp_bin)
        .env("RTS_DAEMON_BIN", &rts_daemon_bin)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("spawn rts-bench latency")?;
    let stdout = String::from_utf8_lossy(&status.stdout);
    let stderr = String::from_utf8_lossy(&status.stderr);
    assert!(
        status.status.success(),
        "rts-bench latency failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    let bytes = tokio::time::timeout(Duration::from_secs(2), tokio::fs::read(&report_path))
        .await
        .context("timeout waiting for report")??;
    let report: Value = serde_json::from_slice(&bytes)?;

    assert_eq!(report["version"], 1);
    assert_eq!(report["queries"], 20);
    assert_eq!(report["cold_count"], 5);
    assert!(report["seed"].as_u64().is_some(), "seed should be a u64");

    let warm_all = &report["warm_all"];
    let warm_count = warm_all["count"].as_u64().unwrap_or(0);
    assert!(
        warm_count >= 10,
        "warm samples should cover most of the run; got {warm_count}"
    );

    for kind in ["find_symbol", "read_symbol", "outline"] {
        assert!(
            report["warm"][kind].is_object(),
            "warm.{kind} should be present"
        );
        assert!(
            report["cold"][kind].is_object(),
            "cold.{kind} should be present"
        );
    }

    Ok(())
}
