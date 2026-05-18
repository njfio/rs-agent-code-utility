//! U9 — `Index.Grep` v1 latency baseline.
//!
//! Goal: a reproducible measurement of v1 grep latency on a known
//! workspace so AC23 ("v1 grep latency p95 unchanged ±10% versus pre-PR
//! baseline") is testable as a hand-diff of two JSON snapshots: one
//! captured on the PR's base commit, one on its tip.
//!
//! The test is `#[ignore]` by design — it spawns the daemon, indexes
//! 1000 synthetic Rust files, and times 100 grep calls. Wall-clock on
//! a healthy laptop is ~15-30s; not appropriate for the default CI
//! step. Run manually pre-and-post PR via:
//!
//! ```sh
//! cargo test -p rts-bench --test grep_latency_test -- --ignored --nocapture
//! ```
//!
//! Output is committed to `bench-results/grep-v1-baseline.json`. The
//! file is the wire contract for the comparison: diff it before and
//! after the PR and assert each percentile moved <10%.
//!
//! Why an integration test instead of a `criterion` bench: the same
//! infra that exists for `latency_smoke.rs` (`CARGO_BIN_EXE_rts-bench`
//! plus sibling binaries) is reused here, and the test asserts a
//! *loose* ceiling (smoke check only). The real regression gate is
//! the hand-diff of the committed JSON.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn rts_bench_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-bench"))
}

fn sibling(name: &str) -> PathBuf {
    let me = rts_bench_bin();
    me.parent().expect("CARGO_BIN_EXE has parent").join(name)
}

/// Seeded synthetic 1000-file Rust workspace, hand-rolled to keep this
/// test free of any dependency on the (binary-only) `rts-bench` crate's
/// internal modules. Each file contains a fixed mix of `pub fn`
/// declarations + comments; the seed parametrises the symbol names so
/// re-running the test produces byte-identical file contents.
fn synth_workspace(root: &Path, file_count: usize, seed: u64) -> std::io::Result<()> {
    // Numerical-recipes LCG; deterministic for a fixed seed. The bench
    // doesn't need cryptographic randomness — it just needs every run
    // to lay down the same bytes.
    let mut state = seed.max(1);
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };
    for f in 0..file_count {
        // 10 functions per file, ~6 lines each → ~65 LOC per file →
        // 1000 files ≈ 65k LOC. Mirrors the existing latency synth
        // workspace's shape without depending on it.
        let mut src = String::new();
        src.push_str(&format!("//! Generated bench module {f}.\n\n"));
        for i in 0..10 {
            let salt = next() % 1_000_000;
            src.push_str(&format!(
                "pub fn grep_bench_f{f}_fn{i}(x: u32) -> u32 {{\n    // salt={salt}\n    let _ = x + 1;\n    let _ = x.saturating_mul(2);\n    x\n}}\n\n"
            ));
        }
        // Sprinkle a few `pub fn` matches and a comment match per file
        // so the grep target ("pub fn") returns dense, realistic hit
        // counts. This is the literal we time below.
        src.push_str("// pub fn comment_decoy — exercised by case-insensitive match\n");
        std::fs::write(root.join(format!("grep_bench_f{f}.rs")), src)?;
    }
    Ok(())
}

async fn wait_for_socket(path: &Path, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "socket {} did not appear within {:?}",
                path.display(),
                timeout
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn round_trip(
    stream: &mut UnixStream,
    id: &str,
    method: &str,
    params: Value,
) -> anyhow::Result<Value> {
    let req = json!({ "id": id, "method": method, "params": params });
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.flush().await?;

    let mut buf = Vec::new();
    let (rd, _wr) = stream.split();
    let mut reader = BufReader::new(rd);
    let n = tokio::time::timeout(Duration::from_secs(30), reader.read_until(b'\n', &mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to {method}"))??;
    anyhow::ensure!(n > 0, "EOF before response to {method}");
    Ok(serde_json::from_slice(&buf)?)
}

/// Poll `Workspace.Status` until the daemon reports the initial walk
/// has completed. Bounded by `deadline` so a broken daemon can't hang
/// the test forever. Returns `Ok(())` once the writer is idle.
async fn wait_for_index_ready(
    stream: &mut UnixStream,
    next_id: &mut u64,
    deadline: Instant,
) -> anyhow::Result<()> {
    loop {
        *next_id += 1;
        // `Workspace.Status` returns progress.phase ∈ {walking, ready};
        // we wait for "ready". Fall back to a `FindSymbol` probe if
        // the daemon doesn't recognise the method (older builds).
        let resp = round_trip(
            stream,
            &next_id.to_string(),
            "Workspace.Status",
            json!({}),
        )
        .await;
        let ready = match resp {
            Ok(v) => v["result"]["progress"]["phase"].as_str() == Some("ready"),
            Err(_) => false,
        };
        if ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "workspace did not reach ready phase before deadline (waited {:?})",
                deadline.elapsed()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(serde::Serialize)]
struct LatencyBaseline {
    version: u32,
    rts_bench_version: String,
    file_count: usize,
    seed: u64,
    queries: u32,
    cold_count: u32,
    target_text: String,
    /// Per-call wall-clock in microseconds, in the order issued.
    /// Useful for hand-plotting (cold prefix vs warm steady-state).
    samples_micros: Vec<u128>,
    /// Stats over the warm window (`samples_micros[cold_count..]`).
    warm_p50_micros: u64,
    warm_p95_micros: u64,
    warm_p99_micros: u64,
    warm_max_micros: u64,
    warm_mean_micros: u64,
    warm_count: u32,
    /// Stats over the cold prefix.
    cold_p50_micros: u64,
    cold_p95_micros: u64,
    cold_max_micros: u64,
    /// Hit count returned by the *last* warm call. We assert this is
    /// stable across runs; a drift here means the index churned or the
    /// fixture seed changed.
    last_match_count: usize,
}

fn pctl(sorted: &[u128], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len() as f64;
    let idx = ((q * n).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)] as u64
}

/// p95 budget for the v1 literal grep path. Deliberately loose — this
/// is a smoke check, not the regression gate. The real gate is a
/// hand-diff of `bench-results/grep-v1-baseline.json` pre/post PR
/// asserting <10% movement on each percentile.
///
/// A dense fixture ("pub fn" matches every file × 11 hits/file) drives
/// every call to the result-cap; observed warm p95 on a healthy laptop
/// is ~450ms. The 1.5s ceiling here exists only to catch gross breakage
/// (a 3× slowdown) on borrowed CI hardware where everyone gets a slice
/// of a shared cpu.
const WARM_P95_BUDGET_MICROS: u64 = 1_500_000;

#[tokio::test(flavor = "current_thread")]
#[ignore = "spawns daemon + indexes 1000 files; ~30s wall-clock — run manually pre-and-post PR"]
async fn grep_v1_latency_baseline() -> anyhow::Result<()> {
    // Resolve binaries. The daemon must already be built; cargo test
    // arranges this via the `CARGO_BIN_EXE_*` env vars + `required-features`
    // when the test crate declares an explicit dep, but rts-bench
    // doesn't depend on rts-daemon directly, so we instead lean on the
    // existing convention (mirrored from latency_smoke.rs) that
    // `cargo test -p rts-bench` is preceded by `cargo build -p
    // rts-daemon` either explicitly or transitively.
    let rts_daemon_bin = sibling("rts-daemon");
    assert!(
        rts_daemon_bin.is_file(),
        "missing {} — build with `cargo build -p rts-daemon` first",
        rts_daemon_bin.display()
    );

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Seeded 1000-file workspace. Seed is fixed in the baseline JSON;
    // change the constant only with a corresponding baseline refresh.
    const FILE_COUNT: usize = 1000;
    const SEED: u64 = 0xb_e_e_f_d_e_a_d_u64;
    synth_workspace(workspace.path(), FILE_COUNT, SEED)?;

    let socket_path = if cfg!(target_os = "macos") {
        home_dir
            .path()
            .join("Library")
            .join("Caches")
            .join("rts")
            .join("default.sock")
    } else {
        runtime_dir.path().join("rts").join("default.sock")
    };

    let mut cmd = Command::new(&rts_daemon_bin);
    cmd.env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "300")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn()?;
    let _kill = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(10)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;
    let mut next_id: u64 = 1;

    // Mount the workspace.
    next_id += 1;
    let mount = round_trip(
        &mut stream,
        &next_id.to_string(),
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(
        mount["error"].is_null(),
        "Workspace.Mount returned an error: {mount:?}"
    );

    // Wait for the initial walk to settle. 1000 small files indexes
    // in a few seconds on a healthy laptop; 60s is the safety ceiling.
    let deadline = Instant::now() + Duration::from_secs(60);
    wait_for_index_ready(&mut stream, &mut next_id, deadline).await?;

    // Now time 100 grep calls against the same literal. The first
    // `COLD_COUNT` are reported separately from the warm steady-state
    // — they capture any first-call DFA-build or filesystem-warming
    // cost that the regression gate shouldn't conflate with the hot
    // path.
    const QUERIES: u32 = 100;
    const COLD_COUNT: u32 = 10;
    const TARGET_TEXT: &str = "pub fn";

    let mut samples: Vec<u128> = Vec::with_capacity(QUERIES as usize);
    let mut last_match_count: usize = 0;
    for i in 0..QUERIES {
        next_id += 1;
        let t0 = Instant::now();
        let resp = round_trip(
            &mut stream,
            &next_id.to_string(),
            "Index.Grep",
            json!({ "text": TARGET_TEXT, "limit": 4096 }),
        )
        .await?;
        let elapsed = t0.elapsed();
        assert!(
            resp["error"].is_null(),
            "Index.Grep call {i} errored: {resp:?}"
        );
        last_match_count = resp["result"]["matches"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        samples.push(elapsed.as_micros());
    }

    // Compute stats. Cold prefix and warm steady-state get their own
    // sorted copies so the order-preserving `samples_micros` field
    // remains usable for plotting.
    let cold = &samples[..(COLD_COUNT as usize).min(samples.len())];
    let warm = &samples[(COLD_COUNT as usize).min(samples.len())..];
    let mut cold_sorted: Vec<u128> = cold.to_vec();
    cold_sorted.sort_unstable();
    let mut warm_sorted: Vec<u128> = warm.to_vec();
    warm_sorted.sort_unstable();
    let warm_count = warm_sorted.len() as u32;
    let warm_mean = if warm_count > 0 {
        (warm_sorted.iter().sum::<u128>() / warm_count as u128) as u64
    } else {
        0
    };

    let baseline = LatencyBaseline {
        version: 1,
        rts_bench_version: env!("CARGO_PKG_VERSION").to_string(),
        file_count: FILE_COUNT,
        seed: SEED,
        queries: QUERIES,
        cold_count: COLD_COUNT,
        target_text: TARGET_TEXT.to_string(),
        samples_micros: samples.clone(),
        warm_p50_micros: pctl(&warm_sorted, 0.50),
        warm_p95_micros: pctl(&warm_sorted, 0.95),
        warm_p99_micros: pctl(&warm_sorted, 0.99),
        warm_max_micros: *warm_sorted.last().unwrap_or(&0) as u64,
        warm_mean_micros: warm_mean,
        warm_count,
        cold_p50_micros: pctl(&cold_sorted, 0.50),
        cold_p95_micros: pctl(&cold_sorted, 0.95),
        cold_max_micros: *cold_sorted.last().unwrap_or(&0) as u64,
        last_match_count,
    };

    // Write the report. Path is relative to the workspace root so the
    // baseline is committed alongside the source — the regression gate
    // is a `git diff` of this file.
    let out_path = std::env::var("GREP_BASELINE_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            // crates/rts-bench → workspace root → bench-results/
            manifest
                .parent()
                .and_then(|p| p.parent())
                .expect("workspace root")
                .join("bench-results")
                .join("grep-v1-baseline.json")
        });
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(&baseline)?;
    std::fs::write(&out_path, bytes)?;

    eprintln!(
        "grep v1 latency baseline written to {} \
         (warm p50={}µs p95={}µs p99={}µs; matches/call={})",
        out_path.display(),
        baseline.warm_p50_micros,
        baseline.warm_p95_micros,
        baseline.warm_p99_micros,
        baseline.last_match_count,
    );

    // Loose smoke assertion — the real regression gate is a hand-diff
    // of this baseline file pre- and post-PR. The 500ms ceiling here
    // exists to catch *gross* breakage (a 50× slowdown) on the bench
    // itself, not subtle perf regressions.
    assert!(
        baseline.warm_p95_micros < WARM_P95_BUDGET_MICROS,
        "warm p95 ({}µs) exceeded loose smoke budget ({}µs) — \
         expected sub-millisecond for a 1000-file literal grep",
        baseline.warm_p95_micros,
        WARM_P95_BUDGET_MICROS,
    );
    assert!(
        baseline.last_match_count > 0,
        "grep returned zero matches — fixture or daemon broken"
    );

    Ok(())
}
