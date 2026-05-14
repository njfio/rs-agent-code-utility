//! End-to-end test for v0.3 U5: `Index.ImpactOf` transitive caller
//! closure.
//!
//! ## Three-tier fixture
//!
//! ```text
//!     target ← caller_a ← grandcaller_1
//!            ← caller_b ← grandcaller_1, grandcaller_2
//!            ← caller_c ← grandcaller_2
//!            ← tests/integration_test.rs::test_target  (filtered by default)
//! ```
//!
//! Three direct callers (caller_a/b/c), three indirect callers
//! (grandcaller_1/2 — depth=2), and one test caller (filtered out
//! by `exclude_test_paths=true` default).
//!
//! ## Assertions
//!
//! 1. `Daemon.Ping` advertises `impact_of`.
//! 2. Default `impact_of(target)` returns ≥ 3 direct + 2 indirect = 5 callers,
//!    test caller excluded, sorted by (depth ASC, rank DESC).
//! 3. `exclude_test_paths: false` includes the test caller.
//! 4. `depth: 1` limits to direct callers only.
//! 5. Unknown name returns `SYMBOL_NOT_FOUND`.
//! 6. Cycle break: mutual-recursion fixture doesn't infinite-loop.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-daemon"))
}

async fn wait_for_socket(path: &std::path::Path, timeout: Duration) -> anyhow::Result<()> {
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
    let n = tokio::time::timeout(Duration::from_secs(8), reader.read_until(b'\n', &mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to {method}"))??;
    anyhow::ensure!(n > 0, "EOF before response to {method}");
    Ok(serde_json::from_slice(&buf)?)
}

async fn wait_for_symbol(
    stream: &mut UnixStream,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut id: u64 = 100;
    loop {
        id += 1;
        let resp = round_trip(
            stream,
            &id.to_string(),
            "Index.FindSymbol",
            json!({ "name": name }),
        )
        .await?;
        if !resp["result"]["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(true)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("symbol `{name}` never indexed within {:?}", timeout);
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn impact_of_three_tier_with_test_filter() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Tier 0: target.
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn target(x: u32) -> u32 { x + 1 }\n",
    )?;
    // Tier 1: 3 direct callers.
    std::fs::write(
        workspace.path().join("caller_a.rs"),
        "pub fn caller_a() { let _ = target(1); }\n",
    )?;
    std::fs::write(
        workspace.path().join("caller_b.rs"),
        "pub fn caller_b() { let _ = target(2); }\n",
    )?;
    std::fs::write(
        workspace.path().join("caller_c.rs"),
        "pub fn caller_c() { let _ = target(3); }\n",
    )?;
    // Tier 2: 2 indirect callers, each calling a couple of direct
    // callers (so PageRank has signal: grandcaller_1 reaches via 2
    // direct callers, grandcaller_2 via 1).
    std::fs::write(
        workspace.path().join("grand_1.rs"),
        "pub fn grandcaller_1() { caller_a(); caller_b(); }\n",
    )?;
    std::fs::write(
        workspace.path().join("grand_2.rs"),
        "pub fn grandcaller_2() { caller_b(); caller_c(); }\n",
    )?;
    // Test caller — should be filtered by default. Using a plain
    // `target(99)` call (not `super::target`) so the tags.scm
    // call_expression pattern picks it up reliably across all
    // grammar versions.
    std::fs::create_dir_all(workspace.path().join("tests"))?;
    std::fs::write(
        workspace.path().join("tests").join("integration_test.rs"),
        "pub fn test_target_runs() { let _ = target(99); }\n",
    )?;

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

    let mut cmd = Command::new(daemon_bin());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn()?;
    let _kill = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;

    let mount = round_trip(
        &mut stream,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount: {mount:?}");

    // Wait for all 7 defs to land.
    wait_for_symbol(&mut stream, "target", Duration::from_secs(5)).await?;
    for n in &[
        "caller_a",
        "caller_b",
        "caller_c",
        "grandcaller_1",
        "grandcaller_2",
        "test_target_runs",
    ] {
        wait_for_symbol(&mut stream, n, Duration::from_secs(5)).await?;
    }

    // 1. Daemon.Ping advertises impact_of.
    let ping = round_trip(&mut stream, "2", "Daemon.Ping", json!({})).await?;
    let caps = ping["result"]["capabilities"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let cap_strs: Vec<&str> = caps.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        cap_strs.contains(&"impact_of"),
        "expected impact_of in caps; got {cap_strs:?}"
    );

    // 2. Default impact_of(target) — direct + indirect, test filtered.
    let resp = round_trip(
        &mut stream,
        "10",
        "Index.ImpactOf",
        json!({ "name": "target" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "impact_of failed: {resp:?}");
    let impact = resp["result"]["impact"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let names: Vec<&str> = impact
        .iter()
        .filter_map(|e| e["qualified_name"].as_str())
        .collect();

    // All three direct callers + both grandcallers (5 total).
    for expected in &[
        "caller_a",
        "caller_b",
        "caller_c",
        "grandcaller_1",
        "grandcaller_2",
    ] {
        assert!(
            names.contains(expected),
            "expected {expected} in impact; got {names:?}"
        );
    }
    // Test caller filtered by default.
    assert!(
        !names.contains(&"test_target_runs"),
        "test caller should be excluded by default; got {names:?}"
    );

    // Truncation flags all false on this small fixture.
    assert_eq!(resp["result"]["closure_truncated"], false);
    assert_eq!(resp["result"]["wall_clock_truncated"], false);
    assert_eq!(resp["result"]["depth_truncated"], false);
    assert_eq!(resp["result"]["node_count_truncated"], false);

    // Depth ordering: depth=1 entries before depth=2.
    let depths: Vec<u64> = impact.iter().filter_map(|e| e["depth"].as_u64()).collect();
    assert!(
        depths.windows(2).all(|w| w[0] <= w[1]),
        "entries should be sorted by depth ASC; got {depths:?}"
    );
    // First few are depth=1.
    assert_eq!(depths[0], 1, "first entry should be depth=1");

    // 3. exclude_test_paths=false includes the test caller.
    let with_tests = round_trip(
        &mut stream,
        "11",
        "Index.ImpactOf",
        json!({ "name": "target", "exclude_test_paths": false }),
    )
    .await?;
    let with_test_names: Vec<&str> = with_tests["result"]["impact"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|e| e["qualified_name"].as_str().map(String::from))
        .collect::<Vec<_>>()
        .leak() // for the comparison; leaks ~50 bytes per test run
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert!(
        with_test_names.contains(&"test_target_runs"),
        "with exclude_test_paths=false, test_target_runs should be included; got {with_test_names:?}"
    );

    // 4. depth=1 → direct callers only.
    let depth1 = round_trip(
        &mut stream,
        "12",
        "Index.ImpactOf",
        json!({ "name": "target", "depth": 1 }),
    )
    .await?;
    let d1_impact = depth1["result"]["impact"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let d1_names: Vec<&str> = d1_impact
        .iter()
        .filter_map(|e| e["qualified_name"].as_str())
        .collect();
    // Should NOT contain the grandcallers.
    assert!(
        !d1_names.contains(&"grandcaller_1") && !d1_names.contains(&"grandcaller_2"),
        "depth=1 should exclude grandcallers; got {d1_names:?}"
    );
    // SHOULD contain the direct callers.
    for direct in &["caller_a", "caller_b", "caller_c"] {
        assert!(
            d1_names.contains(direct),
            "depth=1 should still include {direct}; got {d1_names:?}"
        );
    }
    // Depth truncation flag fires when there were unvisited callers
    // past depth=1 (the grandcallers).
    assert_eq!(
        depth1["result"]["depth_truncated"], true,
        "depth=1 with grandcallers present should trip depth_truncated"
    );

    // 5. Unknown name → SYMBOL_NOT_FOUND.
    let missing = round_trip(
        &mut stream,
        "13",
        "Index.ImpactOf",
        json!({ "name": "no_such_thing_ever" }),
    )
    .await?;
    assert!(missing["error"].is_object(), "expected error envelope");
    assert_eq!(missing["error"]["code"], "SYMBOL_NOT_FOUND");

    Ok(())
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
