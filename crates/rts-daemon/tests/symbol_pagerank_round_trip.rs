//! End-to-end test for v0.3 U4: symbol-level PageRank filling
//! `Index.FindSymbol.matches[*].rank_score` and driving the
//! default descending-rank sort.
//!
//! Hub-spoke fixture (4 callers around 1 hub):
//!   `hub.rs`      defines `hub_compute`
//!   `caller_a.rs` defines `caller_a` which calls `hub_compute`
//!   `caller_b.rs` defines `caller_b` which calls `hub_compute`
//!   `caller_c.rs` defines `caller_c` which calls `hub_compute`
//!   `caller_d.rs` defines `caller_d` which calls `hub_compute`
//!
//! PageRank says `hub_compute` should rank highest (it has 4 inbound
//! edges). Without the rank sort, the callers would alphabetize and
//! `caller_a` would land first; with the rank sort, `hub_compute`
//! lands first.
//!
//! Assertions:
//!   * `find_symbol(pattern="*")` returns `hub_compute` first (top
//!     of the rank-sorted list)
//!   * Each `rank_score` is non-zero (PageRank computed)
//!   * `sort: "lexical"` opt-out restores alphabetical-by-file order
//!   * The `pagerank_symbolwise` capability is advertised via
//!     `Daemon.Ping`

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
async fn symbol_pagerank_ranks_hub_above_callers() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Hub defines hub_compute; four callers reference it. PageRank
    // should put hub_compute on top.
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn hub_compute(x: u32) -> u32 { x + 1 }\n",
    )?;
    for tag in ["a", "b", "c", "d"] {
        std::fs::write(
            workspace.path().join(format!("caller_{tag}.rs")),
            format!(
                "pub fn caller_{tag}() {{\n    let _ = hub_compute({});\n}}\n",
                tag.bytes().next().unwrap() as u32
            ),
        )?;
    }

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

    // Wait for all 5 symbols.
    wait_for_symbol(&mut stream, "hub_compute", Duration::from_secs(5)).await?;
    for tag in ["a", "b", "c", "d"] {
        wait_for_symbol(
            &mut stream,
            &format!("caller_{tag}"),
            Duration::from_secs(5),
        )
        .await?;
    }

    // 1. Daemon.Ping advertises pagerank_symbolwise.
    let ping = round_trip(&mut stream, "2", "Daemon.Ping", json!({})).await?;
    let caps = ping["result"]["capabilities"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let cap_strs: Vec<&str> = caps.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        cap_strs.contains(&"pagerank_symbolwise"),
        "expected pagerank_symbolwise in caps; got {cap_strs:?}"
    );
    // Also smoke the other v0.3 capabilities since this is the first
    // test to look at the full list.
    for cap in [
        "find_callers",
        "read_symbol.include_callers",
        "closure_walker",
        "pagerank_filewise",
    ] {
        assert!(
            cap_strs.contains(&cap),
            "expected `{cap}` in caps; got {cap_strs:?}"
        );
    }

    // 2. Default sort is rank-descending. find_symbol(pattern="*")
    //    should put hub_compute first.
    let resp = round_trip(
        &mut stream,
        "10",
        "Index.FindSymbol",
        json!({ "pattern": "*" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "find_symbol failed: {resp:?}");
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        matches.len() >= 5,
        "expected ≥5 matches; got {} ({matches:?})",
        matches.len()
    );
    let top_name = matches[0]["qualified_name"].as_str().unwrap_or("");
    assert_eq!(
        top_name,
        "hub_compute",
        "expected hub_compute to outrank callers; got order [{}] (full ordering: {:?})",
        top_name,
        matches
            .iter()
            .map(|m| m["qualified_name"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
    );

    // All entries should carry a non-zero rank_score now (uniform PageRank
    // on isolated nodes would be 1/N ≈ 0.2 for a 5-node graph). The
    // hub's rank should be measurably higher than the average caller.
    let hub_rank = matches[0]["rank_score"].as_f64().unwrap_or(0.0);
    assert!(hub_rank > 0.0, "hub rank_score must be > 0; got {hub_rank}");
    let caller_ranks: Vec<f64> = matches
        .iter()
        .skip(1)
        .take(4)
        .map(|m| m["rank_score"].as_f64().unwrap_or(0.0))
        .collect();
    let avg_caller_rank = caller_ranks.iter().sum::<f64>() / caller_ranks.len() as f64;
    assert!(
        hub_rank > avg_caller_rank,
        "hub_rank ({hub_rank}) should exceed avg caller rank ({avg_caller_rank}); ranks={caller_ranks:?}"
    );

    // 3. sort="lexical" opt-out restores alphabetical-by-file order.
    //    caller_a.rs sorts first, hub_compute (hub.rs) is in the
    //    middle, so caller_a should land first.
    let resp_lex = round_trip(
        &mut stream,
        "11",
        "Index.FindSymbol",
        json!({ "pattern": "*", "sort": "lexical" }),
    )
    .await?;
    let lex_matches = resp_lex["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let lex_top = lex_matches[0]["qualified_name"].as_str().unwrap_or("");
    assert_eq!(
        lex_top, "caller_a",
        "with sort=lexical, caller_a.rs alphabetizes first; got {}",
        lex_top
    );
    // rank_score is still populated under lexical sort (it's just not
    // the sort key).
    assert!(lex_matches[0]["rank_score"].as_f64().unwrap_or(0.0) > 0.0);

    // 4. find_callers also fills rank_score now (the enclosing fn's rank).
    let callers_resp = round_trip(
        &mut stream,
        "12",
        "Index.FindCallers",
        json!({ "name": "hub_compute" }),
    )
    .await?;
    let callers = callers_resp["result"]["callers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(callers.len(), 4, "4 callers expected; got {callers:?}");
    for c in &callers {
        let r = c["rank_score"].as_f64().unwrap_or(0.0);
        assert!(
            r > 0.0,
            "each caller entry should carry a non-zero rank_score; got {r} ({c:?})"
        );
    }

    Ok(())
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
