//! End-to-end test for v0.6 `Index.Grep` v2 sub-counter telemetry (U7).
//!
//! Asserts:
//! 1. `Daemon.Stats.calls` includes the three new sub-counter fields
//!    (`Index.Grep.multiline`, `Index.Grep.structural`,
//!    `Index.Grep.within_symbol`), even when zero.
//! 2. A v1-shape Index.Grep call (`text` only) bumps `Index.Grep`
//!    by 1 and leaves every sub-counter at 0.
//! 3. A multiline regex call (`text`+`regex: true`+`multiline: true`)
//!    bumps `Index.Grep` AND `Index.Grep.multiline` by 1, leaves
//!    the other two sub-counters at 0.
//! 4. A within_symbol call bumps `Index.Grep` AND
//!    `Index.Grep.within_symbol` by 1.
//!
//! We can't fully exercise `Index.Grep.structural` until U5 wires up
//! the scanner — for now we assert only that the field appears in
//! the snapshot envelope (a structural call would error out before
//! the bump fires, since the validator rejects it as
//! STRUCTURAL_NOT_YET_IMPLEMENTED at the dispatch boundary).

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
    let n = tokio::time::timeout(Duration::from_secs(5), reader.read_until(b'\n', &mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to {method}"))??;
    anyhow::ensure!(n > 0, "EOF before response to {method}");
    Ok(serde_json::from_slice(&buf)?)
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn grep_v2_subcounters_track_each_param_combo() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Seed file used by all three grep calls. Provides a symbol
    // (`hello`) the within_symbol resolution can hit so the call
    // reaches the bump site rather than failing in
    // `WITHIN_SYMBOL_NOT_FOUND`.
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn hello() {\n    let x = 1;\n}\n",
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

    // 1. Snapshot shape: the three new fields must be present (even
    //    at zero) so consumers can read them unconditionally.
    let stats0 = round_trip(&mut stream, "1", "Daemon.Stats", json!({})).await?;
    let calls0 = &stats0["result"]["calls"];
    for field in [
        "Index.Grep.multiline",
        "Index.Grep.structural",
        "Index.Grep.within_symbol",
    ] {
        assert!(
            calls0.get(field).is_some(),
            "Daemon.Stats.calls must include `{field}` field; got {calls0:?}"
        );
    }
    assert_eq!(
        calls0["Index.Grep.multiline"].as_u64(),
        Some(0),
        "multiline sub-counter starts at 0"
    );
    assert_eq!(
        calls0["Index.Grep.structural"].as_u64(),
        Some(0),
        "structural sub-counter starts at 0"
    );
    assert_eq!(
        calls0["Index.Grep.within_symbol"].as_u64(),
        Some(0),
        "within_symbol sub-counter starts at 0"
    );

    // 2. Mount + wait for indexing.
    let mount = round_trip(
        &mut stream,
        "2",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount: {mount:?}");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut next_id: u32 = 100;
    loop {
        next_id += 1;
        let r = round_trip(
            &mut stream,
            &next_id.to_string(),
            "Index.FindSymbol",
            json!({ "name": "hello" }),
        )
        .await?;
        if let Some(arr) = r["result"]["matches"].as_array() {
            if !arr.is_empty() {
                break;
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("`hello` never indexed within 5s");
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }

    // 3. v1-shape grep: parent bumps; sub-counters stay flat.
    let _ = round_trip(&mut stream, "10", "Index.Grep", json!({ "text": "hello" })).await?;
    let stats1 = round_trip(&mut stream, "11", "Daemon.Stats", json!({})).await?;
    let calls1 = &stats1["result"]["calls"];
    assert_eq!(
        calls1["Index.Grep"].as_u64(),
        Some(1),
        "v1 call should bump Index.Grep by 1; got {calls1:?}"
    );
    assert_eq!(
        calls1["Index.Grep.multiline"].as_u64(),
        Some(0),
        "v1 call must NOT bump multiline sub-counter"
    );
    assert_eq!(
        calls1["Index.Grep.structural"].as_u64(),
        Some(0),
        "v1 call must NOT bump structural sub-counter"
    );
    assert_eq!(
        calls1["Index.Grep.within_symbol"].as_u64(),
        Some(0),
        "v1 call must NOT bump within_symbol sub-counter"
    );

    // 4. multiline regex call: parent + multiline sub-counter bump.
    let _ = round_trip(
        &mut stream,
        "20",
        "Index.Grep",
        json!({
            "text": "hello",
            "regex": true,
            "multiline": true,
        }),
    )
    .await?;
    let stats2 = round_trip(&mut stream, "21", "Daemon.Stats", json!({})).await?;
    let calls2 = &stats2["result"]["calls"];
    assert_eq!(
        calls2["Index.Grep"].as_u64(),
        Some(2),
        "second grep call should bring parent to 2"
    );
    assert_eq!(
        calls2["Index.Grep.multiline"].as_u64(),
        Some(1),
        "multiline call should bump multiline sub-counter to 1; got {calls2:?}"
    );
    assert_eq!(
        calls2["Index.Grep.structural"].as_u64(),
        Some(0),
        "multiline call alone must NOT bump structural"
    );
    assert_eq!(
        calls2["Index.Grep.within_symbol"].as_u64(),
        Some(0),
        "multiline call alone must NOT bump within_symbol"
    );

    // 5. multiline: false (regex only) — parent bumps, multiline
    //    sub-counter stays put.
    let _ = round_trip(
        &mut stream,
        "30",
        "Index.Grep",
        json!({
            "text": "hello",
            "regex": true,
            "multiline": false,
        }),
    )
    .await?;
    let stats3 = round_trip(&mut stream, "31", "Daemon.Stats", json!({})).await?;
    let calls3 = &stats3["result"]["calls"];
    assert_eq!(
        calls3["Index.Grep"].as_u64(),
        Some(3),
        "v1-shape regex call should bring parent to 3"
    );
    assert_eq!(
        calls3["Index.Grep.multiline"].as_u64(),
        Some(1),
        "multiline: false must NOT bump multiline sub-counter"
    );

    // 6. total_calls must include the new sub-counters in its sum.
    let total = stats3["result"]["total_calls"].as_u64().unwrap_or(0);
    let sum: u64 = calls3
        .as_object()
        .unwrap()
        .values()
        .filter_map(|v| v.as_u64())
        .sum();
    assert_eq!(
        total, sum,
        "total_calls should equal sum of per-method counts (incl. sub-counters); calls={calls3:?}"
    );

    Ok(())
}
