//! End-to-end test for verify-v0 P2.U1: `Index.VerifyImpact`.
//!
//! `Index.VerifyImpact` is a verification-framed wrapper over the impact
//! analysis: the agent declares an intended change to a symbol and gets the
//! blast radius as a pass/fail verdict so it can gate an edit before making
//! it.
//!
//! Fixture:
//!   `hub.rs`      defines `target` (called) and `orphan` (uncalled).
//!   `caller_a.rs` calls `target`.
//!
//! Cases:
//!   1. `remove` of a called fn  → would_break + the caller listed.
//!   2. `remove` of an uncalled fn → safe.
//!   3. `signature` arity 1→2 on a called fn → would_break + per-caller
//!      `reason` "arity 1 -> 2".
//!   4. `signature` arity-preserving rename of a param → safe.
//!   5. unknown symbol → not_found + non-empty candidates.

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

/// Poll `Index.FindCallers(target)` until every name in `expected_callers`
/// is present — the REFS edges `Index.VerifyImpact`'s BFS depends on are
/// committed in a separate writer batch from the DEF rows. Mirrors
/// `impact_of_round_trip.rs::wait_for_refs`.
async fn wait_for_refs(
    stream: &mut UnixStream,
    target: &str,
    expected_callers: &[&str],
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut id: u64 = 200;
    loop {
        id += 1;
        let resp = round_trip(
            stream,
            &id.to_string(),
            "Index.FindCallers",
            json!({ "name": target }),
        )
        .await?;
        let callers = resp["result"]["callers"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let caller_names: Vec<&str> = callers
            .iter()
            .filter_map(|c| c["enclosing_qualified_name"].as_str())
            .collect();
        let all_present = expected_callers
            .iter()
            .all(|expected| caller_names.contains(expected));
        if all_present {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "REFS to `{target}` never fully settled within {:?} — expected {:?}, got {:?}",
                timeout,
                expected_callers,
                caller_names
            );
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn verify_impact_round_trip() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // `target` is called by caller_a; `orphan` is defined but never called.
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn target(x: u32) -> u32 { x + 1 }\n\
         pub fn orphan(y: u32) -> u32 { y + 2 }\n",
    )?;
    std::fs::write(
        workspace.path().join("caller_a.rs"),
        "use crate::target;\n\
         pub fn caller_a() { let _ = target(1); }\n",
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

    wait_for_symbol(&mut stream, "target", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "orphan", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "caller_a", Duration::from_secs(5)).await?;
    wait_for_refs(&mut stream, "target", &["caller_a"], Duration::from_secs(5)).await?;

    // 1. remove of a called fn → would_break + caller listed.
    let rm = round_trip(
        &mut stream,
        "10",
        "Index.VerifyImpact",
        json!({ "symbol": "target", "change": "remove" }),
    )
    .await?;
    assert!(rm["error"].is_null(), "verify_impact remove failed: {rm:?}");
    let r = &rm["result"];
    assert_eq!(r["resolution"], "exact");
    assert_eq!(r["verdict"], "would_break", "remove of a called fn: {r:?}");
    assert_eq!(r["change"], "remove");
    assert!(
        r["affected_count"].as_u64().unwrap_or(0) >= 1,
        "expected >=1 affected caller; got {r:?}"
    );
    let callers = r["affected_callers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        callers
            .iter()
            .any(|c| c["enclosing"].as_str() == Some("caller_a")),
        "caller_a should be listed; got {callers:?}"
    );
    assert_eq!(
        callers[0]["reason"], "references removed symbol",
        "remove reason; got {callers:?}"
    );

    // 2. remove of an uncalled fn → safe.
    let rm_orphan = round_trip(
        &mut stream,
        "11",
        "Index.VerifyImpact",
        json!({ "symbol": "orphan", "change": "remove" }),
    )
    .await?;
    let ro = &rm_orphan["result"];
    assert_eq!(ro["resolution"], "exact");
    assert_eq!(ro["verdict"], "safe", "remove of an uncalled fn: {ro:?}");
    assert_eq!(ro["affected_count"], 0);

    // 3. signature arity 1 -> 2 on a called fn → would_break + per-caller reason.
    let sig = round_trip(
        &mut stream,
        "12",
        "Index.VerifyImpact",
        json!({
            "symbol": "target",
            "change": "signature",
            "new_signature": "target(x: u32, y: u32) -> u32"
        }),
    )
    .await?;
    assert!(
        sig["error"].is_null(),
        "verify_impact signature failed: {sig:?}"
    );
    let s = &sig["result"];
    assert_eq!(s["resolution"], "exact", "decidable arity change: {s:?}");
    assert_eq!(s["verdict"], "would_break", "arity 1 -> 2: {s:?}");
    let scallers = s["affected_callers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        scallers
            .iter()
            .any(|c| c["reason"].as_str() == Some("arity 1 -> 2")),
        "per-caller arity reason; got {scallers:?}"
    );

    // 4. signature arity-preserving param rename → safe.
    let sig_ok = round_trip(
        &mut stream,
        "13",
        "Index.VerifyImpact",
        json!({
            "symbol": "target",
            "change": "signature",
            "new_signature": "target(renamed: u32) -> u32"
        }),
    )
    .await?;
    let so = &sig_ok["result"];
    assert_eq!(so["resolution"], "exact", "arity-preserving: {so:?}");
    assert_eq!(so["verdict"], "safe", "arity unchanged is safe: {so:?}");

    // 5. unknown symbol → not_found + non-empty candidates, no verdict.
    let miss = round_trip(
        &mut stream,
        "14",
        "Index.VerifyImpact",
        json!({ "symbol": "targett", "change": "remove" }),
    )
    .await?;
    let mr = &miss["result"];
    assert_eq!(mr["resolution"], "not_found");
    assert_eq!(mr["exists"], false);
    assert!(
        mr["verdict"].is_null(),
        "not_found must not carry a verdict; got {mr:?}"
    );
    let cands = mr["candidates"].as_array().cloned().unwrap_or_default();
    assert!(
        !cands.is_empty(),
        "expected candidates on a miss; got {mr:?}"
    );

    Ok(())
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
