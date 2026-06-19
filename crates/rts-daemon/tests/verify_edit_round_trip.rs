//! End-to-end test for verify-v0 P3: `Index.VerifyEdit`.
//!
//! `Index.VerifyEdit` validates a PROPOSED patch against the live index
//! *before it is written* and returns a pass/warn/fail verdict so an agent
//! can gate a multi-file edit before committing it to disk. It is a scoped
//! in-memory delta (re-parse the patched files, diff defs, query the live
//! index for callers) — strictly read-only.
//!
//! Fixture:
//!   `hub.rs`      defines `target` (called) and an arity-1 signature.
//!   `caller_a.rs` calls `target`.
//!
//! Cases:
//!   1. edit REMOVING a called fn → `fail` + `broken_caller` naming the
//!      live caller.
//!   2. edit changing a called fn's ARITY → `fail` + `signature_break`
//!      "callee arity 1 -> 2".
//!   3. edit ADDING a new fn → `pass` + `new_symbol` info.
//!   4. arity-preserving body edit of a called fn → `pass`.
//!   5. editing BOTH callee and its only caller consistently (caller in the
//!      patched set) → `pass` (no false broken_caller).
//!   6. > max_files (here forced via many tiny edits is impractical; we
//!      instead assert the partial-result shape directly by sending more
//!      than the cap) → `files_skipped` populated, verdict NOT a bare pass.

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

/// Poll `Index.FindCallers(target)` until `expected` is among the callers —
/// the REFS edges `Index.VerifyEdit`'s caller queries depend on are
/// committed in a separate writer batch from the DEF rows.
async fn wait_for_refs(
    stream: &mut UnixStream,
    target: &str,
    expected: &str,
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
        let present = resp["result"]["callers"]
            .as_array()
            .map(|a| {
                a.iter()
                    .any(|c| c["enclosing_qualified_name"].as_str() == Some(expected))
            })
            .unwrap_or(false);
        if present {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("REFS to `{target}` from `{expected}` never settled within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn verify_edit_round_trip() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // `target` is called by `caller_a`.
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn target(x: u32) -> u32 { x + 1 }\n",
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
    wait_for_symbol(&mut stream, "caller_a", Duration::from_secs(5)).await?;
    wait_for_refs(&mut stream, "target", "caller_a", Duration::from_secs(5)).await?;

    // 1. REMOVE a called fn (hub.rs no longer defines `target`) → fail +
    //    broken_caller naming the live caller (`caller_a`, outside the patch).
    let removed = round_trip(
        &mut stream,
        "10",
        "Index.VerifyEdit",
        json!({ "edits": [{
            "file": "hub.rs",
            "content": "pub fn unrelated() -> u32 { 0 }\n"
        }]}),
    )
    .await?;
    assert!(
        removed["error"].is_null(),
        "verify_edit remove: {removed:?}"
    );
    let r = &removed["result"];
    assert_eq!(
        r["verdict"], "fail",
        "removing a called fn must fail: {r:?}"
    );
    let findings = r["findings"].as_array().cloned().unwrap_or_default();
    let broken = findings
        .iter()
        .find(|f| f["kind"] == "broken_caller" && f["symbol"] == "target")
        .unwrap_or_else(|| panic!("expected a broken_caller for `target`; got {findings:?}"));
    assert_eq!(
        broken["site"]["file"], "caller_a.rs",
        "the broken caller's file must be listed: {broken:?}"
    );
    assert_eq!(
        broken["site"]["enclosing"], "caller_a",
        "the broken caller's enclosing def must be `caller_a`: {broken:?}"
    );
    assert!(
        r["summary"]["critical"].as_u64().unwrap_or(0) >= 1,
        "critical count: {r:?}"
    );

    // 2. Change a called fn's ARITY (1 -> 2) → fail + signature_break with
    //    detail "callee arity 1 -> 2".
    let arity = round_trip(
        &mut stream,
        "11",
        "Index.VerifyEdit",
        json!({ "edits": [{
            "file": "hub.rs",
            "content": "pub fn target(x: u32, y: u32) -> u32 { x + y }\n"
        }]}),
    )
    .await?;
    let a = &arity["result"];
    assert_eq!(a["verdict"], "fail", "arity change must fail: {a:?}");
    let afindings = a["findings"].as_array().cloned().unwrap_or_default();
    let sigbreak = afindings
        .iter()
        .find(|f| f["kind"] == "signature_break")
        .unwrap_or_else(|| panic!("expected a signature_break; got {afindings:?}"));
    assert_eq!(
        sigbreak["detail"], "callee arity 1 -> 2",
        "signature_break detail: {sigbreak:?}"
    );
    assert_eq!(sigbreak["site"]["file"], "caller_a.rs");

    // 3. ADD a new fn (keep `target` intact) → pass + new_symbol info.
    let added = round_trip(
        &mut stream,
        "12",
        "Index.VerifyEdit",
        json!({ "edits": [{
            "file": "hub.rs",
            "content": "pub fn target(x: u32) -> u32 { x + 1 }\npub fn brand_new() -> u32 { 9 }\n"
        }]}),
    )
    .await?;
    let ad = &added["result"];
    assert_eq!(ad["verdict"], "pass", "adding a fn is a pass: {ad:?}");
    let adfindings = ad["findings"].as_array().cloned().unwrap_or_default();
    assert!(
        adfindings
            .iter()
            .any(|f| f["kind"] == "new_symbol" && f["symbol"] == "brand_new"),
        "expected a new_symbol finding for `brand_new`; got {adfindings:?}"
    );

    // 4. Arity-preserving body edit of a called fn → pass.
    let body = round_trip(
        &mut stream,
        "13",
        "Index.VerifyEdit",
        json!({ "edits": [{
            "file": "hub.rs",
            "content": "pub fn target(x: u32) -> u32 { x + 100 }\n"
        }]}),
    )
    .await?;
    let b = &body["result"];
    assert_eq!(
        b["verdict"], "pass",
        "an arity-preserving body edit is a pass: {b:?}"
    );
    assert_eq!(b["summary"]["critical"], 0);

    // 5. Edit BOTH the callee (arity change) AND its only caller consistently
    //    in the SAME patch → pass: the caller is inside the patched set, so it
    //    must NOT be flagged as a broken_caller against the stale index.
    let consistent = round_trip(
        &mut stream,
        "14",
        "Index.VerifyEdit",
        json!({ "edits": [
            { "file": "hub.rs",
              "content": "pub fn target(x: u32, y: u32) -> u32 { x + y }\n" },
            { "file": "caller_a.rs",
              "content": "use crate::target;\npub fn caller_a() { let _ = target(1, 2); }\n" }
        ]}),
    )
    .await?;
    let c = &consistent["result"];
    assert_eq!(
        c["verdict"], "pass",
        "a callee+caller edited together must not self-flag: {c:?}"
    );
    let cfindings = c["findings"].as_array().cloned().unwrap_or_default();
    assert!(
        !cfindings
            .iter()
            .any(|f| f["kind"] == "broken_caller" || f["kind"] == "signature_break"),
        "no caller-side findings when the caller is in the patch: {cfindings:?}"
    );

    // 6. Over the file cap → files_skipped populated, verdict NOT a bare pass.
    //    Send 55 trivial edits (default cap is 50). Each is a benign new file
    //    with one fn, so absent the cap the verdict would be a clean pass.
    let mut many: Vec<Value> = Vec::new();
    for i in 0..55 {
        many.push(json!({
            "file": format!("gen/file_{i}.rs"),
            "content": format!("pub fn gen_{i}() -> u32 {{ {i} }}\n"),
        }));
    }
    let capped = round_trip(
        &mut stream,
        "15",
        "Index.VerifyEdit",
        json!({ "edits": many }),
    )
    .await?;
    let cap = &capped["result"];
    let skipped = cap["files_skipped"].as_array().cloned().unwrap_or_default();
    assert!(
        !skipped.is_empty(),
        "over-cap edits must populate files_skipped: {cap:?}"
    );
    assert_ne!(
        cap["verdict"], "pass",
        "a partial (skipped-files) result must not read as a bare pass: {cap:?}"
    );
    assert_eq!(cap["files_analyzed"].as_u64().unwrap_or(0), 50);

    // The frozen response shape carries `content_version_base`.
    assert!(
        cap["content_version_base"].is_string(),
        "content_version_base must be present: {cap:?}"
    );

    // 7. `checks` is a DISPLAY filter, not a verdict lever. Removing a called
    //    fn while asking to see only `new_symbol` must STILL verdict `fail`
    //    (the broken_caller is suppressed from `findings[]` but the verdict and
    //    summary reflect the full analysis) — otherwise a caller could buy a
    //    false `pass` with `checks: []`.
    let filtered = round_trip(
        &mut stream,
        "16",
        "Index.VerifyEdit",
        json!({
            "edits": [{ "file": "hub.rs", "content": "pub fn unrelated() -> u32 { 0 }\n" }],
            "checks": ["new_symbol"]
        }),
    )
    .await?;
    let fl = &filtered["result"];
    assert_eq!(
        fl["verdict"], "fail",
        "`checks` must NOT lower the verdict — a real break still fails: {fl:?}"
    );
    assert!(
        fl["summary"]["critical"].as_u64().unwrap_or(0) >= 1,
        "summary must reflect the full analysis regardless of `checks`: {fl:?}"
    );
    // The display filter DID hide the broken_caller (checks=["new_symbol"]),
    // even though it still drives the verdict + summary.
    let shown = fl["findings"].as_array().cloned().unwrap_or_default();
    assert!(
        !shown.iter().any(|f| f["kind"] == "broken_caller"),
        "checks=[new_symbol] must hide broken_caller from findings[]; got {shown:?}"
    );

    // And an empty `checks` must not buy a false pass either.
    let empty_checks = round_trip(
        &mut stream,
        "17",
        "Index.VerifyEdit",
        json!({
            "edits": [{ "file": "hub.rs", "content": "pub fn unrelated() -> u32 { 0 }\n" }],
            "checks": []
        }),
    )
    .await?;
    assert_eq!(
        empty_checks["result"]["verdict"], "fail",
        "`checks: []` must not yield a false pass: {empty_checks:?}"
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
