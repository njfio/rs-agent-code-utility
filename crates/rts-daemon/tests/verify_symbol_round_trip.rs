//! End-to-end test for verify-v0 P1.U1: `Index.VerifySymbol`.
//!
//! Fixture:
//!   `store.rs`  defines `commit_batch` (a fn) and `helper`.
//!   `dup_a.rs`  defines `overloaded`.
//!   `dup_b.rs`  defines `overloaded` (same name, second file).
//!
//! After indexing:
//!   1. `verify_symbol(commit_batch)` → exists:true, resolution:"exact",
//!      matches[0] carries the right line/kind/signature.
//!   2. `verify_symbol(commit_batchs)` (misspelling) → exists:false,
//!      resolution:"not_found", with `commit_batch` as the top candidate.
//!   3. `verify_symbol(overloaded)` (two defs, no filter) →
//!      resolution:"indeterminate", reason:"ambiguous_overload",
//!      exists:true, matches lists both.
//!   4. `verify_symbol(overloaded, file="dup_a.rs")` → exact (filter
//!      disambiguates to one def).

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
async fn verify_symbol_round_trip() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    std::fs::write(
        workspace.path().join("store.rs"),
        "pub fn commit_batch(x: u32) -> u32 { x + 1 }\n\
         pub fn helper() -> u32 { 0 }\n",
    )?;
    std::fs::write(
        workspace.path().join("dup_a.rs"),
        "pub fn overloaded() -> u32 { 1 }\n",
    )?;
    std::fs::write(
        workspace.path().join("dup_b.rs"),
        "pub fn overloaded() -> u32 { 2 }\n",
    )?;
    // A method whose container is `Store` — drives the qualified-name cases.
    std::fs::write(
        workspace.path().join("api.rs"),
        "pub struct Store;\nimpl Store { pub fn boot() -> u32 { 0 } }\n",
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

    wait_for_symbol(&mut stream, "commit_batch", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "overloaded", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "boot", Duration::from_secs(5)).await?;

    // 1. Indexed symbol → exists:true, resolution:"exact".
    let resp = round_trip(
        &mut stream,
        "10",
        "Index.VerifySymbol",
        json!({ "name": "commit_batch" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "verify_symbol failed: {resp:?}");
    let r = &resp["result"];
    assert_eq!(r["exists"], true, "expected exists:true; got {r:?}");
    assert_eq!(r["resolution"], "exact");
    let matches = r["matches"].as_array().cloned().unwrap_or_default();
    assert_eq!(matches.len(), 1, "expected one match; got {matches:?}");
    let m0 = &matches[0];
    assert_eq!(m0["qualified_name"], "commit_batch");
    assert_eq!(m0["kind"], "fn");
    assert_eq!(m0["file"], "store.rs");
    assert_eq!(m0["line"], 1, "commit_batch is on line 1");
    assert!(
        m0["signature"]
            .as_str()
            .map(|s| s.contains("commit_batch"))
            .unwrap_or(false),
        "signature should render and contain the symbol name; got {m0:?}"
    );
    assert!(m0["pagerank"].is_number());
    assert!(
        r["candidates"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "candidates must be empty on an exact hit; got {r:?}"
    );
    assert!(r["content_version"].is_string());

    // 2. Misspelling → exists:false, resolution:"not_found", top
    //    candidate is the real symbol.
    let miss = round_trip(
        &mut stream,
        "11",
        "Index.VerifySymbol",
        json!({ "name": "commit_batchs" }),
    )
    .await?;
    assert!(miss["error"].is_null(), "verify miss errored: {miss:?}");
    let mr = &miss["result"];
    assert_eq!(mr["exists"], false);
    assert_eq!(mr["resolution"], "not_found");
    assert!(
        mr["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "matches must be empty on a miss; got {mr:?}"
    );
    let cands = mr["candidates"].as_array().cloned().unwrap_or_default();
    assert!(
        !cands.is_empty(),
        "expected candidates on a miss; got {mr:?}"
    );
    assert_eq!(
        cands[0]["qualified_name"], "commit_batch",
        "top candidate should be the real symbol; got {cands:?}"
    );

    // 3. Two defs, no filter → indeterminate / ambiguous_overload.
    let amb = round_trip(
        &mut stream,
        "12",
        "Index.VerifySymbol",
        json!({ "name": "overloaded" }),
    )
    .await?;
    assert!(amb["error"].is_null(), "verify ambiguous errored: {amb:?}");
    let ar = &amb["result"];
    assert_eq!(ar["exists"], true);
    assert_eq!(ar["resolution"], "indeterminate");
    assert_eq!(ar["reason"], "ambiguous_overload");
    let am = ar["matches"].as_array().cloned().unwrap_or_default();
    assert_eq!(
        am.len(),
        2,
        "ambiguous case should list both defs; got {am:?}"
    );

    // 4. Same name + file filter selecting one → exact.
    let filtered = round_trip(
        &mut stream,
        "13",
        "Index.VerifySymbol",
        json!({ "name": "overloaded", "file": "dup_a.rs" }),
    )
    .await?;
    assert!(
        filtered["error"].is_null(),
        "verify filtered errored: {filtered:?}"
    );
    let fr = &filtered["result"];
    assert_eq!(fr["exists"], true);
    assert_eq!(fr["resolution"], "exact");
    let fm = fr["matches"].as_array().cloned().unwrap_or_default();
    assert_eq!(fm.len(), 1, "file filter should select one def; got {fm:?}");
    assert_eq!(fm[0]["file"], "dup_a.rs");
    assert!(
        fr["reason"].is_null(),
        "exact result must not carry a reason; got {fr:?}"
    );

    // 5. Qualified name whose container matches → exact.
    let q_ok = round_trip(
        &mut stream,
        "14",
        "Index.VerifySymbol",
        json!({ "name": "Store::boot" }),
    )
    .await?;
    let qok = &q_ok["result"];
    assert_eq!(
        qok["exists"], true,
        "Store::boot should resolve; got {qok:?}"
    );
    assert_eq!(qok["resolution"], "exact");

    // 6. Qualified name whose container does NOT match → not_found, even
    //    though a bare `boot` exists (the false-positive Codex flagged).
    let q_bad = round_trip(
        &mut stream,
        "15",
        "Index.VerifySymbol",
        json!({ "name": "Other::boot" }),
    )
    .await?;
    let qbad = &q_bad["result"];
    assert_eq!(
        qbad["exists"], false,
        "Other::boot must NOT match the bare `boot` under Store; got {qbad:?}"
    );
    assert_eq!(qbad["resolution"], "not_found");

    Ok(())
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
