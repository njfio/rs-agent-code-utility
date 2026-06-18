//! End-to-end test for verify-v0 P1.U2: `Index.VerifySignature`.
//!
//! Fixture (`sig.rs`):
//!   `fn flush(entries: Vec<u32>) -> u32` — arity 1, one param `entries`,
//!   returns `u32`. Drives the match / arity-diff / unknown-param /
//!   exact-match cases.
//!   `unsafe extern "C" fn vararg(x: u32, ...)` — a C-variadic callee,
//!   which `signature_shape` cannot decide → indeterminate.

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
            anyhow::bail!("socket {} did not appear within {:?}", path.display(), timeout);
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
        let resp = round_trip(stream, &id.to_string(), "Index.FindSymbol", json!({ "name": name }))
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
async fn verify_signature_round_trip() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    std::fs::write(
        workspace.path().join("sig.rs"),
        "pub fn flush(entries: Vec<u32>) -> u32 { entries.len() as u32 }\n\
         pub unsafe extern \"C\" fn vararg(x: u32, ...) -> u32 { x }\n\
         pub fn pair(a: u32, b: u32) -> u32 { a + b }\n",
    )?;

    let socket_path = if cfg!(target_os = "macos") {
        home_dir.path().join("Library").join("Caches").join("rts").join("default.sock")
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

    let mount = round_trip(&mut stream, "1", "Workspace.Mount", json!({ "root": workspace.path() }))
        .await?;
    assert!(mount["error"].is_null(), "mount: {mount:?}");

    wait_for_symbol(&mut stream, "flush", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "vararg", Duration::from_secs(5)).await?;

    // 1. Exact match → match:true, diff:[].
    let exact = round_trip(
        &mut stream,
        "10",
        "Index.VerifySignature",
        json!({ "name": "flush", "claimed": { "arity": 1, "params": ["entries"], "returns": "u32" } }),
    )
    .await?;
    assert!(exact["error"].is_null(), "exact errored: {exact:?}");
    let r = &exact["result"];
    assert_eq!(r["match"], true, "expected match:true; got {r:?}");
    assert_eq!(r["resolution"], "exact");
    assert!(
        r["diff"].as_array().map(|a| a.is_empty()).unwrap_or(false),
        "exact match must have empty diff; got {r:?}"
    );
    assert_eq!(r["actual"]["arity"], 1);
    assert_eq!(r["actual"]["params"][0], "entries");
    assert_eq!(r["actual"]["returns"], "u32");

    // 2. Wrong arity (claimed 2 vs actual 1) → match:false + {issue:"arity"}.
    let arity = round_trip(
        &mut stream,
        "11",
        "Index.VerifySignature",
        json!({ "name": "flush", "claimed": { "arity": 2, "params": ["entries", "n"] } }),
    )
    .await?;
    let ar = &arity["result"];
    assert_eq!(ar["match"], false, "arity mismatch should be match:false; got {ar:?}");
    let diff = ar["diff"].as_array().cloned().unwrap_or_default();
    let has_arity = diff.iter().any(|d| d["issue"] == "arity");
    assert!(has_arity, "expected an arity diff; got {diff:?}");
    let arity_entry = diff.iter().find(|d| d["issue"] == "arity").unwrap();
    assert_eq!(arity_entry["claimed"], 2);
    assert_eq!(arity_entry["actual"], 1);

    // 3. Bogus claimed param `flush` → {issue:"unknown_param", name:"flush"}.
    let unknown = round_trip(
        &mut stream,
        "12",
        "Index.VerifySignature",
        json!({ "name": "flush", "claimed": { "arity": 1, "params": ["flush"] } }),
    )
    .await?;
    let ur = &unknown["result"];
    assert_eq!(ur["match"], false);
    let udiff = ur["diff"].as_array().cloned().unwrap_or_default();
    let unknown_entry = udiff.iter().find(|d| d["issue"] == "unknown_param");
    assert!(unknown_entry.is_some(), "expected unknown_param diff; got {udiff:?}");
    assert_eq!(unknown_entry.unwrap()["name"], "flush");

    // 4. Variadic callee → indeterminate, match omitted.
    let variadic = round_trip(
        &mut stream,
        "13",
        "Index.VerifySignature",
        json!({ "name": "vararg", "claimed": { "arity": 1, "params": ["x"] } }),
    )
    .await?;
    let vr = &variadic["result"];
    assert_eq!(vr["resolution"], "indeterminate", "variadic should be indeterminate; got {vr:?}");
    assert_eq!(
        vr["reason"], "undecidable_signature",
        "variadic shape is undecidable, not an FFI/unresolved reason; got {vr:?}"
    );
    assert!(vr["match"].is_null(), "indeterminate must OMIT match; got {vr:?}");

    // 5. Same param set, wrong order → match:false + {issue:"param_order"}.
    let reordered = round_trip(
        &mut stream,
        "15",
        "Index.VerifySignature",
        json!({ "name": "pair", "claimed": { "arity": 2, "params": ["b", "a"] } }),
    )
    .await?;
    let rr = &reordered["result"];
    assert_eq!(rr["match"], false, "reordered params should be match:false; got {rr:?}");
    let rdiff = rr["diff"].as_array().cloned().unwrap_or_default();
    assert!(
        rdiff.iter().any(|d| d["issue"] == "param_order"),
        "expected a param_order diff; got {rdiff:?}"
    );
    // Same set, different order ⇒ NOT reported as unknown_param.
    assert!(
        !rdiff.iter().any(|d| d["issue"] == "unknown_param"),
        "same-set reorder must not report unknown_param; got {rdiff:?}"
    );

    // 6. Missing symbol → not_found + candidates.
    let miss = round_trip(
        &mut stream,
        "14",
        "Index.VerifySignature",
        json!({ "name": "flushh", "claimed": { "arity": 1 } }),
    )
    .await?;
    let mr = &miss["result"];
    assert_eq!(mr["resolution"], "not_found");
    assert_eq!(mr["exists"], false);
    let cands = mr["candidates"].as_array().cloned().unwrap_or_default();
    assert!(!cands.is_empty(), "miss should carry candidates; got {mr:?}");

    Ok(())
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
