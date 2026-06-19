//! End-to-end test for verify-v0 P1.U4: `Index.VerifyClaims`.
//!
//! Fixture (`lib.rs`):
//!   `fn flush(entries: Vec<u32>) -> u32` on line 1 (arity 1).
//!   `unsafe extern "C" fn vararg(x: u32, ...)` — a C-variadic callee
//!   whose signature shape is undecidable → indeterminate.
//!
//! The headline test is the decidability math: a mixed batch of 4 claims
//! (2 grounded, 1 not_found, 1 indeterminate) yields grounded:2, total:3
//! (the indeterminate claim is EXCLUDED from the denominator), and
//! grounding_rate ≈ 0.667. An empty batch yields grounding_rate: null.

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
async fn verify_claims_round_trip() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    std::fs::write(
        workspace.path().join("lib.rs"),
        "pub fn flush(entries: Vec<u32>) -> u32 { entries.len() as u32 }\n\
         pub unsafe extern \"C\" fn vararg(x: u32, ...) -> u32 { x }\n",
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

    wait_for_symbol(&mut stream, "flush", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "vararg", Duration::from_secs(5)).await?;

    // Mixed batch of 4:
    //   - symbol "flush" exists           → grounded
    //   - location flush@lib.rs:1         → grounded
    //   - symbol "nonexistent_xyz"        → not_found (decidable miss)
    //   - signature vararg (variadic)     → indeterminate (excluded)
    // Expect: grounded:2, total:3, grounding_rate ≈ 0.667.
    let batch = round_trip(
        &mut stream,
        "10",
        "Index.VerifyClaims",
        json!({ "claims": [
            { "type": "symbol", "name": "flush" },
            { "type": "location", "symbol": "flush", "file": "lib.rs", "line": 1 },
            { "type": "symbol", "name": "nonexistent_xyz" },
            { "type": "signature", "name": "vararg", "claimed": { "arity": 1, "params": ["x"] } }
        ]}),
    )
    .await?;
    assert!(batch["error"].is_null(), "batch errored: {batch:?}");
    let b = &batch["result"];
    assert_eq!(b["grounded"], 2, "expected grounded:2; got {b:?}");
    assert_eq!(
        b["total"], 3,
        "indeterminate must be excluded from total; got {b:?}"
    );
    let rate = b["grounding_rate"]
        .as_f64()
        .expect("rate should be a number");
    assert!(
        (rate - 0.666_667).abs() < 1e-3,
        "expected rate ~0.667; got {rate}"
    );

    let results = b["results"].as_array().cloned().unwrap_or_default();
    assert_eq!(
        results.len(),
        4,
        "results must carry one entry per claim; got {results:?}"
    );
    // The 4th claim (variadic signature) is indeterminate → ok:null.
    assert!(
        results[3]["ok"].is_null(),
        "indeterminate claim must have ok:null; got {:?}",
        results[3]
    );
    assert_eq!(results[0]["ok"], true);
    assert_eq!(results[1]["ok"], true);
    assert_eq!(results[2]["ok"], false);

    // Empty claims → grounding_rate: null (not NaN), total 0.
    let empty = round_trip(
        &mut stream,
        "11",
        "Index.VerifyClaims",
        json!({ "claims": [] }),
    )
    .await?;
    let e = &empty["result"];
    assert_eq!(e["total"], 0);
    assert_eq!(e["grounded"], 0);
    assert!(
        e["grounding_rate"].is_null(),
        "empty batch rate must be null; got {e:?}"
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
