//! End-to-end test for verify-v0 P1.U3: `Index.VerifyImport`.
//!
//! Fixture (`store.rs`):
//!   `struct CommitOptions` and `struct CommitBatch` — two sibling types.
//!
//! Cases:
//!   1. A path whose final segment is a present sibling type → resolves.
//!   2. A single-segment absent name whose sibling exists → not_found,
//!      with the sibling as a candidate.
//!   3. A deep external path (final segment absent, multi-segment) →
//!      indeterminate (no confident false negative).

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
async fn verify_import_round_trip() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    std::fs::write(
        workspace.path().join("store.rs"),
        "pub struct CommitOptions { pub n: u32 }\n\
         pub struct CommitBatch { pub m: u32 }\n",
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

    wait_for_symbol(&mut stream, "CommitOptions", Duration::from_secs(5)).await?;

    // 1. Present sibling type → resolves.
    let present = round_trip(
        &mut stream,
        "10",
        "Index.VerifyImport",
        json!({ "path": "crate::store::CommitOptions" }),
    )
    .await?;
    assert!(present["error"].is_null(), "present errored: {present:?}");
    let r = &present["result"];
    assert_eq!(r["resolves"], true, "expected resolves:true; got {r:?}");
    assert_eq!(r["resolution"], "exact");

    // 2. Single-segment absent name whose sibling exists → not_found +
    //    sibling candidate.
    let absent = round_trip(
        &mut stream,
        "11",
        "Index.VerifyImport",
        json!({ "path": "CommitOptionz" }),
    )
    .await?;
    let mr = &absent["result"];
    assert_eq!(mr["resolves"], false, "expected resolves:false; got {mr:?}");
    assert_eq!(mr["resolution"], "not_found");
    let cands = mr["candidates"].as_array().cloned().unwrap_or_default();
    assert!(!cands.is_empty(), "expected candidates; got {mr:?}");
    let names: Vec<&str> = cands
        .iter()
        .filter_map(|c| c["qualified_name"].as_str())
        .collect();
    assert!(
        names.iter().any(|n| n.contains("CommitOptions")),
        "expected the real sibling as a candidate; got {names:?}"
    );

    // 3. Deep external path (final segment absent, multi-segment) →
    //    indeterminate. We must NOT claim a confident not_found for a
    //    path that may cross un-indexed modules.
    let deep = round_trip(
        &mut stream,
        "12",
        "Index.VerifyImport",
        json!({ "path": "std::collections::TotallyMadeUpType" }),
    )
    .await?;
    let dr = &deep["result"];
    assert_eq!(
        dr["resolution"], "indeterminate",
        "deep external path should be indeterminate; got {dr:?}"
    );
    assert!(
        dr["reason"].is_string(),
        "indeterminate must carry a reason; got {dr:?}"
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
