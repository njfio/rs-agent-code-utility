//! Daemon.Ping capability advertisement + GrepParams schema-acceptance
//! tests for the Index.Grep v2 surface (U1).
//!
//! What this asserts (characterization-first invariants):
//!
//! 1. `Daemon.Ping` advertises the four new capabilities:
//!    `index_grep_multiline`, `index_grep_structural`,
//!    `index_grep_within_symbol`, and the `index_grep_v2` bundle.
//! 2. A v1-shape `Index.Grep` request (no new fields) still returns
//!    a response with the v1 fields populated — backward-compat by
//!    construction.
//! 3. A request that *sets* one of the new fields (e.g. `multiline: true`,
//!    `language: ["rust"]`) deserializes cleanly. The implementation
//!    units U3+ will give those fields semantic meaning; this test
//!    only proves the schema accepts them.

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
async fn grep_v2_capabilities_advertised_and_schema_accepts_new_fields() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    std::fs::write(workspace.path().join("hub.rs"), "pub fn hello() {}\n")?;

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

    // 1. Ping advertises the four new capabilities.
    let pong = round_trip(&mut stream, "1", "Daemon.Ping", json!({})).await?;
    let caps = pong["result"]["capabilities"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let cap_strs: Vec<&str> = caps.iter().filter_map(|v| v.as_str()).collect();
    for expected in [
        "index_grep_multiline",
        "index_grep_structural",
        "index_grep_within_symbol",
        "index_grep_v2",
    ] {
        assert!(
            cap_strs.contains(&expected),
            "expected `{expected}` in capability list; got {cap_strs:?}"
        );
    }

    // 2. Mount the workspace so Index.Grep has something to look at.
    let mount = round_trip(
        &mut stream,
        "2",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");
    // Poll for "hello" indexing to complete.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut id: u32 = 100;
    loop {
        id += 1;
        let r = round_trip(
            &mut stream,
            &id.to_string(),
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

    // 3. A v1-shape grep request still returns matches — backward
    //    compat by construction (no v2 fields in payload).
    let v1 = round_trip(&mut stream, "10", "Index.Grep", json!({ "text": "hello" })).await?;
    assert!(v1["error"].is_null(), "v1 grep errored: {v1:?}");
    let v1_matches = v1["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !v1_matches.is_empty(),
        "v1 grep returned no matches: {v1:?}"
    );

    // 4. A request that sets v2 fields deserializes cleanly. The
    //    handler may not yet honor these (U2-U6 land the behavior)
    //    but the schema must NOT reject the request. We use the
    //    `language` filter alone, which is the least intrusive
    //    addition and applies on the literal path.
    let v2_lang = round_trip(
        &mut stream,
        "11",
        "Index.Grep",
        json!({ "text": "hello", "language": ["rust"] }),
    )
    .await?;
    assert!(
        v2_lang["error"].is_null(),
        "v2 grep with `language` filter errored at schema layer: {v2_lang:?}"
    );

    // 5. Multiline = true on the regex path also deserializes cleanly.
    //    U3 will give this semantic meaning.
    let v2_multiline = round_trip(
        &mut stream,
        "12",
        "Index.Grep",
        json!({ "text": "hello", "regex": true, "multiline": true }),
    )
    .await?;
    assert!(
        v2_multiline["error"].is_null(),
        "v2 grep with `multiline` errored at schema layer: {v2_multiline:?}"
    );

    Ok(())
}
