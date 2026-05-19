//! End-to-end test for `Index.Grep` v2 `within_symbol` filter (U4).
//!
//! Seeds a small workspace with two functions and confirms:
//!
//! - A `text` match strictly inside `parse_request`'s def range is
//!   kept; an otherwise-identical match outside that range is dropped.
//! - A `within_symbol` name that resolves to zero defs returns the
//!   structured `WITHIN_SYMBOL_NOT_FOUND` envelope.
//!
//! The unit-test layer (`grep_v2::within_symbol::tests`) already covers
//! the byte-range and cardinality-cap logic against synthetic inputs;
//! this test exercises the live `Store::find_symbol` resolution path
//! and the wire-shape envelope so we know the handler actually wires
//! the filter in.

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

async fn poll_for_match(
    stream: &mut UnixStream,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<Value> {
    let deadline = Instant::now() + timeout;
    let mut next_id: u64 = 100;
    loop {
        next_id += 1;
        let resp = round_trip(
            stream,
            &next_id.to_string(),
            "Index.FindSymbol",
            json!({ "name": name }),
        )
        .await?;
        let matches = resp["result"]["matches"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if !matches.is_empty() {
            return Ok(resp);
        }
        if Instant::now() >= deadline {
            return Ok(resp);
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn within_symbol_filters_to_def_byte_range() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Two top-level functions in one file. `parse_request` contains
    // a `panic!` with the string "deadbeef"; `other_func` also has a
    // `panic!` with the same string. With `within_symbol:
    // "parse_request"`, only the first should survive the filter.
    std::fs::write(
        workspace.path().join("lib.rs"),
        "pub fn parse_request() {\n    panic!(\"deadbeef inside parse_request\");\n}\n\npub fn other_func() {\n    panic!(\"deadbeef outside parse_request\");\n}\n",
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
    // Wait for the writer to index `parse_request` so within_symbol's
    // `find_symbol` lookup can find it.
    let _ = poll_for_match(&mut stream, "parse_request", Duration::from_secs(5)).await?;

    // Case A: no within_symbol — both `deadbeef` matches surface.
    let unscoped = round_trip(
        &mut stream,
        "10",
        "Index.Grep",
        json!({ "text": "deadbeef" }),
    )
    .await?;
    assert!(unscoped["error"].is_null(), "unscoped grep: {unscoped:?}");
    let unscoped_matches = unscoped["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        unscoped_matches.len(),
        2,
        "two `deadbeef` literals exist in the file: {unscoped:?}"
    );

    // Case B: within_symbol: "parse_request" — only the inside match
    // survives.
    let scoped = round_trip(
        &mut stream,
        "11",
        "Index.Grep",
        json!({ "text": "deadbeef", "within_symbol": "parse_request" }),
    )
    .await?;
    assert!(scoped["error"].is_null(), "scoped grep: {scoped:?}");
    let scoped_matches = scoped["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        scoped_matches.len(),
        1,
        "within_symbol filter should keep one match: {scoped:?}"
    );
    let line_text = scoped_matches[0]["line_text"].as_str().unwrap_or("");
    assert!(
        line_text.contains("inside parse_request"),
        "kept match should be the one inside parse_request: line_text={line_text:?}"
    );

    // Case C: within_symbol resolves to zero defs → structured error
    // with `data.code == "WITHIN_SYMBOL_NOT_FOUND"`.
    let not_found = round_trip(
        &mut stream,
        "12",
        "Index.Grep",
        json!({ "text": "deadbeef", "within_symbol": "no_such_symbol_anywhere" }),
    )
    .await?;
    let err = &not_found["error"];
    assert!(
        !err.is_null(),
        "zero-def within_symbol must fail: {not_found:?}"
    );
    let code = err
        .get("data")
        .and_then(|d| d.get("code"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        code, "WITHIN_SYMBOL_NOT_FOUND",
        "expected WITHIN_SYMBOL_NOT_FOUND code; got error={err:?}"
    );

    Ok(())
}
