//! End-to-end test for `Index.Grep` — literal-substring search across
//! indexed file bytes. Closes the v0.5.4 dogfood gap where the daemon
//! couldn't help find error messages, version strings, log output, or
//! any non-symbol text content.

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

/// Poll Index.FindSymbol until the writer has caught up. Used here to
/// confirm the workspace mount has settled before grep queries fire.
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
async fn grep_finds_string_literals_across_workspace() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Three files with different string-literal patterns. The
    // motivating dogfood example: find_symbol can't help here
    // because `timeout reading MCP response` isn't a symbol name —
    // it's a runtime string literal inside an `anyhow!()` call.
    std::fs::write(
        workspace.path().join("a.rs"),
        "pub fn a() {\n    panic!(\"timeout reading MCP response\");\n}\n",
    )?;
    std::fs::write(
        workspace.path().join("b.rs"),
        "// Comment about TIMEOUT reading the bus.\npub fn b() {}\n",
    )?;
    std::fs::write(
        workspace.path().join("c.rs"),
        "pub fn c() { println!(\"other content\"); }\n",
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
    // Wait for the writer to commit at least one symbol so we know
    // the workspace is indexed.
    let _ = poll_for_match(&mut stream, "a", Duration::from_secs(5)).await?;

    // Case A: exact phrase only in one file.
    let exact = round_trip(
        &mut stream,
        "10",
        "Index.Grep",
        json!({ "text": "timeout reading MCP response" }),
    )
    .await?;
    let matches_a = exact["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        matches_a.len(),
        1,
        "exact phrase should match only a.rs: {exact:?}"
    );
    assert!(
        matches_a[0]["file"]
            .as_str()
            .map(|s| s.ends_with("a.rs"))
            .unwrap_or(false),
        "match file should be a.rs: {exact:?}"
    );
    let line_text = matches_a[0]["line_text"].as_str().unwrap_or("");
    assert!(
        line_text.contains("timeout reading MCP response"),
        "line_text should contain the matched literal: {line_text:?}"
    );
    let start_line = matches_a[0]["range"]["start_line"].as_u64();
    assert_eq!(start_line, Some(2), "match should be on line 2");

    // Case B: case-insensitive (default). "timeout" lowercase in
    // a.rs, "TIMEOUT" uppercase in b.rs. Default should match both.
    let ci = round_trip(
        &mut stream,
        "11",
        "Index.Grep",
        json!({ "text": "timeout" }),
    )
    .await?;
    let matches_b = ci["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        matches_b.len() >= 2,
        "case-insensitive default should match both files: {ci:?}"
    );
    let files_b: Vec<&str> = matches_b
        .iter()
        .map(|m| m["file"].as_str().unwrap_or(""))
        .collect();
    assert!(files_b.iter().any(|f| f.ends_with("a.rs")));
    assert!(files_b.iter().any(|f| f.ends_with("b.rs")));

    // Case C: case-sensitive (opt-in). Only the lowercase
    // "timeout" in a.rs should match.
    let cs = round_trip(
        &mut stream,
        "12",
        "Index.Grep",
        json!({ "text": "timeout", "case_insensitive": false }),
    )
    .await?;
    let matches_c = cs["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        matches_c.iter().all(|m| {
            m["file"]
                .as_str()
                .map(|f| f.ends_with("a.rs"))
                .unwrap_or(false)
        }),
        "case-sensitive should match only a.rs: {cs:?}"
    );

    // Case D: no matches → empty list, no error.
    let none = round_trip(
        &mut stream,
        "13",
        "Index.Grep",
        json!({ "text": "no_such_string_anywhere" }),
    )
    .await?;
    assert!(
        none["result"]["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "no-match query should yield empty matches: {none:?}"
    );
    assert!(
        none["error"].is_null(),
        "no-match must NOT be an error: {none:?}"
    );

    // Case E: response carries files_scanned + files_with_matches.
    let scanned = none["result"]["files_scanned"].as_u64().unwrap_or(0);
    assert!(
        scanned >= 3,
        "files_scanned should report all indexed files: {none:?}"
    );
    let with_matches = none["result"]["files_with_matches"].as_u64();
    assert_eq!(
        with_matches,
        Some(0),
        "no-match query should report 0 files_with_matches: {none:?}"
    );

    // Case F: empty `text` → INVALID_PARAMS.
    let empty = round_trip(&mut stream, "14", "Index.Grep", json!({ "text": "" })).await?;
    assert_eq!(
        empty["error"]["code"], "INVALID_PARAMS",
        "empty text must error with INVALID_PARAMS: {empty:?}"
    );

    Ok(())
}
