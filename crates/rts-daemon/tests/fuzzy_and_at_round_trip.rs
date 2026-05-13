//! End-to-end test for the alpha.24 dogfooding-gap closures:
//! - `Index.FindSymbol` with `pattern` (glob) instead of `name` (exact)
//! - `Index.ReadSymbolAt` for line-anchored reads
//!
//! Verifies the wire contract for both, plus that the existing
//! `name`-based path still works (back-compat).

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
            anyhow::bail!("socket {} never appeared", path.display());
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
        .map_err(|_| anyhow::anyhow!("timed out waiting for {method}"))??;
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
async fn fuzzy_search_and_read_symbol_at() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Seed several symbols with shared name patterns so the glob has
    // signal to match against, plus an unrelated symbol so wrong
    // matches would be obvious.
    std::fs::write(
        workspace.path().join("widget.rs"),
        "pub fn make_widget(id: u32) -> u32 {\n    \
         id + 1\n\
         }\n\
         \n\
         pub fn make_circle(r: u32) -> u32 {\n    \
         r * 2\n\
         }\n\
         \n\
         pub fn format_widget(w: u32) -> String {\n    \
         format!(\"w#{w}\")\n\
         }\n\
         \n\
         pub fn unrelated_helper(x: u32) -> u32 {\n    \
         x\n\
         }\n",
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
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");

    wait_for_symbol(&mut stream, "make_widget", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "unrelated_helper", Duration::from_secs(5)).await?;

    // ---- 1. find_symbol back-compat: `name` still works ----
    let exact = round_trip(
        &mut stream,
        "10",
        "Index.FindSymbol",
        json!({ "name": "make_widget" }),
    )
    .await?;
    assert!(exact["error"].is_null(), "exact find failed: {exact:?}");
    let exact_matches = exact["result"]["matches"]
        .as_array()
        .expect("matches array");
    assert_eq!(exact_matches.len(), 1);
    assert_eq!(exact_matches[0]["qualified_name"], "make_widget");

    // ---- 2. pattern: `make_*` should return 2 widgets + circle ----
    let make_star = round_trip(
        &mut stream,
        "11",
        "Index.FindSymbol",
        json!({ "pattern": "make_*" }),
    )
    .await?;
    assert!(
        make_star["error"].is_null(),
        "pattern find failed: {make_star:?}"
    );
    let names: Vec<&str> = make_star["result"]["matches"]
        .as_array()
        .expect("matches array")
        .iter()
        .filter_map(|m| m["qualified_name"].as_str())
        .collect();
    assert!(
        names.contains(&"make_widget") && names.contains(&"make_circle"),
        "expected make_widget + make_circle; got {names:?}"
    );
    assert!(
        !names.contains(&"unrelated_helper"),
        "unrelated_helper should NOT match `make_*`; got {names:?}"
    );
    // truncated must be a bool — the wire contract.
    assert!(make_star["result"]["truncated"].is_boolean());

    // ---- 3. pattern: `*_widget` returns both widget fns ----
    let widget_suffix = round_trip(
        &mut stream,
        "12",
        "Index.FindSymbol",
        json!({ "pattern": "*_widget" }),
    )
    .await?;
    assert!(widget_suffix["error"].is_null());
    let names: Vec<&str> = widget_suffix["result"]["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["qualified_name"].as_str())
        .collect();
    assert!(
        names.contains(&"make_widget") && names.contains(&"format_widget"),
        "expected both *_widget fns; got {names:?}"
    );
    assert!(!names.contains(&"make_circle"));

    // ---- 4. pattern: `?ake_widget` exercises the `?` wildcard ----
    let q = round_trip(
        &mut stream,
        "13",
        "Index.FindSymbol",
        json!({ "pattern": "?ake_widget" }),
    )
    .await?;
    let names: Vec<&str> = q["result"]["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["qualified_name"].as_str())
        .collect();
    assert!(
        names.contains(&"make_widget"),
        "?-glob should match make_widget; got {names:?}"
    );

    // ---- 5. mutually-exclusive error path ----
    let conflict = round_trip(
        &mut stream,
        "14",
        "Index.FindSymbol",
        json!({ "name": "foo", "pattern": "f*" }),
    )
    .await?;
    assert_eq!(
        conflict["error"]["code"], "INVALID_PARAMS",
        "name + pattern should error; got {conflict:?}"
    );

    // ---- 6. neither-given error path ----
    let neither = round_trip(&mut stream, "15", "Index.FindSymbol", json!({})).await?;
    assert_eq!(
        neither["error"]["code"], "INVALID_PARAMS",
        "no name or pattern should error; got {neither:?}"
    );

    // ---- 7. Index.ReadSymbolAt — compiler-error flow ----
    // `make_widget` is defined starting at line 1 of widget.rs. Reading
    // at any line in its range (1-3) should return its body.
    let at_line = round_trip(
        &mut stream,
        "20",
        "Index.ReadSymbolAt",
        json!({ "file": "widget.rs", "line": 2 }),
    )
    .await?;
    assert!(
        at_line["error"].is_null(),
        "read_symbol_at failed: {at_line:?}"
    );
    assert_eq!(at_line["result"]["qualified_name"], "make_widget");
    assert_eq!(at_line["result"]["kind"], "fn");
    let body = at_line["result"]["text"].as_str().expect("body text");
    assert!(
        body.contains("make_widget") && body.contains("id + 1"),
        "expected make_widget body; got {body:?}"
    );

    // ---- 8. read_symbol_at on a line outside any def → SYMBOL_NOT_FOUND ----
    let between = round_trip(
        &mut stream,
        "21",
        "Index.ReadSymbolAt",
        // Line 4 is the blank gap between make_widget and make_circle.
        // Both end at line 3 (start_line 1, end_line 3 for make_widget),
        // so line 4 belongs to no def.
        json!({ "file": "widget.rs", "line": 4 }),
    )
    .await?;
    assert_eq!(
        between["error"]["code"], "SYMBOL_NOT_FOUND",
        "gap line should miss; got {between:?}"
    );

    // ---- 9. read_symbol_at on an unknown file → FILE_NOT_INDEXED ----
    let missing = round_trip(
        &mut stream,
        "22",
        "Index.ReadSymbolAt",
        json!({ "file": "ghost.rs", "line": 1 }),
    )
    .await?;
    assert_eq!(
        missing["error"]["code"], "FILE_NOT_INDEXED",
        "unindexed file should fail loudly; got {missing:?}"
    );

    // ---- 10. read_symbol_at honors include_dependencies ----
    // make_widget's body doesn't actually reference other defs in this
    // tiny fixture, so dependencies will be empty — but the wire
    // contract must still be present.
    let with_deps = round_trip(
        &mut stream,
        "23",
        "Index.ReadSymbolAt",
        json!({ "file": "widget.rs", "line": 1, "include_dependencies": true }),
    )
    .await?;
    assert!(with_deps["error"].is_null());
    assert!(with_deps["result"]["dependencies"].is_array());
    assert_eq!(with_deps["result"]["closure_truncated"], false);

    // ---- 11. read_symbol_at validates line=0 ----
    let zero = round_trip(
        &mut stream,
        "24",
        "Index.ReadSymbolAt",
        json!({ "file": "widget.rs", "line": 0 }),
    )
    .await?;
    assert_eq!(
        zero["error"]["code"], "INVALID_PARAMS",
        "line=0 should error; got {zero:?}"
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
