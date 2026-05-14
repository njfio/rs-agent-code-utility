//! End-to-end test for v0.3 U2': `Index.FindCallers` + `Index.ReadSymbol.include_callers`.
//!
//! Hub-spoke fixture (same shape as `outline_round_trip`'s hub-spoke):
//!   `hub.rs`      defines `hub_compute`
//!   `caller_a.rs` defines `caller_a_one` which calls `hub_compute`
//!   `caller_b.rs` defines `caller_b_one` which calls `hub_compute`
//!
//! After indexing:
//!   * `Index.FindCallers(hub_compute)` should return 2 callers, one
//!     per file, each with `enclosing_qualified_name` resolving to
//!     the caller fn name.
//!   * `Index.ReadSymbol(hub_compute, include_callers=true)` should
//!     return the hub fn body PLUS the same 2 callers.
//!   * `Index.FindCallers` for an unknown name returns SYMBOL_NOT_FOUND.

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
async fn find_callers_and_include_callers_round_trip() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn hub_compute(x: u32) -> u32 { x + 1 }\n",
    )?;
    std::fs::write(
        workspace.path().join("caller_a.rs"),
        "pub fn caller_a_one() {\n    let _ = hub_compute(1);\n}\n",
    )?;
    std::fs::write(
        workspace.path().join("caller_b.rs"),
        "pub fn caller_b_one() {\n    let _ = hub_compute(2);\n}\n",
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

    // Wait for all three defs to land in the index.
    wait_for_symbol(&mut stream, "hub_compute", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "caller_a_one", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "caller_b_one", Duration::from_secs(5)).await?;

    // 1. Index.FindCallers(hub_compute) → 2 callers.
    let resp = round_trip(
        &mut stream,
        "10",
        "Index.FindCallers",
        json!({ "name": "hub_compute" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "find_callers failed: {resp:?}");
    let callers = resp["result"]["callers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        callers.len(),
        2,
        "expected 2 callers of hub_compute; got {callers:?}"
    );
    assert_eq!(resp["result"]["truncated"], false);

    // Each caller's enclosing_qualified_name should resolve to the
    // calling fn. Order is (file, start_byte) — alphabetical by file
    // here: caller_a.rs then caller_b.rs.
    let enclosing_names: Vec<&str> = callers
        .iter()
        .map(|c| c["enclosing_qualified_name"].as_str().unwrap_or(""))
        .collect();
    assert!(
        enclosing_names.contains(&"caller_a_one"),
        "expected caller_a_one in {enclosing_names:?}"
    );
    assert!(
        enclosing_names.contains(&"caller_b_one"),
        "expected caller_b_one in {enclosing_names:?}"
    );

    // Each caller carries kind=fn + an enclosing_def_range.
    for c in &callers {
        assert_eq!(c["kind"], "fn");
        assert!(
            c["enclosing_def_range"].is_object(),
            "expected enclosing_def_range to be populated; got {c:?}"
        );
        assert!(
            c["range"]["start_byte"].as_u64().unwrap_or(0) > 0,
            "call site byte range should be populated; got {c:?}"
        );
    }

    // 2. file= filter should narrow to one caller.
    let filtered = round_trip(
        &mut stream,
        "11",
        "Index.FindCallers",
        json!({ "name": "hub_compute", "file": "caller_a.rs" }),
    )
    .await?;
    let f_callers = filtered["result"]["callers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(f_callers.len(), 1, "file filter should narrow to 1 caller");
    assert_eq!(f_callers[0]["enclosing_qualified_name"], "caller_a_one");

    // 3. Unknown name returns SYMBOL_NOT_FOUND.
    let missing = round_trip(
        &mut stream,
        "12",
        "Index.FindCallers",
        json!({ "name": "no_such_thing_ever" }),
    )
    .await?;
    assert!(
        missing["error"].is_object(),
        "expected error envelope; got {missing:?}"
    );
    assert_eq!(missing["error"]["code"], "SYMBOL_NOT_FOUND");

    // 4. Index.ReadSymbol(hub_compute, include_callers=true) returns
    //    the body PLUS the same 2 callers.
    let combined = round_trip(
        &mut stream,
        "20",
        "Index.ReadSymbol",
        json!({
            "name": "hub_compute",
            "include_callers": true,
            "token_budget": 4096,
        }),
    )
    .await?;
    assert!(
        combined["error"].is_null(),
        "read_symbol --include-callers failed: {combined:?}"
    );
    // Body present.
    let text = combined["result"]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("hub_compute"),
        "body should contain the symbol name; got `{text}`"
    );
    // Callers present and equal length.
    let rs_callers = combined["result"]["callers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        rs_callers.len(),
        2,
        "expected 2 callers in include_callers response; got {rs_callers:?}"
    );
    // Same wire shape as find_callers entries — spot-check one.
    assert!(rs_callers[0]["enclosing_qualified_name"].is_string());
    assert_eq!(rs_callers[0]["kind"], "fn");
    assert!(rs_callers[0]["enclosing_def_range"].is_object());

    // 5. Without include_callers, callers[] is an empty array and
    //    callers_truncated is false. (v0.2 back-compat path.)
    let no_callers = round_trip(
        &mut stream,
        "21",
        "Index.ReadSymbol",
        json!({ "name": "hub_compute" }),
    )
    .await?;
    let nc = no_callers["result"]["callers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        nc.is_empty(),
        "default ReadSymbol should not carry callers; got {nc:?}"
    );
    assert_eq!(no_callers["result"]["callers_truncated"], false);

    Ok(())
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
