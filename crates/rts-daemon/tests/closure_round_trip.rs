//! End-to-end test for `Index.ReadSymbol` with `include_dependencies: true`.
//!
//! Seeds a hub-spoke workspace: `caller.rs` defines a function whose
//! body references two functions from `hub.rs`. Asserts the closure
//! walker surfaces both as dep entries with rendered signatures, and
//! that the wire shape matches protocol-v0 §7.7.

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
async fn read_symbol_returns_dependencies_when_requested() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // `hub.rs` defines two pub fns. `caller.rs::process()` references
    // both — the closure walker should surface them.
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn make_widget(id: u32) -> Widget {\n    Widget { id }\n}\n\
         pub fn format_widget(w: &Widget) -> String {\n    format!(\"widget#{}\", w.id)\n}\n\
         pub struct Widget { pub id: u32 }\n",
    )?;
    std::fs::write(
        workspace.path().join("caller.rs"),
        "pub fn process(id: u32) -> String {\n    \
         let w = make_widget(id);\n    \
         format_widget(&w)\n\
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

    // Wait for all three referenced symbols to land.
    wait_for_symbol(&mut stream, "process", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "make_widget", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "format_widget", Duration::from_secs(5)).await?;

    // 1) Without `include_dependencies`, the wire field stays empty
    //    (back-compat with v0 callers that don't ask for the closure).
    let bare = round_trip(
        &mut stream,
        "10",
        "Index.ReadSymbol",
        json!({ "name": "process" }),
    )
    .await?;
    assert!(bare["error"].is_null(), "bare ReadSymbol failed: {bare:?}");
    assert_eq!(
        bare["result"]["dependencies"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(99),
        0,
        "dependencies should be empty when include_dependencies is omitted"
    );
    assert_eq!(bare["result"]["closure_truncated"], false);

    // 2) With `include_dependencies: true`, both hub functions
    //    surface as deps with rendered signatures.
    let resp = round_trip(
        &mut stream,
        "11",
        "Index.ReadSymbol",
        json!({ "name": "process", "include_dependencies": true }),
    )
    .await?;
    assert!(
        resp["error"].is_null(),
        "closure ReadSymbol failed: {resp:?}"
    );
    let deps = resp["result"]["dependencies"]
        .as_array()
        .expect("dependencies array");
    let dep_names: Vec<&str> = deps
        .iter()
        .filter_map(|d| d["qualified_name"].as_str())
        .collect();
    assert!(
        dep_names.contains(&"make_widget"),
        "expected make_widget in deps; got {dep_names:?}"
    );
    assert!(
        dep_names.contains(&"format_widget"),
        "expected format_widget in deps; got {dep_names:?}"
    );

    // Each entry must carry the wire-stable fields.
    for d in deps {
        assert!(d["qualified_name"].is_string());
        assert!(d["kind"].is_string());
        assert!(d["file"].is_string());
        assert!(d["range"]["start_line"].is_u64());
        assert!(d["range"]["end_line"].is_u64());
        assert!(d["range"]["start_byte"].is_u64());
        assert!(d["range"]["end_byte"].is_u64());
        // Signature must either be a non-empty string (Rust renderer
        // success path) or null. For these hub functions the Rust
        // renderer should succeed.
        let sig = &d["signature"];
        assert!(
            sig.is_string() || sig.is_null(),
            "signature must be string|null"
        );
    }

    // The signature renderer should at minimum produce the `pub fn`
    // declaration line for each dep.
    let make_widget_sig = deps
        .iter()
        .find(|d| d["qualified_name"] == "make_widget")
        .and_then(|d| d["signature"].as_str())
        .expect("make_widget signature");
    assert!(
        make_widget_sig.contains("make_widget"),
        "make_widget signature should mention the name; got {make_widget_sig:?}"
    );

    // The anchor's own body still ships under `text` — the closure
    // walk is additive.
    let body = resp["result"]["text"].as_str().expect("text");
    assert!(
        body.contains("make_widget(id)") && body.contains("format_widget"),
        "anchor body should still include the call sites; got {body:?}"
    );

    // 3) Squeeze the budget so only one dep can fit. The closure
    //    walker should set closure_truncated=true and surface the
    //    dropped name under truncated_symbols.
    let tight = round_trip(
        &mut stream,
        "12",
        "Index.ReadSymbol",
        json!({
            "name": "process",
            "include_dependencies": true,
            "token_budget": 100   // enough for body + one dep
        }),
    )
    .await?;
    assert!(
        tight["error"].is_null(),
        "tight-budget call failed: {tight:?}"
    );
    let tight_deps = tight["result"]["dependencies"]
        .as_array()
        .expect("dependencies array");
    let tight_truncated = tight["result"]["truncated_symbols"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    // We expect *some* truncation: either deps got fewer entries than
    // the full case, or closure_truncated fired. (Exact-equality on
    // the count is flakey under budget edge cases.)
    let saw_truncation = tight["result"]["closure_truncated"].as_bool() == Some(true)
        || tight_deps.len() < deps.len()
        || !tight_truncated.is_empty();
    assert!(
        saw_truncation,
        "tight budget should trigger truncation; got deps={tight_deps:?}, truncated_symbols={tight_truncated:?}"
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
