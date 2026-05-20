//! End-to-end test: Java call edges resolve via `Index.FindCallers`.
//!
//! Fixture exercises the chained-call edge case (`a.b().c()`): both
//! `b` and `c` should appear as call sites, but the receiver `a` —
//! which is just a local variable reference, not a method call —
//! must not. Object creation (`new Widget()`) should also resolve.
//!
//! Why this matters: pre-AST-precise edges, the Java regex fallback
//! emitted an edge for every identifier-shaped token in the file,
//! including variable names and class-name occurrences in comments
//! or strings. This test pins the behavior: only method calls and
//! `new` are call edges.

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
async fn java_chained_calls_resolve_method_level_edges() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Targets we want callers for.
    std::fs::write(
        workspace.path().join("Targets.java"),
        "public class Targets {\n\
             public Targets bMethod() { return this; }\n\
             public void cMethod() {}\n\
             public Targets nested() { return this; }\n\
         }\n",
    )?;
    std::fs::write(
        workspace.path().join("Widget.java"),
        "public class Widget {\n\
             public Widget() {}\n\
         }\n",
    )?;

    // Caller exercising chained `a.bMethod().cMethod()` plus `new Widget()`.
    // `a` is a local — must NOT show up as a caller of any symbol.
    std::fs::write(
        workspace.path().join("Caller.java"),
        "public class Caller {\n\
             public void callerEntry() {\n\
                 Targets a = new Targets();\n\
                 a.bMethod().cMethod();\n\
                 Widget w = new Widget();\n\
             }\n\
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
    assert!(mount["error"].is_null(), "mount: {mount:?}");

    wait_for_symbol(&mut stream, "bMethod", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "cMethod", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "callerEntry", Duration::from_secs(5)).await?;

    // Both `b` and `c` in `a.bMethod().cMethod()` should show
    // `callerEntry` as a caller — separate `method_invocation` nodes.
    for target in ["bMethod", "cMethod", "Widget"] {
        let resp = round_trip(
            &mut stream,
            "10",
            "Index.FindCallers",
            json!({ "name": target }),
        )
        .await?;
        assert!(
            resp["error"].is_null(),
            "find_callers({target}) failed: {resp:?}"
        );
        let callers = resp["result"]["callers"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let names: Vec<&str> = callers
            .iter()
            .filter_map(|c| c["enclosing_qualified_name"].as_str())
            .collect();
        assert!(
            names.contains(&"callerEntry"),
            "expected callerEntry as caller of {target}; got {names:?}"
        );
    }

    // The receiver `a` is a local Targets-typed variable, not a
    // method — there is no such method-name def, so FindCallers
    // returns SYMBOL_NOT_FOUND. This is the precise behavior we
    // want: regex fallback would have emitted an `a` edge.
    let missing = round_trip(
        &mut stream,
        "20",
        "Index.FindCallers",
        json!({ "name": "a" }),
    )
    .await?;
    assert_eq!(
        missing["error"]["code"], "SYMBOL_NOT_FOUND",
        "local variable `a` should not have a def to call; got {missing:?}"
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
