//! End-to-end test: PHP call edges resolve via `Index.FindCallers`.
//!
//! Exercises all five call shapes the AST query covers and the symbol
//! extractor indexes targets for:
//!   1. bare function call:        `bare_target()`
//!   2. namespace-qualified call:  `\namespaced_target()`
//!   3. object creation:           `new Klass()`
//!   4. member call:               `$obj->member_target()`
//!   5. scoped (static) call:      `Klass::static_target()`
//!
//! Member-call and scoped-call coverage landed in the follow-up that
//! taught `extract_php_symbols` to index `method_declaration` —
//! shipping in the same PR as this test edit. Before that fix the
//! AST query captured these references correctly (see
//! `php_references_capture_calls_member_and_static` in
//! `refs.rs`) but the targets were never indexed, so `FindCallers`
//! returned `SYMBOL_NOT_FOUND`.
//!
//! Variable-function `$fn()` is intentionally NOT a call edge in the
//! AST query (no static target); regex fallback would have included
//! it as junk.

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
async fn php_bare_namespaced_and_new_calls_resolve() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    std::fs::write(
        workspace.path().join("targets.php"),
        "<?php\n\
         function bare_target() {}\n\
         function namespaced_target() {}\n\
         class Klass {\n\
             public function member_target() {}\n\
             public static function static_target() {}\n\
         }\n",
    )?;

    // All five call shapes — bare, namespaced, new, member, scoped.
    // Member-call and scoped-call resolution requires the
    // method_declaration extractor branch (the gap closed in this PR).
    std::fs::write(
        workspace.path().join("caller.php"),
        "<?php\n\
         function caller_entry() {\n\
             bare_target();\n\
             $obj = new Klass();\n\
             $obj->member_target();\n\
             Klass::static_target();\n\
             \\namespaced_target();\n\
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

    for sym in [
        "bare_target",
        "namespaced_target",
        "Klass",
        "caller_entry",
        "member_target",
        "static_target",
    ] {
        wait_for_symbol(&mut stream, sym, Duration::from_secs(5)).await?;
    }

    for target in [
        "bare_target",
        "namespaced_target",
        "Klass",
        "member_target",
        "static_target",
    ] {
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
        let names: Vec<String> = resp["result"]["callers"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|c| c["enclosing_qualified_name"].as_str().map(String::from))
            .collect();
        assert!(
            names.iter().any(|n| n == "caller_entry"),
            "expected caller_entry to call {target}; got {names:?}"
        );
    }

    Ok(())
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
