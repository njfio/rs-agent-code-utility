//! Integration test for the alpha.27 tags.scm precision upgrade.
//!
//! Seeds a workspace where the regex tokenizer would produce a false
//! positive in the closure walker's dep list (a local variable shadowing
//! a def name). With tags.scm precision, the local variable is dropped
//! because tree-sitter sees only the actual call site.

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
async fn closure_walker_excludes_local_shadowing_a_def_name() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Two files. `hub.rs` defines two pub fns:
    //   - real_callee (a function `caller` actually calls)
    //   - decoy_target (a function whose *name* the caller has as a
    //     local variable, but never invokes)
    //
    // Pre-alpha.27 regex tokenizer would pick up `decoy_target` as a
    // ref from `caller.rs` because the identifier text appears in the
    // body. Post-alpha.27 tags.scm sees only the call site
    // `real_callee(...)` — `decoy_target` is a local binding, not a
    // call.
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn real_callee(id: u32) -> u32 { id + 1 }\n\
         pub fn decoy_target(id: u32) -> u32 { id + 2 }\n",
    )?;
    std::fs::write(
        workspace.path().join("caller.rs"),
        // The local `let decoy_target = ...` has the same NAME as the
        // pub fn in hub.rs but is *not* a call. Tags.scm correctly
        // ignores this — the regex tokenizer would have surfaced it.
        "pub fn caller(x: u32) -> u32 {\n    \
         let decoy_target = x.saturating_add(10);\n    \
         real_callee(decoy_target)\n\
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

    wait_for_symbol(&mut stream, "caller", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "real_callee", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "decoy_target", Duration::from_secs(5)).await?;

    // ReadSymbol with include_dependencies on `caller`.
    let resp = round_trip(
        &mut stream,
        "10",
        "Index.ReadSymbol",
        json!({ "name": "caller", "include_dependencies": true }),
    )
    .await?;
    assert!(resp["error"].is_null(), "ReadSymbol failed: {resp:?}");

    let deps = resp["result"]["dependencies"]
        .as_array()
        .expect("dependencies array");
    let dep_names: Vec<&str> = deps
        .iter()
        .filter_map(|d| d["qualified_name"].as_str())
        .collect();

    // PRECISION ASSERTION: real_callee IS a dep (true call site).
    assert!(
        dep_names.contains(&"real_callee"),
        "real_callee should be in deps (true call site); got {dep_names:?}"
    );

    // PRECISION ASSERTION: decoy_target is NOT a dep (local var with
    // same name, no call). Pre-alpha.27 regex tokenizer would have
    // surfaced this. The tags.scm precision upgrade is what drops it.
    assert!(
        !dep_names.contains(&"decoy_target"),
        "decoy_target is a local variable with no call site; should NOT be in deps. got {dep_names:?}"
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
