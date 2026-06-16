//! End-to-end plumbing test for the v0.7 `parent_scope` capability.
//!
//! This task threads a def's `parent` (nearest enclosing container) from
//! the on-disk DEFS value through `FoundSymbol` to the
//! `Index.FindSymbol` / `Index.ReadSymbol` wire, and adds the
//! `parent_scope` capability. Extraction does NOT yet assign parents
//! (a later task populates `rts_core::Symbol::parent` from the tree), so
//! every def currently carries `parent: null`. The observable contract
//! here is therefore the *neutral* one:
//!
//! 1. `Daemon.Ping` advertises the `parent_scope` capability.
//! 2. `Index.FindSymbol` for a method emits a `parent` field that is
//!    `null` and a `qualified_name` equal to the bare symbol name (no
//!    `Container::` prefix while `parent` is unpopulated).
//!
//! The daemon-spawn / Unix-socket round-trip harness is copied from
//! `deadline.rs` / `cancel_in_flight.rs` to keep each integration test
//! self-contained (cargo compiles each `tests/*.rs` as its own crate).

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
    let mut req = serde_json::Map::new();
    req.insert("id".into(), Value::String(id.to_string()));
    req.insert("method".into(), Value::String(method.to_string()));
    req.insert("params".into(), params);
    let req = Value::Object(req);
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.flush().await?;

    let mut buf = Vec::new();
    let (rd, _wr) = stream.split();
    let mut reader = BufReader::new(rd);
    let n = tokio::time::timeout(Duration::from_secs(30), reader.read_until(b'\n', &mut buf))
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

fn socket_path(home_dir: &std::path::Path, runtime_dir: &std::path::Path) -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        home_dir
            .join("Library")
            .join("Caches")
            .join("rts")
            .join("default.sock")
    } else {
        runtime_dir.join("rts").join("default.sock")
    }
}

fn spawn_daemon(
    runtime_dir: &std::path::Path,
    state_dir: &std::path::Path,
    home_dir: &std::path::Path,
) -> anyhow::Result<std::process::Child> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir, std::fs::Permissions::from_mode(0o700));

    let mut cmd = Command::new(daemon_bin());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir)
        .env("XDG_STATE_HOME", state_dir)
        .env("HOME", home_dir)
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(cmd.spawn()?)
}

/// Wait until the cold walk has committed at least `min_files` distinct
/// files to the index, so a `find_symbol` against the fixture resolves.
async fn wait_for_index_warm(
    stream: &mut UnixStream,
    min_files: u64,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut probe_id: u64 = 9000;
    loop {
        probe_id += 1;
        let resp = round_trip(stream, &probe_id.to_string(), "Workspace.Status", json!({})).await?;
        let files_done = resp["result"]["progress"]["files_done"]
            .as_u64()
            .unwrap_or(0);
        if files_done >= min_files {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "index never reached {min_files} files within {:?} (saw files_done={files_done})",
                timeout
            );
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

/// Capability surface: `Daemon.Ping` advertises `parent_scope`. No mount
/// needed — `Daemon.Ping` answers pre-mount.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capability_advertises_parent_scope() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
    let mut child = spawn_daemon(runtime_dir.path(), state_dir.path(), home_dir.path())?;
    let _kill = KillOnDrop(&mut child);
    wait_for_socket(&sock, Duration::from_secs(5)).await?;

    let mut stream = UnixStream::connect(&sock).await?;
    let ping = round_trip(&mut stream, "1", "Daemon.Ping", json!({})).await?;
    assert!(ping["error"].is_null(), "ping failed: {ping:?}");
    let caps = ping["result"]["capabilities"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        caps.iter().any(|c| c.as_str() == Some("parent_scope")),
        "Daemon.Ping must advertise the parent_scope capability; got: {ping:?}"
    );
    Ok(())
}

/// Plumbing: a method's `find_symbol` response carries a `parent` field
/// that is `null` (extraction hasn't assigned parents yet) AND a
/// `qualified_name` equal to the bare method name (no `Container::`
/// prefix while `parent` is unpopulated).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn find_symbol_method_parent_is_null_and_qualified_name_is_bare() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // A struct with a method + a free function. `compute` is the method
    // we resolve; once a later task populates parents its `parent` will
    // become `Some("Widget")`, but for now it must be null.
    std::fs::write(
        workspace.path().join("lib.rs"),
        "pub struct Widget {\n    pub size: u32,\n}\n\n\
         impl Widget {\n    pub fn compute(&self) -> u32 {\n        self.size * 2\n    }\n}\n\n\
         pub fn free_helper() -> u32 {\n    7\n}\n",
    )?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
    let mut child = spawn_daemon(runtime_dir.path(), state_dir.path(), home_dir.path())?;
    let _kill = KillOnDrop(&mut child);
    wait_for_socket(&sock, Duration::from_secs(5)).await?;

    let mut stream = UnixStream::connect(&sock).await?;
    let mount = round_trip(
        &mut stream,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");
    wait_for_index_warm(&mut stream, 1, Duration::from_secs(30)).await?;

    let resp = round_trip(
        &mut stream,
        "2",
        "Index.FindSymbol",
        json!({ "name": "compute" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "find_symbol errored: {resp:?}");

    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !matches.is_empty(),
        "expected to resolve `compute`; got: {resp:?}"
    );
    let m = &matches[0];

    // `parent` field is present and null (extraction unpopulated).
    assert!(
        m.get("parent").is_some(),
        "match must carry a `parent` field; got: {m:?}"
    );
    assert!(
        m["parent"].is_null(),
        "extraction does not assign parents yet, so `parent` must be null; got: {m:?}"
    );

    // `qualified_name` is the bare name (no `Widget::` prefix yet).
    assert_eq!(
        m["qualified_name"].as_str(),
        Some("compute"),
        "while `parent` is null the qualified_name must be the bare symbol name; got: {m:?}"
    );
    Ok(())
}
