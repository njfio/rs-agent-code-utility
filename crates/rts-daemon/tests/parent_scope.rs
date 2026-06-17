//! End-to-end test for the v0.7 `parent_scope` capability.
//!
//! A def's `parent` (nearest enclosing container) is threaded from the
//! on-disk DEFS value through `FoundSymbol` to the `Index.FindSymbol` /
//! `Index.ReadSymbol` / `Index.ReadSymbolAt` wire, extraction now
//! populates `rts_core::Symbol::parent` from the tree (all 12 code
//! languages), and the daemon advertises the `parent_scope` capability.
//! The observable contracts exercised here:
//!
//! 1. `Daemon.Ping` advertises the `parent_scope` capability.
//! 2. `Index.FindSymbol` for a method emits the method's `parent`
//!    (its enclosing container) and a `qualified_name` rendered as
//!    `parent::name`; a top-level free function has `parent: null` and
//!    a bare `qualified_name`.
//! 3. The `parent` exact-match filter on `Index.FindSymbol` /
//!    `Index.ReadSymbol` disambiguates same-named methods across types
//!    (`A::make` vs `B::make`).
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

/// A Rust fixture with two same-named methods on different types plus a
/// distinctly-named free function. Mounted by the overload-disambiguation
/// tests below.
const OVERLOAD_FIXTURE: &str = "pub struct A;\n\
     pub struct B;\n\n\
     impl A {\n    pub fn make() -> A {\n        A\n    }\n}\n\n\
     impl B {\n    pub fn make() -> B {\n        B\n    }\n}\n\n\
     pub fn make_free() {}\n";

/// Bring a daemon up, mount `workspace`, and wait for the index to warm.
/// Returns the connected stream so the caller can fire queries.
async fn mount_and_warm(
    sock: &std::path::Path,
    workspace: &std::path::Path,
) -> anyhow::Result<UnixStream> {
    wait_for_socket(sock, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(sock).await?;
    let mount = round_trip(
        &mut stream,
        "mnt",
        "Workspace.Mount",
        json!({ "root": workspace }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount failed: {mount:?}");
    wait_for_index_warm(&mut stream, 1, Duration::from_secs(30)).await?;
    Ok(stream)
}

/// A method's `find_symbol` response carries its enclosing container in
/// `parent` and a `qualified_name` rendered as `Container::name`, while
/// a top-level free function reports `parent: null` and a bare
/// `qualified_name`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn find_symbol_method_carries_parent_and_qualified_name() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // A struct with a method + a free function. `compute`'s parent is
    // `Widget`; `free_helper` is top-level (parent null).
    std::fs::write(
        workspace.path().join("lib.rs"),
        "pub struct Widget {\n    pub size: u32,\n}\n\n\
         impl Widget {\n    pub fn compute(&self) -> u32 {\n        self.size * 2\n    }\n}\n\n\
         pub fn free_helper() -> u32 {\n    7\n}\n",
    )?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
    let mut child = spawn_daemon(runtime_dir.path(), state_dir.path(), home_dir.path())?;
    let _kill = KillOnDrop(&mut child);
    let mut stream = mount_and_warm(&sock, workspace.path()).await?;

    // Method: parent = "Widget", qualified_name = "Widget::compute".
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
    assert_eq!(
        m["parent"].as_str(),
        Some("Widget"),
        "method's parent must be its enclosing container; got: {m:?}"
    );
    assert_eq!(
        m["qualified_name"].as_str(),
        Some("Widget::compute"),
        "qualified_name must render as parent::name; got: {m:?}"
    );

    // Free function: parent = null, qualified_name = bare name.
    let resp = round_trip(
        &mut stream,
        "3",
        "Index.FindSymbol",
        json!({ "name": "free_helper" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "find_symbol errored: {resp:?}");
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let m = matches
        .iter()
        .find(|m| m["kind"].as_str() == Some("fn"))
        .unwrap_or_else(|| panic!("expected a free fn match; got: {matches:?}"));
    assert!(
        m["parent"].is_null(),
        "top-level fn must have null parent; got: {m:?}"
    );
    assert_eq!(
        m["qualified_name"].as_str(),
        Some("free_helper"),
        "top-level fn qualified_name must be bare; got: {m:?}"
    );
    Ok(())
}

/// `find_symbol("make")` returns BOTH methods, each tagged with its own
/// parent and a `Container::make` qualified name. This is the overload
/// case the feature exists to disambiguate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn find_symbol_overload_lists_both_parents() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;
    std::fs::write(workspace.path().join("lib.rs"), OVERLOAD_FIXTURE)?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
    let mut child = spawn_daemon(runtime_dir.path(), state_dir.path(), home_dir.path())?;
    let _kill = KillOnDrop(&mut child);
    let mut stream = mount_and_warm(&sock, workspace.path()).await?;

    let resp = round_trip(
        &mut stream,
        "2",
        "Index.FindSymbol",
        json!({ "name": "make" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "find_symbol errored: {resp:?}");
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // Collect (parent, qualified_name) for every `make` row.
    let mut seen: Vec<(Option<String>, String)> = matches
        .iter()
        .map(|m| {
            (
                m["parent"].as_str().map(|s| s.to_string()),
                m["qualified_name"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    seen.sort();

    // Both A::make and B::make are present, each with the matching parent.
    assert!(
        seen.contains(&(Some("A".to_string()), "A::make".to_string())),
        "expected an A::make row with parent=A; got: {seen:?}"
    );
    assert!(
        seen.contains(&(Some("B".to_string()), "B::make".to_string())),
        "expected a B::make row with parent=B; got: {seen:?}"
    );
    Ok(())
}

/// `find_symbol("make", parent="A")` returns ONLY the `A::make` row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn find_symbol_parent_filter_selects_one_overload() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;
    std::fs::write(workspace.path().join("lib.rs"), OVERLOAD_FIXTURE)?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
    let mut child = spawn_daemon(runtime_dir.path(), state_dir.path(), home_dir.path())?;
    let _kill = KillOnDrop(&mut child);
    let mut stream = mount_and_warm(&sock, workspace.path()).await?;

    let resp = round_trip(
        &mut stream,
        "2",
        "Index.FindSymbol",
        json!({ "name": "make", "parent": "A" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "find_symbol errored: {resp:?}");
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        matches.len(),
        1,
        "parent=A must select exactly one overload; got: {matches:?}"
    );
    let m = &matches[0];
    assert_eq!(m["parent"].as_str(), Some("A"));
    assert_eq!(m["qualified_name"].as_str(), Some("A::make"));
    Ok(())
}

/// `read_symbol("make", parent="B")` resolves to B's definition — the
/// returned `parent`/`qualified_name`/body all correspond to `B::make`.
/// This is the canonical disambiguation workflow: `find_symbol` lists
/// the candidate parents, then `read_symbol parent=...` pins one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_symbol_parent_filter_resolves_to_b() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;
    std::fs::write(workspace.path().join("lib.rs"), OVERLOAD_FIXTURE)?;

    let sock = socket_path(home_dir.path(), runtime_dir.path());
    let mut child = spawn_daemon(runtime_dir.path(), state_dir.path(), home_dir.path())?;
    let _kill = KillOnDrop(&mut child);
    let mut stream = mount_and_warm(&sock, workspace.path()).await?;

    let resp = round_trip(
        &mut stream,
        "2",
        "Index.ReadSymbol",
        json!({ "name": "make", "parent": "B" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "read_symbol errored: {resp:?}");
    let result = &resp["result"];

    // The pinned def emits `parent` directly (no new error type needed).
    assert_eq!(
        result["parent"].as_str(),
        Some("B"),
        "read_symbol parent=B must pin B's def; got: {result:?}"
    );
    assert_eq!(
        result["qualified_name"].as_str(),
        Some("B::make"),
        "qualified_name must render as B::make; got: {result:?}"
    );
    // Body must be B's `make`, which returns `B` (not `A`).
    let text = result["text"].as_str().unwrap_or_default();
    assert!(
        text.contains("-> B"),
        "returned body must be B::make (returns B); got: {text:?}"
    );
    assert!(
        !text.contains("-> A"),
        "must not have resolved to A::make; got: {text:?}"
    );
    Ok(())
}
