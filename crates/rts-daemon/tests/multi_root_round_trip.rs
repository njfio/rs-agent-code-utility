//! Multi-root: one daemon serving several workspace roots at once.
//!
//! Before multi-root, a daemon was pinned to the first `Workspace.Mount`
//! path: a second mount of a *different* path returned `WORKSPACE_MISMATCH`,
//! so a swarm of agents in separate git worktrees needed one daemon per
//! worktree (and every tool call against the "wrong" daemon answered from the
//! wrong tree).
//!
//! This test drives one daemon through the real wire protocol and asserts:
//!
//! 1. Two different roots mount on one daemon, each with its own
//!    `workspace_id`.
//! 2. An `Index.*` call is served by the root its envelope `workspace_id`
//!    names — the same symbol is defined differently in each root, so the
//!    answer proves which index replied.
//! 3. Re-mounting a root joins it (same id, extra ref); the root survives an
//!    unmount that only drops one of the refs.
//! 4. Unmounting one root leaves the other serving; naming the released root
//!    afterwards is `WORKSPACE_MISMATCH`, never a silent fallback.
//! 5. With every root unmounted the daemon still idle-shuts down (the
//!    process exits) — the multi-root table must not leak the idle timer.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-daemon"))
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for_socket(path: &std::path::Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "socket {} did not appear within {timeout:?}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// One request/response on `stream`. `workspace_id` (when set) names the
/// mounted root the request concerns — it goes in the **envelope**, the same
/// place the MCP shim puts it, never in `params`.
async fn round_trip(
    stream: &mut UnixStream,
    id: &str,
    method: &str,
    params: Value,
    workspace_id: Option<&str>,
) -> anyhow::Result<Value> {
    let mut req = json!({ "id": id, "method": method, "params": params });
    if let Some(root) = workspace_id {
        req["workspace_id"] = json!(root);
    }
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.flush().await?;

    let mut buf = Vec::new();
    let read = async {
        loop {
            let mut byte = [0u8; 1];
            let n = stream.read(&mut byte).await?;
            if n == 0 {
                break Ok::<usize, std::io::Error>(0);
            }
            buf.push(byte[0]);
            if byte[0] == b'\n' {
                break Ok(buf.len());
            }
        }
    };
    let n = tokio::time::timeout(Duration::from_secs(30), read)
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for {method} response"))??;
    anyhow::ensure!(n > 0, "EOF before {method} response");
    Ok(serde_json::from_slice(&buf)?)
}

/// `Workspace.Mount` for `root`, returning its `workspace_id`.
async fn mount(
    stream: &mut UnixStream,
    id: &str,
    root: &std::path::Path,
) -> anyhow::Result<String> {
    let resp = round_trip(stream, id, "Workspace.Mount", json!({ "root": root }), None).await?;
    anyhow::ensure!(
        resp["error"].is_null(),
        "Workspace.Mount({}) failed: {resp:?}",
        root.display()
    );
    let ws_id = resp["result"]["workspace_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Mount response carried no workspace_id: {resp:?}"))?;
    Ok(ws_id.to_string())
}

/// Grep `text` in the root named by `workspace_id`, returning the match count.
async fn grep_matches(
    stream: &mut UnixStream,
    id: &str,
    text: &str,
    workspace_id: &str,
) -> anyhow::Result<Value> {
    let resp = round_trip(
        stream,
        id,
        "Index.Grep",
        json!({ "text": text }),
        Some(workspace_id),
    )
    .await?;
    Ok(resp)
}

fn root_with(path: &std::path::Path, marker: &str, answer: u32) -> std::io::Result<()> {
    std::fs::create_dir_all(path.join("src"))?;
    std::fs::write(
        path.join("src/lib.rs"),
        format!(
            "pub const MARKER: &str = \"{marker}\";\n\n\
             /// Returns this root's answer.\n\
             pub fn answer() -> u32 {{ {answer} }}\n"
        ),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_daemon_serves_two_roots_by_workspace_id() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let root_a = tempfile::tempdir()?;
    let root_b = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    root_with(root_a.path(), "MARKER_ROOT_A", 1)?;
    root_with(root_b.path(), "MARKER_ROOT_B", 2)?;

    // No `--workspace` → no prewarm; the daemon binds `default.sock` and
    // mounts whatever the RPCs ask for. A 2 s idle window lets the last
    // assertion watch the daemon exit once every root is released.
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
        .env("RTS_IDLE_SHUTDOWN_SECS", "2")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = KillOnDrop(cmd.spawn()?);
    wait_for_socket(&socket_path, Duration::from_secs(10)).await;

    let mut stream = UnixStream::connect(&socket_path).await?;

    // 1. Both roots mount on the SAME daemon (pre-multi-root this second
    //    mount was WORKSPACE_MISMATCH) and get distinct ids.
    let id_a = mount(&mut stream, "1", root_a.path()).await?;
    let id_b = mount(&mut stream, "2", root_b.path()).await?;
    assert_ne!(id_a, id_b, "two roots must get distinct workspace ids");
    assert_eq!(id_a.len(), 32, "workspace_id is the hex fingerprint id");

    // 2. Each call is served by the root it names. `answer` is defined
    //    differently in each tree, so the body proves which index replied.
    let a_answer = round_trip(
        &mut stream,
        "3",
        "Index.ReadSymbol",
        json!({ "name": "answer", "shape": "body" }),
        Some(&id_a),
    )
    .await?;
    let b_answer = round_trip(
        &mut stream,
        "4",
        "Index.ReadSymbol",
        json!({ "name": "answer", "shape": "body" }),
        Some(&id_b),
    )
    .await?;
    assert!(a_answer["error"].is_null(), "read_symbol(A): {a_answer:?}");
    assert!(b_answer["error"].is_null(), "read_symbol(B): {b_answer:?}");
    let a_body = a_answer["result"]["text"].as_str().unwrap_or_default();
    let b_body = b_answer["result"]["text"].as_str().unwrap_or_default();
    assert!(
        a_body.contains("{ 1 }"),
        "root A's answer must come from root A's index: {a_body:?}"
    );
    assert!(
        b_body.contains("{ 2 }"),
        "root B's answer must come from root B's index: {b_body:?}"
    );

    // Same for grep: a marker literal that exists in exactly one root.
    let grep_b = grep_matches(&mut stream, "5", "MARKER_ROOT_B", &id_b).await?;
    let grep_a = grep_matches(&mut stream, "6", "MARKER_ROOT_B", &id_a).await?;
    assert_eq!(
        grep_b["result"]["matches"].as_array().map(Vec::len),
        Some(1),
        "root B's own marker must be found in root B: {grep_b:?}"
    );
    assert_eq!(
        grep_a["result"]["matches"].as_array().map(Vec::len),
        Some(0),
        "root A must not answer with root B's content: {grep_a:?}"
    );

    // 3. Status reports the default root (first mounted) and lists both.
    let status = round_trip(&mut stream, "7", "Workspace.Status", json!({}), None).await?;
    assert_eq!(status["result"]["workspace_id"], json!(id_a));
    assert_eq!(
        status["result"]["mounted_roots"].as_array().map(Vec::len),
        Some(2),
        "Status must list every mounted root: {status:?}"
    );
    let status_b = round_trip(
        &mut stream,
        "8",
        "Workspace.Status",
        json!({ "root": id_b }),
        None,
    )
    .await?;
    assert_eq!(status_b["result"]["workspace_id"], json!(id_b));

    // 4. A second mount of root A joins it: same id, one more ref.
    let id_a2 = mount(&mut stream, "9", root_a.path()).await?;
    assert_eq!(id_a2, id_a, "re-mounting a root joins it");

    // 5. Unmount releases one ref: root A keeps serving after one unmount.
    let unmount_a1 = round_trip(
        &mut stream,
        "10",
        "Workspace.Unmount",
        json!({ "root": id_a }),
        None,
    )
    .await?;
    assert_eq!(unmount_a1["result"]["unmounted"], json!(id_a));
    let still_a = grep_matches(&mut stream, "11", "MARKER_ROOT_A", &id_a).await?;
    assert_eq!(
        still_a["result"]["matches"].as_array().map(Vec::len),
        Some(1),
        "root A holds two refs; one unmount must not tear it down: {still_a:?}"
    );

    // 6. Unmounting root B leaves root A serving and drops B from the table.
    let unmount_b = round_trip(
        &mut stream,
        "12",
        "Workspace.Unmount",
        json!({ "root": id_b }),
        None,
    )
    .await?;
    assert_eq!(unmount_b["result"]["unmounted"], json!(id_b));
    assert_eq!(
        unmount_b["result"]["mounted_roots"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "only root A should remain: {unmount_b:?}"
    );

    // 7. Naming the released root is an error, not a silent substitution.
    let gone = grep_matches(&mut stream, "13", "MARKER_ROOT_B", &id_b).await?;
    assert_eq!(
        gone["error"]["code"], "WORKSPACE_MISMATCH",
        "an unmounted root must be refused, not answered from another tree: {gone:?}"
    );

    // ...while root A still answers.
    let a_again = grep_matches(&mut stream, "14", "MARKER_ROOT_A", &id_a).await?;
    assert_eq!(
        a_again["result"]["matches"].as_array().map(Vec::len),
        Some(1),
        "root A must still serve after root B is released: {a_again:?}"
    );

    // 8. Release the last root (two refs on A) and watch the daemon exit on
    //    its idle window — the multi-root table must not hold it open.
    for request_id in ["15", "16"] {
        let resp = round_trip(
            &mut stream,
            request_id,
            "Workspace.Unmount",
            json!({ "root": id_a }),
            None,
        )
        .await?;
        assert!(resp["error"].is_null(), "unmount(A): {resp:?}");
    }
    let status_after = round_trip(&mut stream, "17", "Workspace.Status", json!({}), None).await?;
    assert_eq!(
        status_after["result"]["state"], "no_workspace",
        "with every root released the daemon reports no_workspace: {status_after:?}"
    );

    // The idle timer only fires with no live connections (`is_idle`), so the
    // client must let go first — an attached client keeps the daemon alive by
    // design.
    drop(stream);

    let deadline = Instant::now() + Duration::from_secs(20);
    let exited = loop {
        match child.0.try_wait()? {
            Some(_) => break true,
            None if Instant::now() >= deadline => break false,
            None => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };
    assert!(
        exited,
        "the daemon must still idle-shut-down once every root is unmounted"
    );
    Ok(())
}
