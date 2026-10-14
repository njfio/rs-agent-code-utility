//! End-to-end multi-root routing through the MCP shim.
//!
//! Spawns `rts-mcp --workspace <A> --workspace <B>` (which auto-spawns ONE
//! `rts-daemon`), then drives real `tools/call` requests over stdio and
//! asserts that each call is served by the root its **own arguments** name —
//! without the model ever passing a root:
//!
//! - `read_symbol { file: "<absolute path under B>" }` → served by B,
//!   `_root.resolved_by == "path_match"`, and the body is B's definition.
//! - `read_symbol { name: "answer" }` (no path at all) → served by the
//!   start-up root, `_root.resolved_by == "default"`, and the response says
//!   so.
//! - `grep { file_glob: "<absolute glob under B>" }` → served by B.
//! - A path into a **git worktree nested inside the start-up root** (which is
//!   not a mounted root and is gitignored by the repo, so the repo's index
//!   skips it) mounts that checkout for the call:
//!   `_root.resolved_by == "mounted"`, `mounted_now` distinguishing the call
//!   that mounted it from the ones that reuse it.
//!
//! The two roots define the same symbol differently, so a mis-route shows up
//! as the wrong body rather than as a plausible-looking answer — the exact
//! failure this change exists to remove.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout};

fn rts_mcp_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-mcp"))
}

/// `CARGO_BIN_EXE_<name>` only resolves inside the current crate, so point the
/// daemon path at the sibling output dir.
fn rts_daemon_bin() -> PathBuf {
    let mcp = rts_mcp_bin();
    let parent = mcp.parent().expect("CARGO_BIN_EXE_rts-mcp has parent dir");
    parent.join("rts-daemon")
}

async fn read_one_response(reader: &mut BufReader<ChildStdout>) -> Result<Value> {
    let mut buf = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(30), reader.read_until(b'\n', &mut buf))
        .await
        .map_err(|_| anyhow!("timeout reading MCP response"))??;
    if n == 0 {
        anyhow::bail!("EOF before MCP response");
    }
    serde_json::from_slice(&buf).context("decode MCP response")
}

async fn send_request(stdin: &mut ChildStdin, req: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(req)?;
    bytes.push(b'\n');
    stdin.write_all(&bytes).await?;
    stdin.flush().await?;
    Ok(())
}

/// One `tools/call`, returning the parsed daemon JSON body (with the shim's
/// `_root` block attached). An error envelope from the daemon comes back as
/// its body (`{"error": …}`), so callers can assert on it.
async fn call_tool(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    id: &mut u64,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    *id += 1;
    send_request(
        stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": *id,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments }
        }),
    )
    .await?;
    let resp = read_one_response(reader).await?;
    if resp["result"]["isError"].as_bool().unwrap_or(false)
        && resp["result"]["content"][0]["text"].is_null()
    {
        anyhow::bail!("{tool} returned an MCP error: {resp:?}");
    }
    let body = resp["result"]["content"][0]["text"]
        .as_str()
        .ok_or_else(|| anyhow!("{tool} returned no text content: {resp:?}"))?;
    serde_json::from_str(body).with_context(|| format!("parse {tool} body"))
}

/// The first call routed to a root pays that root's mount (cold walk + first
/// writer batch), so retry until the index answers — the same shape
/// `mcp_round_trip.rs` uses for a freshly mounted workspace.
async fn call_tool_until_indexed(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    id: &mut u64,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let body = call_tool(stdin, reader, id, tool, arguments.clone()).await?;
        if body.get("error").is_none() {
            return Ok(body);
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("{tool} never became answerable: {body:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A `grep` whose answer must arrive with `expected` matches: a freshly
/// mounted root's cold walk lands asynchronously, and until it does the index
/// legitimately answers with none.
async fn grep_until_matches(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    id: &mut u64,
    arguments: Value,
    expected: usize,
) -> Result<Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let body = call_tool(stdin, reader, id, "grep", arguments.clone()).await?;
        if body["matches"].as_array().map(Vec::len) == Some(expected) {
            return Ok(body);
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("grep never reached {expected} matches: {body:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn seed_root(path: &Path, marker: &str, answer: u32) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(path.join("src"))?;
    let file = path.join("src/lib.rs");
    std::fs::write(
        &file,
        format!(
            "pub const MARKER: &str = \"{marker}\";\n\n\
             /// Returns this root's answer.\n\
             pub fn answer() -> u32 {{ {answer} }}\n"
        ),
    )?;
    Ok(file)
}

/// A repo with a **git worktree nested inside it** — `git worktree add` writes
/// a `.git` *file* there — and `.wt/` gitignored, which is the layout an agent
/// editing in a worktree produces. The repo's own index skips the worktree's
/// files, so a path into the worktree can only be answered by the worktree
/// itself.
fn seed_worktree(repo: &Path, worktree: &Path, marker: &str, answer: u32) -> std::io::Result<()> {
    seed_root(repo, "MARKER_REPO", 1)?;
    std::fs::write(repo.join(".gitignore"), ".wt/\n")?;
    std::fs::create_dir_all(worktree.join("src"))?;
    std::fs::write(
        worktree.join(".git"),
        format!("gitdir: {}/.git/worktrees/w\n", repo.display()),
    )?;
    seed_root(worktree, marker, answer)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn mcp_routes_each_tool_call_to_the_root_its_paths_name() -> Result<()> {
    let daemon_bin = rts_daemon_bin();
    assert!(
        daemon_bin.is_file(),
        "rts-daemon must be built before this test; missing at {}",
        daemon_bin.display()
    );

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let root_a = tempfile::tempdir()?;
    let root_b = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    seed_root(root_a.path(), "MARKER_ROOT_A", 1)?;
    let file_b = seed_root(root_b.path(), "MARKER_ROOT_B", 2)?;

    // Canonical (as the shim and the daemon both canonicalise) so the absolute
    // path we send really is under root B.
    let canonical_a = root_a.path().canonicalize()?;
    let canonical_b = root_b.path().canonicalize()?;
    let file_b_abs = file_b.canonicalize()?;
    let glob_b = format!("{}/src/**/*.rs", canonical_b.display());

    let mut cmd = tokio::process::Command::new(rts_mcp_bin());
    cmd.arg("--workspace")
        .arg(&canonical_a)
        .arg("--workspace")
        .arg(&canonical_b)
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RTS_LOG", "warn")
        .env("RTS_DAEMON_BIN", &daemon_bin)
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = cmd.spawn().context("spawn rts-mcp")?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("piped stdout"));

    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "rts-mcp-multiroot-itest", "version": "0.0.0" }
            }
        }),
    )
    .await?;
    let init = read_one_response(&mut reader).await?;
    assert_eq!(init["id"], 1, "initialize failed: {init:?}");
    send_request(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} }),
    )
    .await?;

    let mut id: u64 = 100;

    // 1. An absolute path under root B routes there — and answers with B's
    //    definition of `answer`, not the start-up root's. This first routed
    //    call also pays root B's mount, hence the retry.
    let routed_to_b = call_tool_until_indexed(
        &mut stdin,
        &mut reader,
        &mut id,
        "read_symbol",
        json!({ "name": "answer", "file": file_b_abs.to_string_lossy(), "shape": "body" }),
    )
    .await?;
    assert_eq!(
        routed_to_b["_root"]["path"],
        json!(canonical_b.to_string_lossy()),
        "an absolute path under root B must route to root B: {routed_to_b:?}"
    );
    assert_eq!(routed_to_b["_root"]["resolved_by"], "path_match");
    let body_b = routed_to_b["text"].as_str().unwrap_or_default();
    assert!(
        body_b.contains("{ 2 }"),
        "root B's body must come from root B's index: {body_b:?}"
    );
    let id_b = routed_to_b["_root"]["workspace_id"]
        .as_str()
        .expect("_root.workspace_id")
        .to_string();

    // 2. A glob under root B routes there too.
    let grep_b = call_tool(
        &mut stdin,
        &mut reader,
        &mut id,
        "grep",
        json!({ "text": "MARKER_ROOT_B", "file_glob": glob_b }),
    )
    .await?;
    assert_eq!(
        grep_b["_root"]["path"],
        json!(canonical_b.to_string_lossy()),
        "an absolute glob under root B must route to root B: {grep_b:?}"
    );
    assert_eq!(
        grep_b["matches"].as_array().map(Vec::len),
        Some(1),
        "root B's marker must be found once: {grep_b:?}"
    );

    // 3. A call with no path at all is served by the start-up root, and the
    //    response says so rather than leaving the caller to guess.
    let default_root = call_tool(
        &mut stdin,
        &mut reader,
        &mut id,
        "read_symbol",
        json!({ "name": "answer", "shape": "body" }),
    )
    .await?;
    assert_eq!(
        default_root["_root"]["path"],
        json!(canonical_a.to_string_lossy()),
        "a name-only call must be served by the start-up root: {default_root:?}"
    );
    assert_eq!(default_root["_root"]["resolved_by"], "default");
    assert!(
        default_root["_root"]["note"]
            .as_str()
            .unwrap_or_default()
            .contains("start-up root"),
        "the default must be stated in the response: {default_root:?}"
    );
    let body_a = default_root["text"].as_str().unwrap_or_default();
    assert!(
        body_a.contains("{ 1 }"),
        "the start-up root's body must come from root A's index: {body_a:?}"
    );

    // 4. Both roots are mounted on ONE daemon: the two routes name different
    //    mount ids.
    let id_a = default_root["_root"]["workspace_id"]
        .as_str()
        .expect("_root.workspace_id")
        .to_string();
    assert_ne!(
        id_a, id_b,
        "the two routes must be distinct mounts of the same daemon"
    );

    Ok(())
}

/// The probe this change exists for: an absolute path into a git worktree
/// nested inside the start-up root. The worktree is not a mounted root, and
/// the repo's index skips it (`.wt/` is gitignored), so before the change the
/// call was served by the repo and came back empty. The call's own path must
/// mount the checkout and be answered by it.
#[tokio::test(flavor = "current_thread")]
async fn a_path_into_a_nested_worktree_mounts_the_worktree() -> Result<()> {
    let daemon_bin = rts_daemon_bin();
    assert!(
        daemon_bin.is_file(),
        "rts-daemon must be built before this test; missing at {}",
        daemon_bin.display()
    );

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let repo_dir = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    let repo = repo_dir.path().canonicalize()?;
    let worktree = repo.join(".wt/w1");
    seed_worktree(&repo, &worktree, "MARKER_WORKTREE", 7)?;
    let worktree = worktree.canonicalize()?;

    // ONE root: the repo. The worktree is deliberately not passed to the shim.
    let mut cmd = tokio::process::Command::new(rts_mcp_bin());
    cmd.arg("--workspace")
        .arg(&repo)
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RTS_LOG", "warn")
        .env("RTS_DAEMON_BIN", &daemon_bin)
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = cmd.spawn().context("spawn rts-mcp")?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("piped stdout"));

    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "rts-mcp-worktree-itest", "version": "0.0.0" }
            }
        }),
    )
    .await?;
    let init = read_one_response(&mut reader).await?;
    assert_eq!(init["id"], 1, "initialize failed: {init:?}");
    send_request(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} }),
    )
    .await?;

    let mut id: u64 = 100;
    let glob = format!("{}/src/**", worktree.display());

    // 1. The failing shape: a glob into the worktree. The call mounts the
    //    checkout the path named, and says so.
    let first = call_tool(
        &mut stdin,
        &mut reader,
        &mut id,
        "grep",
        json!({ "text": "MARKER_WORKTREE", "file_glob": glob }),
    )
    .await?;
    assert_eq!(
        first["_root"]["path"],
        json!(worktree.to_string_lossy()),
        "a path into the nested checkout must be served by the checkout: {first:?}"
    );
    assert_eq!(first["_root"]["resolved_by"], "mounted");
    assert_eq!(
        first["_root"]["mounted_now"],
        json!(true),
        "the call that named the checkout mounts it: {first:?}"
    );

    // The cold walk of a freshly mounted root lands asynchronously, so this
    // answer may be empty for a moment; retry until the worktree's own file is
    // there.
    let body = grep_until_matches(
        &mut stdin,
        &mut reader,
        &mut id,
        json!({ "text": "MARKER_WORKTREE", "file_glob": glob }),
        1,
    )
    .await?;
    let reused = call_tool(
        &mut stdin,
        &mut reader,
        &mut id,
        "grep",
        json!({ "text": "MARKER_WORKTREE", "file_glob": glob }),
    )
    .await?;
    assert_eq!(
        reused["matches"].as_array().map(Vec::len),
        Some(1),
        "the worktree's marker must come from the worktree's own index: {reused:?} (was {body:?})"
    );
    assert_eq!(reused["_root"]["resolved_by"], "mounted");
    assert_eq!(
        reused["_root"]["mounted_now"],
        json!(false),
        "a later call to the same checkout reuses its mount: {reused:?}"
    );

    // 2. A `file` argument inside the checkout routes there too, and answers
    //    with the worktree's body — the repo defines `answer` differently.
    let read = call_tool(
        &mut stdin,
        &mut reader,
        &mut id,
        "read_symbol",
        json!({
            "name": "answer",
            "file": worktree.join("src/lib.rs").to_string_lossy(),
            "shape": "body"
        }),
    )
    .await?;
    assert_eq!(read["_root"]["path"], json!(worktree.to_string_lossy()));
    assert_eq!(read["_root"]["resolved_by"], "mounted");
    let read_body = read["text"].as_str().unwrap_or_default();
    assert!(
        read_body.contains("{ 7 }"),
        "the worktree's body must come from the worktree's index: {read_body:?}"
    );

    // 3. The inference is narrow: an ordinary subdirectory of the repo, and a
    //    path that names no directory at all, keep the repo as their root.
    let plain = grep_until_matches(
        &mut stdin,
        &mut reader,
        &mut id,
        json!({ "text": "MARKER_REPO", "file_glob": format!("{}/src/**", repo.display()) }),
        1,
    )
    .await?;
    assert_eq!(plain["_root"]["path"], json!(repo.to_string_lossy()));
    assert_eq!(plain["_root"]["resolved_by"], "path_match");

    let missing = call_tool(
        &mut stdin,
        &mut reader,
        &mut id,
        "grep",
        json!({ "text": "MARKER", "file_glob": format!("{}/nope/deep/**", repo.display()) }),
    )
    .await?;
    assert_eq!(
        missing["_root"]["path"],
        json!(repo.to_string_lossy()),
        "a path with no directory of its own must stay on the start-up root: {missing:?}"
    );
    assert_eq!(missing["_root"]["resolved_by"], "path_match");

    Ok(())
}

/// The bound on the inference: a checkout is mounted only when it sits under
/// the shim's **start-up** root. Outside it — even under another configured
/// root, and certainly under no root at all — the path stays with the root
/// that matched, so a tool call can never make the shim mount an arbitrary
/// filesystem directory.
#[tokio::test(flavor = "current_thread")]
async fn a_nested_worktree_outside_the_start_up_root_is_not_mounted() -> Result<()> {
    let daemon_bin = rts_daemon_bin();
    assert!(
        daemon_bin.is_file(),
        "rts-daemon must be built before this test; missing at {}",
        daemon_bin.display()
    );

    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let start_up_dir = tempfile::tempdir()?;
    let other_dir = tempfile::tempdir()?;
    let stray_dir = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    let start_up = start_up_dir.path().canonicalize()?;
    seed_root(&start_up, "MARKER_START_UP", 1)?;
    let other = other_dir.path().canonicalize()?;
    let other_worktree = other.join(".wt/w2");
    seed_worktree(&other, &other_worktree, "MARKER_OTHER_WORKTREE", 9)?;
    let other_worktree = other_worktree.canonicalize()?;
    // A checkout under no configured root at all.
    let stray = stray_dir.path().canonicalize()?;
    seed_worktree(&stray, &stray.join(".wt/w3"), "MARKER_STRAY_WORKTREE", 11)?;

    let mut cmd = tokio::process::Command::new(rts_mcp_bin());
    cmd.arg("--workspace")
        .arg(&start_up)
        .arg("--workspace")
        .arg(&other)
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RTS_LOG", "warn")
        .env("RTS_DAEMON_BIN", &daemon_bin)
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = cmd.spawn().context("spawn rts-mcp")?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("piped stdout"));

    send_request(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "rts-mcp-worktree-bound-itest", "version": "0.0.0" }
            }
        }),
    )
    .await?;
    let init = read_one_response(&mut reader).await?;
    assert_eq!(init["id"], 1, "initialize failed: {init:?}");
    send_request(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} }),
    )
    .await?;

    let mut id: u64 = 100;

    // 1. A checkout under the *other* root: the path is served by that root,
    //    and the checkout is not mounted (its files are gitignored by that
    //    root, so the call legitimately comes back empty — the cost of the
    //    bound, paid deliberately).
    let routed = grep_until_matches(
        &mut stdin,
        &mut reader,
        &mut id,
        json!({
            "text": "MARKER_OTHER_WORKTREE",
            "file_glob": format!("{}/src/**", other_worktree.display())
        }),
        0,
    )
    .await?;
    assert_eq!(
        routed["_root"]["path"],
        json!(other.to_string_lossy()),
        "a checkout outside the start-up root must not become a root: {routed:?}"
    );
    assert_eq!(routed["_root"]["resolved_by"], "path_match");

    // 2. A path under no configured root at all stays a visible default — and
    //    nothing is mounted for it. (`grep` rather than `read_symbol`: a daemon
    //    *error* is reported without a `_root` block, and this call is about
    //    where the path routed.)
    let stray_glob = format!("{}/.wt/w3/src/**", stray.display());
    let outside = grep_until_matches(
        &mut stdin,
        &mut reader,
        &mut id,
        json!({ "text": "answer", "file_glob": stray_glob }),
        0,
    )
    .await?;
    assert_eq!(
        outside["_root"]["path"],
        json!(start_up.to_string_lossy()),
        "a path outside every root must stay a visible default: {outside:?}"
    );
    assert_eq!(outside["_root"]["resolved_by"], "default");

    Ok(())
}
