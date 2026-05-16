//! Smoke test for `rts-bench query <tool>`. Spawns the CLI against a
//! tiny seeded workspace and verifies stdout is valid JSON containing
//! the expected keys.
//!
//! This closes the dogfooding gap from alpha.23's honest eval: gives
//! Bash-only callers (including this Claude Code session) a way to
//! invoke the daemon without configuring an MCP client.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::process::Command;

fn rts_bench_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-bench"))
}

fn sibling(name: &str) -> PathBuf {
    let me = rts_bench_bin();
    me.parent().expect("CARGO_BIN_EXE has parent").join(name)
}

/// Run `rts-bench query ...` against `workspace` and return parsed
/// JSON stdout. Fails the test on non-zero exit unless `expect_error`
/// is set.
async fn run_query(
    workspace: &std::path::Path,
    runtime: &std::path::Path,
    state: &std::path::Path,
    home: &std::path::Path,
    args: &[&str],
    expect_error: bool,
) -> Result<Value> {
    let rts_mcp_bin = sibling("rts-mcp");
    let rts_daemon_bin = sibling("rts-daemon");
    assert!(rts_mcp_bin.is_file(), "missing {}", rts_mcp_bin.display());
    assert!(
        rts_daemon_bin.is_file(),
        "missing {}",
        rts_daemon_bin.display()
    );

    let mut cmd = Command::new(rts_bench_bin());
    cmd.arg("query");
    for a in args {
        cmd.arg(a);
    }
    cmd.arg("--workspace").arg(workspace);
    cmd.env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_STATE_HOME", state)
        .env("HOME", home)
        .env("RTS_MCP_BIN", &rts_mcp_bin)
        .env("RTS_DAEMON_BIN", &rts_daemon_bin)
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().await.context("spawn rts-bench query")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if expect_error {
        assert!(
            !out.status.success(),
            "expected non-zero exit; got stdout: {stdout}\nstderr: {stderr}"
        );
    } else {
        assert!(
            out.status.success(),
            "rts-bench query failed\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
    serde_json::from_str(&stdout).context("parse stdout JSON")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn query_subcommand_exercises_all_five_tools() -> Result<()> {
    let workspace = tempfile::tempdir()?;
    let runtime = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let home = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700));

    // Seed a small workspace with predictable symbol names.
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn make_widget(id: u32) -> u32 { id + 1 }\n\
         pub fn make_circle(r: u32) -> u32 { r * 2 }\n\
         pub fn format_widget(w: u32) -> String { format!(\"w#{w}\") }\n",
    )?;

    // ---- find_symbol --pattern ----
    let found = run_query(
        workspace.path(),
        runtime.path(),
        state.path(),
        home.path(),
        &["find-symbol", "--pattern", "make_*"],
        false,
    )
    .await?;
    let names: Vec<&str> = found["matches"]
        .as_array()
        .expect("matches array")
        .iter()
        .filter_map(|m| m["qualified_name"].as_str())
        .collect();
    assert!(
        names.contains(&"make_widget") && names.contains(&"make_circle"),
        "expected make_widget + make_circle from `make_*`; got {names:?}"
    );
    assert!(
        !names.contains(&"format_widget"),
        "format_widget should not match `make_*`; got {names:?}"
    );

    // ---- read_symbol --shape signature ----
    let read = run_query(
        workspace.path(),
        runtime.path(),
        state.path(),
        home.path(),
        &[
            "read-symbol",
            "--name",
            "make_widget",
            "--shape",
            "signature",
        ],
        false,
    )
    .await?;
    let sig = read["signature"].as_str().expect("signature string");
    assert!(
        sig.contains("pub fn make_widget"),
        "expected signature with pub fn make_widget; got {sig:?}"
    );
    assert_eq!(read["shape"], "signature");
    assert_eq!(read["qualified_name"], "make_widget");

    // ---- read_symbol_at --file hub.rs --line 2 ----
    let at = run_query(
        workspace.path(),
        runtime.path(),
        state.path(),
        home.path(),
        &["read-symbol-at", "--file", "hub.rs", "--line", "2"],
        false,
    )
    .await?;
    // Line 2 of hub.rs is make_circle.
    assert_eq!(at["qualified_name"], "make_circle");
    assert_eq!(at["file"], "hub.rs");

    // ---- outline ----
    let outline = run_query(
        workspace.path(),
        runtime.path(),
        state.path(),
        home.path(),
        &["outline", "--token-budget", "256"],
        false,
    )
    .await?;
    assert!(outline["files_considered"].as_u64().unwrap_or(0) >= 1);
    assert!(outline["files_included"].as_u64().unwrap_or(0) >= 1);
    assert!(outline["outline_text"].is_string());

    // ---- read_range ----
    let range = run_query(
        workspace.path(),
        runtime.path(),
        state.path(),
        home.path(),
        &[
            "read-range",
            "--file",
            "hub.rs",
            "--start-line",
            "1",
            "--end-line",
            "1",
        ],
        false,
    )
    .await?;
    let text = range["text"].as_str().expect("text string");
    assert!(
        text.contains("pub fn make_widget"),
        "line 1 should contain make_widget definition; got {text:?}"
    );

    // ---- error path: find_symbol with neither --name nor --pattern ----
    // clap rejects this at parse time (because we declared the
    // conflict but not the required-one-of). The CLI exits with a
    // clap usage error, not a daemon error.
    let mut bad = Command::new(rts_bench_bin());
    bad.arg("query")
        .arg("find-symbol")
        .arg("--workspace")
        .arg(workspace.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_STATE_HOME", state.path())
        .env("HOME", home.path())
        .env("RTS_MCP_BIN", sibling("rts-mcp"))
        .env("RTS_DAEMON_BIN", sibling("rts-daemon"))
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let bad_out = bad.output().await?;
    assert!(
        !bad_out.status.success(),
        "no --name or --pattern should error"
    );

    Ok(())
}

/// Run `rts-bench query --output lines ...` and return stdout as a
/// string. Lines mode emits `path:line:content` text, not JSON.
async fn run_query_lines(
    workspace: &std::path::Path,
    runtime: &std::path::Path,
    state: &std::path::Path,
    home: &std::path::Path,
    args: &[&str],
) -> Result<String> {
    let rts_mcp_bin = sibling("rts-mcp");
    let rts_daemon_bin = sibling("rts-daemon");
    let mut cmd = Command::new(rts_bench_bin());
    cmd.arg("query").arg("--output").arg("lines");
    for a in args {
        cmd.arg(a);
    }
    cmd.arg("--workspace").arg(workspace);
    cmd.env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_STATE_HOME", state)
        .env("HOME", home)
        .env("RTS_MCP_BIN", &rts_mcp_bin)
        .env("RTS_DAEMON_BIN", &rts_daemon_bin)
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().await.context("spawn rts-bench query")?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "rts-bench query --output lines failed\nstdout: {stdout}\nstderr: {stderr}"
    );
    Ok(stdout)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn query_output_lines_renders_rg_shaped_text() -> Result<()> {
    let workspace = tempfile::tempdir()?;
    let runtime = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let home = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700));

    // Seed two files so we exercise file-scope and fn-scope grep
    // matches separately. `hub.rs` puts the literal inside a fn body
    // (so `enclosing_qualified_name` is non-null on v0.5.5+). `notes.rs`
    // puts a similar literal in a top-of-file comment (file-scope).
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn target() -> u32 { 42 }\n\
         pub fn caller_a() { let _ = target(); }\n\
         pub fn caller_b() { let _ = target(); }\n",
    )?;
    std::fs::write(
        workspace.path().join("notes.rs"),
        "// notes about the target API and how to call it.\n\
         pub fn unrelated() {}\n",
    )?;

    // ---- find-symbol --output lines ----
    let find_lines = run_query_lines(
        workspace.path(),
        runtime.path(),
        state.path(),
        home.path(),
        &["find-symbol", "--pattern", "caller_*"],
    )
    .await?;
    let lines: Vec<&str> = find_lines.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "find-symbol --pattern caller_* should emit 2 lines, got {lines:?}"
    );
    // Each line must match `path:line:name (kind)` shape.
    for line in &lines {
        // First two colons split path / line / rest.
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        assert_eq!(parts.len(), 3, "expected path:line:rest; got {line:?}");
        assert!(
            parts[0].ends_with(".rs"),
            "first field should be a .rs path; got {:?}",
            parts[0]
        );
        assert!(
            parts[1].parse::<u32>().is_ok(),
            "second field should be a line number; got {:?}",
            parts[1]
        );
        assert!(
            parts[2].contains("caller_") && parts[2].contains('('),
            "third field should be `name (kind)`; got {:?}",
            parts[2]
        );
    }

    // ---- find-callers --output lines ----
    // `target` is called from both caller_a + caller_b.
    let callers_lines = run_query_lines(
        workspace.path(),
        runtime.path(),
        state.path(),
        home.path(),
        &["find-callers", "--name", "target"],
    )
    .await?;
    let cl: Vec<&str> = callers_lines.lines().collect();
    assert!(
        cl.len() >= 2,
        "find-callers should emit >=2 caller lines; got {cl:?}"
    );
    assert!(
        cl.iter().any(|l| l.contains("caller_a")),
        "expected caller_a in output; got {cl:?}"
    );
    assert!(
        cl.iter().any(|l| l.contains("caller_b")),
        "expected caller_b in output; got {cl:?}"
    );

    // ---- grep --output lines ----
    // `target` literal appears in: target def, caller_a body, caller_b
    // body (all in hub.rs) and the notes.rs comment.
    let grep_lines = run_query_lines(
        workspace.path(),
        runtime.path(),
        state.path(),
        home.path(),
        &["grep", "--text", "target"],
    )
    .await?;
    let gl: Vec<&str> = grep_lines.lines().collect();
    assert!(
        gl.len() >= 4,
        "grep target should hit >=4 lines (3 in hub.rs + 1 in notes.rs); got {gl:?}"
    );
    // Each line must match `path:line:...` (content may contain `:`).
    for line in &gl {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        assert_eq!(
            parts.len(),
            3,
            "grep line should be path:line:text; got {line:?}"
        );
        assert!(
            parts[1].parse::<u32>().is_ok(),
            "grep line should have line-number field; got {parts:?}"
        );
    }

    // ---- grep --output lines | wc -l no-match exits 0 and emits nothing ----
    let empty = run_query_lines(
        workspace.path(),
        runtime.path(),
        state.path(),
        home.path(),
        &["grep", "--text", "no_such_string_anywhere_xyz_42"],
    )
    .await?;
    assert!(
        empty.is_empty(),
        "no-match grep should emit empty stdout; got {empty:?}"
    );

    // ---- pipe composability: extract unique file names ----
    // This is the killer use-case: `rts-bench query --output lines grep` |
    // bash idioms. Reproduce it inline using string ops, since `awk` /
    // `sort -u` aren't part of the test harness — the goal is to
    // confirm the SHAPE makes this trivial, not to exec bash.
    let unique_files: std::collections::BTreeSet<&str> = grep_lines
        .lines()
        .filter_map(|l| l.split(':').next())
        .collect();
    assert!(
        unique_files.iter().any(|f| f.ends_with("hub.rs")),
        "expected hub.rs in unique files; got {unique_files:?}"
    );
    assert!(
        unique_files.iter().any(|f| f.ends_with("notes.rs")),
        "expected notes.rs in unique files; got {unique_files:?}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn query_returns_nonzero_on_daemon_error() -> Result<()> {
    let workspace = tempfile::tempdir()?;
    let runtime = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let home = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700));

    // Empty workspace — querying a name produces SYMBOL_NOT_FOUND.
    std::fs::write(workspace.path().join("readme.md"), "# empty\n")?;

    // SYMBOL_NOT_FOUND surfaces with `is_error=true`; the CLI exits 1.
    let _err = run_query(
        workspace.path(),
        runtime.path(),
        state.path(),
        home.path(),
        &["read-symbol", "--name", "does_not_exist"],
        true,
    )
    .await?;
    // The JSON body should carry the error code; the CLI's contract
    // is "exit 1 + JSON describes the failure", so callers can `jq
    // .error.code` for branching.
    // (We're not asserting on the specific code because the
    // wire-error envelope may evolve.)
    Ok(())
}
