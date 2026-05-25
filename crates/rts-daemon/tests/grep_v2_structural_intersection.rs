//! Integration test for the v0.6 Index.Grep v2 structural × literal
//! intersection (PR #110 Codex review C5).
//!
//! The protocol matrix in `grep_v2::compose` defines
//! `structural_query + text` as **intersection**: a returned match
//! must satisfy BOTH the structural query AND the literal text
//! filter. Without the intersection post-pass added in this commit,
//! the daemon returned structural-only matches and effectively
//! ignored the `text` filter, breaking client behavior.
//!
//! This test pins the intersection invariant end-to-end:
//!
//!   1. Seed a workspace with two Rust functions.
//!   2. Run a structural query `(function_item) @fn` that matches
//!      both functions.
//!   3. Add `text: "panic"` to the same call. Only one function's
//!      body contains `panic!(...)`.
//!   4. Assert: the response carries exactly that one match — not
//!      both, not zero.

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
    let n = tokio::time::timeout(Duration::from_secs(5), reader.read_until(b'\n', &mut buf))
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

#[tokio::test(flavor = "current_thread")]
async fn structural_plus_text_returns_intersection_only() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Seed two Rust functions: only the second contains "panic!".
    std::fs::write(
        workspace.path().join("lib.rs"),
        r#"
pub fn safe_add(a: u32, b: u32) -> u32 {
    a + b
}

pub fn unsafe_div(a: u32, b: u32) -> u32 {
    if b == 0 {
        panic!("divide by zero");
    }
    a / b
}
"#,
    )?;

    let sock = if cfg!(target_os = "macos") {
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

    // Poll until both functions are indexed.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut id: u32 = 10;
    loop {
        id += 1;
        let r = round_trip(
            &mut stream,
            &id.to_string(),
            "Index.FindSymbol",
            json!({ "name": "unsafe_div" }),
        )
        .await?;
        if let Some(arr) = r["result"]["matches"].as_array() {
            if !arr.is_empty() {
                break;
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("seeded functions never indexed within 5s");
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }

    // ---- Structural-only sanity check ----
    //
    // The query matches every `function_item` node. Without
    // intersection, this should return BOTH seeded functions.
    let structural_only = round_trip(
        &mut stream,
        "100",
        "Index.Grep",
        json!({
            "structural_query": "(function_item) @fn",
            "language": ["rust"],
        }),
    )
    .await?;
    assert!(
        structural_only["error"].is_null(),
        "structural-only call errored: {structural_only:?}"
    );
    let baseline_matches = structural_only["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        baseline_matches.len() >= 2,
        "structural-only should match both seeded functions; got {baseline_matches:?}"
    );

    // ---- Structural × literal intersection ----
    //
    // Adding `text: "panic"` must drop the `safe_add` function (no
    // `panic` in its body) and keep `unsafe_div`. Exactly one match.
    let intersected = round_trip(
        &mut stream,
        "101",
        "Index.Grep",
        json!({
            "structural_query": "(function_item) @fn",
            "language": ["rust"],
            "text": "panic",
        }),
    )
    .await?;
    assert!(
        intersected["error"].is_null(),
        "structural+text call errored: {intersected:?}"
    );
    let matches = intersected["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        matches.len(),
        1,
        "structural × literal intersection: expected exactly one match (the function whose body contains `panic`); got {} \nResponse: {intersected:?}",
        matches.len(),
    );

    // The single surviving match must be the `unsafe_div` function.
    // Its enclosing range covers the `panic!` line; we just check the
    // captured byte slice contains "panic" (the contract).
    let m = &matches[0];
    let captures = m["captures"]["fn"].as_array().cloned().unwrap_or_default();
    assert!(!captures.is_empty(), "expected @fn capture; got {m:?}");
    let captured_text = captures[0]["text"].as_str().unwrap_or("");
    assert!(
        captured_text.contains("panic"),
        "surviving match's captured text must contain `panic`; got `{captured_text}`"
    );

    Ok(())
}
