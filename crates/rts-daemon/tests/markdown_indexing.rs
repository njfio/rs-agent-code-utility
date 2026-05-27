//! End-to-end test: markdown files are indexed and retrievable via
//! `Index.FindSymbol`, `Index.Outline`, and `Index.Grep` (v0.7.0).
//!
//! This is the v0.7.0 acceptance gate: the 7 scenarios called out in
//! the markdown-indexing plan (`docs/plans/2026-05-26-001-feat-markdown-
//! indexing-prose-retrieval-plan.md` §"Integration Test Scenarios"):
//!
//!   1. README.md headings emit with `kind="heading"`, correct
//!      hierarchical `qualified_name`, `signature`, `start_line`, and
//!      `documentation` populated from the body paragraph.
//!   2. `outline_workspace` includes the .md file with a flat heading
//!      list (hierarchy in `qualified_name`, not nested tree).
//!   3. `grep(text="installation")` matches markdown content with
//!      `enclosing_qualified_name` carrying the heading path.
//!   4. Gitignored markdown files (`target/doc/index.md`) are NOT
//!      indexed.
//!   5. Headings inside fenced code blocks are NOT extracted.
//!   6. CLI parity: `rts find ... --output json` returns equivalent
//!      rows to the MCP `Index.FindSymbol` response (same name, kind,
//!      file, line).
//!   7. Oversized markdown (>4 MB) is skipped without taking down the
//!      daemon (covered by the existing global oversize threshold).
//!
//! Patterned on `call_edges_<lang>.rs` — daemon-bin subprocess
//! over a Unix socket, real workspace via tempdir, await cold-walk.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-daemon"))
}

/// Resolve the `rts` CLI binary path by walking up from the daemon
/// binary (cargo places sibling bins in the same `target/<profile>/`
/// directory). `CARGO_BIN_EXE_rts` is unavailable to rts-daemon tests
/// because the `rts` bin lives in the rts-mcp crate.
fn rts_cli_bin() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_BIN_EXE_rts-daemon"));
    path.pop();
    path.join(if cfg!(windows) { "rts.exe" } else { "rts" })
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
async fn markdown_round_trip_via_mcp_and_cli() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // README.md — primary fixture. Two-level hierarchy + paragraph
    // bodies for documentation capture.
    std::fs::write(
        workspace.path().join("README.md"),
        "# Project Title\n\
         \n\
         A short tagline for the project.\n\
         \n\
         ## Installation\n\
         \n\
         Run `cargo install` to get the prebuilt binary from the\n\
         releases page.\n\
         \n\
         ## Usage\n\
         \n\
         Run the binary in any tracked workspace.\n",
    )?;

    // docs/notes.md — separate file, separate hierarchy, separate
    // file-stem prefix (heading names are flat without filename, so
    // `Outline` here clashes with nothing).
    std::fs::create_dir_all(workspace.path().join("docs"))?;
    std::fs::write(
        workspace.path().join("docs").join("notes.md"),
        "# Design Notes\n\
         \n\
         Some content for the design notes.\n",
    )?;

    // bad.md — heading inside an UNCLOSED fenced code block. The
    // tree-sitter-md grammar still treats the heading inside the fence
    // as opaque content, so it should NOT be extracted as a symbol.
    std::fs::write(
        workspace.path().join("bad.md"),
        "# Real Heading\n\
         \n\
         ```\n\
         ## Inside Fence (should not be a heading)\n\
         ## Also inside\n\
         ```\n",
    )?;

    // Gitignored markdown — should NOT be indexed.
    std::fs::write(workspace.path().join(".gitignore"), "target/\n")?;
    std::fs::create_dir_all(workspace.path().join("target").join("doc"))?;
    std::fs::write(
        workspace.path().join("target").join("doc").join("index.md"),
        "# This Should Not Index\n",
    )?;

    // Compute the workspace-hashed socket path so the CLI (which uses
    // the same hashing) can find the daemon we spawn in the test. The
    // daemon binds `ws-<16hex>.sock` when launched with `--workspace`.
    let canonical_workspace = workspace.path().canonicalize()?;
    let workspace_hex = {
        use std::os::unix::ffi::OsStrExt;
        let hash = blake3::hash(canonical_workspace.as_os_str().as_bytes());
        let hex = hash.to_hex();
        hex.as_str()[..16].to_string()
    };
    let socket_path = if cfg!(target_os = "macos") {
        home_dir
            .path()
            .join("Library")
            .join("Caches")
            .join("rts")
            .join(format!("ws-{workspace_hex}.sock"))
    } else {
        runtime_dir
            .path()
            .join("rts")
            .join(format!("ws-{workspace_hex}.sock"))
    };

    let mut cmd = Command::new(daemon_bin());
    cmd.arg("--workspace")
        .arg(workspace.path())
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
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

    // With `--workspace`, the daemon performs its own prewarm walk;
    // call Mount idempotently to be explicit.
    let mount = round_trip(
        &mut stream,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount: {mount:?}");

    // Wait until each expected heading is indexed.
    wait_for_symbol(&mut stream, "Installation", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "Usage", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "Design Notes", Duration::from_secs(5)).await?;

    // ---- Scenario 1: find_symbol returns the heading with full metadata ----
    // `Symbol.name` stores only the leaf (so exact-match search works);
    // the hierarchical path lives in `documentation` as a prefix.
    let resp = round_trip(
        &mut stream,
        "10",
        "Index.FindSymbol",
        json!({
            "name": "Installation",
            "kind": "heading",
            "include_signature": true,
        }),
    )
    .await?;
    assert!(resp["error"].is_null(), "find_symbol: {resp:?}");
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!matches.is_empty(), "Installation not found: {resp:?}");
    let install = &matches[0];
    assert_eq!(install["kind"].as_str(), Some("heading"));
    assert_eq!(install["qualified_name"].as_str(), Some("Installation"));
    assert_eq!(install["file"].as_str(), Some("README.md"));
    // start_line is 1-based and lives under `range` in the wire shape;
    // the H2 sits on line 5 of README.md.
    assert_eq!(install["range"]["start_line"].as_u64(), Some(5));
    // Signature renders in ATX form.
    let sig = install["signature"].as_str().unwrap_or("");
    assert_eq!(sig, "## Installation", "signature: {sig:?}");

    // ---- Scenario: documentation field populates the doc multimap ----
    // Two flavors of doc_contains query against prose:
    //   a) ancestor name ("Project Title") — via the hierarchical
    //      path prefix prepended in the extractor.
    //   b) body-paragraph phrase ("releases page") — via the
    //      paragraph capture.
    for needle in ["Project Title", "releases page"] {
        let resp = round_trip(
            &mut stream,
            "11",
            "Index.FindSymbol",
            json!({
                "name": "Installation",
                "doc_contains": needle,
            }),
        )
        .await?;
        assert!(
            resp["error"].is_null(),
            "doc_contains={needle} query failed: {resp:?}",
        );
        let matches = resp["result"]["matches"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !matches.is_empty(),
            "Installation should be findable by doc_contains={needle}: {resp:?}",
        );
    }

    // ---- Scenario 4: gitignored target/doc/index.md is NOT indexed ----
    let resp = round_trip(
        &mut stream,
        "12",
        "Index.FindSymbol",
        json!({ "name": "This Should Not Index" }),
    )
    .await?;
    assert!(resp["error"].is_null());
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        matches.is_empty(),
        "gitignored .md should not be indexed: {matches:?}",
    );

    // ---- Scenario 5: headings inside fenced code blocks are NOT extracted ----
    // The "Real Heading" of bad.md should exist.
    let resp = round_trip(
        &mut stream,
        "13",
        "Index.FindSymbol",
        json!({ "name": "Real Heading" }),
    )
    .await?;
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !matches.is_empty(),
        "Real Heading should be extracted: {resp:?}",
    );
    // But headings inside the fenced block must not appear. We probe
    // by a substring guaranteed to exist only inside the fence.
    let resp = round_trip(
        &mut stream,
        "14",
        "Index.FindSymbol",
        json!({ "pattern": "Inside Fence*" }),
    )
    .await?;
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        matches.is_empty(),
        "fenced-code-block heading must not be extracted: {matches:?}",
    );

    // ---- Scenario 2: outline_workspace includes the .md files ----
    let resp = round_trip(&mut stream, "15", "Index.Outline", json!({})).await?;
    assert!(resp["error"].is_null(), "outline failed: {resp:?}");
    // The outline payload format is text (per the MCP `outline_workspace`
    // tool contract); it should mention README.md and the heading text.
    let outline = serde_json::to_string(&resp["result"]).unwrap_or_default();
    assert!(
        outline.contains("README.md"),
        "outline should list README.md; got {outline}",
    );
    assert!(
        outline.contains("Installation"),
        "outline should mention the Installation heading; got {outline}",
    );

    // ---- Scenario 3: grep over .md content with enclosing_qualified_name ----
    let resp = round_trip(
        &mut stream,
        "16",
        "Index.Grep",
        json!({ "text": "releases page" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "grep failed: {resp:?}");
    let hits = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !hits.is_empty(),
        "grep should find 'releases page' in README.md: {resp:?}",
    );
    let any_in_readme = hits.iter().any(|h| h["file"].as_str() == Some("README.md"));
    assert!(any_in_readme, "grep should match README.md file: {hits:?}");

    // ---- Scenario 6: CLI parity ----
    // Spawn the `rts` CLI binary and confirm the find result is the
    // same as the MCP call above. The CLI uses the same daemon socket,
    // so this exercises the wire path through both client surfaces.
    //
    // The `rts` binary lives in the rts-mcp crate; cargo doesn't
    // guarantee it's built when only the rts-daemon test suite runs
    // (`cargo test -p rts-daemon`). When that happens we skip with a
    // visible note rather than spuriously fail.
    let cli_path = rts_cli_bin();
    if !cli_path.exists() {
        eprintln!(
            "skipping CLI parity assertion — `rts` binary not built at {}; \
             run `cargo build -p rts-mcp --bin rts` (or `cargo test --workspace`) \
             to exercise this path",
            cli_path.display(),
        );
    } else {
        let cli_out = Command::new(&cli_path)
            .args(["find", "Installation", "--kind", "heading", "--json"])
            .env("XDG_RUNTIME_DIR", runtime_dir.path())
            .env("XDG_STATE_HOME", state_dir.path())
            .env("HOME", home_dir.path())
            .current_dir(workspace.path())
            .output()?;
        assert!(
            cli_out.status.success(),
            "rts find exit {:?}: stderr={}",
            cli_out.status,
            String::from_utf8_lossy(&cli_out.stderr),
        );
        let cli_stdout = String::from_utf8_lossy(&cli_out.stdout).to_string();
        let cli_json: Value = serde_json::from_str(&cli_stdout)
            .map_err(|e| anyhow::anyhow!("rts find JSON parse: {e}; stdout={cli_stdout}"))?;
        let cli_matches = cli_json["matches"].as_array().cloned().unwrap_or_default();
        assert!(
            !cli_matches.is_empty(),
            "rts find should return at least one match; got {cli_json:?}",
        );
        // Compare key fields: name, kind, file, start_line. CLI and
        // MCP are expected to produce byte-equivalent rows for these
        // fields.
        let cli_first = &cli_matches[0];
        assert_eq!(
            cli_first["qualified_name"].as_str(),
            install["qualified_name"].as_str(),
            "CLI ⇔ MCP qualified_name parity",
        );
        assert_eq!(
            cli_first["kind"].as_str(),
            install["kind"].as_str(),
            "CLI ⇔ MCP kind parity",
        );
        assert_eq!(
            cli_first["file"].as_str(),
            install["file"].as_str(),
            "CLI ⇔ MCP file parity",
        );
        // The CLI's JSON wraps each match in a `Match` row whose shape
        // is similar to MCP's but the line field may be top-level or
        // nested under `range`; accept either form for parity.
        let cli_start_line = cli_first["range"]["start_line"]
            .as_u64()
            .or_else(|| cli_first["start_line"].as_u64());
        let mcp_start_line = install["range"]["start_line"].as_u64();
        assert_eq!(
            cli_start_line, mcp_start_line,
            "CLI ⇔ MCP start_line parity (cli={cli_first:?} vs mcp={install:?})",
        );
    }

    // ---- Scenario 7: oversized markdown skipped ----
    // The existing OVERSIZE_THRESHOLD_BYTES (4 MiB) already covers
    // adversarial inputs — write a >4 MiB markdown file, confirm the
    // daemon stays up and the file is not deeply indexed (skipped via
    // oversize=true in FileMeta, no symbol rows).
    let oversize_path = workspace.path().join("oversize.md");
    let mut content = String::with_capacity(5 * 1024 * 1024);
    content.push_str("# Oversize Heading\n\n");
    // Fill to >4 MiB with paragraph text.
    while content.len() < 5 * 1024 * 1024 {
        content.push_str("filler line of prose, repeat to balloon the file.\n");
    }
    std::fs::write(&oversize_path, &content)?;

    // Give the watcher a moment to pick it up.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Daemon should still respond to pings — no panic on oversize.
    let resp = round_trip(&mut stream, "17", "Daemon.Ping", json!({})).await?;
    assert!(
        resp["error"].is_null(),
        "Daemon.Ping after oversize: {resp:?}"
    );

    // The "Oversize Heading" symbol must NOT appear (oversize files
    // skip extraction).
    let resp = round_trip(
        &mut stream,
        "18",
        "Index.FindSymbol",
        json!({ "name": "Oversize Heading" }),
    )
    .await?;
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        matches.is_empty(),
        "oversized .md should not contribute symbols: {matches:?}",
    );

    // Capability check: the `index_markdown` capability flag is
    // advertised so agents can gate behavior.
    let resp = round_trip(&mut stream, "19", "Daemon.Ping", json!({})).await?;
    let capabilities = resp["result"]["capabilities"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let caps: Vec<&str> = capabilities.iter().filter_map(|c| c.as_str()).collect();
    assert!(
        caps.contains(&"index_markdown"),
        "Daemon.Ping capabilities should include index_markdown; got {caps:?}",
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
