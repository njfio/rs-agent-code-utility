//! End-to-end test for `Index.Grep` — literal-substring search across
//! indexed file bytes. Closes the v0.5.4 dogfood gap where the daemon
//! couldn't help find error messages, version strings, log output, or
//! any non-symbol text content.

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

/// Poll Index.FindSymbol until the writer has caught up. Used here to
/// confirm the workspace mount has settled before grep queries fire.
async fn poll_for_match(
    stream: &mut UnixStream,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<Value> {
    let deadline = Instant::now() + timeout;
    let mut next_id: u64 = 100;
    loop {
        next_id += 1;
        let resp = round_trip(
            stream,
            &next_id.to_string(),
            "Index.FindSymbol",
            json!({ "name": name }),
        )
        .await?;
        let matches = resp["result"]["matches"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if !matches.is_empty() {
            return Ok(resp);
        }
        if Instant::now() >= deadline {
            return Ok(resp);
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn grep_finds_string_literals_across_workspace() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Three files with different string-literal patterns. The
    // motivating dogfood example: find_symbol can't help here
    // because `timeout reading MCP response` isn't a symbol name —
    // it's a runtime string literal inside an `anyhow!()` call.
    std::fs::write(
        workspace.path().join("a.rs"),
        "pub fn a() {\n    panic!(\"timeout reading MCP response\");\n}\n",
    )?;
    std::fs::write(
        workspace.path().join("b.rs"),
        "// Comment about TIMEOUT reading the bus.\npub fn b() {}\n",
    )?;
    std::fs::write(
        workspace.path().join("c.rs"),
        "pub fn c() { println!(\"other content\"); }\n",
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
    // Wait for the writer to commit at least one symbol so we know
    // the workspace is indexed.
    let _ = poll_for_match(&mut stream, "a", Duration::from_secs(5)).await?;

    // Case A: exact phrase only in one file.
    let exact = round_trip(
        &mut stream,
        "10",
        "Index.Grep",
        json!({ "text": "timeout reading MCP response" }),
    )
    .await?;
    let matches_a = exact["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        matches_a.len(),
        1,
        "exact phrase should match only a.rs: {exact:?}"
    );
    assert!(
        matches_a[0]["file"]
            .as_str()
            .map(|s| s.ends_with("a.rs"))
            .unwrap_or(false),
        "match file should be a.rs: {exact:?}"
    );
    let line_text = matches_a[0]["line_text"].as_str().unwrap_or("");
    assert!(
        line_text.contains("timeout reading MCP response"),
        "line_text should contain the matched literal: {line_text:?}"
    );
    let start_line = matches_a[0]["range"]["start_line"].as_u64();
    assert_eq!(start_line, Some(2), "match should be on line 2");

    // Case B: case-insensitive (default). "timeout" lowercase in
    // a.rs, "TIMEOUT" uppercase in b.rs. Default should match both.
    let ci = round_trip(
        &mut stream,
        "11",
        "Index.Grep",
        json!({ "text": "timeout" }),
    )
    .await?;
    let matches_b = ci["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        matches_b.len() >= 2,
        "case-insensitive default should match both files: {ci:?}"
    );
    let files_b: Vec<&str> = matches_b
        .iter()
        .map(|m| m["file"].as_str().unwrap_or(""))
        .collect();
    assert!(files_b.iter().any(|f| f.ends_with("a.rs")));
    assert!(files_b.iter().any(|f| f.ends_with("b.rs")));

    // Case C: case-sensitive (opt-in). Only the lowercase
    // "timeout" in a.rs should match.
    let cs = round_trip(
        &mut stream,
        "12",
        "Index.Grep",
        json!({ "text": "timeout", "case_insensitive": false }),
    )
    .await?;
    let matches_c = cs["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        matches_c.iter().all(|m| {
            m["file"]
                .as_str()
                .map(|f| f.ends_with("a.rs"))
                .unwrap_or(false)
        }),
        "case-sensitive should match only a.rs: {cs:?}"
    );

    // Case D: no matches → empty list, no error.
    let none = round_trip(
        &mut stream,
        "13",
        "Index.Grep",
        json!({ "text": "no_such_string_anywhere" }),
    )
    .await?;
    assert!(
        none["result"]["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "no-match query should yield empty matches: {none:?}"
    );
    assert!(
        none["error"].is_null(),
        "no-match must NOT be an error: {none:?}"
    );

    // Case E: response carries files_scanned + files_with_matches.
    let scanned = none["result"]["files_scanned"].as_u64().unwrap_or(0);
    assert!(
        scanned >= 3,
        "files_scanned should report all indexed files: {none:?}"
    );
    let with_matches = none["result"]["files_with_matches"].as_u64();
    assert_eq!(
        with_matches,
        Some(0),
        "no-match query should report 0 files_with_matches: {none:?}"
    );

    // Case F: empty `text` → INVALID_PARAMS.
    let empty = round_trip(&mut stream, "14", "Index.Grep", json!({ "text": "" })).await?;
    assert_eq!(
        empty["error"]["code"], "INVALID_PARAMS",
        "empty text must error with INVALID_PARAMS: {empty:?}"
    );

    // Case G (v0.5.5): regex mode. `\btimeout\b` should match the
    // literal `timeout` (a.rs) and `TIMEOUT` (b.rs) under default
    // case-insensitivity, but not the inside of `times_out` if it
    // existed. Here we just verify the regex compiles and matches.
    let regex_default = round_trip(
        &mut stream,
        "20",
        "Index.Grep",
        json!({ "text": "\\btimeout\\b", "regex": true }),
    )
    .await?;
    let r_matches = regex_default["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        r_matches.len() >= 2,
        "regex \\btimeout\\b should hit both a.rs + b.rs under default case-insensitivity: {regex_default:?}"
    );

    // Case H (v0.5.5): regex mode with explicit case-sensitive.
    // Only the lowercase `timeout` in a.rs should hit.
    let regex_cs = round_trip(
        &mut stream,
        "21",
        "Index.Grep",
        json!({ "text": "\\btimeout\\b", "regex": true, "case_insensitive": false }),
    )
    .await?;
    let h_matches = regex_cs["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        h_matches.iter().all(|m| {
            m["file"]
                .as_str()
                .map(|f| f.ends_with("a.rs"))
                .unwrap_or(false)
        }),
        "case-sensitive regex must match only a.rs: {regex_cs:?}"
    );

    // Case I (v0.5.5 → updated): `regex: true` is a no-op alias.
    // An invalid regex pattern with `regex: true` must fall back to
    // literal search — IDENTICALLY to the same pattern without the
    // flag. Neither call should error; both should report
    // `matched == "literal"`. "[unclosed" does not appear in the test
    // workspace, so both must return an empty matches array.
    let bad_regex_with_flag = round_trip(
        &mut stream,
        "22",
        "Index.Grep",
        json!({ "text": "[unclosed", "regex": true }),
    )
    .await?;
    assert!(
        bad_regex_with_flag["error"].is_null(),
        "regex:true + bad pattern must NOT error: {bad_regex_with_flag:?}"
    );
    assert_eq!(
        bad_regex_with_flag["result"]["matched"].as_str(),
        Some("literal"),
        "regex:true + bad pattern must fall back to literal: {bad_regex_with_flag:?}"
    );
    assert_eq!(
        bad_regex_with_flag["result"]["matches"]
            .as_array()
            .map(|v| v.len()),
        Some(0),
        "literal '[unclosed' should not appear in test workspace: {bad_regex_with_flag:?}"
    );

    // Equivalence: same pattern without the flag must produce the same
    // matched kind and same (empty) result.
    let bad_regex_no_flag = round_trip(
        &mut stream,
        "22b",
        "Index.Grep",
        json!({ "text": "[unclosed" }),
    )
    .await?;
    assert!(
        bad_regex_no_flag["error"].is_null(),
        "bad pattern without flag must NOT error: {bad_regex_no_flag:?}"
    );
    assert_eq!(
        bad_regex_no_flag["result"]["matched"].as_str(),
        Some("literal"),
        "bad pattern without flag must also fall back to literal: {bad_regex_no_flag:?}"
    );
    assert_eq!(
        bad_regex_with_flag["result"]["matched"],
        bad_regex_no_flag["result"]["matched"],
        "regex:true and no-flag must produce identical matched kind"
    );
    // Full result equality: the no-op claim is airtight only if the
    // entire result object (matches, files_scanned, files_with_matches,
    // matched) is byte-identical. Both calls run against the same
    // workspace snapshot so the counts must agree.
    assert_eq!(
        bad_regex_with_flag["result"],
        bad_regex_no_flag["result"],
        "regex:true and no-flag must produce identical result objects"
    );

    // Case J (v0.5.5): file_glob scopes the scan. Restrict to a.rs
    // only — the "timeout" search must now miss b.rs.
    let scoped = round_trip(
        &mut stream,
        "23",
        "Index.Grep",
        json!({ "text": "timeout", "file_glob": "a.rs" }),
    )
    .await?;
    let j_matches = scoped["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        j_matches.iter().all(|m| {
            m["file"]
                .as_str()
                .map(|f| f.ends_with("a.rs"))
                .unwrap_or(false)
        }),
        "file_glob=a.rs should restrict matches to a.rs: {scoped:?}"
    );
    // files_scanned must reflect the glob — only one file made it
    // past the filter, so the count should be 1 (b.rs and c.rs were
    // skipped by the path matcher before any I/O).
    let scoped_scanned = scoped["result"]["files_scanned"].as_u64();
    assert_eq!(
        scoped_scanned,
        Some(1),
        "file_glob filter must skip non-matching files BEFORE counting them as scanned: {scoped:?}"
    );

    // Case K (v0.5.5): file_glob with wildcard. `*.rs` should match
    // all three test files; `*.toml` should match none.
    let glob_rs = round_trip(
        &mut stream,
        "24",
        "Index.Grep",
        json!({ "text": "pub fn", "file_glob": "*.rs" }),
    )
    .await?;
    let k_scanned = glob_rs["result"]["files_scanned"].as_u64().unwrap_or(0);
    assert!(
        k_scanned >= 3,
        "file_glob=*.rs should scan all three .rs files: {glob_rs:?}"
    );
    let glob_toml = round_trip(
        &mut stream,
        "25",
        "Index.Grep",
        json!({ "text": "pub fn", "file_glob": "*.toml" }),
    )
    .await?;
    let toml_scanned = glob_toml["result"]["files_scanned"].as_u64();
    assert_eq!(
        toml_scanned,
        Some(0),
        "file_glob=*.toml should skip all .rs files: {glob_toml:?}"
    );

    // Case L (v0.5.5): invalid file_glob → INVALID_PARAMS.
    let bad_glob = round_trip(
        &mut stream,
        "26",
        "Index.Grep",
        json!({ "text": "pub fn", "file_glob": "[unclosed" }),
    )
    .await?;
    assert_eq!(
        bad_glob["error"]["code"], "INVALID_PARAMS",
        "invalid file_glob must error with INVALID_PARAMS: {bad_glob:?}"
    );

    // Case M (v0.5.5): empty file_glob → INVALID_PARAMS (separate
    // diagnostic from a compile failure so agents get a useful hint).
    let empty_glob = round_trip(
        &mut stream,
        "27",
        "Index.Grep",
        json!({ "text": "pub fn", "file_glob": "" }),
    )
    .await?;
    assert_eq!(
        empty_glob["error"]["code"], "INVALID_PARAMS",
        "empty file_glob must error with INVALID_PARAMS: {empty_glob:?}"
    );

    // Case N (v0.5.5): enclosing-symbol resolution. The "timeout
    // reading MCP response" literal is on line 2 of a.rs, inside
    // `pub fn a()` which spans lines 1..=3. The grep response must
    // surface `enclosing_qualified_name` = "a", `enclosing_kind`
    // = "fn", with `enclosing_def_range` covering that span.
    let enclosing = round_trip(
        &mut stream,
        "28",
        "Index.Grep",
        json!({ "text": "timeout reading MCP response" }),
    )
    .await?;
    let enc_matches = enclosing["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        enc_matches.len(),
        1,
        "enclosing case expects exactly one match: {enclosing:?}"
    );
    let m0 = &enc_matches[0];
    assert_eq!(
        m0["enclosing_qualified_name"].as_str(),
        Some("a"),
        "enclosing_qualified_name should be the function name 'a': {m0:?}"
    );
    assert_eq!(
        m0["enclosing_kind"].as_str(),
        Some("fn"),
        "enclosing_kind should be 'fn': {m0:?}"
    );
    let def_range = &m0["enclosing_def_range"];
    assert!(
        def_range.is_object(),
        "enclosing_def_range should be an object when enclosing is resolved: {m0:?}"
    );
    let def_start = def_range["start_line"].as_u64().unwrap_or(0);
    let def_end = def_range["end_line"].as_u64().unwrap_or(0);
    assert!(
        def_start == 1 && def_end >= 2,
        "enclosing_def_range should cover the match line: {def_range:?}"
    );

    // Case O (v0.5.5): file-scope match (no enclosing def). The
    // comment in b.rs sits on line 1, outside any function — the
    // response should surface explicit JSON null for each of the
    // three enclosing_* fields so the agent can distinguish
    // "outside any def" from "missing data".
    let comment_match = round_trip(
        &mut stream,
        "29",
        "Index.Grep",
        json!({ "text": "Comment about TIMEOUT" }),
    )
    .await?;
    let c_matches = comment_match["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        c_matches.len(),
        1,
        "file-scope match expects one hit: {comment_match:?}"
    );
    let c0 = &c_matches[0];
    assert!(
        c0["enclosing_qualified_name"].is_null(),
        "file-scope match must report null enclosing_qualified_name: {c0:?}"
    );
    assert!(
        c0["enclosing_kind"].is_null(),
        "file-scope match must report null enclosing_kind: {c0:?}"
    );
    assert!(
        c0["enclosing_def_range"].is_null(),
        "file-scope match must report null enclosing_def_range: {c0:?}"
    );

    // Case P (v0.5.5): rank_score field is present on every match
    // and is a finite f64. Even on cold-start (PageRank not yet
    // computed for tiny fixture workspaces), the convention is 0.0,
    // not absent. The wire shape must stay consistent so agents
    // can rely on the field always being readable.
    let rank_shape =
        round_trip(&mut stream, "30", "Index.Grep", json!({ "text": "pub fn" })).await?;
    let p_matches = rank_shape["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !p_matches.is_empty(),
        "`pub fn` search must hit at least one indexed file: {rank_shape:?}"
    );
    for m in &p_matches {
        let rs = m["rank_score"].as_f64();
        assert!(
            rs.is_some_and(|v| v.is_finite()),
            "every match must carry a finite rank_score: {m:?}"
        );
    }
    // And matches must be in non-increasing rank_score order — the
    // post-scan sort is what guarantees agents see most-central hits
    // first without re-ranking client-side.
    for window in p_matches.windows(2) {
        let prev = window[0]["rank_score"].as_f64().unwrap_or(0.0);
        let next = window[1]["rank_score"].as_f64().unwrap_or(0.0);
        assert!(
            prev >= next,
            "matches must be sorted by rank_score desc: prev={prev} next={next}, m={window:?}"
        );
    }

    Ok(())
}

// Case Q (Task 2): regex alternation (`astroid|tomlkit`) must match
// both lines; response must carry `matched: "regex"`.
#[tokio::test(flavor = "current_thread")]
async fn grep_regex_alternation_and_matched_field() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Use a .rs file so the daemon indexes it.
    std::fs::write(
        workspace.path().join("deps.rs"),
        "// astroid>=2.0\n// tomlkit>=0.11\n// other\npub fn placeholder() {}\n",
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

    let mut cmd = std::process::Command::new(daemon_bin());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = cmd.spawn()?;
    let _kill = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = tokio::net::UnixStream::connect(&socket_path).await?;

    let mount = round_trip(
        &mut stream,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount: {mount:?}");

    // Poll until the workspace is indexed.
    let _ = poll_for_match(&mut stream, "placeholder", Duration::from_secs(5)).await?;

    let resp = round_trip(
        &mut stream,
        "50",
        "Index.Grep",
        json!({ "text": "astroid|tomlkit" }),
    )
    .await?;

    assert!(
        resp["error"].is_null(),
        "regex alternation must not error: {resp:?}"
    );
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let lines: Vec<&str> = matches
        .iter()
        .map(|m| m["line_text"].as_str().unwrap_or(""))
        .collect();
    assert!(
        lines.iter().any(|l| l.contains("astroid")),
        "must find astroid line: {resp:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("tomlkit")),
        "must find tomlkit line: {resp:?}"
    );
    assert_eq!(
        resp["result"]["matched"].as_str(),
        Some("regex"),
        "matched field must be 'regex': {resp:?}"
    );

    Ok(())
}

// Case R (Task 2): a pattern that is invalid as a regex (`def foo(`)
// must fall back to literal search and return `matched: "literal"`.
#[tokio::test(flavor = "current_thread")]
async fn grep_regex_compile_failure_falls_back_to_literal() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    std::fs::write(
        workspace.path().join("sample.py"),
        "def foo(x, y):\n    return x + y\n",
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

    let mut cmd = std::process::Command::new(daemon_bin());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = cmd.spawn()?;
    let _kill = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = tokio::net::UnixStream::connect(&socket_path).await?;

    let mount = round_trip(
        &mut stream,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount: {mount:?}");

    // Poll until the workspace is indexed (using symbol name "foo").
    let _ = poll_for_match(&mut stream, "foo", Duration::from_secs(5)).await?;

    // `def foo(` is an invalid regex (unclosed paren) — must fall back
    // to literal and find the line.
    let resp = round_trip(
        &mut stream,
        "60",
        "Index.Grep",
        json!({ "text": "def foo(" }),
    )
    .await?;

    assert!(
        resp["error"].is_null(),
        "literal fallback must not error: {resp:?}"
    );
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !matches.is_empty(),
        "literal fallback must find the line containing 'def foo(': {resp:?}"
    );
    assert_eq!(
        resp["result"]["matched"].as_str(),
        Some("literal"),
        "matched field must be 'literal' when fallback fires: {resp:?}"
    );

    Ok(())
}

/// Spawn a daemon, mount `workspace`, and return the connected stream
/// plus the kill guard. Mirrors the inline scaffolding used by the
/// other tests in this file but keeps the Task-4 ranking/budget tests
/// readable. `poll_name` is a symbol the writer is expected to commit
/// so we know indexing has settled before grepping.
async fn spawn_and_mount(
    workspace: &std::path::Path,
    runtime_dir: &tempfile::TempDir,
    state_dir: &tempfile::TempDir,
    home_dir: &tempfile::TempDir,
    poll_name: &str,
) -> anyhow::Result<(UnixStream, std::process::Child)> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

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
    let child = cmd.spawn()?;

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;
    let mount = round_trip(
        &mut stream,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace }),
    )
    .await?;
    anyhow::ensure!(mount["error"].is_null(), "mount failed: {mount:?}");
    let _ = poll_for_match(&mut stream, poll_name, Duration::from_secs(5)).await?;
    Ok((stream, child))
}

/// Task 4: matches are returned in non-increasing `rank_score` order.
/// The workspace gives `hub` a high PageRank (called from many sites)
/// while `lonely` is uncalled (rank ~0). Both function bodies contain
/// the common search term, so the ranked response must surface `hub`'s
/// match before `lonely`'s.
#[tokio::test(flavor = "current_thread")]
async fn matches_are_ranked_by_rank_score_desc() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // `hub` is called by 12 distinct callers => high PageRank.
    // `lonely` is never called => PageRank floor.
    // Both bodies contain the literal "needle_token".
    //
    // CRUCIAL for the pool/budget decoupling: `hub`'s definition is
    // emitted LAST, after 60 low-rank `noise_*` functions that each
    // also contain "needle_token". In scan order hub's match sits well
    // past position 40, so if the handler truncated to the response
    // budget BEFORE ranking, hub's high-rank hit would be dropped and
    // could never surface first. Its appearance at/near the top proves
    // ranking drew from a real candidate pool, not the first-N.
    let mut lib = String::new();
    lib.push_str("pub fn lonely() -> i32 {\n    let needle_token = 2;\n    needle_token\n}\n");
    for i in 0..60 {
        lib.push_str(&format!(
            "pub fn noise_{i}() -> i32 {{\n    let needle_token = {i};\n    needle_token\n}}\n"
        ));
    }
    for i in 0..12 {
        lib.push_str(&format!(
            "pub fn caller_{i}() -> i32 {{\n    hub()\n}}\n"
        ));
    }
    // hub defined last => its body's match is late in scan order.
    lib.push_str("pub fn hub() -> i32 {\n    let needle_token = 1;\n    needle_token\n}\n");
    std::fs::write(workspace.path().join("lib.rs"), lib)?;

    let (mut stream, mut child) =
        spawn_and_mount(workspace.path(), &runtime_dir, &state_dir, &home_dir, "hub").await?;
    let _kill = KillOnDrop(&mut child);

    let resp = round_trip(
        &mut stream,
        "50",
        "Index.Grep",
        json!({ "text": "needle_token" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "grep errored: {resp:?}");
    let matches = resp["result"]["matches"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        matches.len() >= 2,
        "expected at least two needle_token matches: {resp:?}"
    );

    // The rank_score sequence over returned matches is non-increasing.
    for window in matches.windows(2) {
        let prev = window[0]["rank_score"].as_f64().unwrap_or(0.0);
        let next = window[1]["rank_score"].as_f64().unwrap_or(0.0);
        assert!(
            prev >= next,
            "matches must be sorted by rank_score desc: prev={prev} next={next}: {window:?}"
        );
    }

    // `hub`'s match (defined LAST in the file, late in scan order) must
    // appear in the returned set despite the response budget — this is
    // the load-bearing assertion for pool/budget decoupling. If the
    // scan truncated to the budget in scan order before ranking, hub
    // would never make the cut.
    let hub_idx = matches.iter().position(|m| {
        m["enclosing_qualified_name"].as_str() == Some("hub")
    });
    let hub_idx = hub_idx.expect("hub's high-rank match must survive into the ranked response");
    let hub_rank = matches[hub_idx]["rank_score"].as_f64().unwrap_or(0.0);
    assert!(
        hub_rank > 0.0,
        "hub must have a real (>0) PageRank: got {hub_rank}"
    );
    // hub must outrank (and thus be positioned before) any `lonely`
    // match if it is present.
    if let Some(l) = matches
        .iter()
        .position(|m| m["enclosing_qualified_name"].as_str() == Some("lonely"))
    {
        let lonely_rank = matches[l]["rank_score"].as_f64().unwrap_or(0.0);
        assert!(
            hub_rank >= lonely_rank && hub_idx <= l,
            "hub (called 12x) must outrank/precede lonely: hub_rank={hub_rank}@{hub_idx} lonely_rank={lonely_rank}@{l}"
        );
    }

    Ok(())
}

/// Task 4: with `limit` unset, a workspace holding far more than the
/// default budget of matches must return exactly `GREP_DEFAULT_BUDGET`
/// (40), flag `truncated: true`, report `shown == 40`, and a
/// `total_matches` that honestly counts every hit seen (> 40).
#[tokio::test(flavor = "current_thread")]
async fn default_budget_bounds_to_40() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // 200 functions, each body containing the search term TWICE (the
    // `let widget_marker = …` binding and the bare return) => 400
    // matches. This deliberately EXCEEDS the 256 rank pool so the
    // handler must keep counting `total_matches` past the pool (without
    // growing the returned set) — exercising the decoupling of all
    // three budget numbers: returned (40), pool (256), counted (400).
    let mut lib = String::new();
    for i in 0..200 {
        lib.push_str(&format!(
            "pub fn f_{i}() -> i32 {{\n    let widget_marker = {i};\n    widget_marker\n}}\n"
        ));
    }
    std::fs::write(workspace.path().join("lib.rs"), lib)?;

    let (mut stream, mut child) =
        spawn_and_mount(workspace.path(), &runtime_dir, &state_dir, &home_dir, "f_0").await?;
    let _kill = KillOnDrop(&mut child);

    let resp = round_trip(
        &mut stream,
        "60",
        "Index.Grep",
        json!({ "text": "widget_marker" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "grep errored: {resp:?}");
    let result = &resp["result"];
    let matches = result["matches"].as_array().cloned().unwrap_or_default();

    assert_eq!(
        matches.len(),
        40,
        "default budget must cap returned matches at 40: got {}",
        matches.len()
    );
    assert_eq!(
        result["shown"].as_u64(),
        Some(40),
        "`shown` must equal returned length (40): {result}"
    );
    assert_eq!(
        result["truncated"].as_bool(),
        Some(true),
        "`truncated` must be true when more matches exist than shown: {result}"
    );
    let total = result["total_matches"].as_u64().unwrap_or(0);
    assert!(
        total > 40,
        "`total_matches` must honestly count all hits (>40): got {total}: {result}"
    );
    assert_eq!(
        total, 400,
        "`total_matches` must count every match past the pool (2 per fn x 200): got {total}"
    );

    Ok(())
}

/// Task 4 Fix A: a `within_symbol` query whose in-symbol matches ALL
/// fit under the budget must report `truncated == false` and
/// `total_matches == shown`. Pre-fix, `total_matches` was counted over
/// every pattern hit in the file (including the hundreds outside the
/// target symbol), so a COMPLETE within_symbol result still reported a
/// huge `total_matches` and `truncated: true` — telling the agent to
/// narrow a result that is already complete.
#[tokio::test(flavor = "current_thread")]
async fn within_symbol_truncation_is_honest_when_complete() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // One target function `target_fn` with exactly THREE in-symbol hits
    // of `needle_marker`, then 200 OTHER functions each with the same
    // marker (400 out-of-symbol hits). Total file hits (403) far exceed
    // both the budget (40) and the rank pool (256). With
    // `within_symbol: "target_fn"`, only the 3 in-symbol matches
    // survive — well under the budget — so the result is COMPLETE and
    // must report `truncated == false`, `total_matches == shown == 3`.
    let mut lib = String::new();
    lib.push_str(
        "pub fn target_fn() -> i32 {\n    \
         let needle_marker = 1;\n    \
         let _x = needle_marker + 1;\n    \
         needle_marker\n}\n\n",
    );
    for i in 0..200 {
        lib.push_str(&format!(
            "pub fn other_{i}() -> i32 {{\n    let needle_marker = {i};\n    needle_marker\n}}\n"
        ));
    }
    std::fs::write(workspace.path().join("lib.rs"), lib)?;

    let (mut stream, mut child) = spawn_and_mount(
        workspace.path(),
        &runtime_dir,
        &state_dir,
        &home_dir,
        "target_fn",
    )
    .await?;
    let _kill = KillOnDrop(&mut child);

    let resp = round_trip(
        &mut stream,
        "70",
        "Index.Grep",
        json!({ "text": "needle_marker", "within_symbol": "target_fn" }),
    )
    .await?;
    assert!(resp["error"].is_null(), "grep errored: {resp:?}");
    let result = &resp["result"];
    let matches = result["matches"].as_array().cloned().unwrap_or_default();

    assert_eq!(
        matches.len(),
        3,
        "within_symbol should keep exactly the 3 in-symbol matches: {result}"
    );
    assert_eq!(
        result["shown"].as_u64(),
        Some(3),
        "`shown` must equal the surviving in-symbol count (3): {result}"
    );
    assert_eq!(
        result["total_matches"].as_u64(),
        Some(3),
        "`total_matches` must reflect the POST-filter in-symbol count (3), \
         not every pattern hit in the file: {result}"
    );
    assert_eq!(
        result["truncated"].as_bool(),
        Some(false),
        "`truncated` must be false when all in-symbol matches are returned: {result}"
    );

    Ok(())
}
