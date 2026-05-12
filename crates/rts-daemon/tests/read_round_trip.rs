//! End-to-end test for `Index.ReadRange` and `Index.ReadSymbol`.
//!
//! Mounts a workspace containing a small `.rs` file, polls
//! `Index.FindSymbol` until the writer commits, then exercises the read
//! handlers' positive *and* negative paths.

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

/// Poll `Index.FindSymbol` until the writer commits, or the deadline trips.
async fn wait_for_symbol(
    stream: &mut UnixStream,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
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
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "symbol `{name}` never appeared in the index within {:?}",
                timeout
            );
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

const SOURCE: &str = "\
//! demo file
pub fn alpha() {
    println!(\"hello\");
}

pub struct Beta {
    pub value: u32,
}
";

#[tokio::test(flavor = "current_thread")]
async fn read_handlers_round_trip() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    std::fs::write(workspace.path().join("src.rs"), SOURCE)?;
    // A file with a disallowed extension, to exercise §13.4.
    std::fs::write(workspace.path().join("data.bin"), b"\x00\x01\x02\x03")?;
    // Python + TypeScript files so the signature dispatch in
    // `methods::index::render_signature_for_path` can be exercised
    // end-to-end alongside the Rust one.
    std::fs::write(
        workspace.path().join("py_demo.py"),
        "def py_target(name: str) -> int:\n    return len(name)\n",
    )?;
    std::fs::write(
        workspace.path().join("ts_demo.ts"),
        "export function tsTarget(a: number, b: number): number { return a + b; }\n",
    )?;
    // Go + Java + C + C++ + PHP + Ruby + Swift — all 7 non-Rust/Python/TS
    // languages now reach Index.ReadSymbol end-to-end after the
    // analyzer-layer fix in alpha.17. Each gets a one-symbol seed file
    // and a `shape: "signature"` assertion below.
    std::fs::write(
        workspace.path().join("go_demo.go"),
        "package demo\n\nfunc GoTarget(name string) (int, error) {\n    return len(name), nil\n}\n",
    )?;
    std::fs::write(
        workspace.path().join("JavaDemo.java"),
        "package demo;\n\npublic class JavaTarget {\n    public int compute(int x) { return x + 1; }\n}\n",
    )?;
    std::fs::write(
        workspace.path().join("c_demo.c"),
        "int c_target(int a, int b) { return a + b; }\n",
    )?;
    std::fs::write(
        workspace.path().join("cpp_demo.cpp"),
        "int cpp_target(int a, int b) { return a + b; }\n",
    )?;
    std::fs::write(
        workspace.path().join("php_demo.php"),
        "<?php\nfunction phpTarget($a, $b) { return $a + $b; }\n",
    )?;
    std::fs::write(
        workspace.path().join("ruby_demo.rb"),
        "def ruby_target(name)\n  name.length\nend\n",
    )?;
    std::fs::write(
        workspace.path().join("swift_demo.swift"),
        "func swiftTarget(_ a: Int, _ b: Int) -> Int { return a + b }\n",
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
    assert!(mount["error"].is_null(), "mount should succeed: {mount:?}");

    // Wait for `alpha` to land in the index — the writer is asynchronous.
    wait_for_symbol(&mut stream, "alpha", Duration::from_secs(5)).await?;

    // ---- Index.ReadRange ----
    // Line 2 of SOURCE is `pub fn alpha() {`.
    let rng = round_trip(
        &mut stream,
        "10",
        "Index.ReadRange",
        json!({ "file": "src.rs", "start_line": 2, "end_line": 2 }),
    )
    .await?;
    assert!(rng["error"].is_null(), "ReadRange should succeed: {rng:?}");
    assert_eq!(rng["result"]["file"], "src.rs");
    assert_eq!(rng["result"]["shape"], "body");
    assert_eq!(rng["result"]["range"]["start_line"], 2);
    assert_eq!(rng["result"]["range"]["end_line"], 2);
    assert!(
        rng["result"]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("pub fn alpha"),
        "expected line 2 to contain `pub fn alpha`; got {rng:?}"
    );
    assert_eq!(rng["result"]["token_counter"], "bytes_div_3");
    let cv = rng["result"]["content_version"]
        .as_str()
        .expect("content_version");
    assert!(cv.contains('@') && cv.contains('+'), "got {cv}");

    // ---- Index.ReadRange — negative cases ----
    // 1) Past EOF → RANGE_OUT_OF_BOUNDS.
    let oob = round_trip(
        &mut stream,
        "11",
        "Index.ReadRange",
        json!({ "file": "src.rs", "start_line": 9999, "end_line": 9999 }),
    )
    .await?;
    assert_eq!(oob["error"]["code"], "RANGE_OUT_OF_BOUNDS", "got {oob:?}");

    // 2) Outside workspace via absolute path → OUT_OF_ROOT.
    let out = round_trip(
        &mut stream,
        "12",
        "Index.ReadRange",
        json!({ "file": "/etc/passwd", "start_line": 1, "end_line": 1 }),
    )
    .await?;
    assert_eq!(out["error"]["code"], "OUT_OF_ROOT", "got {out:?}");

    // 3) `..` segment → PATH_TRAVERSAL.
    let trav = round_trip(
        &mut stream,
        "13",
        "Index.ReadRange",
        json!({ "file": "../etc/passwd", "start_line": 1, "end_line": 1 }),
    )
    .await?;
    assert_eq!(trav["error"]["code"], "PATH_TRAVERSAL", "got {trav:?}");

    // 4) Disallowed body extension → OUT_OF_ALLOWED_BODY_EXTENSIONS.
    let ext = round_trip(
        &mut stream,
        "14",
        "Index.ReadRange",
        json!({ "file": "data.bin", "start_line": 1, "end_line": 1 }),
    )
    .await?;
    assert_eq!(
        ext["error"]["code"], "OUT_OF_ALLOWED_BODY_EXTENSIONS",
        "got {ext:?}"
    );

    // 5) token_budget out of range → BUDGET_TOO_SMALL / BUDGET_TOO_LARGE.
    let bsmall = round_trip(
        &mut stream,
        "15",
        "Index.ReadRange",
        json!({ "file": "src.rs", "start_line": 1, "end_line": 1, "token_budget": 1 }),
    )
    .await?;
    assert_eq!(
        bsmall["error"]["code"], "BUDGET_TOO_SMALL",
        "got {bsmall:?}"
    );
    let blarge = round_trip(
        &mut stream,
        "16",
        "Index.ReadRange",
        json!({ "file": "src.rs", "start_line": 1, "end_line": 1, "token_budget": 999_999 }),
    )
    .await?;
    assert_eq!(
        blarge["error"]["code"], "BUDGET_TOO_LARGE",
        "got {blarge:?}"
    );

    // ---- Index.ReadSymbol ----
    let sym = round_trip(
        &mut stream,
        "20",
        "Index.ReadSymbol",
        json!({ "name": "alpha" }),
    )
    .await?;
    assert!(sym["error"].is_null(), "ReadSymbol should succeed: {sym:?}");
    assert_eq!(sym["result"]["qualified_name"], "alpha");
    assert_eq!(sym["result"]["kind"], "fn");
    assert_eq!(sym["result"]["file"], "src.rs");
    assert_eq!(sym["result"]["shape"], "body");
    let text = sym["result"]["text"].as_str().expect("text");
    assert!(text.contains("pub fn alpha"), "got {text:?}");
    assert!(
        text.contains("println!"),
        "body should contain the function body; got {text:?}"
    );

    // ---- Index.ReadSymbol — negative ----
    let unknown = round_trip(
        &mut stream,
        "21",
        "Index.ReadSymbol",
        json!({ "name": "no_such_thing" }),
    )
    .await?;
    assert_eq!(
        unknown["error"]["code"], "SYMBOL_NOT_FOUND",
        "got {unknown:?}"
    );

    // ---- Filter test: kind=struct on `alpha` → SYMBOL_NOT_FOUND ----
    let mismatch = round_trip(
        &mut stream,
        "22",
        "Index.ReadSymbol",
        json!({ "name": "alpha", "kind": "struct" }),
    )
    .await?;
    assert_eq!(
        mismatch["error"]["code"], "SYMBOL_NOT_FOUND",
        "got {mismatch:?}"
    );

    // ---- shape=signature returns the declaration prefix, not the body ----
    let sig_resp = round_trip(
        &mut stream,
        "23",
        "Index.ReadSymbol",
        json!({ "name": "alpha", "shape": "signature" }),
    )
    .await?;
    assert!(
        sig_resp["error"].is_null(),
        "shape=signature should succeed: {sig_resp:?}"
    );
    assert_eq!(sig_resp["result"]["shape"], "signature");
    let sig_field = sig_resp["result"]["signature"]
        .as_str()
        .expect("signature field is a string");
    assert!(
        sig_field.contains("pub fn alpha"),
        "signature should contain `pub fn alpha`; got {sig_field:?}"
    );
    assert!(
        !sig_field.contains("println!"),
        "signature must NOT include the function body; got {sig_field:?}"
    );
    let sig_text = sig_resp["result"]["text"]
        .as_str()
        .expect("text field is a string");
    assert!(
        !sig_text.contains("println!"),
        "shape=signature `text` should be the cheap signature, not the body; got {sig_text:?}"
    );

    // ---- shape=both carries the full body in `text` AND signature ----
    let both_resp = round_trip(
        &mut stream,
        "24",
        "Index.ReadSymbol",
        json!({ "name": "alpha", "shape": "both" }),
    )
    .await?;
    assert!(
        both_resp["error"].is_null(),
        "shape=both should succeed: {both_resp:?}"
    );
    assert_eq!(both_resp["result"]["shape"], "both");
    let both_sig = both_resp["result"]["signature"]
        .as_str()
        .expect("signature field is a string under shape=both");
    assert!(
        both_sig.contains("pub fn alpha"),
        "got signature={both_sig:?}"
    );
    let both_text = both_resp["result"]["text"]
        .as_str()
        .expect("text field is a string under shape=both");
    assert!(
        both_text.contains("println!"),
        "shape=both should keep the body in `text`; got {both_text:?}"
    );

    // ---- struct signature strips fields ----
    let beta = round_trip(
        &mut stream,
        "25",
        "Index.ReadSymbol",
        json!({ "name": "Beta", "shape": "signature" }),
    )
    .await?;
    assert!(
        beta["error"].is_null(),
        "Beta signature should succeed: {beta:?}"
    );
    let beta_sig = beta["result"]["signature"]
        .as_str()
        .expect("signature field is a string");
    assert!(beta_sig.contains("pub struct Beta"), "got {beta_sig:?}");
    assert!(
        !beta_sig.contains("pub value: u32"),
        "struct signature must drop the field block; got {beta_sig:?}"
    );

    // ---- Per-language dispatch: Python ----
    // Wait for the Python symbol to land in the index (the writer is
    // asynchronous; py_demo.py is parsed alongside src.rs).
    wait_for_symbol(&mut stream, "py_target", Duration::from_secs(5)).await?;
    let py_sig = round_trip(
        &mut stream,
        "30",
        "Index.ReadSymbol",
        json!({ "name": "py_target", "shape": "signature" }),
    )
    .await?;
    assert!(
        py_sig["error"].is_null(),
        "py_target signature should succeed: {py_sig:?}"
    );
    let py_text = py_sig["result"]["signature"]
        .as_str()
        .expect("signature field for python");
    assert!(
        py_text.starts_with("def py_target(name: str) -> int:"),
        "python signature shape wrong; got {py_text:?}"
    );
    assert!(
        !py_text.contains("return len(name)"),
        "python signature must strip body; got {py_text:?}"
    );

    // ---- Per-language dispatch: TypeScript ----
    wait_for_symbol(&mut stream, "tsTarget", Duration::from_secs(5)).await?;
    let ts_sig = round_trip(
        &mut stream,
        "31",
        "Index.ReadSymbol",
        json!({ "name": "tsTarget", "shape": "signature" }),
    )
    .await?;
    assert!(
        ts_sig["error"].is_null(),
        "tsTarget signature should succeed: {ts_sig:?}"
    );
    let ts_text = ts_sig["result"]["signature"]
        .as_str()
        .expect("signature field for typescript");
    assert!(
        ts_text.contains("function tsTarget(a: number, b: number): number"),
        "typescript signature shape wrong; got {ts_text:?}"
    );
    assert!(
        !ts_text.contains("return a + b"),
        "typescript signature must strip body; got {ts_text:?}"
    );

    // Per-language dispatch — all 7 newly-end-to-end languages route
    // correctly to their signature renderer + the result is body-free.
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "32",
            "GoTarget",
            "func GoTarget(name string) (int, error)",
            "return len",
        ),
        ("33", "JavaTarget", "public class JavaTarget", "compute"),
        (
            "34",
            "c_target",
            "int c_target(int a, int b)",
            "return a + b",
        ),
        (
            "35",
            "cpp_target",
            "int cpp_target(int a, int b)",
            "return a + b",
        ),
        (
            "36",
            "phpTarget",
            "function phpTarget($a, $b)",
            "return $a + $b",
        ),
        ("37", "ruby_target", "def ruby_target(name)", "name.length"),
        (
            "38",
            "swiftTarget",
            "func swiftTarget(_ a: Int, _ b: Int) -> Int",
            "return a + b",
        ),
    ];
    for (id, symbol, expected_substring, forbidden_substring) in cases {
        wait_for_symbol(&mut stream, symbol, Duration::from_secs(5)).await?;
        let resp = round_trip(
            &mut stream,
            id,
            "Index.ReadSymbol",
            json!({ "name": symbol, "shape": "signature" }),
        )
        .await?;
        assert!(
            resp["error"].is_null(),
            "{symbol} signature should succeed: {resp:?}"
        );
        let sig = resp["result"]["signature"]
            .as_str()
            .unwrap_or_else(|| panic!("signature field for {symbol}; got {resp:?}"));
        assert!(
            sig.contains(expected_substring),
            "{symbol} signature wrong; expected `{expected_substring}` in {sig:?}"
        );
        assert!(
            !sig.contains(forbidden_substring),
            "{symbol} signature must strip body; expected `{forbidden_substring}` to be absent from {sig:?}"
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
