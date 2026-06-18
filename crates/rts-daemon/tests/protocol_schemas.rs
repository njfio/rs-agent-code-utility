//! Drift-defense for `schemas/v0/` against the daemon's runtime
//! wire shape.
//!
//! Three properties are enforced here. The first two run on every
//! `cargo test` invocation — they're cheap (read JSON, parse JSON,
//! match strings). The third spawns a daemon, mounts a fixture
//! workspace, and round-trips each RPC; it's gated behind
//! `#[ignore]` so the default test path stays under the workspace's
//! existing budget. CI opts back in via
//! `cargo test -p rts-daemon --test protocol_schemas -- --include-ignored`.
//!
//! Why static-file schemas with this drift test (not `schemars`-derive
//! on the typed params/results): smaller blast radius across the daemon
//! crates, and the round-trip check catches the same kind of drift a
//! derive macro would prevent at compile time. If schemas start
//! drifting more often than once a release, the schemars approach is
//! the right migration; until then, static files keep the diff
//! reviewable.
//!
//! See `schemas/v0/README.md` for the schema-versioning convention.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Every method the daemon's dispatcher routes. Source of truth:
/// `crates/rts-daemon/src/methods/mod.rs::dispatch`. New methods that
/// land without a `schemas/v0/methods/<name>.{req,resp}.schema.json`
/// pair fail the `every_method_has_request_and_response_schemas` test.
const PROTOCOL_METHODS: &[&str] = &[
    "Daemon.Ping",
    "Daemon.Stats",
    "Daemon.Telemetry",
    "Daemon.Cancel",
    "Workspace.Mount",
    "Workspace.Status",
    "Workspace.Unmount",
    "Session.Open",
    "Session.Close",
    "Index.FindSymbol",
    "Index.FindCallers",
    "Index.VerifySymbol",
    "Index.VerifySignature",
    "Index.VerifyImport",
    "Index.VerifyClaims",
    "Index.ImpactOf",
    "Index.ReadRange",
    "Index.ReadSymbol",
    "Index.ReadSymbolAt",
    "Index.Outline",
    "Index.Grep",
];

fn schemas_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `crates/rts-daemon/`. The schemas live at
    // the repo root in `schemas/v0/`. Two `..` segments and we're there.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("schemas")
        .join("v0")
}

fn read_schema_file(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Compile a JSON Schema 2020-12 document. Panics with a readable
/// pointer when compilation fails — saves the reader a `grep` round
/// trip if a schema file goes bad.
fn compile_schema(schema_path: &Path) -> jsonschema::Validator {
    let schema = read_schema_file(schema_path);
    jsonschema::draft202012::new(&schema).unwrap_or_else(|e| {
        panic!(
            "{} did not compile as JSON Schema 2020-12: {e}",
            schema_path.display()
        )
    })
}

/// **Property 1.** Every method in the dispatcher has both `.req` and
/// `.resp` schema files. A new method that ships without schema files
/// fails this test, which gives the next agent a clear "you owe two
/// schema files" signal.
#[test]
fn every_method_has_request_and_response_schemas() {
    let root = schemas_root();
    let methods_dir = root.join("methods");
    assert!(
        methods_dir.is_dir(),
        "missing {} — schemas were not committed?",
        methods_dir.display()
    );

    let mut missing = Vec::new();
    for method in PROTOCOL_METHODS {
        for suffix in ["req", "resp"] {
            let file = methods_dir.join(format!("{method}.{suffix}.schema.json"));
            if !file.exists() {
                missing.push(file.display().to_string());
            }
        }
    }
    assert!(
        missing.is_empty(),
        "missing schema files (one .req + .resp per method): {missing:#?}"
    );
}

/// **Property 2.** Every schema file under `schemas/v0/` loads cleanly
/// as a JSON Schema 2020-12 document. Guards against typos that would
/// silently break the contract.
#[test]
fn schemas_parse_as_valid_json_schema_2020_12() {
    let root = schemas_root();

    // Envelope and error first — the shared schemas every method
    // implicitly depends on for the envelope/error shape.
    let envelope = root.join("envelope.schema.json");
    let error = root.join("error.schema.json");
    let _ = compile_schema(&envelope);
    let _ = compile_schema(&error);

    // Then every method schema.
    let methods_dir = root.join("methods");
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&methods_dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", methods_dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|x| x.to_str()) == Some("json")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with(".schema.json"))
                    .unwrap_or(false)
        })
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "no method schemas found");
    for path in &entries {
        let _ = compile_schema(path);
    }
}

// ----------------------------------------------------------------------
// The remaining two tests spawn the real daemon binary, mount a
// fixture workspace, and validate live RPC responses against their
// schema. They're behind `#[ignore]` so the default `cargo test
// --workspace` path stays under the workspace's existing budget; CI
// runs them via `-- --include-ignored`.

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
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_until(b'\n', &mut buf))
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

/// **Property 3.** Spin up a real daemon, mount a fixture workspace,
/// fire every method with valid params, and validate the live response
/// against its `.resp` schema. This is the test that catches
/// schema-vs-code drift.
///
/// Per-method params are picked to exercise the happy path — agents
/// reading the schemas will recognise these as the canonical request
/// shape. Any method whose response shape changes without a matching
/// schema bump fails this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns the daemon binary; opt-in via --include-ignored"]
async fn response_matches_schema_for_each_method() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // Plant a small fixture so Index.* methods have something to
    // chew on. A single `.rs` file with one fn + a comment is enough
    // to exercise FindSymbol / Grep / ReadSymbol / ReadRange / etc.
    let fixture_src = workspace.path().join("src");
    std::fs::create_dir_all(&fixture_src)?;
    std::fs::write(
        fixture_src.join("lib.rs"),
        "/// Compute the answer to life, the universe, and everything.\n\
         pub fn answer() -> u32 {\n    42\n}\n\
         \n\
         /// A second fn so FindCallers has someone to point at.\n\
         pub fn call_answer() -> u32 {\n    answer() + 1\n}\n",
    )?;

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
    let mut child = cmd.spawn()?;
    let _kill_on_drop = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;

    // Pre-compile every response schema once so we don't pay the
    // compile cost per RPC.
    let root = schemas_root();
    let methods_dir = root.join("methods");
    let resp_schema = |method: &str| -> jsonschema::Validator {
        compile_schema(&methods_dir.join(format!("{method}.resp.schema.json")))
    };

    // Mount first so Index.* and Workspace.Status see a workspace.
    let mount = round_trip(
        &mut stream,
        "mnt",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    let mount_validator = resp_schema("Workspace.Mount");
    assert_valid(&mount_validator, "Workspace.Mount", &mount["result"]);

    // Now run every other method.
    let methods: &[(&str, Value)] = &[
        ("Daemon.Ping", json!({})),
        ("Daemon.Stats", json!({})),
        ("Daemon.Telemetry", json!({})),
        ("Workspace.Status", json!({})),
        ("Session.Open", json!({"client_name": "schema-test"})),
        ("Index.FindSymbol", json!({"name": "answer"})),
        ("Index.FindCallers", json!({"name": "answer"})),
        ("Index.VerifySymbol", json!({"name": "answer"})),
        (
            "Index.VerifySignature",
            json!({"name": "answer", "claimed": {"arity": 0, "params": [], "returns": "u32"}}),
        ),
        ("Index.VerifyImport", json!({"path": "answer"})),
        (
            "Index.VerifyClaims",
            json!({"claims": [
                {"type": "symbol", "name": "answer"},
                {"type": "signature", "name": "answer", "claimed": {"arity": 0}},
                {"type": "import", "path": "answer"},
                {"type": "location", "symbol": "answer", "file": "src/lib.rs", "line": 2}
            ]}),
        ),
        ("Index.ImpactOf", json!({"name": "answer"})),
        ("Index.Outline", json!({"token_budget": 4096})),
        ("Index.Grep", json!({"text": "answer"})),
        (
            "Index.ReadRange",
            json!({"file": "src/lib.rs", "start_line": 1, "end_line": 4}),
        ),
        ("Index.ReadSymbol", json!({"name": "answer"})),
        (
            "Index.ReadSymbolAt",
            json!({"file": "src/lib.rs", "line": 2}),
        ),
    ];

    let mut session_id: Option<String> = None;
    for (i, (method, params)) in methods.iter().enumerate() {
        let id = format!("{}", 10 + i);
        let resp = round_trip(&mut stream, &id, method, params.clone()).await?;

        // We expect every probe to succeed — pick easy params. A
        // non-null `error` here means the test params drifted out of
        // sync with the daemon, NOT that the schema is wrong; surface
        // both so the failure mode is obvious.
        if !resp["error"].is_null() {
            panic!("{method} returned error (schema test sends valid params): {resp:?}");
        }

        let validator = resp_schema(method);
        assert_valid(&validator, method, &resp["result"]);

        if *method == "Session.Open" {
            session_id = resp["result"]["session_id"].as_str().map(|s| s.to_string());
        }
    }

    // Session.Close needs the id from Session.Open. Validate
    // separately to keep the loop's param list clean.
    if let Some(sid) = session_id {
        let close = round_trip(
            &mut stream,
            "close",
            "Session.Close",
            json!({ "session_id": sid }),
        )
        .await?;
        let validator = resp_schema("Session.Close");
        assert_valid(&validator, "Session.Close", &close["result"]);
    }

    // Workspace.Unmount + Daemon.Cancel — Unmount tears down the watcher,
    // and Cancel against an unregistered id returns `{ cancelled: false }`.
    let unmount = round_trip(&mut stream, "um", "Workspace.Unmount", json!({})).await?;
    let validator = resp_schema("Workspace.Unmount");
    assert_valid(&validator, "Workspace.Unmount", &unmount["result"]);

    let cancel = round_trip(
        &mut stream,
        "ca",
        "Daemon.Cancel",
        json!({ "cancel_id": "nope" }),
    )
    .await?;
    let validator = resp_schema("Daemon.Cancel");
    assert_valid(&validator, "Daemon.Cancel", &cancel["result"]);

    Ok(())
}

/// **Property 6 (capabilities).** `Daemon.Ping` advertises every
/// capability string the protocol expects. The `capabilities` array is
/// additive (new strings appear, old ones never vanish without a
/// protocol-major bump), so the live response must be a *superset* of
/// this expected set. A capability dropped from `DAEMON_CAPABILITIES`
/// fails this test, which is the drift signal for the wire contract.
///
/// When a feature adds a capability, add its string here too. Most
/// recent: `parent_scope` (v0.7 — overload disambiguation via the
/// nearest enclosing container; `find_symbol`/`read_symbol` render
/// `parent::name` and accept a `parent` filter).
const EXPECTED_CAPABILITIES: &[&str] = &[
    "find_symbol",
    "read_symbol",
    "read_symbol_at",
    "find_callers",
    "impact_of",
    "index_grep",
    "index_grep_v2",
    "index_markdown",
    "request_deadlines",
    "parent_scope",
    "verify_symbol",
    "verify_signature",
    "verify_import",
    "verify_claims",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns the daemon binary; opt-in via --include-ignored"]
async fn ping_advertises_expected_capabilities() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;

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
    let mut child = cmd.spawn()?;
    let _kill_on_drop = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;

    let ping = round_trip(&mut stream, "1", "Daemon.Ping", json!({})).await?;
    assert!(ping["error"].is_null(), "ping failed: {ping:?}");

    // Validate against the shared Daemon.Ping schema first.
    let root = schemas_root();
    let validator = compile_schema(&root.join("methods").join("Daemon.Ping.resp.schema.json"));
    assert_valid(&validator, "Daemon.Ping", &ping["result"]);

    let caps: Vec<String> = ping["result"]["capabilities"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|c| c.as_str().map(|s| s.to_string()))
        .collect();
    let missing: Vec<&str> = EXPECTED_CAPABILITIES
        .iter()
        .copied()
        .filter(|want| !caps.iter().any(|have| have == want))
        .collect();
    assert!(
        missing.is_empty(),
        "Daemon.Ping is missing expected capabilities {missing:?}; advertised: {caps:?}"
    );
    Ok(())
}

fn assert_valid(validator: &jsonschema::Validator, method: &str, payload: &Value) {
    if let Err(err) = validator.validate(payload) {
        panic!(
            "{method} response did not match its schema: {err}\n\npayload: {}",
            serde_json::to_string_pretty(payload).unwrap()
        );
    }
}

/// **Property 4 (bonus).** A method invoked with invalid params
/// produces an error envelope whose `error` object matches
/// `error.schema.json`. Locks in the v0 error shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns the daemon binary; opt-in via --include-ignored"]
async fn error_responses_match_error_schema() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;

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
    let mut child = cmd.spawn()?;
    let _kill_on_drop = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;

    let error_validator = compile_schema(&schemas_root().join("error.schema.json"));

    // Unknown method → INVALID_PARAMS per dispatcher's unknown arm.
    let bad = round_trip(&mut stream, "1", "Index.NotARealVerb", json!({})).await?;
    assert!(
        !bad["error"].is_null(),
        "expected error envelope, got {bad:?}"
    );
    if let Err(err) = error_validator.validate(&bad["error"]) {
        panic!("error object did not match error.schema.json: {err}\n\npayload: {bad:?}");
    }

    // Daemon.Cancel with an empty cancel_id → INVALID_PARAMS too.
    let bad_cancel =
        round_trip(&mut stream, "2", "Daemon.Cancel", json!({"cancel_id": ""})).await?;
    assert!(!bad_cancel["error"].is_null());
    if let Err(err) = error_validator.validate(&bad_cancel["error"]) {
        panic!("Daemon.Cancel empty-id error did not match error.schema.json: {err}");
    }

    Ok(())
}

/// **Property 5 (telemetry-specific).** `Daemon.Telemetry` exposes
/// `unresolved_refs_count` as a non-negative integer. The real-repo CI
/// bench (PR #123) gates regressions on this field — if the daemon
/// stops emitting it, that bench's `Option<u64>` collapses to `None`
/// and the regression check silently no-ops.
///
/// We assert the field's presence + type live (not just via the
/// schema-drift property), because the schema property only fires
/// under `--include-ignored`. This test runs there too — but the
/// assertion is direct so the failure message points at the missing
/// field rather than a generic "schema mismatch".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns the daemon binary; opt-in via --include-ignored"]
async fn unresolved_refs_count_appears_in_telemetry_response() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    // Plant a tiny Rust fixture so the workspace mounts cleanly.
    // The exact contents don't matter for this assertion — we only
    // care that the field is present and well-typed.
    let fixture_src = workspace.path().join("src");
    std::fs::create_dir_all(&fixture_src)?;
    std::fs::write(
        fixture_src.join("lib.rs"),
        "pub fn answer() -> u32 { 42 }\n",
    )?;

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
    let mut child = cmd.spawn()?;
    let _kill_on_drop = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;

    let mount = round_trip(
        &mut stream,
        "mnt",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(
        mount["error"].is_null(),
        "Workspace.Mount unexpectedly errored: {mount:?}"
    );

    let resp = round_trip(&mut stream, "t", "Daemon.Telemetry", json!({})).await?;
    assert!(
        resp["error"].is_null(),
        "Daemon.Telemetry errored: {resp:?}"
    );
    let result = &resp["result"];
    let count = result
        .get("unresolved_refs_count")
        .unwrap_or_else(|| panic!("missing unresolved_refs_count in {result}"));
    let n = count
        .as_u64()
        .unwrap_or_else(|| panic!("unresolved_refs_count not a u64: {count:?}"));
    // Implicit >=0 via u64; explicit assert for the human reader.
    let _ = n;

    Ok(())
}
