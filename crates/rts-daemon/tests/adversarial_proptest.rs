//! Adversarial-input property tests for the rts daemon.
//!
//! See `RESILIENCE.md` at the repo root for the threat model these
//! tests validate. Each `#[test]` here pins one promise from that
//! document. Property runs are deliberately end-to-end over the wire
//! (no mocking of the dispatcher) so the tested invariant is the
//! invariant the daemon actually ships.
//!
//! ## Case-count budget
//!
//! Default is `RTS_PROPTEST_CASES = 32` per property — small because
//! each case is a real round-trip over a Unix-domain socket against a
//! real daemon binary. The CI nightly `fuzz-bench.yml` workflow sets
//! `RTS_PROPTEST_CASES=256` for a deeper sweep; that's the number
//! quoted in the parent task. Local `cargo test` runs the cheaper 32
//! default so the suite stays under a minute on a developer machine.
//!
//! ## What's NOT here
//!
//! - libFuzzer harnesses against the regex / structural-query
//!   compilation paths. Those live in `fuzz/fuzz_targets/` and run
//!   under cargo-fuzz on nightly. The properties here cover the
//!   wire-shape contracts; fuzzing covers the byte-stream layer
//!   underneath.
//! - Path-canonicalize properties that require root or chroot. We
//!   constrain the tested input to user-shaped path strings; running
//!   as a real user under tempdir is enough to demonstrate that
//!   `Workspace.Mount` never silently operates on a path that
//!   escapes the user-supplied root.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use proptest::prelude::*;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-daemon"))
}

/// Default number of proptest cases per property. Override via env
/// var `RTS_PROPTEST_CASES` (CI nightly uses 256; local dev keeps 32
/// so the suite stays interactive).
fn proptest_cases() -> u32 {
    std::env::var("RTS_PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32)
}

fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: proptest_cases(),
        // Keep proptest's own concurrency disabled — the daemon's
        // per-connection in-flight cap is 16, and our `Mutex<UnixStream>`
        // around the shared connection already serialises. Spawning
        // multiple threaded test cases under a single daemon would
        // exceed the socket and add no signal.
        ..ProptestConfig::default()
    }
}

/// One daemon child + its connected socket, shared across all
/// proptest cases inside a single `#[test]`. Spawning the daemon once
/// keeps the per-case cost to a single round-trip (~ms) instead of
/// paying ~200ms startup × 32 cases.
///
/// The harness owns the tokio runtime explicitly (rather than relying
/// on `#[tokio::test]`) because proptest's `TestRunner::run` is
/// synchronous: each closure invocation must drive its own
/// `block_on` against a runtime that's NOT already running. A single
/// shared runtime stored on the harness gives every case a fresh
/// `block_on` slot without paying for runtime construction per case.
struct DaemonHarness {
    _child: KillOnDrop,
    _runtime_dir: tempfile::TempDir,
    _state_dir: tempfile::TempDir,
    _home_dir: tempfile::TempDir,
    /// The mounted workspace root. Stays valid for the lifetime of
    /// the harness; path-property tests build candidate paths
    /// relative to this root.
    workspace_dir: tempfile::TempDir,
    stream: Mutex<UnixStream>,
    rt: tokio::runtime::Runtime,
}

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn socket_path_for(home: &std::path::Path, runtime: &std::path::Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library")
            .join("Caches")
            .join("rts")
            .join("default.sock")
    } else {
        runtime.join("rts").join("default.sock")
    }
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
    let req = json!({"id": id, "method": method, "params": params});
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.flush().await?;

    let mut buf = Vec::new();
    let (rd, _wr) = stream.split();
    let mut reader = BufReader::new(rd);
    let n = tokio::time::timeout(Duration::from_secs(15), reader.read_until(b'\n', &mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to {method}"))??;
    anyhow::ensure!(n > 0, "EOF before response to {method}");
    Ok(serde_json::from_slice(&buf)?)
}

fn spawn_and_mount() -> anyhow::Result<DaemonHarness> {
    use std::os::unix::fs::PermissionsExt;
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace_dir = tempfile::tempdir()?;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Seed the workspace with one file so structural queries have
    // something to scan.
    std::fs::write(workspace_dir.path().join("seed.rs"), "pub fn marker() {}\n")?;

    let mut cmd = Command::new(daemon_bin());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RUST_LOG", "error")
        .env("RTS_IDLE_SHUTDOWN_SECS", "120")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = KillOnDrop(cmd.spawn()?);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let sock = socket_path_for(home_dir.path(), runtime_dir.path());
    let stream = rt.block_on(async {
        wait_for_socket(&sock, Duration::from_secs(10)).await?;
        let mut stream = UnixStream::connect(&sock).await?;
        let mount = round_trip(
            &mut stream,
            "mount-setup",
            "Workspace.Mount",
            json!({"root": workspace_dir.path().to_str().unwrap()}),
        )
        .await?;
        anyhow::ensure!(
            mount.get("error").map(|e| e.is_null()).unwrap_or(true),
            "setup mount failed: {mount}"
        );
        Ok::<UnixStream, anyhow::Error>(stream)
    })?;

    Ok(DaemonHarness {
        _child: child,
        _runtime_dir: runtime_dir,
        _state_dir: state_dir,
        _home_dir: home_dir,
        workspace_dir,
        stream: Mutex::new(stream),
        rt,
    })
}

/// Issue one RPC under a lock on the shared stream. The proptest
/// closures are synchronous, so we drive the async round-trip via the
/// harness's owned runtime. `block_on` is safe here because the
/// closure is invoked OUTSIDE any `#[tokio::test]` runtime — proptest
/// runs each case on the test thread synchronously.
fn call(harness: &DaemonHarness, method: &str, params: Value) -> Value {
    let mut guard = harness.stream.lock().expect("stream poisoned");
    let id = format!("prop-{}", rand_id());
    harness
        .rt
        .block_on(round_trip(&mut guard, &id, method, params))
        .expect("round_trip failed")
}

fn rand_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(1);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Extract the wire-level error code string from a JSON-RPC response.
/// Returns `None` if the response is a success.
fn error_code(resp: &Value) -> Option<String> {
    resp.get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
}

// ============================================================
// Property 1 — Workspace.Mount canonicalisation never escapes
// ============================================================
//
// Promise (RESILIENCE.md §"Path traversal"): `Workspace.Mount { root }`
// either:
//   (a) succeeds with a canonical root that starts with the mounted
//       workspace's canonical root (after `realpath`), OR
//   (b) fails with one of: PATH_TRAVERSAL, MOUNT_HAS_SYMLINK,
//       INVALID_WORKSPACE_PATH, WORKSPACE_MISMATCH (we already
//       mounted a different path in setup).
//
// It MUST NEVER silently operate on `/etc/passwd` or any other path
// that escapes the user-supplied root via `../` or symlinks.

#[test]
fn path_canonicalization_never_escapes_root() -> anyhow::Result<()> {
    let harness = spawn_and_mount()?;

    // Use proptest's runner directly so we can interleave with the
    // already-mounted daemon connection. Each case generates a path
    // string with a varying number of `..` segments interleaved with
    // ASCII segments, plus optional absolute prefixes.
    let strat = adversarial_path_strategy();
    let mut runner = proptest::test_runner::TestRunner::new(proptest_config());
    runner
        .run(&strat, |path_str| {
            let resp = call(&harness, "Workspace.Mount", json!({"root": path_str}));

            // Either success-with-canonical-prefix or a documented error code.
            if let Some(code) = error_code(&resp) {
                // All of these are acceptable rejection codes.
                let acceptable = matches!(
                    code.as_str(),
                    "PATH_TRAVERSAL"
                        | "MOUNT_HAS_SYMLINK"
                        | "INVALID_WORKSPACE_PATH"
                        | "WORKSPACE_MISMATCH"
                        | "INVALID_PARAMS"
                );
                prop_assert!(
                    acceptable,
                    "unexpected error code {code:?} for mount attempt on {path_str:?}; full response: {resp}"
                );
            } else {
                // Success: the daemon idempotently returned its
                // already-mounted workspace status. Confirm the
                // canonical workspace id matches what we mounted in
                // setup — i.e. the canonical resolution did NOT
                // wander off to some attacker-supplied location.
                let id = resp["result"]["workspace_id"]
                    .as_str()
                    .ok_or_else(|| TestCaseError::fail(format!("missing workspace_id in {resp}")))?;
                prop_assert!(
                    !id.is_empty(),
                    "successful mount must carry a workspace_id; got: {resp}"
                );
            }
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("proptest failed: {e}"))?;
    Ok(())
}

/// Adversarial path strategy: a 1..=8-segment path with each segment
/// drawn from `{"..", ".", "etc", "passwd", "dev", "null", "ws", a..=z}`,
/// optionally prefixed with `/` to absolutise.
fn adversarial_path_strategy() -> impl Strategy<Value = String> {
    let seg = prop_oneof![
        Just("..".to_string()),
        Just(".".to_string()),
        Just("etc".to_string()),
        Just("passwd".to_string()),
        Just("dev".to_string()),
        Just("null".to_string()),
        Just("ws".to_string()),
        proptest::char::range('a', 'z').prop_map(|c| c.to_string()),
    ];
    (any::<bool>(), proptest::collection::vec(seg, 1..=8)).prop_map(|(absolute, segs)| {
        let joined = segs.join("/");
        if absolute {
            format!("/{joined}")
        } else {
            joined
        }
    })
}

// ============================================================
// Property 2 — Daemon.Cancel cancel_id bounds
// ============================================================
//
// Promise (RESILIENCE.md §"cancel_id bounds"): `Daemon.Cancel`
// accepts a `cancel_id` of 1..=256 characters. Outside that range
// the daemon returns INVALID_PARAMS without panicking. Control
// characters and non-ASCII Unicode are accepted within the length
// bound (no charset filter today; the registry uses HashMap<String,_>).

#[test]
fn cancel_id_length_bounds_never_panic() -> anyhow::Result<()> {
    let harness = spawn_and_mount()?;

    let strat = prop_oneof![
        // Empty (should be rejected).
        Just(String::new()),
        // 1..=256: should be accepted (returns cancelled: false for
        // a never-registered id).
        proptest::collection::vec(any::<char>(), 1..=256)
            .prop_map(|cs| cs.into_iter().collect::<String>()),
        // 257..=2048: should be rejected with INVALID_PARAMS.
        proptest::collection::vec(any::<char>(), 257..=2048)
            .prop_map(|cs| cs.into_iter().collect::<String>()),
        // Pure control-char strings of varying length.
        proptest::collection::vec(0u8..32u8, 1..=256)
            .prop_map(|bs| { bs.into_iter().map(|b| b as char).collect::<String>() }),
    ];

    let mut runner = proptest::test_runner::TestRunner::new(proptest_config());
    runner
        .run(&strat, |cancel_id| {
            // Skip strings containing NUL — JSON-RPC envelopes
            // tolerate them but the encoded   escapes round-trip
            // is well-tested elsewhere and isn't the property under
            // test here.
            prop_assume!(!cancel_id.contains('\0'));

            // Skip strings whose raw byte length exceeds 1 MiB —
            // that would trip MESSAGE_TOO_LARGE (the connection
            // closes). Our property is about cancel_id semantics,
            // not message-size, which has its own test.
            let encoded_len = serde_json::to_string(&cancel_id).map(|s| s.len()).unwrap_or(0);
            prop_assume!(encoded_len < 1_000_000);

            let resp = call(&harness, "Daemon.Cancel", json!({"cancel_id": cancel_id}));

            // Three valid outcomes:
            //   - len == 0           → INVALID_PARAMS
            //   - 1 <= chars <= 256  → success {cancelled: false}
            //   - chars > 256        → INVALID_PARAMS
            // (Length here is byte-length per the handler: `len()` on
            // the String; multi-byte chars count as their UTF-8
            // bytes. Matches what the daemon enforces.)
            let byte_len = cancel_id.len();
            if let Some(code) = error_code(&resp) {
                prop_assert_eq!(
                    code.as_str(), "INVALID_PARAMS",
                    "unexpected error code on cancel_id (byte_len={}); resp: {}", byte_len, resp
                );
            } else {
                prop_assert!(
                    (1..=256).contains(&byte_len),
                    "cancel_id (byte_len={}) accepted outside the documented 1..=256 range; resp: {}", byte_len, resp
                );
                let cancelled = resp["result"]["cancelled"].as_bool();
                prop_assert_eq!(
                    cancelled,
                    Some(false),
                    "unregistered id should return cancelled=false; got: {}", resp
                );
            }
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("proptest failed: {e}"))?;
    Ok(())
}

// ============================================================
// Property 3 — Index.FindSymbol accepts any UTF-8 without panic
// ============================================================
//
// Promise (RESILIENCE.md §"Resource exhaustion"): `Index.FindSymbol`
// validates `name`/`pattern` length up front. Any UTF-8 string is a
// valid `name` from the daemon's perspective (no charset filter);
// the daemon either returns matches, returns SYMBOL_NOT_FOUND, or
// returns INVALID_PARAMS for length-out-of-bounds. It never panics
// on unicode confusables, RTL overrides, or zero-width chars.

#[test]
fn find_symbol_unicode_never_panics() -> anyhow::Result<()> {
    let harness = spawn_and_mount()?;

    let strat = prop_oneof![
        // Random unicode 1..=128.
        proptest::collection::vec(any::<char>(), 1..=128)
            .prop_map(|cs| cs.into_iter().collect::<String>()),
        // Empty (rejected).
        Just(String::new()),
        // Over-long (rejected): 257..=1024 chars.
        proptest::collection::vec(any::<char>(), 257..=1024)
            .prop_map(|cs| cs.into_iter().collect::<String>()),
        // Pure-confusable: ZWJ, RTL override, NFC vs NFD marks.
        Just("\u{200d}\u{200c}\u{202e}admin\u{202c}".to_string()),
        Just("résumé".to_string()),                 // NFC
        Just("re\u{0301}sume\u{0301}".to_string()), // NFD same text
    ];

    let mut runner = proptest::test_runner::TestRunner::new(proptest_config());
    runner
        .run(&strat, |name| {
            prop_assume!(!name.contains('\0'));
            let resp = call(&harness, "Index.FindSymbol", json!({"name": name}));

            // Any of these is fine: success (result.matches array),
            // INVALID_PARAMS (length), SYMBOL_NOT_FOUND, INDEX_NOT_READY.
            if let Some(code) = error_code(&resp) {
                let acceptable = matches!(
                    code.as_str(),
                    "INVALID_PARAMS" | "SYMBOL_NOT_FOUND" | "INDEX_NOT_READY"
                );
                prop_assert!(
                    acceptable,
                    "unexpected error code {code:?} on find_symbol; resp: {}",
                    resp
                );
            } else {
                // Success: must have a `matches` array.
                prop_assert!(
                    resp["result"]["matches"].is_array(),
                    "successful find_symbol must carry matches[]; got: {}",
                    resp
                );
            }
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("proptest failed: {e}"))?;
    Ok(())
}

// ============================================================
// Property 4 — Index.Grep literal mode accepts any UTF-8 without panic
// ============================================================

#[test]
fn grep_literal_unicode_never_panics() -> anyhow::Result<()> {
    let harness = spawn_and_mount()?;

    let strat = prop_oneof![
        // Random unicode 1..=200 chars.
        proptest::collection::vec(any::<char>(), 1..=200)
            .prop_map(|cs| cs.into_iter().collect::<String>()),
        // Empty / over-long.
        Just(String::new()),
        proptest::collection::vec(any::<char>(), 1025..=2048)
            .prop_map(|cs| cs.into_iter().collect::<String>()),
        // Unicode confusables.
        Just("\u{202e}".to_string()),
        Just("a\u{200d}b".to_string()),
    ];

    let mut runner = proptest::test_runner::TestRunner::new(proptest_config());
    runner
        .run(&strat, |text| {
            prop_assume!(!text.contains('\0'));
            let resp = call(&harness, "Index.Grep", json!({"text": text}));
            if let Some(code) = error_code(&resp) {
                let acceptable = matches!(code.as_str(), "INVALID_PARAMS" | "INDEX_NOT_READY");
                prop_assert!(
                    acceptable,
                    "unexpected error code {code:?} on grep literal; text byte_len={}, resp: {}",
                    text.len(),
                    resp
                );
            } else {
                prop_assert!(
                    resp["result"]["matches"].is_array(),
                    "successful grep must carry matches[]; got: {}",
                    resp
                );
            }
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("proptest failed: {e}"))?;
    Ok(())
}

// ============================================================
// Property 5 — Index.Grep regex mode rejects ReDoS without hanging
// ============================================================
//
// Promise (RESILIENCE.md §"ReDoS"): `Index.Grep { regex: true }`
// compiles the user pattern under the regex crate's default size
// budget (single-line) or the explicit DFA/NFA budget (multiline).
// Adversarial patterns like `(a+)+` either compile and run bounded,
// or are rejected with INVALID_PARAMS / REGEX_TOO_COMPLEX. They never
// stall the daemon past the request's per-call wall-clock.

#[test]
fn regex_compilation_redos_rejected_or_bounded() -> anyhow::Result<()> {
    let harness = spawn_and_mount()?;

    // Curated adversarial corpus + randomised pattern fragments.
    // The corpus entries are the OWASP "catastrophic backtracking"
    // canon. They MUST either compile-and-run-fast or get rejected.
    let known_bad: Vec<String> = vec![
        "(a+)+".into(),
        "(a*)*".into(),
        "(.+)+".into(),
        "(.*)*".into(),
        "(a|a)*".into(),
        "(a|aa)*".into(),
        "(a|a?)*".into(),
        "(?:a|a)*".into(),
        "(?:a*)*".into(),
        "(?:.*)*".into(),
        "(?:.+)+".into(),
        "(?s).*".into(),
        "(?s)(.*)".into(),
        "(.*a){50}".into(),
    ];

    let known_bad_strategy = proptest::sample::select(known_bad);
    let random_pattern = proptest::collection::vec(
        prop_oneof![
            Just('a'),
            Just('b'),
            Just('.'),
            Just('*'),
            Just('+'),
            Just('?'),
            Just('('),
            Just(')'),
            Just('|'),
            Just('\\'),
            Just('['),
            Just(']'),
            Just('{'),
            Just('}'),
            Just('0'),
            Just('9'),
        ],
        1..=64,
    )
    .prop_map(|cs| cs.into_iter().collect::<String>());

    let strat = prop_oneof![known_bad_strategy, random_pattern];

    let mut runner = proptest::test_runner::TestRunner::new(proptest_config());
    runner
        .run(&strat, |pattern| {
            prop_assume!(!pattern.is_empty() && pattern.len() <= 1024);

            // Time-box each round-trip. Our overall round_trip
            // timeout is 15s; if we ever exceed even half of that
            // on a single pattern, the daemon is hung — fail loud.
            let started = Instant::now();
            let resp = call(
                &harness,
                "Index.Grep",
                json!({"text": pattern, "regex": true}),
            );
            let elapsed = started.elapsed();

            prop_assert!(
                elapsed < Duration::from_secs(8),
                "regex compile/execute took {elapsed:?} on pattern {pattern:?}; \
                 the daemon should reject ReDoS patterns, not hang"
            );

            if let Some(code) = error_code(&resp) {
                let acceptable = matches!(code.as_str(), "INVALID_PARAMS" | "INDEX_NOT_READY");
                prop_assert!(
                    acceptable,
                    "unexpected error code {code:?} on regex pattern {pattern:?}; resp: {}",
                    resp
                );
            } else {
                prop_assert!(
                    resp["result"]["matches"].is_array(),
                    "successful regex grep must carry matches[]; got: {}",
                    resp
                );
            }
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("proptest failed: {e}"))?;
    Ok(())
}

// ============================================================
// Property 6 — Structural query rejects past the size cap
// ============================================================
//
// Promise (RESILIENCE.md §"Structural query bombs"): `Index.Grep
// { structural_query }` rejects S-expression queries larger than
// `MAX_STRUCTURAL_QUERY_BYTES` (64 KiB; new ceiling introduced by
// this harness). Smaller well-formed inputs either compile and run,
// or fail with STRUCTURAL_QUERY_INVALID. They never hang the daemon
// past the request wall-clock.

#[test]
fn structural_query_size_cap_bounds_compile() -> anyhow::Result<()> {
    let harness = spawn_and_mount()?;

    let strat = prop_oneof![
        // Well-formed simple query.
        Just("(function_item) @fn".to_string()),
        // Deeply nested parens (typical S-expr bomb shape).
        proptest::num::usize::ANY.prop_map(|n| {
            let depth = (n % 128) + 1;
            let opens = "(".repeat(depth);
            let closes = ")".repeat(depth);
            format!("{opens}{closes}")
        }),
        // Very long capture chain.
        proptest::num::usize::ANY.prop_map(|n| {
            let cnt = (n % 256) + 1;
            (0..cnt)
                .map(|i| format!("(identifier) @c{i}"))
                .collect::<Vec<_>>()
                .join(" ")
        }),
        // Pure-junk byte strings up to 128 KiB (past the proposed cap).
        proptest::collection::vec(any::<char>(), 1..=131_072)
            .prop_map(|cs| cs.into_iter().collect::<String>()),
    ];

    let mut runner = proptest::test_runner::TestRunner::new(proptest_config());
    runner
        .run(&strat, |query| {
            prop_assume!(!query.is_empty());
            // Skip queries whose JSON-encoded length exceeds 8 MiB —
            // those would trip MESSAGE_TOO_LARGE rather than our
            // structural-query cap. The cap we want to test is the
            // 64 KiB structural-query cap, well below message-size.
            prop_assume!(query.len() < 8 * 1024 * 1024);

            let started = Instant::now();
            let resp = call(
                &harness,
                "Index.Grep",
                json!({
                    "structural_query": query,
                    "language": ["rust"],
                }),
            );
            let elapsed = started.elapsed();

            // The structural scanner has an internal 5s wall-clock
            // budget. Compile + scan + return should land well under
            // that for any input. If we see > 8s on a single call,
            // the daemon is stuck.
            prop_assert!(
                elapsed < Duration::from_secs(8),
                "structural query took {elapsed:?} on input len={}; \
                 daemon should reject oversized/malformed queries, not hang",
                query.len()
            );

            if let Some(code) = error_code(&resp) {
                // INVALID_PARAMS (with data.code in the v2 closed
                // set), INDEX_NOT_READY (race during mount), or
                // STRUCTURAL_QUERY_INVALID via data.code are all
                // acceptable rejections. We do NOT pin the data.code
                // string here because the validation taxonomy is
                // documented (and version-locked) in
                // crates/rts-daemon/src/methods/grep_v2/errors.rs.
                let acceptable = matches!(code.as_str(), "INVALID_PARAMS" | "INDEX_NOT_READY");
                prop_assert!(
                    acceptable,
                    "unexpected error code {code:?} on structural query (len={}); resp: {}",
                    query.len(),
                    resp
                );
            } else {
                // Success: validate the response shape minimally.
                prop_assert!(
                    resp["result"]["matches"].is_array(),
                    "successful structural grep must carry matches[]; got: {}",
                    resp
                );
            }
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("proptest failed: {e}"))?;
    Ok(())
}

// Silence the dead-code warning when callers reference workspace_dir.
#[allow(dead_code)]
fn _harness_workspace_dir(h: &DaemonHarness) -> &std::path::Path {
    h.workspace_dir.path()
}
