//! `rts verify-edit --edits <path|->` — the CI/pre-merge gate over a
//! proposed multi-file patch (verify-v0 P3.U2).
//!
//! Exit-code contract (`--fail-on <none|warn|critical>`, default critical):
//!   - `--fail-on critical` (default): pass/warn → 0, fail → 2
//!   - `--fail-on warn`:               pass → 0,  warn/fail → 2
//!   - `--fail-on none`:               always 0 (report-only)
//!   - daemon / contact error:         3
//!   - malformed edits json / no edits: clean error (not a panic), 3

mod cli_common;

use cli_common::{TestEnv, parts};

/// Seed a workspace where `hub.rs` defines `target(x)` (arity 1) and
/// `caller_a.rs` calls it — the canonical broken-caller fixture.
fn seed_target_caller(env: &TestEnv) {
    let root = env.workspace_path();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("hub.rs"),
        "pub fn target(x: u32) -> u32 { x + 1 }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("caller_a.rs"),
        "use crate::target;\npub fn caller_a() { let _ = target(1); }\n",
    )
    .unwrap();
}

/// Wait until `target` is indexed AND `caller_a` shows up as a caller, so
/// `Index.VerifyEdit`'s caller queries have settled REFS edges. Polls via
/// the `rts callers` CLI surface.
async fn wait_until_refs_ready(env: &TestEnv) {
    for _ in 0..80 {
        let out = env
            .run(&["--no-color", "--json", "callers", "target"])
            .await;
        let (stdout, _stderr, _code) = parts(&out);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let has = v["callers"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .any(|c| c["enclosing_qualified_name"].as_str() == Some("caller_a"))
                })
                .unwrap_or(false);
            if has {
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
    }
    panic!("REFS target<-caller_a never settled");
}

fn write_edits(env: &TestEnv, name: &str, json: &str) -> std::path::PathBuf {
    let p = env.workspace_path().join(name);
    std::fs::write(&p, json).unwrap();
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn breaking_edit_fail_on_critical_exits_two_and_names_caller() {
    let env = TestEnv::new();
    seed_target_caller(&env);
    wait_until_refs_ready(&env).await;

    // Remove `target` → fail + broken_caller (caller_a is outside the patch).
    let edits = write_edits(
        &env,
        "edits.json",
        r#"[{"file":"hub.rs","content":"pub fn unrelated() -> u32 { 0 }\n"}]"#,
    );

    let out = env
        .run(&[
            "--no-color",
            "verify-edit",
            "--edits",
            edits.to_str().unwrap(),
        ])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 2,
        "a caller-breaking patch must fail the gate (exit 2); stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("target") || stdout.contains("caller_a"),
        "the broken caller must be named in the output; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn safe_edit_exits_zero() {
    let env = TestEnv::new();
    seed_target_caller(&env);
    wait_until_refs_ready(&env).await;

    // Keep `target` intact, add a new fn → pass.
    let edits = write_edits(
        &env,
        "edits.json",
        r#"[{"file":"hub.rs","content":"pub fn target(x: u32) -> u32 { x + 1 }\npub fn brand_new() -> u32 { 9 }\n"}]"#,
    );

    let out = env
        .run(&[
            "--no-color",
            "verify-edit",
            "--edits",
            edits.to_str().unwrap(),
        ])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "a safe patch must pass the gate (exit 0); stdout={stdout:?} stderr={stderr:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn breaking_edit_fail_on_none_is_report_only_exit_zero() {
    let env = TestEnv::new();
    seed_target_caller(&env);
    wait_until_refs_ready(&env).await;

    let edits = write_edits(
        &env,
        "edits.json",
        r#"[{"file":"hub.rs","content":"pub fn unrelated() -> u32 { 0 }\n"}]"#,
    );

    let out = env
        .run(&[
            "--no-color",
            "verify-edit",
            "--edits",
            edits.to_str().unwrap(),
            "--fail-on",
            "none",
        ])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "--fail-on none is report-only (exit 0) even on a break; stdout={stdout:?} stderr={stderr:?}"
    );
    // It still REPORTS the break (the verdict is fail) — only the exit is 0.
    assert!(
        stdout.to_lowercase().contains("fail") || stdout.contains("target"),
        "report-only must still surface the finding; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_edits_json_errors_cleanly_not_panic() {
    let env = TestEnv::new();
    seed_target_caller(&env);

    // Not a JSON array of edits — a bare string.
    let edits = write_edits(&env, "bad.json", r#"{"not":"an array"}"#);

    let out = env
        .run(&[
            "--no-color",
            "verify-edit",
            "--edits",
            edits.to_str().unwrap(),
        ])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 3,
        "malformed edits json → clean setup error (exit 3); stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        !stderr.contains("panicked"),
        "must not panic on malformed input; stderr={stderr:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn json_flag_passes_daemon_response_through() {
    let env = TestEnv::new();
    seed_target_caller(&env);
    wait_until_refs_ready(&env).await;

    let edits = write_edits(
        &env,
        "edits.json",
        r#"[{"file":"hub.rs","content":"pub fn unrelated() -> u32 { 0 }\n"}]"#,
    );

    let out = env
        .run(&[
            "--no-color",
            "--json",
            "verify-edit",
            "--edits",
            edits.to_str().unwrap(),
        ])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(code, 2, "still gates on the verdict; stderr={stderr:?}");
    let body: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("json parse {e}: {stdout:?}"));
    assert_eq!(
        body["verdict"], "fail",
        "--json passes the daemon verdict through; got {stdout:?}"
    );
}
