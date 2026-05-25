//! Tests for the daemon-side telemetry collectors that feed the
//! `2026-05-19-003-feat-anonymous-opt-in-telemetry-plan.md` schema.
//!
//! PR #115 froze the wire schema but shipped most collector fields
//! as zeros / empty maps because the daemon-side timers, hit-rate
//! counters, and language registry weren't yet wired. This file
//! covers the follow-up: each collector pulls a real value out of
//! the daemon and the receiver-side bounded-enum filter still drops
//! every user-controlled string.
//!
//! Two test surfaces:
//!
//! 1. **End-to-end CLI**: `rts telemetry preview` against a fresh
//!    daemon with a seeded workspace. Verifies the full flow —
//!    `Daemon.Telemetry` RPC → bounded filter → wire JSON.
//! 2. **Parse-only**: feed a synthetic `Daemon.Telemetry` response
//!    through `parse_daemon_telemetry` + `build_payload` to assert
//!    the bounded-enum filter runs at the boundary even if the
//!    daemon-side enumerate ever leaks an unexpected key.
//!
//! The second surface is the "bright line #2" defense in depth — the
//! daemon's `Daemon.Telemetry` already constructs map keys from
//! closed enums, but the receiver should still hold the line if a
//! future code change accidentally widens the daemon-side enum.

mod cli_common;

use std::collections::BTreeMap;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};
use serde_json::Value;

/// Helper: run `rts telemetry preview` in the test env and return
/// the parsed JSON payload. Panics with a useful error message on
/// any failure (non-zero exit, non-JSON output).
async fn telemetry_preview(env: &TestEnv) -> Value {
    let mut cmd = env.rts();
    // `--workspace` must be passed explicitly: `fetch_daemon_telemetry`
    // computes the daemon socket path from the resolved workspace, and
    // without this arg the CLI walks up from the test process's cwd
    // (the rts-mcp crate dir) and lands on a different socket than the
    // `rts mount` / `rts find` calls used to seed counters. Mirrors the
    // `--workspace` injection in `TestEnv::run` so preview and the
    // traffic-driving RPCs share a daemon.
    cmd.arg("telemetry")
        .arg("preview")
        .arg("--workspace")
        .arg(env.workspace_path());
    let out = cmd.output().await.expect("spawn rts telemetry preview");
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "telemetry preview must succeed. stdout={stdout}\nstderr={stderr}"
    );
    serde_json::from_str::<Value>(&stdout)
        .unwrap_or_else(|e| panic!("preview output not JSON: {e}. stdout=\n{stdout}"))
}

/// Helper: mount a workspace and fire a few `rts` calls so collectors
/// have real data to report. Each command spawns the daemon (or
/// re-uses the running one), so by the time we ask for `telemetry
/// preview` the call counters / latency histograms / cold-walk
/// timing have all been exercised.
async fn drive_some_traffic(env: &TestEnv) {
    // Explicit mount first — `rts mount` returns a workspace_id we
    // can grep on, which gives us a known-success signal before the
    // telemetry preview runs.
    let out = env.run(&["mount"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "mount must succeed: stdout={stdout}\nstderr={stderr}"
    );

    // A find-symbol that hits the index. The seed fixture defines
    // `make_widget`, so this is guaranteed to return at least one
    // match — but even on a miss the dispatcher would record latency,
    // so the test is robust to fixture changes.
    let out = env.run(&["find", "make_widget"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "find make_widget must succeed (counter bumps depend on it). stdout={stdout}\nstderr={stderr}"
    );
    // A grep call exercises the `Index.Grep` counter + its own
    // latency histogram.
    let out = env.run(&["grep", "make_widget"]).await;
    let (stdout, stderr, code) = parts(&out);
    // Grep may legitimately exit 1 (no matches); 0 and 1 are both
    // success for our purposes — only an unexpected error (2+) means
    // the dispatcher never saw the call.
    assert!(
        code == 0 || code == 1,
        "grep make_widget unexpected exit. code={code} stdout={stdout}\nstderr={stderr}"
    );
    // A few more find calls so the latency histogram has more than
    // one bucket entry — without this the p99 = p50 = same-bucket-edge
    // assertion below would be brittle.
    for _ in 0..3 {
        let out = env.run(&["find", "format_widget"]).await;
        let (stdout, stderr, code) = parts(&out);
        assert!(
            code == 0 || code == 1,
            "find format_widget unexpected exit. code={code} stdout={stdout}\nstderr={stderr}"
        );
    }
}

/// Bright-line test (the headline acceptance criterion from the
/// follow-up spec): all formerly-zero collector fields populate with
/// real values after a workspace mount + a handful of RPCs.
#[tokio::test]
async fn collectors_populate_real_values() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    drive_some_traffic(&env).await;

    let payload = telemetry_preview(&env).await;

    // Schema invariants stay frozen.
    assert_eq!(payload["schema_version"], 1);

    // method_counts: at least one Index.FindSymbol call.
    let method_counts = payload["method_counts"]
        .as_object()
        .expect("method_counts is an object");
    let find_count = method_counts
        .get("Index.FindSymbol")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        find_count >= 1,
        "Index.FindSymbol count must be >= 1; got {find_count}. \
         full method_counts: {method_counts:?}"
    );

    // method_latency_p50 / p99: present for Index.FindSymbol, p99 >= p50.
    let p50_map = payload["method_latency_p50_ms"]
        .as_object()
        .expect("p50 map is an object");
    let p99_map = payload["method_latency_p99_ms"]
        .as_object()
        .expect("p99 map is an object");
    let p50 = p50_map
        .get("Index.FindSymbol")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let p99 = p99_map
        .get("Index.FindSymbol")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    assert!(
        p50 != u64::MAX,
        "Index.FindSymbol p50 must be reported; got missing. \
         full p50_map: {p50_map:?}"
    );
    assert!(
        p99 >= p50,
        "Index.FindSymbol p99 ({p99}) must be >= p50 ({p50})"
    );

    // cache_hit_rate is in [0.0, 1.0] (the schema's clamp).
    let hit_rate = payload["cache_hit_rate"].as_f64().unwrap_or(-1.0);
    assert!(
        (0.0..=1.0).contains(&hit_rate),
        "cache_hit_rate must be in [0.0, 1.0]; got {hit_rate}"
    );

    // cold_walk_ms_p50 > 0 — the mount fired a cold walk which has
    // since completed (we awaited mount above).
    let cold = payload["cold_walk_ms_p50"].as_u64().unwrap_or(0);
    assert!(
        cold > 0,
        "cold_walk_ms_p50 must be > 0 after a real mount; got {cold}. \
         full payload: {payload}"
    );

    // languages_indexed contains "rust" — the fixture is a Rust crate.
    let langs = payload["languages_indexed"]
        .as_array()
        .expect("languages_indexed is array");
    let langs_str: Vec<String> = langs
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        langs_str.iter().any(|s| s == "rust"),
        "languages_indexed must contain 'rust'; got {langs_str:?}"
    );

    // workspace_size_bucket is one of the four enum values.
    let bucket = payload["workspace_size_bucket"].as_str().unwrap_or("");
    assert!(
        matches!(bucket, "lt_1k" | "1k_to_10k" | "10k_to_100k" | "gt_100k"),
        "workspace_size_bucket must be a bounded enum; got {bucket:?}"
    );
}

/// Bright-line #2 defense in depth: even if the daemon-side
/// `Daemon.Telemetry` enumerate ever leaked an attacker-controlled
/// string into its response map keys (which it doesn't, by
/// construction), the receiver-side `build_payload` filter MUST drop
/// it before the wire is serialized.
///
/// This is a library-level test against the parse + filter chain;
/// no daemon involvement. The corresponding network-level
/// daemon-RPC bright-line test stays in
/// `crates/rts-mcp/tests/telemetry_privacy.rs::bright_line_no_user_controlled_strings`.
#[test]
fn bright_line_no_user_strings_in_collectors() {
    use rts_mcp::telemetry as tlm;

    // Construct a payload mimicking what a hypothetically-broken
    // daemon `Daemon.Telemetry` response *could* return: a mix of
    // bounded-enum keys (which must pass) and adversarial keys
    // (which must drop).
    let mut method_counts = BTreeMap::new();
    method_counts.insert("Index.FindSymbol".to_string(), 42u64);
    method_counts.insert("/etc/passwd".to_string(), 999u64);
    method_counts.insert("ResolvedSymbolName::secret_token".to_string(), 1u64);

    let mut p50 = BTreeMap::new();
    p50.insert("Index.FindSymbol".to_string(), 2u64);
    p50.insert("Index.SecretRpc".to_string(), 7u64);

    let mut error_counts = BTreeMap::new();
    error_counts.insert("TIMEOUT".to_string(), 1u64);
    error_counts.insert("WORKSPACE_PATH_/Users/private".to_string(), 1u64);

    let inputs = tlm::PayloadInputs {
        uptime_secs: 60,
        languages_raw: vec!["rust".into(), "homemade_lang".into()],
        method_counts_raw: method_counts,
        method_latency_p50_raw: p50,
        method_latency_p99_raw: BTreeMap::new(),
        error_counts_raw: error_counts,
        cache_hit_rate: 0.5,
        cold_walk_ms_p50: 100,
        workspace_files: 50,
    };
    let payload = tlm::build_payload("11111111-1111-4111-8111-111111111111", &inputs);
    let json = tlm::payload_to_compact_json(&payload);

    // Whitelist survivors.
    assert!(payload.method_counts.contains_key("Index.FindSymbol"));
    assert!(
        payload
            .method_latency_p50_ms
            .contains_key("Index.FindSymbol")
    );
    assert!(payload.error_counts.contains_key("TIMEOUT"));

    // Attacker strings dropped from every map.
    for needle in [
        "/etc/passwd",
        "ResolvedSymbolName",
        "secret_token",
        "Index.SecretRpc",
        "WORKSPACE_PATH_/Users/private",
        "homemade_lang",
    ] {
        assert!(
            !json.contains(needle),
            "wire JSON leaked attacker string {needle:?}: {json}"
        );
    }
}

/// Even when the collectors return real data, the receiver-side
/// filter is the single source of truth on bounded enums. Pass a
/// realistic-but-malformed daemon-style response through the parser
/// and assert it doesn't leak into `build_payload`'s output.
#[test]
fn build_payload_filter_runs_after_daemon_response_parse() {
    use rts_mcp::telemetry as tlm;

    // The `lang` field of `FileMeta` in older snapshots could be a
    // tag that maps to no known language (e.g. a never-shipped
    // experimental enum). Our daemon's `language_tag_counts` →
    // `lang_tag_to_name` chain drops these silently; the test
    // shores up the receiver-side filter so we're double-defended.
    let mut languages_raw = vec!["rust".to_string()];
    languages_raw.push("unicode\u{0000}null".into());
    languages_raw.push("rust\nrust".into());

    let inputs = tlm::PayloadInputs {
        languages_raw,
        ..Default::default()
    };
    let payload = tlm::build_payload("test", &inputs);
    let json = tlm::payload_to_compact_json(&payload);

    // "rust" passes; the malformed strings do not.
    assert_eq!(payload.languages_indexed, vec!["rust"]);
    assert!(!json.contains("unicode"));
    assert!(!json.contains("\u{0000}"));
}
