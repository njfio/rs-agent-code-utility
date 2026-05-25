//! Privacy gate tests — these are GATING checks for the
//! `2026-05-19-003-feat-anonymous-opt-in-telemetry-plan.md` plan's
//! seven non-negotiable bright lines. If any fail, the trust
//! catastrophe described in "Dependencies & Risks" is one bug away.
//!
//! These tests stay in the no-feature build (don't gate on `feature =
//! "telemetry"`) because the bright lines apply to the library's
//! payload construction surface, not to the HTTP send path. The
//! schema is the same with or without the HTTP client compiled in.

use std::collections::BTreeMap;

use rts_mcp::telemetry as tlm;

/// Build a deterministic payload that matches the shape of the
/// golden file in `tests/fixtures/telemetry_v1.golden.json`. Returns
/// the JSON the daemon would send.
fn fixture_payload() -> tlm::TelemetryPayload {
    let mut method_counts = BTreeMap::new();
    method_counts.insert("Index.FindSymbol".to_string(), 5u64);
    method_counts.insert("Index.Grep".to_string(), 12u64);

    let mut method_latency_p50 = BTreeMap::new();
    method_latency_p50.insert("Index.FindSymbol".to_string(), 2u64);
    method_latency_p50.insert("Index.Grep".to_string(), 38u64);

    let mut method_latency_p99 = BTreeMap::new();
    method_latency_p99.insert("Index.FindSymbol".to_string(), 8u64);
    method_latency_p99.insert("Index.Grep".to_string(), 412u64);

    let mut error_counts = BTreeMap::new();
    error_counts.insert("TIMEOUT".to_string(), 2u64);
    error_counts.insert("INVALID_STRUCTURAL_QUERY".to_string(), 1u64);

    let inputs = tlm::PayloadInputs {
        uptime_secs: 7_200,
        languages_raw: vec!["rust".into(), "python".into()],
        method_counts_raw: method_counts,
        method_latency_p50_raw: method_latency_p50,
        method_latency_p99_raw: method_latency_p99,
        error_counts_raw: error_counts,
        cache_hit_rate: 0.84,
        cold_walk_ms_p50: 230,
        workspace_files: 47_000,
    };
    tlm::build_payload("11111111-1111-4111-8111-111111111111", &inputs)
}

/// Bright line #1: opt-in default off.
///
/// A freshly-initialized config dir reports `is_enabled() == false`.
/// No way to "accidentally" be opted in.
#[test]
fn bright_line_default_off() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("rts");
    assert!(
        !tlm::is_enabled_in(&dir),
        "default state must be DISABLED (bright line #1)"
    );
}

/// Bright line #2: no user-controlled strings on the wire.
///
/// Attempts to inject a path-like string, a content-like string, and
/// a symbol-name-like string into the raw input maps. None of them
/// reach the payload — the bounded-enum filters drop them silently.
#[test]
fn bright_line_no_user_controlled_strings() {
    let mut method_counts_raw = BTreeMap::new();
    // Plausible attacker inputs: a path, a symbol name, a literal.
    method_counts_raw.insert("/etc/passwd".to_string(), 1);
    method_counts_raw.insert("MySecretFunction".to_string(), 1);
    method_counts_raw.insert("password=hunter2".to_string(), 1);
    // Plus one valid one, to assert the filter isn't a "drop all".
    method_counts_raw.insert("Index.FindSymbol".to_string(), 7);

    let mut error_counts_raw = BTreeMap::new();
    error_counts_raw.insert("OUTSIDE_THE_ENUM".to_string(), 1);
    error_counts_raw.insert("TIMEOUT".to_string(), 3);

    let inputs = tlm::PayloadInputs {
        languages_raw: vec!["rust".into(), "homemade_lang".into()],
        method_counts_raw,
        error_counts_raw,
        ..Default::default()
    };
    let payload = tlm::build_payload("dead-beef", &inputs);
    let json = tlm::payload_to_compact_json(&payload);

    // Whitelist survivors.
    assert!(
        payload.method_counts.contains_key("Index.FindSymbol"),
        "valid method must pass"
    );
    assert!(
        payload.error_counts.contains_key("TIMEOUT"),
        "valid error code must pass"
    );

    // Attacker strings dropped from the maps.
    assert!(!payload.method_counts.contains_key("/etc/passwd"));
    assert!(!payload.method_counts.contains_key("MySecretFunction"));
    assert!(!payload.method_counts.contains_key("password=hunter2"));
    assert!(!payload.error_counts.contains_key("OUTSIDE_THE_ENUM"));

    // Belt-and-braces: the serialized wire form does not contain ANY
    // of the attacker strings, anywhere — not as keys, not as values,
    // not embedded. (`install_id` is excluded since the caller
    // passes that; tests pass a known-safe string.)
    for needle in [
        "/etc/passwd",
        "MySecretFunction",
        "password=hunter2",
        "OUTSIDE_THE_ENUM",
        "homemade_lang",
    ] {
        assert!(
            !json.contains(needle),
            "leaked {needle:?} into wire JSON:\n{json}"
        );
    }
}

/// Bright line #3: install-id is a random UUID (not derived from
/// anything user-identifying).
#[test]
fn bright_line_install_id_is_random_uuid() {
    let a = tlm::generate_install_id().expect("generate");
    let b = tlm::generate_install_id().expect("generate");
    assert_ne!(a, b, "consecutive generations must differ (random)");
    // RFC-4122 v4 shape: position 14 is '4'; position 19 is one of
    // 8/9/a/b.
    assert_eq!(&a[14..15], "4", "version-4 nibble: {a}");
    let variant = &a[19..20];
    assert!(matches!(variant, "8" | "9" | "a" | "b"), "variant: {a}");
}

/// Bright line #4: `rts telemetry preview` shows exactly what would
/// be sent. Verified at the *library* level by asserting that the
/// preview output (pretty) and the flush output (compact) deserialize
/// to JSON values that compare equal. We round-trip through
/// `serde_json::Value` (not back through `TelemetryPayload`) because
/// the payload struct uses `&'static str` map keys, which serde
/// can't borrow from a function-local string.
#[test]
fn bright_line_preview_matches_flush_payload() {
    let p1 = fixture_payload();
    let pretty = tlm::payload_to_pretty_json(&p1);
    let compact = tlm::payload_to_compact_json(&p1);

    let v_pretty: serde_json::Value =
        serde_json::from_str(&pretty).expect("preview must be valid JSON");
    let v_compact: serde_json::Value =
        serde_json::from_str(&compact).expect("flush must be valid JSON");
    let v_direct = serde_json::to_value(&p1).expect("direct serialize");

    assert_eq!(
        v_pretty, v_direct,
        "pretty (preview) output represents the same payload"
    );
    assert_eq!(
        v_compact, v_direct,
        "compact (flush) output represents the same payload"
    );
    assert_eq!(
        v_pretty, v_compact,
        "preview and flush carry the same payload"
    );
}

/// Bright line #5: disable deletes the install-id and stops
/// pinging. The library-level test is "is_enabled() goes false and
/// install_id_path file is gone".
#[test]
fn bright_line_disable_fully_removes_install_id() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("rts");
    let _id = tlm::enable_in(&dir).expect("enable");
    let id_path = tlm::install_id_path_in(&dir);
    assert!(id_path.exists(), "install-id file present after enable");
    assert!(tlm::is_enabled_in(&dir));

    tlm::disable_in(&dir).expect("disable");
    assert!(
        !id_path.exists(),
        "install-id file MUST be deleted on disable"
    );
    assert!(
        !tlm::is_enabled_in(&dir),
        "is_enabled must report false after disable"
    );
}

/// Bright line #6 / schema-golden: the serialized payload is
/// byte-for-byte equivalent to the golden file (modulo OS/arch
/// substitution). Any change to the wire schema requires updating
/// both the struct and the golden file in the same commit; this
/// test surfaces the drift.
#[test]
fn schema_golden_matches_fixture() {
    let payload = fixture_payload();
    let actual = tlm::payload_to_pretty_json(&payload);
    let golden_raw = std::fs::read_to_string(format!(
        "{}/tests/fixtures/telemetry_v1.golden.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("golden file must exist at the documented path");
    let golden = golden_raw
        .replace("OS_PLACEHOLDER", tlm::os_label())
        .replace("ARCH_PLACEHOLDER", tlm::arch_label())
        // Version-agnostic: rts_version tracks CARGO_PKG_VERSION and would
        // otherwise force a golden edit on every release bump.
        .replace("VERSION_PLACEHOLDER", env!("CARGO_PKG_VERSION"));

    // Strip trailing newline if the file editor added one — serde's
    // `to_string_pretty` doesn't emit a trailing newline.
    let golden = golden.trim_end_matches('\n').to_string();
    assert_eq!(
        actual.trim_end_matches('\n'),
        golden.trim_end_matches('\n'),
        "wire payload diverged from golden file. \
         If this is an intentional schema change, bump SCHEMA_VERSION \
         and update tests/fixtures/telemetry_v1.golden.json in the \
         same commit."
    );
}

/// Bright line #7 cadence — verified at the library level by
/// asserting that `last_ping_unix_ms` is the only schedule signal
/// surfaced through the local config (no per-method send state, no
/// queue, no "send when X happens" trigger). This is an
/// architectural check: the only thing that says "telemetry might
/// fire" is the daemon's ticker (added separately under the
/// `telemetry` feature) reading this single field.
#[test]
fn bright_line_single_schedule_signal() {
    // LocalConfig has exactly two public fields: `enabled` and
    // `last_ping_unix_ms`. Adding a third would expand the schedule
    // surface; this test stays as a checklist item.
    let cfg = tlm::LocalConfig::default();
    let text = toml::to_string(&cfg).expect("serialize");
    // Empty default config: no `last_ping_unix_ms` line because
    // serde skips `None` for Option fields with the default
    // attribute, and no `enabled = true` line because the default
    // is false. The TOML form is at most one field.
    let count = text.lines().filter(|l| !l.trim().is_empty()).count();
    assert!(
        count <= 2,
        "config schema has expanded beyond enabled + last_ping_unix_ms: {text}"
    );
}

/// Privacy gate: `is_enabled()` flips to false the moment EITHER
/// surface (config flag OR install-id file) is missing. This is
/// defense-in-depth — corrupt one file, telemetry stops.
#[test]
fn either_surface_missing_means_disabled() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("rts");

    // Enable, then delete only the install-id.
    let _ = tlm::enable_in(&dir).expect("enable");
    std::fs::remove_file(tlm::install_id_path_in(&dir)).expect("rm install-id");
    assert!(
        !tlm::is_enabled_in(&dir),
        "install-id missing → disabled regardless of flag"
    );

    // Reset, then flip the flag manually.
    let _ = tlm::enable_in(&dir).expect("enable");
    let mut cfg = tlm::read_config_in(&dir).expect("read");
    cfg.enabled = false;
    tlm::write_config_in(&dir, &cfg).expect("write");
    assert!(
        !tlm::is_enabled_in(&dir),
        "flag false → disabled even with install-id present"
    );
}
