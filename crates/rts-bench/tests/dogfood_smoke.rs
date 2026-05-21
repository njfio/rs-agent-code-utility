//! Smoke tests for `rts-bench dogfood`.
//!
//! Each test embeds a synthetic JSONL fixture inline so the test
//! suite has no dependency on real session transcripts (which carry
//! workspace paths and other session-private context we don't want
//! in fixtures). Synthetic fixtures shape themselves to match real
//! Claude Code event lines — verified against `~/.claude/projects/*/`
//! shapes during PR development — but contain no real session data.
//!
//! Tests spawn the `rts-bench` binary as a subprocess and pipe the
//! fixture in over stdin (`session = "-"`). That matches the
//! convention used by every other `crates/rts-bench/tests/*.rs`
//! integration test, and exercises the full clap-derive → dispatcher
//! → renderer path the maintainer actually hits.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn rts_bench_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-bench"))
}

/// Build a single JSONL tool_use line. The shape matches Claude
/// Code's transcript format (verified against real session files
/// during PR development).
fn tool_use_line(ts: &str, tool: &str, input_json: &str) -> String {
    format!(
        r#"{{"type":"assistant","timestamp":"{ts}","message":{{"role":"assistant","content":[{{"type":"tool_use","id":"t","name":"{tool}","input":{input_json}}}]}}}}"#,
    )
}

/// Synthetic mixed-tool session with rts mount signal present.
/// Contents:
/// - 1 `mcp__rts__find_symbol` call (rts-mounted signal),
/// - 1 `Bash(grep)` (a candidate fall-through),
/// - 1 `Bash(cat /tmp/...)` (excluded: tempfile),
/// - 1 `Bash(cargo test)` (excluded: build invocation),
/// - 1 `Read` call (not a candidate, not rts).
///
/// Expected report shape:
/// - total_tool_calls = 5
/// - by_source: Bash=3, Read=1, mcp__rts__*=1
/// - grep_or_rg candidate count = 1
/// - rts ratio = 1 / (1+1) = 0.5
fn synthetic_mixed_session() -> String {
    [
        tool_use_line(
            "2026-05-19T14:32:11.000Z",
            "mcp__rts__find_symbol",
            r#"{"name":"foo"}"#,
        ),
        tool_use_line(
            "2026-05-19T14:32:12.000Z",
            "Bash",
            r#"{"command":"grep -rn 'fn foo' crates/"}"#,
        ),
        tool_use_line(
            "2026-05-19T14:32:13.000Z",
            "Bash",
            r#"{"command":"cat /tmp/test.log"}"#,
        ),
        tool_use_line(
            "2026-05-19T14:32:14.000Z",
            "Bash",
            r#"{"command":"cargo test"}"#,
        ),
        tool_use_line(
            "2026-05-19T14:32:15.000Z",
            "Read",
            r#"{"file_path":"/x.rs"}"#,
        ),
    ]
    .join("\n")
}

/// Run `rts-bench dogfood - --report <fmt>` piping `jsonl` over
/// stdin. Returns (stdout, exit_status_code) so tests can assert
/// both content and CLI contract (exit 0 on a happy-path run).
fn run_dogfood(jsonl: &str, fmt: &str, extra_args: &[&str]) -> (String, i32) {
    let mut cmd = Command::new(rts_bench_bin());
    cmd.arg("dogfood")
        .arg("-")
        .arg("--report")
        .arg(fmt)
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn rts-bench");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin.write_all(jsonl.as_bytes()).expect("write");
    }
    let out = child.wait_with_output().expect("wait");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    if code != 0 {
        eprintln!("stderr: {}", String::from_utf8_lossy(&out.stderr));
    }
    (stdout, code)
}

/// Smoke test 1: hand-crafted JSONL with known mix → assert counts.
///
/// What this verifies: the parser + report assembly correctly
/// flattens a multi-tool session into the expected `by_source` map,
/// the `total_tool_calls` counter, and the `mcp__rts__*` bucket
/// rollup. Without this guard, a regression that double-counted
/// tool_uses or dropped the rts prefix bucket would silently land.
#[test]
fn parses_synthetic_session() {
    let (stdout, code) = run_dogfood(&synthetic_mixed_session(), "json", &[]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert_eq!(parsed["total_tool_calls"], 5);
    assert_eq!(parsed["by_source"]["Bash"], 3);
    assert_eq!(parsed["by_source"]["Read"], 1);
    assert_eq!(parsed["by_source"]["mcp__rts__*"], 1);

    // 1 rts call + 1 grep candidate → ratio = 0.5
    let ratio = parsed["rts_vs_bash_ratio_in_navigation_contexts"]
        .as_f64()
        .expect("ratio f64");
    assert!((ratio - 0.5).abs() < 1e-6, "expected 0.5, got {ratio}");

    // Candidate detail: just the grep call; cat /tmp/* + cargo excluded.
    let details = parsed["candidate_bash_commands"]
        .as_array()
        .expect("details array");
    assert_eq!(details.len(), 1);
    assert_eq!(details[0]["would_prefer"], "mcp__rts__grep");
}

/// Smoke test 2: a Bash(`grep`) call is classified as an
/// `mcp__rts__grep` candidate fall-through.
///
/// What this verifies: the dogfood report's `would_prefer` mapping
/// stays pinned to `mcp__rts__grep` for the grep family. If somebody
/// renames the rts tool surface and forgets to update the classifier,
/// this test catches the drift before it ships.
#[test]
fn classifies_grep_bash_as_rts_candidate() {
    // rts mount signal is required for the default filter to count
    // the Bash call. Inline a single `mcp__rts__*` call before the
    // grep so the session is "rts-mounted".
    let jsonl = [
        tool_use_line(
            "2026-05-19T14:32:10.000Z",
            "mcp__rts__outline_workspace",
            "{}",
        ),
        tool_use_line(
            "2026-05-19T14:32:11.000Z",
            "Bash",
            r#"{"command":"grep -rn pattern ."}"#,
        ),
    ]
    .join("\n");

    let (stdout, code) = run_dogfood(&jsonl, "json", &[]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert_eq!(parsed["bash_candidate_fallthroughs"]["total"], 1);
    assert_eq!(parsed["bash_candidate_fallthroughs"]["grep_or_rg"], 1);
    assert_eq!(
        parsed["candidate_bash_commands"][0]["would_prefer"],
        "mcp__rts__grep"
    );
    assert!(
        parsed["candidate_bash_commands"][0]["command"]
            .as_str()
            .unwrap()
            .contains("grep"),
    );
}

/// Smoke test 3: `--report json` output parses cleanly back through
/// `serde_json`.
///
/// What this verifies: the JSON shape is round-trip stable. Tests
/// that consume the dogfood JSON shape downstream (post-hoc analysis
/// pipelines) need a guarantee that the harness emits valid JSON
/// even on edge cases.
#[test]
fn json_report_is_valid_json() {
    let (stdout, code) = run_dogfood(&synthetic_mixed_session(), "json", &[]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(parsed["schema_version"], "dogfood-v0");
    assert!(parsed["candidate_bash_commands"].is_array());
    // Required top-level fields per the schema.
    for field in [
        "session_path",
        "total_tool_calls",
        "by_source",
        "bash_candidate_fallthroughs",
        "rts_vs_bash_ratio_in_navigation_contexts",
        "rts_mounted_only",
    ] {
        assert!(parsed.get(field).is_some(), "missing field: {field}");
    }
}

/// Smoke test 4: `--report text` produces a stable set of section
/// headings smoke-testable by string match.
///
/// What this verifies: section headings the maintainer relies on
/// when eyeballing output stay stable. Renames here would break
/// grep-driven downstream parsing (e.g. piping into `awk` to extract
/// just the ratio line).
#[test]
fn text_report_renders() {
    let (stdout, code) = run_dogfood(&synthetic_mixed_session(), "text", &[]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Tool calls: 5 total"), "{stdout}");
    assert!(stdout.contains("By tool source:"), "{stdout}");
    assert!(stdout.contains("candidate fall-throughs"), "{stdout}");
    assert!(stdout.contains("Rts-vs-Bash ratio"), "{stdout}");
}

/// Bonus guard: when rts was NEVER mounted in the session and
/// `--rts-mounted-only` is on (default), classification is skipped
/// and the report explicitly reports the filter dropped the call.
///
/// What this verifies: the filter behavior is observable in the
/// report. Without this guard, a session that nobody ran with rts
/// could yield a high fall-through count that looks like an agent
/// bug rather than "rts wasn't available".
#[test]
fn rts_not_mounted_session_filters_candidates() {
    let jsonl = tool_use_line(
        "2026-05-19T14:32:11.000Z",
        "Bash",
        r#"{"command":"grep -rn pattern ."}"#,
    );

    let (stdout, code) = run_dogfood(&jsonl, "json", &[]);
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(parsed["bash_candidate_fallthroughs"]["total"], 0);
    assert_eq!(parsed["events_dropped_filter"], 1);

    // Same fixture with the filter explicitly disabled → DOES count.
    let (stdout2, code2) = run_dogfood(&jsonl, "json", &["--rts-mounted-only=false"]);
    assert_eq!(code2, 0);
    let parsed2: serde_json::Value = serde_json::from_str(&stdout2).expect("valid JSON");
    assert_eq!(parsed2["bash_candidate_fallthroughs"]["total"], 1);
}
