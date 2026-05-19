//! `rts <cmd> --json` — machine-readable output.
//!
//! Asserts that every subcommand that returns matchable data emits
//! valid JSON when `--json` is set. This is what `jq` pipelines
//! depend on; drift here breaks every script using the CLI.

mod cli_common;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};
use serde_json::Value;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn find_json_emits_parseable_matches_array() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env
        .run(&["--no-color", "--json", "find", "make_widget"])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "json find should succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    let v: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON: {e}\nstdout={stdout:?}"));
    let names: Vec<&str> = v["matches"]
        .as_array()
        .expect(".matches must be an array")
        .iter()
        .filter_map(|m| m["qualified_name"].as_str())
        .collect();
    assert!(
        names.contains(&"make_widget"),
        ".matches[0].qualified_name should reach 'make_widget'; got {names:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grep_json_emits_parseable_matches_array() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env.run(&["--no-color", "--json", "grep", "TODO"]).await;
    let (stdout, _stderr, code) = parts(&out);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(
        v["matches"].is_array(),
        ".matches array must be present; got {v:?}"
    );
}
