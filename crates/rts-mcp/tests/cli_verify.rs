//! `rts verify <FILE>` — check a file's symbol/import references against
//! the index and report hallucinated (not_found) references.
//!
//! Exit-code contract (mirrors the rg-style convention in `rts.rs`):
//!   0 — clean (or unsupported language / nothing to check)
//!   1 — ≥1 hallucinated reference found
//!   3 — daemon error / not reachable

mod cli_common;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_real_symbol_file_is_clean() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    // A file that only references symbols that exist in the index
    // (`make_widget` is defined in the seeded `hub.rs`).
    let file = env.workspace_path().join("good.rs");
    std::fs::write(&file, "pub fn use_it() { let _ = make_widget(7); }\n").unwrap();

    let out = env
        .run(&["--no-color", "verify", file.to_str().unwrap()])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "all references resolve → clean exit 0; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "clean file emits no hallucination lines; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_invented_symbol_file_exits_one_and_names_it() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    // References a symbol that does NOT exist anywhere in the index.
    let file = env.workspace_path().join("bad.rs");
    std::fs::write(
        &file,
        "pub fn use_it() { let _ = totally_invented_symbol(1, 2); }\n",
    )
    .unwrap();

    let out = env
        .run(&["--no-color", "verify", file.to_str().unwrap()])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 1,
        "a hallucinated reference → exit 1; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("totally_invented_symbol"),
        "expected the invented symbol named in output; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_unsupported_language_is_clean_silent() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    // Go has no F3 reference extraction → "nothing checkable" → exit 0.
    let file = env.workspace_path().join("main.go");
    std::fs::write(
        &file,
        "package main\nfunc main() { totally_invented_symbol() }\n",
    )
    .unwrap();

    let out = env
        .run(&["--no-color", "verify", file.to_str().unwrap()])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "unsupported language → exit 0; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "unsupported language emits nothing; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_json_flag_emits_structured_hallucinations() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let file = env.workspace_path().join("bad_json.rs");
    std::fs::write(
        &file,
        "pub fn use_it() { let _ = totally_invented_symbol(1); }\n",
    )
    .unwrap();

    let out = env
        .run(&["--no-color", "--json", "verify", file.to_str().unwrap()])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 1,
        "hallucination present → exit 1; stdout={stdout:?} stderr={stderr:?}"
    );
    let body: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("json parse {e}: {stdout:?}"));
    let halls = body
        .get("hallucinations")
        .and_then(|v| v.as_array())
        .expect("hallucinations array present");
    assert!(
        halls
            .iter()
            .any(|h| h.get("name").and_then(|n| n.as_str()) == Some("totally_invented_symbol")),
        "expected the invented symbol in the json hallucinations; got {stdout:?}"
    );
}
