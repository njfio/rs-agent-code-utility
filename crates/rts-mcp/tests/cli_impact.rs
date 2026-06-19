//! `rts impact <SYMBOL> --change <C>` — verify a change's blast radius
//! and render the pass/fail verdict + affected callers.

mod cli_common;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn impact_remove_of_called_fn_is_would_break() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env
        .run(&["--no-color", "impact", "make_widget", "--change", "remove"])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "a resolved verdict exits 0; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("WOULD BREAK"),
        "remove of a called fn should be WOULD BREAK; got {stdout:?}"
    );
    assert!(
        stdout.contains("caller_a") || stdout.contains("caller_b"),
        "expected an affected caller listed; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn impact_remove_of_uncalled_fn_is_safe() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env
        .run(&["--no-color", "impact", "make_circle", "--change", "remove"])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "a resolved verdict exits 0; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("SAFE"),
        "remove of an uncalled fn should be SAFE; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn impact_unknown_symbol_exits_no_results() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env
        .run(&["--no-color", "impact", "make_widgett", "--change", "remove"])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 1,
        "unknown symbol → not_found → NO_RESULTS exit; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("not found"),
        "expected a not-found headline; got {stdout:?}"
    );
}
