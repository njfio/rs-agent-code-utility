//! `rts callers <NAME>` — find direct callers, render tree-grouped.

mod cli_common;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn callers_lists_known_callers_and_groups_by_file() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env.run(&["--no-color", "callers", "make_widget"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "callers of make_widget should be found; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("callers.rs"),
        "expected caller file group header; got {stdout:?}"
    );
    assert!(
        stdout.contains("caller_a"),
        "expected caller_a enclosing name; got {stdout:?}"
    );
    assert!(
        stdout.contains("caller_b"),
        "expected caller_b enclosing name; got {stdout:?}"
    );
}
