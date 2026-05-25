//! `rts read <NAME>` — print symbol source with a header.

mod cli_common;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_emits_source_with_header() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env.run(&["--no-color", "read", "make_widget"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "read of make_widget should succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("make_widget"),
        "header should carry qualified name; got {stdout:?}"
    );
    assert!(
        stdout.contains("pub fn make_widget"),
        "body should contain the function signature; got {stdout:?}"
    );
}
