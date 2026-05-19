//! `rts outline` — workspace tree summary.

mod cli_common;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outline_emits_dotted_hierarchy() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env.run(&["--no-color", "outline"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "outline of a seeded workspace should succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    // The outline_text from the daemon is dotted-indented per
    // protocol-v0 §7.5. Just check we got a non-empty body containing
    // one of the seeded symbol names.
    assert!(
        stdout.contains("make_widget")
            || stdout.contains("make_circle")
            || stdout.contains("format_widget"),
        "outline should mention at least one seeded symbol; got {stdout:?}"
    );
}
