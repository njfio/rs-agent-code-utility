//! `rts find` on a cold machine — no daemon running, no socket
//! present. Asserts the auto-spawn path: the CLI brings up `rts-daemon`
//! itself and the query still resolves.
//!
//! This is the "I just installed rts, what now?" first-impression test.
//! If autobootstrap drifts, every new-user funnel breaks.

mod cli_common;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn autobootstrap_spawns_daemon_on_first_call() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    // No daemon is running for this TestEnv's isolated XDG dirs. The
    // first `rts find` must spawn the daemon, Mount, and return the
    // symbol.
    let out = env.run(&["--no-color", "find", "make_widget"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "autobootstrap should yield exit 0; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("make_widget"),
        "stdout should contain the seeded symbol after autobootstrap; got {stdout:?}"
    );
}
