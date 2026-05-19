//! Exit-code contract for `rts` — non-trivial enough to deserve a
//! standalone test file. The plan documents:
//!
//!   0 — success with results
//!   1 — success with zero results
//!   2 — invalid argument (clap handles)
//!   3 — daemon error
//!   4 — timeout
//!   5 — workspace resolution error
//!
//! We cover 2 and 5 here (the synchronous failure modes); 0 and 1 are
//! covered by `cli_find.rs`/`cli_grep.rs`; 3 + 4 are integration-tested
//! in the daemon-disconnect tests already shipped (and exercised
//! implicitly when `rts find` hits a bad path).

mod cli_common;

use cli_common::{TestEnv, parts};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_workspace_path_exits_five() {
    let env = TestEnv::new();
    // Don't seed anything; the workspace path we pass is bogus.
    let mut cmd = env.rts();
    cmd.arg("--workspace")
        .arg("/this/path/cannot/possibly/exist/rts_test")
        .arg("find")
        .arg("foo");
    let out = cmd.output().await.expect("spawn rts");
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 5,
        "missing workspace should exit 5; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stderr.contains("rts workspace error"),
        "stderr should announce workspace error; got {stderr:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_subcommand_exits_two() {
    let env = TestEnv::new();
    let mut cmd = env.rts();
    cmd.arg("no-such-subcommand");
    let out = cmd.output().await.expect("spawn rts");
    let (_stdout, _stderr, code) = parts(&out);
    // clap exits 2 on invalid args by default — we don't override
    // that behavior, so the plan's "2 = clap-handled invalid arg"
    // contract is just clap's default.
    assert_eq!(code, 2, "clap rejects unknown subcommand with exit 2");
}
