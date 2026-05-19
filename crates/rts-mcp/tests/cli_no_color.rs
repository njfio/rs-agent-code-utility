//! `NO_COLOR=1` / `--no-color` — no ANSI escapes must reach stdout.
//!
//! The cli pipeline contract: if you pipe `rts ...` into anything that
//! isn't a TTY, escape codes mustn't smuggle through. Two paths feed
//! this: `--no-color` (an opt-in flag) and `NO_COLOR=1` (the
//! <https://no-color.org/> standard). Both must work.

mod cli_common;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};

const ESC: char = '\x1b';

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_color_flag_suppresses_ansi_escapes() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env.run(&["--no-color", "find", "make_widget"]).await;
    let (stdout, _stderr, code) = parts(&out);
    assert_eq!(code, 0);
    assert!(
        !stdout.contains(ESC),
        "--no-color must suppress ANSI escapes; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_color_env_var_suppresses_ansi_escapes() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    // Crucially DON'T pass `--no-color` — only the env var. Per the
    // no-color.org standard, any non-empty value of NO_COLOR is enough.
    let out = env
        .run_with_env(&["find", "make_widget"], "NO_COLOR", "1")
        .await;
    let (stdout, _stderr, code) = parts(&out);
    assert_eq!(code, 0);
    assert!(
        !stdout.contains(ESC),
        "NO_COLOR=1 must suppress ANSI escapes; got {stdout:?}"
    );
}
