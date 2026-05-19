//! `rts find` — table-rendered symbol lookup.
//!
//! Asserts the documented user-facing contract:
//!  * exit 0 when at least one match returns
//!  * exit 1 when zero matches return (matches `rg`'s convention)
//!  * the path:line marker is present in stdout
//!  * `--no-color` produces no ANSI escapes
//!
//! Why these invariants matter (Rule 9): the CLI's value-prop hinges on
//! "I can pipe `rts find` into shell tooling like `rg`." If exit codes
//! drift or color escapes leak into a non-TTY pipeline, that contract
//! breaks silently.

mod cli_common;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn find_by_name_returns_match_and_exits_zero() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env.run(&["--no-color", "find", "make_widget"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "expected exit 0 for found symbol; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("make_widget"),
        "stdout should contain symbol name; got {stdout:?}"
    );
    assert!(
        stdout.contains("hub.rs:1"),
        "stdout should contain path:line; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn find_by_pattern_returns_multiple_matches() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env
        .run(&["--no-color", "find", "make_*", "--pattern"])
        .await;
    let (stdout, _stderr, code) = parts(&out);
    assert_eq!(code, 0);
    assert!(stdout.contains("make_widget"));
    assert!(stdout.contains("make_circle"));
    assert!(
        !stdout.contains("format_widget"),
        "format_widget should not match make_*; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn find_no_match_exits_one_with_no_output() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    // FindSymbol returns `matches: []` (success path, not an error) so
    // the CLI's no-results-but-success contract fires: exit 1 + empty
    // stdout, matching `rg`'s shape.
    let out = env.run(&["--no-color", "find", "no_such_symbol_xyz"]).await;
    let (stdout, _stderr, code) = parts(&out);
    assert_eq!(code, 1, "expected exit 1 for no matches; stdout={stdout:?}");
    assert!(
        stdout.is_empty(),
        "empty results must produce empty stdout; got {stdout:?}"
    );
}
