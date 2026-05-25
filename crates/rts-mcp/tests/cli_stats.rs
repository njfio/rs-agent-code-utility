//! `rts stats` — daemon per-method call counters.

mod cli_common;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stats_prints_non_empty_counters() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    // First call: warm up the daemon so total_calls > 0 by the time
    // we run stats. (A bare `rts stats` against a fresh daemon would
    // print zero counters, which is still a valid pass — but proving
    // the renderer formats real data is more useful.)
    let _ = env.run(&["--no-color", "find", "make_widget"]).await;
    let out = env.run(&["--no-color", "stats"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "stats should always exit 0; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("daemon"),
        "stats header must include 'daemon'; got {stdout:?}"
    );
    assert!(
        stdout.contains("total:"),
        "stats must include total counter; got {stdout:?}"
    );
    // Daemon.Stats v2 names counters by JSON-RPC method (Pascal-cased
    // wire shape, not MCP tool snake_case). The warmup above bumps
    // `Index.FindSymbol`; if the renderer omitted that row, something
    // is wrong with the per-method table.
    assert!(
        stdout.contains("Index.FindSymbol"),
        "expected Index.FindSymbol method row; got {stdout:?}"
    );
}
