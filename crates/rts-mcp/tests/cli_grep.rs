//! `rts grep` — ripgrep-shape output validation.
//!
//! The hard contract: each match is `path:line:col:content`. This is
//! what makes `rts grep TODO | awk -F: '{print $1}' | sort -u` work
//! as a drop-in upgrade over `rg TODO`. Drift here breaks every
//! downstream pipeline.

mod cli_common;

use cli_common::{TestEnv, parts, seed_minimal_rust_workspace};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grep_emits_ripgrep_shaped_lines() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env.run(&["--no-color", "grep", "TODO"]).await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "TODO is seeded → exit 0 expected; stdout={stdout:?} stderr={stderr:?}"
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        !lines.is_empty(),
        "expected at least one TODO match in seeded fixture"
    );
    for line in &lines {
        // path:line:col:content — three colon splits, four fields.
        let parts: Vec<&str> = line.splitn(4, ':').collect();
        assert_eq!(
            parts.len(),
            4,
            "ripgrep shape requires path:line:col:content; got {line:?}"
        );
        assert!(
            parts[1].parse::<u32>().is_ok(),
            "line field must be numeric; got {parts:?}"
        );
        assert!(
            parts[2].parse::<u32>().is_ok(),
            "col field must be numeric; got {parts:?}"
        );
        // Content must contain the matched literal (case-insensitive).
        assert!(
            parts[3].to_lowercase().contains("todo"),
            "content must contain matched literal; got {parts:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grep_no_match_exits_one_with_no_output() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env
        .run(&["--no-color", "grep", "no_such_string_anywhere_xyz_42"])
        .await;
    let (stdout, _stderr, code) = parts(&out);
    assert_eq!(
        code, 1,
        "no matches → exit 1 (rg convention); got stdout={stdout:?}"
    );
    assert!(
        stdout.is_empty(),
        "no-match stdout must be empty for clean piping; got {stdout:?}"
    );
}
