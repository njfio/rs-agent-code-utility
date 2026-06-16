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
async fn grep_structural_string_literal_with_text_filter() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    // The fixture's `format!("w#{w}")` contains a string literal. Scope
    // to `string_literal` nodes and filter to those containing `w#` —
    // the thing plain grep cannot do (it would also match comments/code).
    let out = env
        .run(&[
            "--no-color",
            "grep",
            "w#",
            "--structural-query",
            "(string_literal) @s",
            "--language",
            "rust",
        ])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "string-literal match expected; stdout={stdout:?} stderr={stderr:?}"
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(!lines.is_empty(), "expected a string-literal match");
    for line in &lines {
        let p: Vec<&str> = line.splitn(4, ':').collect();
        assert_eq!(p.len(), 4, "ripgrep shape required; got {line:?}");
        assert!(p[1].parse::<u32>().is_ok(), "line numeric; got {p:?}");
        assert!(p[2].parse::<u32>().is_ok(), "col numeric; got {p:?}");
        // Content is the captured node text — a string literal with `w#`.
        assert!(
            p[3].contains("w#"),
            "content should be the matched string literal; got {p:?}"
        );
        assert_content_on_reported_line(env.workspace_path(), &p);
    }
}

/// Verify the ripgrep contract for structural matches: the reported
/// `path:line:col` actually points at the displayed content. Guards the
/// multi-capture coordinate bug where the rendered capture could start on
/// a different line than the enclosing match range.
fn assert_content_on_reported_line(workspace: &std::path::Path, parts: &[&str]) {
    let (path, line_no, content) = (parts[0], parts[1], parts[3]);
    let src = std::fs::read_to_string(workspace.join(path))
        .unwrap_or_else(|e| panic!("read {path}: {e}"));
    let n: usize = line_no.parse().unwrap();
    let actual = src.lines().nth(n - 1).unwrap_or_else(|| {
        panic!(
            "reported line {n} out of range for {path} ({} lines)",
            src.lines().count()
        )
    });
    assert!(
        actual.contains(content.trim()),
        "reported {path}:{n} must contain shown content {content:?}; line is {actual:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grep_structural_identifier_usages() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    // `make_widget` appears as a definition (hub.rs) and call sites
    // (callers.rs). `(identifier) @i` + text filter finds the usages.
    let out = env
        .run(&[
            "--no-color",
            "grep",
            "make_widget",
            "--structural-query",
            "(identifier) @i",
            "--language",
            "rust",
        ])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "make_widget usages expected; stdout={stdout:?} stderr={stderr:?}"
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() >= 2,
        "expected multiple make_widget identifier usages; got {lines:?}"
    );
    for line in &lines {
        let p: Vec<&str> = line.splitn(4, ':').collect();
        assert_eq!(p.len(), 4, "ripgrep shape required; got {line:?}");
        assert!(
            p[3].contains("make_widget"),
            "content should be the identifier; got {p:?}"
        );
        assert_content_on_reported_line(env.workspace_path(), &p);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grep_structural_limit_does_not_truncate_before_filter() {
    // Regression for #147. `format_widget` is the *last* fn def in
    // hub.rs, so it is never among the first identifier node scanned.
    // With `--limit 1` the old code capped the raw structural scan at 1
    // node (`make_widget`), then applied the text filter → 0 matches.
    // The limit must bound RETURNED matches, so the scan has to continue
    // past the filtered-out nodes and still find `format_widget`.
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env
        .run(&[
            "--no-color",
            "grep",
            "format_widget",
            "--structural-query",
            "(identifier) @i",
            "--language",
            "rust",
            "--glob",
            "**/hub.rs",
            "--limit",
            "1",
        ])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "limit=1 must still find format_widget (not truncate before the \
         text filter); stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.lines().any(|l| l.contains("format_widget")),
        "expected format_widget match; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grep_structural_limit_caps_returned_matches() {
    // The limit must still be enforced on the returned set. `make_widget`
    // occurs 4× (def + use + 2 call sites); `--limit 2` returns exactly 2.
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    let out = env
        .run(&[
            "--no-color",
            "grep",
            "make_widget",
            "--structural-query",
            "(identifier) @i",
            "--language",
            "rust",
            "--limit",
            "2",
        ])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_eq!(
        code, 0,
        "expected matches; stdout={stdout:?} stderr={stderr:?}"
    );
    assert_eq!(
        stdout.lines().count(),
        2,
        "limit=2 must cap returned matches to 2; got {stdout:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grep_structural_without_language_errors() {
    let env = TestEnv::new();
    seed_minimal_rust_workspace(env.workspace_path());

    // `--structural-query` requires `--language`; the daemon rejects the
    // call and the CLI surfaces a non-zero exit with a clear message.
    let out = env
        .run(&[
            "--no-color",
            "grep",
            "make_widget",
            "--structural-query",
            "(identifier) @i",
        ])
        .await;
    let (stdout, stderr, code) = parts(&out);
    assert_ne!(
        code, 0,
        "structural query without --language must fail; stdout={stdout:?}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("language"),
        "error should mention the language requirement; got {combined:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grep_structural_combine_scans_past_the_row_cap() {
    // Regression for #152. With more than STRUCTURAL_MAX_ROWS (4096)
    // structural nodes before the match, the combine (text) filter must
    // still find it: the filter runs INLINE so the cap counts post-filter
    // matches, not raw nodes. The old post-pass capped 4096 raw
    // identifiers first (none matching), then filtered → empty.
    let env = TestEnv::new();
    std::fs::write(
        env.workspace_path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    // 5000 padding fn-name identifiers, then the unique target LAST — so
    // it sits past the 4096 cap in document scan order.
    let mut src = String::with_capacity(120_000);
    for i in 0..5000 {
        src.push_str(&format!("pub fn pad_{i}() {{}}\n"));
    }
    src.push_str("pub fn zzz_unique_target() {}\n");
    std::fs::write(env.workspace_path().join("big.rs"), src).unwrap();

    // Structural grep scans the committed file set; on a debug daemon
    // indexing 5k fns can lag the first call. Poll until ready (or the
    // deadline) so the test asserts the cap behavior, not a cold-index
    // race. The target is past the 4096-node cap, so finding it at all is
    // the regression signal.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut last = String::new();
    loop {
        let out = env
            .run(&[
                "--no-color",
                "grep",
                "zzz_unique_target",
                "--structural-query",
                "(identifier) @i",
                "--language",
                "rust",
            ])
            .await;
        let (stdout, _stderr, _code) = parts(&out);
        if stdout.lines().any(|l| l.contains("zzz_unique_target")) {
            return; // found past the cap → fix works
        }
        last = stdout;
        assert!(
            std::time::Instant::now() < deadline,
            "target identifier past the 4096-node cap was never found \
             (issue #152); last stdout={last:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
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
