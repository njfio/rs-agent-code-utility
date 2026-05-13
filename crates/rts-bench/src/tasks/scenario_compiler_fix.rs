//! Scenario task: "agent fixes a compiler error at file:line."
//!
//! This is the **real-agent-loop bench** that closes the dogfooding-eval
//! honesty gap from alpha.23. The existing per-task benches measure
//! isolated single-call wins; this one chains the calls a real agent
//! would make when responding to a compiler error.
//!
//! ### Scenario
//!
//! Agent receives `error[E0308] mismatched types --> src/foo.rs:42:18`
//! and wants to (a) see the containing function, (b) understand what
//! it references, (c) inspect the type of one referenced symbol.
//!
//! ### Baseline (no MCP)
//!
//! 1. `rg -n "<symbol>"` to locate every mention of one symbol in the
//!    enclosing fn (we approximate the referenced-symbol set via the
//!    `symbol_name` task input — a real agent wouldn't know it
//!    upfront, but neither path gets to magic-up names from thin air).
//! 2. Read the file containing the line in full (no symbol-end
//!    awareness — the agent doesn't know where the fn ends).
//! 3. For one referenced symbol, `rg -n` and read the containing files.
//!
//! ### MCP (with this slice's new tools)
//!
//! 1. `read_symbol_at(file, line, include_dependencies=true)` → one
//!    call returns the containing fn body + signatures of its
//!    referenced symbols. No "read the whole file" anymore.
//! 2. For one referenced symbol, `read_symbol(name, shape=signature)`
//!    — one call, signature only.
//!
//! Two MCP calls vs ~3-4 grep+read sequences. **This is the loop
//! `read_symbol_at` was built for.**

use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use serde_json::json;

use crate::baseline;
use crate::mcp_runner::{McpRun, McpSession};
use crate::tasks::{TaskContext, TaskOutcome};

/// Cap on baseline file reads — a real agent doesn't open every
/// ripgrep hit, just the first few.
const BASELINE_MAX_FILES: usize = 4;

pub async fn run(ctx: &TaskContext<'_>) -> Result<TaskOutcome> {
    let file = ctx.task_inputs["file"]
        .as_str()
        .ok_or_else(|| anyhow!("`file` required for scenario_compiler_fix"))?
        .to_string();
    let line = ctx.task_inputs["line"]
        .as_u64()
        .ok_or_else(|| anyhow!("`line` required for scenario_compiler_fix"))? as u32;
    // The symbol the agent wants to follow up on after seeing the
    // containing fn. A real agent picks this from the dependency
    // closure; the bench hardcodes it as input so the two paths
    // measure the same workload.
    let referenced_symbol = ctx.task_inputs["referenced_symbol"]
        .as_str()
        .ok_or_else(|| anyhow!("`referenced_symbol` required for scenario_compiler_fix"))?
        .to_string();

    let description = format!(
        "Compiler-error fix scenario at `{file}:{line}`. Baseline = `rg` + read each \
         containing file in full, twice (once for the error site, once for the \
         referenced symbol). MCP = `read_symbol_at(...)` with closure walking, then \
         `read_symbol(name, shape=signature)` for the referenced symbol — 2 calls."
    );

    if !baseline::rg_available().await {
        return Err(anyhow!(
            "ripgrep (`rg`) is not on PATH; install it to run this task's baseline."
        ));
    }

    // ---- baseline ----
    // Step 1: agent grepss the file path to figure out where the error is
    // and reads the file in full. We model this as `locate_and_read`
    // over the *file name* (one hit, one full read).
    let file_pattern = regex_escape(&file);
    let baseline_step1 =
        baseline::locate_and_read(ctx.workspace, &file_pattern, BASELINE_MAX_FILES).await?;
    // Step 2: follow-up grep for the referenced symbol, read each file.
    let sym_pattern = regex_escape(&referenced_symbol);
    let baseline_step2 = baseline::locate_and_read(ctx.workspace, &sym_pattern, BASELINE_MAX_FILES)
        .await
        .with_context(|| format!("baseline step 2: rg {referenced_symbol}"))?;

    let baseline_total = crate::baseline::BaselineRun {
        tokens: baseline_step1.tokens + baseline_step2.tokens,
        rg_stdout_bytes: baseline_step1.rg_stdout_bytes + baseline_step2.rg_stdout_bytes,
        file_bytes_read: baseline_step1.file_bytes_read + baseline_step2.file_bytes_read,
        files_read: [baseline_step1.files_read, baseline_step2.files_read].concat(),
        elapsed_ms: baseline_step1.elapsed_ms + baseline_step2.elapsed_ms,
    };

    // ---- MCP ----
    let mcp_start = Instant::now();
    let mut session =
        McpSession::spawn(ctx.rts_mcp_bin, ctx.rts_daemon_bin, ctx.workspace, &[]).await?;

    // Call 1: read_symbol_at with closure walking.
    let at_call = session
        .tools_call(
            "read_symbol_at",
            json!({
                "file": file,
                "line": line,
                "shape": "body",
                "include_dependencies": true,
            }),
            30,
        )
        .await?;

    // Call 2: read_symbol for the follow-up signature.
    let sig_call = session
        .tools_call(
            "read_symbol",
            json!({ "name": referenced_symbol, "shape": "signature" }),
            5,
        )
        .await?;

    session.close().await?;

    let mcp = McpRun {
        tokens: at_call.tokens.saturating_add(sig_call.tokens),
        calls: vec![at_call, sig_call],
        elapsed_ms: mcp_start.elapsed().as_millis(),
    };

    Ok(TaskOutcome::Ran {
        baseline: baseline_total,
        mcp,
        inputs: json!({
            "file": file,
            "line": line,
            "referenced_symbol": referenced_symbol,
            "baseline_max_files": BASELINE_MAX_FILES,
        }),
        description,
    })
}

/// Same shape as the other tasks; inlined to avoid a tiny shared
/// helper module.
fn regex_escape(s: &str) -> String {
    const ESCAPE: &[char] = &[
        '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$',
    ];
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if ESCAPE.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// The integration test in `tests/scenario_compiler_fix_bench.rs`
// inlines its own fixture source — no shared seed helper here. (The
// other tasks have `seed_test_workspace` helpers for legacy reasons;
// new tasks don't need the indirection.)
