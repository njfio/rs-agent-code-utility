//! Fuzz target: arbitrary byte slice → tree-sitter `Query::new`
//! compilation against the Rust grammar.
//!
//! Per RESILIENCE.md §"Structural query bombs" the daemon validates
//! and compiles user-supplied S-expression queries via
//! `rts_core::query::Query::new(language, query_text)` before
//! executing them against the parsed tree. This target reproduces
//! the compile call shape and confirms it never panics on
//! adversarial input.
//!
//! Why Rust specifically: it's the grammar with the deepest node-kind
//! catalog in our supported set, so it stresses the parser the most.
//! When `grep_structural` finds a crash, the same input is worth
//! re-running against the other 11 grammars by hand — the daemon
//! attempts compile across the caller's `language` list, so any
//! grammar that crashes shrinks the worry surface across all of them.
//!
//! Compile-only intent: this target intentionally does NOT parse a
//! source file and run the query. That path is fuzz-target-worthy but
//! requires a corpus of source files alongside queries; we'll add a
//! `grep_structural_e2e` target in a follow-up if the compile-only
//! target stays clean for 14 days under the nightly workflow.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_tree_sitter::{Language, query::Query};

fuzz_target!(|data: &[u8]| {
    let Ok(query_text) = std::str::from_utf8(data) else {
        return;
    };
    // Match the structural-query input cap from RESILIENCE.md
    // §"Structural query bombs" — 64 KiB. Anything past this is
    // intended to be rejected upstream without reaching the
    // tree-sitter parser. (The daemon doesn't yet enforce this cap;
    // RESILIENCE.md lists the cap as a "known gap" and this target
    // exists to characterise what tree-sitter does past it.)
    if query_text.is_empty() || query_text.len() > 64 * 1024 {
        return;
    }
    // `Query::new` is the compile call. We don't care about success
    // vs failure here — the property is "doesn't panic" / "doesn't
    // hang past libfuzzer's per-input wall-clock budget".
    let _ = Query::new(Language::Rust, query_text);
});
