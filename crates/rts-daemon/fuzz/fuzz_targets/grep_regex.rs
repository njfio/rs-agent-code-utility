//! Fuzz target: arbitrary byte slice → regex compile under the
//! daemon's `Index.Grep { regex: true }` budget.
//!
//! Per RESILIENCE.md §"ReDoS (catastrophic backtracking)" the daemon
//! enforces the regex crate's default DFA size limit on the
//! single-line path and an explicit 32 MiB limit on the multiline
//! path. This target reproduces both shapes against arbitrary input.
//!
//! What this catches:
//! - panics during pattern compile or match (regex crate bugs)
//! - hangs that exceed libfuzzer's per-input wall-clock
//! - memory blow-ups past the configured DFA budget
//!
//! What this does NOT catch:
//! - daemon-side dispatch bugs (wire-shape, cancel_id handling).
//!   Those are covered by the property tests under
//!   `tests/adversarial_proptest.rs`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(pattern) = std::str::from_utf8(data) else {
        return;
    };
    // Mirror the daemon's input-length cap (the `compose::validate`
    // rejection that fires before any compile attempt). Anything past
    // this would short-circuit upstream.
    if pattern.is_empty() || pattern.len() > 1024 {
        return;
    }

    // Single-line path: regex crate defaults. The daemon maps a
    // compile failure to INVALID_PARAMS — we just want to confirm the
    // compile call doesn't panic on adversarial input.
    let mut single = regex::bytes::RegexBuilder::new(pattern);
    single.case_insensitive(true);
    let _ = single.build();

    // Multiline path: explicit 32 MiB DFA + NFA caps matching
    // `MULTILINE_DFA_SIZE_LIMIT` / `MULTILINE_NFA_SIZE_LIMIT` in
    // `methods/grep_v2/multiline.rs`.
    let mut multi = regex::bytes::RegexBuilder::new(pattern);
    multi
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .multi_line(true)
        .size_limit(32 * 1024 * 1024)
        .dfa_size_limit(32 * 1024 * 1024);
    if let Ok(re) = multi.build() {
        // Run one match against a small fixed buffer so we exercise
        // the run-time DFA path, not just the compile path. The
        // input is bounded so even a worst-case pattern can't burn
        // libfuzzer's per-input budget here.
        let haystack: &[u8] = b"the quick brown fox jumps over the lazy dog\n\
            fn main() { let x = 1; }\n\
            // multiline\nsignature\nspanning\n";
        let _ = re.is_match(haystack);
    }
});
