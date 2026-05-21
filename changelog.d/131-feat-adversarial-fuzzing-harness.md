### Adversarial-input fuzzing + property tests + threat model

Closes the silent-correctness gap that the past 22-PR session arc didn't address. Across PRs #102–#129 the daemon shipped schema-drift gates (#122), tool-description regression tests (#121), and the real-repo CI bench (#123), but none of those exercise the daemon's API surface with **malicious** input — only well-formed input. This PR introduces three layers of adversarial-input coverage and a documented threat model.

#### What

1. **Property tests (`crates/rts-daemon/tests/adversarial_proptest.rs`)** — 6 properties pinning the daemon's promises under adversarial input. Default 32 cases per property locally; CI nightly runs 256 via `RTS_PROPTEST_CASES`. Each property fires inputs end-to-end against a real daemon over the protocol wire (no mocks):
   - `path_canonicalization_never_escapes_root` — `Workspace.Mount { root }` either returns the workspace's canonical root or one of `PATH_TRAVERSAL` / `MOUNT_HAS_SYMLINK` / `INVALID_WORKSPACE_PATH` / `WORKSPACE_MISMATCH`.
   - `cancel_id_length_bounds_never_panic` — `Daemon.Cancel { cancel_id }` rejects out-of-range with `INVALID_PARAMS`; control chars and Unicode within the 1..=256 byte range round-trip cleanly.
   - `find_symbol_unicode_never_panics` — any UTF-8 string is a valid `name` from the daemon's perspective; ZWJ/RTL/NFC/NFD never panic.
   - `grep_literal_unicode_never_panics` — same shape for `Index.Grep { text }`.
   - `regex_compilation_redos_rejected_or_bounded` — OWASP catastrophic-backtracking corpus + random adversarial patterns; each case asserts the daemon responds in <8s.
   - `structural_query_size_cap_bounds_compile` — deeply-nested S-expr bombs, long capture chains, and 128 KiB junk strings.

2. **cargo-fuzz targets (`crates/rts-daemon/fuzz/`)** — two libFuzzer harnesses for the regex compile path and the tree-sitter `Query::new` path. Excluded from the workspace (nightly-only); run via `cargo +nightly fuzz run <target> -- -max_total_time=60`.

3. **Adversarial corpus (`crates/rts-daemon/fuzz/corpus/`)** — committed seed inputs for `grep_regex`, `grep_structural`, `path_traversal`, `unicode_confusables`, `resource_exhaustion`. Each subdirectory has a `README.md` documenting what class of input it covers and which target consumes it.

4. **`RESILIENCE.md`** — top-level threat model documenting what the daemon promises under adversarial input. Each promise cites its property test or fuzz target. Includes a "Known gaps" section for promises that aren't yet enforced.

5. **Nightly `fuzz-bench` workflow (`.github/workflows/fuzz-bench.yml`)** — peer to `real-repo-bench.yml`. Runs property tests on stable + both fuzz targets on nightly. Cron at `0 8 * * *` (one hour after real-repo bench). Crashes are uploaded as workflow artifacts and surfaced via `::error` annotations.

#### Why

The 22-PR session arc shipped many regression gates against wire shape, schemas, descriptions, and metrics — but every one of those tests assumes a well-behaved caller. The daemon accepts attacker-controllable strings on `Workspace.Mount.root`, `Index.Grep.{text, structural_query}`, `Index.FindSymbol.{name, pattern}`, and `Daemon.Cancel.cancel_id`. Before this PR there was no test that asked "what happens when these are malicious?" — only "what happens when they're well-formed?" This PR closes that gap with a documented, testable threat model.

#### What was found

The harness surfaced two real adversarial-input gaps the daemon does NOT yet enforce. Per the harness's "small bug → fix inline; large bug → document + flag" policy, both are documented in `RESILIENCE.md` §"Known gaps" rather than fixed in this PR:

- **G1 — No explicit byte cap on `structural_query`.** The 1024-char cap is enforced on `text` but not on `structural_query`. A multi-MB S-expression would be passed to tree-sitter's `Query::new` (which in practice rejects quickly, so the risk is bounded — but the explicit cap is missing). Suggested fix: ~30 LOC adding `MAX_STRUCTURAL_QUERY_BYTES = 64 KiB` to `grep_v2/limits.rs`.
- **G2 — Envelope `cancel_id` has no length cap at registration.** `Daemon.Cancel`'s handler validates 1..=256 bytes, but the dispatcher passes the request envelope's `cancel_id` directly to `CancelGuard::register` without bounds. Worst case ~256 MB held in the registry (16 in-flight × 16 MB) for the slowest request's duration. Suggested fix: ~15 LOC mirroring the handler-side check in `methods/mod.rs::dispatch`.

Both are documented for maintainer triage as follow-up PRs.

#### Out of scope

- Runtime sandboxing (capability tokens, seccomp, namespaces) — separate workstream.
- Multi-tenant authentication / authorisation.
- Network-touching fuzz targets — the daemon binds a Unix-domain socket; no network listener exists.
- AFL / honggfuzz — cargo-fuzz (libFuzzer) is the Rust standard and matches the workspace's no-extra-tooling preference.
- Per-PR fuzzing — fuzz is nightly only; the property tests run on every `cargo test`.

#### Quality gates

- `cargo test -p rts-daemon --test adversarial_proptest` — 6 properties pass at default 32 cases.
- `cargo test --workspace` — no regressions.
- `cargo fmt --all` clean.
- `cargo clippy -p rts-daemon -p rts-mcp -p rts-bench --all-targets` clean.
- Zero `unsafe` blocks added.
- cargo-fuzz targets compile (presence is the gate; libFuzzer-finding is the nightly job).

#### Post-deploy monitoring

Watch the nightly `fuzz-bench` workflow's crash count over the next 14 days. Healthy signal: green check on the schedule with no crash artifacts requiring investigation. Failure signal: any crash artifact added to corpus → maintainer triage required, promoted to a regression test in `tests/adversarial_proptest.rs` (NOT silently fed back into the corpus).
