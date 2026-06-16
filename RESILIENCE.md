# Resilience — what the rts daemon promises under adversarial input

This document is the tested threat model for the `rts-daemon` (and,
by extension, `rts-mcp` as the agent-facing front). Every claim
listed here has a corresponding property test or fuzz target that
validates it. Promises without coverage are listed in
[Known gaps](#known-gaps) at the bottom and are tracked separately.

## Scope

The daemon accepts attacker-controllable strings on every RPC:
`Workspace.Mount { root }`, `Index.Grep { text, regex, structural_query }`,
`Index.FindSymbol { name, pattern }`, `Daemon.Cancel { cancel_id }`,
and the optional `cancel_id` field on every request envelope. The
threat model here covers what the daemon does when those strings are
malicious — not what it does when they're well-formed, which is the
job of the rest of the test suite.

Out of scope (separate workstreams):

- Runtime sandboxing (capability tokens, seccomp, namespaces).
- Multi-tenant authentication / authorisation.
- Network-facing attack surface — the daemon binds a per-workspace
  Unix-domain socket with mode `0600`; no network listener exists.

## Path traversal

- **Promise:** `Workspace.Mount { root }` canonicalises the user-supplied
  path via `std::fs::canonicalize` and refuses any `..` segments
  outright (`PATH_TRAVERSAL`) and any symlinked workspace root
  (`MOUNT_HAS_SYMLINK`). Canonicalisation failures map to
  `INVALID_WORKSPACE_PATH`. The daemon is workspace-pinned for the
  lifetime of the socket: a second `Workspace.Mount` from the same
  connection asking for a different canonical path returns
  `WORKSPACE_MISMATCH` rather than silently re-pointing the index.
- **Validated by:** `adversarial_proptest::path_canonicalization_never_escapes_root`
  (32 random adversarial path shapes by default, 256 in nightly CI)
  + corpus `crates/rts-daemon/fuzz/corpus/path_traversal/`.
- **Stable wire codes:** `PATH_TRAVERSAL`, `MOUNT_HAS_SYMLINK`,
  `INVALID_WORKSPACE_PATH`, `WORKSPACE_MISMATCH` —
  see `docs/protocol-v0.md` §14.

## ReDoS (catastrophic backtracking)

- **Promise:** `Index.Grep { regex: true }` compiles the user pattern
  with `regex::bytes::RegexBuilder`. The single-line path inherits
  the regex crate's default DFA size cap; the multiline path
  (`multiline: true`) sets an explicit 32 MiB DFA + NFA budget via
  `MULTILINE_DFA_SIZE_LIMIT` / `MULTILINE_NFA_SIZE_LIMIT`. Patterns
  that exceed those budgets — or that fail to compile for any other
  reason — surface as `INVALID_PARAMS` (single-line) or
  `REGEX_TOO_COMPLEX` (multiline, via `data.code`). They never hang
  the daemon past the request's wall-clock budget.
- **Validated by:** `adversarial_proptest::regex_compilation_redos_rejected_or_bounded`
  (curated OWASP backtracking corpus + 32 random adversarial
  patterns by default; each property case asserts < 8 s
  wall-clock) + fuzz target `grep_regex` against
  `crates/rts-daemon/fuzz/corpus/grep_regex/`.
- **Stable wire codes:** `INVALID_PARAMS`, `REGEX_TOO_COMPLEX`
  (multiline path; `data.code` per grep-v2 sub-codes).
- **Source of truth:** `crates/rts-daemon/src/methods/grep_v2/multiline.rs`.

## Structural query bombs

- **Promise (PARTIAL — see "Known gaps" below).** `Index.Grep
  { structural_query }` compiles the user S-expression via
  `rts_core::query::Query::new(language, query_text)` and runs the
  resulting `Query` against parsed trees. Per-execution wall-clock
  budget (`STRUCTURAL_WALL_CLOCK_MS = 5_000`), per-match capture cap
  (`STRUCTURAL_MAX_CAPTURES_PER_MATCH = 64`), and per-capture byte
  cap (`STRUCTURAL_MAX_CAPTURE_BYTES = 8 KiB`) are all enforced.
  Predicate set is the v1 whitelist (`#eq?`, `#not-eq?`, `#match?`,
  `#not-match?`, `#any-of?`, `#is?`, `#is-not?`).
- **Validated by:** `adversarial_proptest::structural_query_size_cap_bounds_compile`
  + fuzz target `grep_structural` against
  `crates/rts-daemon/fuzz/corpus/grep_structural/`.
- **Stable wire codes:** `STRUCTURAL_QUERY_INVALID`,
  `STRUCTURAL_QUERY_TIMEOUT`, `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`,
  `UNKNOWN_LANGUAGE` — see `docs/protocol-v0.md` §14 v2 sub-codes.
- **Source of truth:** `crates/rts-daemon/src/methods/grep_v2/`.

## `cancel_id` bounds

- **Promise:** `Daemon.Cancel { cancel_id }` rejects empty strings and
  strings longer than 256 bytes with `INVALID_PARAMS`. Strings within
  the documented 1..=256 range are accepted regardless of charset
  (control characters, RTL overrides, NFC vs NFD all accepted). An
  unregistered id returns `{cancelled: false}` (idempotent, no
  error).
- **Validated by:** `adversarial_proptest::cancel_id_length_bounds_never_panic`
  (32 random shapes by default, including pure-control-char,
  high-codepoint Unicode, and length boundary cases).
- **Stable wire codes:** `INVALID_PARAMS`.
- **Source of truth:** `crates/rts-daemon/src/methods/daemon.rs::cancel`.

## Unicode handling

- **Promise:** `Index.FindSymbol { name | pattern }` and `Index.Grep
  { text }` accept any UTF-8 string within their length bounds
  without panicking. Specifically: zero-width joiners, RTL overrides,
  NFC/NFD-equivalent strings, and high-codepoint Unicode all
  round-trip — they may produce zero matches, but they never crash
  the daemon. Length validation is byte-length (`.len()`), not char
  count, so a 1000-codepoint multi-byte string may be rejected even
  though it looks "short".
- **Validated by:** `adversarial_proptest::find_symbol_unicode_never_panics`
  + `adversarial_proptest::grep_literal_unicode_never_panics`
  + corpus `crates/rts-daemon/fuzz/corpus/unicode_confusables/`.
- **Stable wire codes:** `INVALID_PARAMS`, `SYMBOL_NOT_FOUND`,
  `INDEX_NOT_READY`.

## Resource exhaustion

- **Promise:** The dispatcher enforces a 16 MiB request envelope cap
  (`MAX_MESSAGE_BYTES`, §3.3). The per-method handlers enforce their
  own input-shape caps: `Index.Grep { text }` 1..=1024 chars,
  `Index.FindSymbol { name | pattern }` 1..=256 chars, `Daemon.Cancel
  { cancel_id }` 1..=256 bytes. Each input cap is wired to
  `INVALID_PARAMS` upstream of any compile / parse / scan work, so an
  attacker cannot drive multi-megabyte arena allocations by sending a
  malformed request.
- **Validated by:** the four proptest length-bound properties listed
  above. Each one generates inputs both inside and outside the
  documented range and asserts the rejection code matches the spec.
- **Stable wire codes:** `INVALID_PARAMS`, `MESSAGE_TOO_LARGE`.

## Concurrent-query DoS

- **Promise:** The per-connection in-flight cap is 16; further
  in-flight requests on the same connection return `BUSY`. The
  per-request deadline is client-supplied (`deadline_ms`); rts-mcp
  stamps a 30 s default (`RTS_DEADLINE_MS`) and on expiry the daemon
  returns `DEADLINE_EXCEEDED`. The
  cancellation registry uses a single `RwLock<HashMap>` keyed on
  the client-supplied `cancel_id` — bounded by the in-flight cap
  and unregistered automatically via `CancelGuard` on handler
  return/panic.
- **Validated by:** existing wire round-trip tests in
  `crates/rts-daemon/tests/cancel_in_flight.rs` cover the in-flight /
  cancel-during-flight semantics; this PR's harness does NOT add a
  property test against concurrent DoS specifically (one connection
  is shared across all proptest cases). Adding a concurrent-stress
  property test would require multiple daemon connections; filed for
  the post-deploy follow-up.

## What's NOT promised

- The daemon does not normalize, sanitize, or otherwise transform
  input strings beyond the per-method validation listed above. If
  you're an MCP / agent host needing additional input filtering
  (e.g. for an audit log that should not contain RTL overrides),
  filter at your layer.
- The daemon does not implement rate limiting. A misbehaving client
  with a working socket can saturate one connection's 16 in-flight
  slot indefinitely — at which point new requests on that socket get
  `BUSY`. Hard rate-limiting is filed as a follow-up under the
  multi-tenant workstream.
- The daemon is workspace-pinned, not multi-tenant. The Unix-socket
  permission (mode `0600` + per-workspace path under
  `${XDG_RUNTIME_DIR}/rts/`) is the only access control. If you need
  multi-tenant isolation, spawn one daemon per tenant.

## Known gaps

These are real adversarial cases the harness found that the daemon
does NOT yet enforce. Each is filed for the maintainer to triage as
a follow-up PR. None blocked landing this PR per the harness's
"document gaps > silent inline fix" policy.

### G1 — No explicit byte cap on `structural_query`

**Status:** Documented, not enforced.

**What:** `Index.Grep { structural_query }` currently passes the raw
S-expression through to `Query::new(language, text)` with no
explicit length cap on `text` itself. The daemon does enforce the
1024-char cap on `Index.Grep { text }` (the literal/regex source)
and the 16 MiB envelope cap, but a `structural_query` of, say, 8 MiB
is currently allowed to reach the tree-sitter compile step.

**What the harness observed:** Tree-sitter's `Query::new` rejects
malformed S-expressions quickly (well under a second per the
proptest budget), so the practical risk is bounded. But the explicit
cap is missing on the daemon side. RESILIENCE.md §"Structural query
bombs" lists this as PARTIAL.

**Suggested fix (~30 LOC):** Add `MAX_STRUCTURAL_QUERY_BYTES = 64 *
1024` to `crates/rts-daemon/src/methods/grep_v2/limits.rs`, gate it
in `compose::validate` before the `Query::new` call, and surface
`STRUCTURAL_QUERY_TOO_LARGE` as a new sub-code under the existing
`INVALID_PARAMS` envelope (mirrors the `INVALID_TEXT_LENGTH`
pattern). Add a property test pinned to the new cap.

### G2 — Envelope `cancel_id` has no length cap at registration

**Status:** Documented, not enforced.

**What:** Per `crates/rts-daemon/src/methods/mod.rs::dispatch`, the
optional `cancel_id` field on the request envelope is passed
straight to `CancelGuard::register` (in
`crates/rts-daemon/src/cancel.rs`) without a length bound. The
1..=256 cap is enforced in `Daemon.Cancel`'s handler (the cancel
trigger side) but NOT in the registration side. An attacker who
controls a connection could send a request with a 16 MB `cancel_id`
(under the 16 MiB envelope cap) and have it stored in the
`RwLock<HashMap<String, CancelToken>>` for the duration of the
in-flight request.

**What the harness observed:** This is a memory-amplification
vector: ~16 in-flight requests × 16 MB `cancel_id` ≈ 256 MB held in
the registry for the slowest request's duration. Real but bounded:
the in-flight cap is 16, and the writer's IO drains in seconds.

**Suggested fix (~15 LOC):** Apply the same 1..=256 validation in
`dispatch` before calling `CancelGuard::register`. Reject the request
with `INVALID_PARAMS` if `cancel_id.len()` is out of range. Add a
property test that fires arbitrarily-sized envelope `cancel_id` and
asserts rejection.

### G3 — Concurrent-stress harness missing

**Status:** Filed as future work.

**What:** Every property test in this PR uses a single connection.
The daemon's per-connection in-flight cap (16) is exercised by the
existing wire round-trip tests, but the property-test layer does not
generate concurrent in-flight load. A truly malicious client would
saturate concurrent slots across multiple connections to drive
CPU/RAM contention.

**Suggested fix:** Add a multi-connection variant of the harness
that opens N connections and fires M requests per connection in
parallel. Out of scope for this PR (would multiply the per-property
setup cost beyond CI tolerance); track separately.

## Running the property suite locally

```sh
# Default: 32 cases per property; ~8s total on a developer machine.
cargo test -p rts-daemon --test adversarial_proptest

# Deep sweep: 256 cases per property. Matches the nightly CI budget.
RTS_PROPTEST_CASES=256 cargo test -p rts-daemon --test adversarial_proptest

# A single property:
cargo test -p rts-daemon --test adversarial_proptest \
    cancel_id_length_bounds_never_panic
```

## Running the fuzz harnesses locally

The fuzz crate lives at `crates/rts-daemon/fuzz/` and is excluded
from the workspace (libfuzzer-sys is nightly-only). Run via
cargo-fuzz:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

cd crates/rts-daemon
cargo +nightly fuzz run grep_regex -- -max_total_time=60
cargo +nightly fuzz run grep_structural -- -max_total_time=60
```

Crashes land in `crates/rts-daemon/fuzz/artifacts/<target>/`; promote
to a regression test in `tests/adversarial_proptest.rs` if you find
one.

## Nightly CI

The nightly `fuzz-bench` workflow runs both targets for 60 s each at
08:00 UTC daily (one hour after the real-repo bench at 07:00 UTC).
Crashes are surfaced as workflow annotations and the artifact is
uploaded for triage. See `.github/workflows/fuzz-bench.yml`.

## Source-of-truth files

- `crates/rts-daemon/src/methods/workspace.rs` — `Workspace.Mount` validation
- `crates/rts-daemon/src/workspace.rs` — `canonicalize`, `refuse_symlinked_components`
- `crates/rts-daemon/src/methods/index.rs` — `Index.Grep`, `Index.FindSymbol` validation
- `crates/rts-daemon/src/methods/grep_v2/compose.rs` — grep-v2 input matrix
- `crates/rts-daemon/src/methods/grep_v2/multiline.rs` — `REGEX_TOO_COMPLEX` budgets
- `crates/rts-daemon/src/methods/grep_v2/structural.rs` — structural-query budgets
- `crates/rts-daemon/src/methods/grep_v2/limits.rs` — numeric resource budgets
- `crates/rts-daemon/src/methods/daemon.rs::cancel` — `cancel_id` validation
- `crates/rts-daemon/src/cancel.rs` — `CancelRegistry`, `CancelGuard`
- `crates/rts-daemon/src/protocol.rs` — envelope parsing, `MAX_MESSAGE_BYTES`
- `crates/rts-daemon/src/error.rs` — `ProtocolError`, `ErrorCode`
- `docs/protocol-v0.md` §14 — wire error code catalog
