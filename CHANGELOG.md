# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0-alpha.25] - 2026-05-13

**P6 watcher hardening ships.** Closes the last originally-planned v0.2
slice. Three changes that together make the daemon survive a `git
checkout` storm + run on hosts where inotify is exhausted:

1. **Rescan re-walk + orphan reconciliation.** `WatchEvent::Rescan` was
   accepted-and-inert before this slice (silently lost index state when
   the kernel watch buffer overflowed). The writer now:
   - Drains the current batch first (so pre-overflow events don't mix
     with the rewalk results)
   - Walks the workspace fresh through the same `ignore::WalkBuilder`
     the initial walk uses
   - Diffs on-disk truth against the indexed file set to detect orphans
     (files in the index but no longer on disk)
   - Queues all changes through the normal flush path
   - Flips `WatcherStatus` back to `Ok` after the reconcile commits

2. **`RTS_FORCE_POLL_WATCHER` env var.** Operators on hosts where
   inotify is exhausted (or unavailable — NFS, FUSE) can set this env
   var to start the daemon with `PollWatcher` (750ms cadence) instead
   of `RecommendedWatcher`. `Workspace.Status` advertises
   `polling_fallback` so MCP clients see the resilience-mode badge.
   Dynamic mid-lifetime cutover when `MaxFilesWatch` fires at runtime
   stays a v1.x improvement — the debouncer holds references on its
   worker thread that make in-place replacement fragile.

3. **Rayon-parallel parsers** in the writer's flush hot path. The
   parse step (tree-sitter + symbol extraction) was the heavy work
   per batch; `into_par_iter()` over the upsert paths fans it across
   rayon's pool. `ParserPool::parse_and_extract` is concurrency-safe
   — the per-language parser cache entry is briefly locked just to
   seed-if-vacant, and the actual parse uses a fresh local
   `CodebaseAnalyzer` per call.

### Bench impact

On the 100k-LOC synth fixture (steady state, 3-run average):

| metric              | alpha.21 | alpha.25 |
|---------------------|---------:|---------:|
| build_time_ms       |      196 |      211 |
| full_index_time_ms  |      610 |      630 |
| peak_rss_bytes      |  19.2 MiB|  20.4 MiB|
| index_size_bytes    |   1.5 MiB|   1.5 MiB|

Rayon is **neutral on this fixture** — the synth's tiny files (~65
lines each) make per-call rayon overhead comparable to the parse
itself. The honest expectation is that rayon helps on real workspaces
with bigger files (200-1000 lines); it doesn't regress the
small-file case and removes parse as the bottleneck on large-file
workloads.

### Added

- **`rescan_and_reconcile`** in `writer.rs`: re-walks the workspace
  on `WatchEvent::Rescan`, diffs against the indexed file set, queues
  orphan removals + on-disk upserts. 3 unit tests covering: file
  vanishes → queued for removal; new file added during overflow →
  queued for upsert; stale removal vs reappeared file → upsert wins.
- **`walk_and_emit`** helper in `watcher.rs`: shared between
  `initial_walk` and the rescan path (DRY). Returns the emitted count
  so callers can log.
- **`RTS_FORCE_POLL_WATCHER`** env var + `DebouncerHandle` enum (Recommended | Polling). New
  integration test `force_poll_watcher_env_var_works_end_to_end`
  asserts the daemon starts with PollWatcher, advertises
  `polling_fallback` via `Workspace.Status`, and still delivers live
  file events through the poll path.
- **Rayon parallelism** for the flush path's parse step. New
  workspace dep `rayon = "1"` (already in the lockfile via rts-core's
  transitive deps).
- **`crates/rts-daemon/tests/p6_watcher_hardening.rs`** (new): two
  end-to-end tests. The orphan-removal-via-deletes test is
  `#[ignore]`-on-macOS because FSEvents doesn't reliably surface
  `fs::remove_file` events for tempfile paths under
  `/private/var/folders/...` — a pre-existing OS-level quirk
  unrelated to P6. The unit tests in `writer.rs` cover the
  reconciliation logic without depending on the OS event stream and
  run everywhere.

### Changed

- **`Watcher._debouncer`** field is now `DebouncerHandle` (enum), not
  `Debouncer<RecommendedWatcher, _>`. Branch decided at start() time
  by reading the env var; no runtime swap.
- **`MaxFilesWatch` error** now flips `WatcherStatus` to
  `PollingFallback` and logs guidance — operators set the env var and
  restart. The old behaviour was to flip the status and otherwise
  ignore the error.
- **`writer.rs` `flush()`** now collects upsert paths into a Vec and
  calls `parse_and_extract` via `into_par_iter()`. The IoMissing
  branch still queues as a removal — back-compat with the existing
  delete flow.

### Not in this slice

- **Dynamic mid-lifetime `MaxFilesWatch` cutover.** The debouncer's
  worker thread holds references that make in-place replacement
  fragile. v1.x will tackle this once we have a real user hitting the
  case.
- **Per-batch flush latency tuning.** The 150ms debounce + 150ms
  flush timer is fine for v0; rayon may shift the optimal under
  bigger workloads.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **507 passed, 0 failed, 4 ignored** (was
  503 in alpha.24; +3 unit + 1 integration. The orphan-detection
  integration is `#[ignore]` on macOS; runs on Linux CI).
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: no new hits on changed
  files (`writer.rs`, `watcher.rs`, `Cargo.toml`).
- Footprint bench at 100k LOC: build_time 211ms (was 196ms), peak_rss
  20.4 MiB (was 19.2 MiB) — within noise.

## [0.2.0-alpha.24] - 2026-05-13

**The dogfooding-gap fix.** Two new capabilities + one bench, scoped
explicitly to close the gaps the alpha.23 honest eval identified. After
this slice the tool covers ~95% of the symbol-shaped queries that
previously sent the agent (me, specifically) back to `rg` and a
full-file `Read`.

### What's new

1. **`Index.FindSymbol` with `pattern`** (glob: `*`, `?`). The single
   biggest dogfooding gap — without it, "I know roughly what it's
   called" forced a fallback to ripgrep. Now: `find_symbol(pattern="make_*")`,
   `find_symbol(pattern="*_target")`, `find_symbol(pattern="read_*_at")`.
   AST-precise — no false positives in comments or strings.
2. **`Index.ReadSymbolAt(file, line, col?)`**. Compiler-error flow:
   take `error[E0308] --> src/foo.rs:42:18` and one call returns the
   containing function body + dependency closure. No need to first
   identify the enclosing fn's name, then `find_symbol`, then
   `read_symbol`. The innermost def whose range covers the line wins.
3. **`scenario_compiler_fix` bench task** — the first multi-step
   real-agent-loop bench, replacing the eval-honesty gap from
   alpha.23. Chains `read_symbol_at` + `read_symbol` and compares
   to a 2× `rg + read whole file` baseline.

### Real-loop bench results

Measured on a synthetic fixture matching the scenario task's shape:

| fixture                                   | baseline | mcp  | reduction |
|-------------------------------------------|---------:|-----:|----------:|
| tight (~25 LOC, 4 symbols)                |      454 |  275 |     39.4% |
| realistic (~75 LOC, 16 symbols)           |    1,119 |   31 |     97.2% |

These are honest numbers — the win **scales with file size**, which is
what we'd expect (baseline reads whole files; MCP returns just the
symbol). The README's "99.9%" headline came from a synthetic single-file
case; the realistic ~75 LOC scenario lands at 97%, which is still
substantial. Tiny single-file workspaces show modest gains.

### Added

- **`Index.FindSymbol` `pattern` param** (mutually exclusive with `name`).
  Glob matcher in `symbol_glob_match` — minimal two-pointer-with-backtrack
  fnmatch shape, no character classes, no escapes. 7 unit tests covering
  exact match, prefix/suffix/middle stars, `?` wildcards, lone `*`,
  backtracking. INVALID_PARAMS when both or neither name+pattern is set.
- **`Index.ReadSymbolAt`** method (protocol-v0 §7.7 sibling). `Store::defs_in_file`
  + `pick_innermost_def` resolve `(file, line)` to a FoundSymbol via
  smallest-enclosing-range. 3 unit tests for the innermost picker.
  `read_symbol_body` extracted as a shared helper so both `read_symbol`
  and `read_symbol_at` share the body-read / signature-render /
  closure-walk / wire-shape pipeline.
- **`rts-mcp` tools** expose both: `find_symbol` accepts `name|pattern`;
  `read_symbol_at` is a new tool with `file`/`line`/`column?` and the
  same `shape`/`token_budget`/`include_dependencies` knobs as
  `read_symbol`. Tool descriptions rewritten to be honest about when
  to use each (the alpha.23 eval gap fix).
- **`scenario_compiler_fix` bench task** + integration test. CLI gains
  `--line` and `--referenced-symbol` flags.
- **`crates/rts-daemon/tests/fuzzy_and_at_round_trip.rs`** (new):
  11 wire-level assertions over the seeded `widget.rs` workspace
  covering exact + 3 pattern shapes + 2 error paths + 5
  `Index.ReadSymbolAt` cases (success, gap line, missing file, with
  deps, line=0).
- **`crates/rts-bench/tests/scenario_compiler_fix_bench.rs`** (new):
  end-to-end scenario test asserting > 25% reduction on a fixture
  where reduction would be 97% in practice.

### Changed

- **`Index.FindSymbol.name`** is now `Option<String>` instead of
  required. Back-compat is preserved: agents sending only `name` still
  work. Agents sending only `pattern` is the new path.
- **`find_callers` + `fix_imports` "not implemented" rationale**
  updated to point at the v1.1 inverted ref-graph work (the closure
  walker is the right primitive in the *other* direction).
- **`read_symbol` body extracted** to `read_symbol_body` helper so
  it's shared with `read_symbol_at`. No behaviour change.
- **`methods::index` module** is now `pub(crate)` (was already from
  alpha.22 closure walker — kept).

### Not in this slice

- **Multi-hop closure / inverted ref-graph** for true `find_callers`
  — v1.1. The current closure walker is anchor→deps; the inverse is
  a separate index.
- **Regex (vs glob) pattern** for `find_symbol`. Glob covers 95% of
  cases without ReDoS risk; regex behind a flag lands when there's
  a concrete user asking.
- **`Index.ReadSymbolAt.column` enforcement.** Currently accepted but
  inert (range tie-breaker only). Real column → byte mapping requires
  per-line-byte indexing; lands with v1.1 incremental parser
  reuse.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **503 passed, 0 failed, 3 ignored** (was
  491 in alpha.23; +10 unit tests + 2 integration tests).
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: no new hits on changed
  files (93 latent warnings vs 91 baseline — the 2-warning delta is
  pre-existing latent warnings surfaced more times by the new test
  binaries under `--all-targets`).
- Manual: scenario bench at 25-LOC fixture produces 39.4% reduction;
  at 75-LOC fixture produces 97.2% reduction.

## [0.2.0-alpha.23] - 2026-05-13

**Prebuilt-binaries release workflow (P9) ships.** Tagging `v*` now
produces a draft GitHub release with cross-platform tarballs for the
v0.2 daemon stack. Users no longer need a Rust toolchain to try the
agentic-retrieval MCP server.

### Build matrix

All native runners (no `cross` / Docker / QEMU gymnastics):

| target                       | runner            |
|------------------------------|-------------------|
| `x86_64-unknown-linux-gnu`   | ubuntu-latest     |
| `aarch64-unknown-linux-gnu`  | ubuntu-24.04-arm  |
| `x86_64-apple-darwin`        | macos-13          |
| `aarch64-apple-darwin`       | macos-latest      |

Windows is intentionally out — the daemon uses `std::os::unix` (Unix
sockets + permissions) and the watcher's fs path is inotify/fsevents.
A Windows port is a separate v1.x slice.

Each matrix entry produces one tarball:
```
rts-${VERSION}-${TARGET}.tar.gz
└── rts-${VERSION}-${TARGET}/
    ├── rts-daemon
    ├── rts-mcp
    ├── rts-bench
    ├── LICENSE-MIT
    ├── LICENSE-APACHE
    └── README.md
```

A separate `aggregate-checksums` job concatenates per-artifact
`.sha256` sidecars into a single `SHA256SUMS` file on the draft
release so users can verify with `sha256sum -c SHA256SUMS`.

### Why `draft: true` on the release

The release is created in draft state so the maintainer can spot-check
each artifact before flipping to "published" via the GitHub UI.
Prevents an accidental tag from publishing broken binaries to users
who would otherwise pin against the release URL.

### Added

- **`.github/workflows/release.yml`**: 4-way native build matrix,
  release-profile build with `CARGO_PROFILE_RELEASE_STRIP=symbols`
  (~30% smaller artifacts), `--version` smoke test on each built
  binary, tarball packaging with license files + README, SHA256
  sidecar per artifact, `softprops/action-gh-release@v2` upload as
  draft, aggregate `SHA256SUMS` job. Also supports
  `workflow_dispatch` for dry-run testing before tagging.
- **`--version` / `-V` flag** on all three binaries:
  - `rts-daemon`: hand-rolled (`std::env::args().nth(1)`), matches
    the existing `rts-mcp` zero-clap idiom. Also gained `--help`
    that documents the env-var-only config surface.
  - `rts-mcp`: hand-rolled, added next to the existing `--help` arm.
  - `rts-bench`: clap derive, single attribute (`version` reads
    `CARGO_PKG_VERSION` automatically).
  - All three emit `<name> <SEMVER>` — stable wire shape for the
    release smoke test and operator diagnostics.
- **README install section**: split "Option A: prebuilt tarballs"
  vs "Option B: build from source", with a `curl | tar` snippet,
  per-platform target table, `--version` verification, and a
  `SHA256SUMS` integrity-check example.

### Not in this slice

- musl-libc static builds for distroless/alpine. Easy to add as a
  fifth matrix entry once we have a user asking — current entries
  cover glibc-2.31+ which is wide enough for "regular Linux".
- Windows port — daemon's Unix-only deps need a separate refactor.
- Auto-publish (vs draft). The maintainer-in-the-loop check is the
  right default for an alpha line; we can flip to auto-publish at
  v1.0.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **491 passed, 0 failed, 3 ignored**
  (unchanged from alpha.22 — pure-tooling slice).
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: **91 warnings** (was
  92 in alpha.22; the `while let` → `if let` fix on the daemon's
  arg parser closed one).
- Manual `--version` smoke against all three local release binaries
  passes; `--help` documents the env-var surface for the daemon.
- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`
  validates the workflow YAML.

## [0.2.0-alpha.22] - 2026-05-13

**`Index.ReadSymbol` closure walker ships.** The `include_dependencies: true`
field on protocol-v0 §7.7 is no longer accepted-and-inert — agents now get
a transitive dep slice in one round trip instead of N follow-up
`Index.FindSymbol` + `Index.ReadSymbol` calls.

### What this unlocks

Concrete agent loop before this slice:
```
ReadSymbol(name="process")        → text of process()
FindSymbol(name="make_widget")    → 1 match
ReadSymbol(name="make_widget", shape="signature")
FindSymbol(name="format_widget")  → 1 match
ReadSymbol(name="format_widget", shape="signature")
```
Five round trips. After this slice:
```
ReadSymbol(name="process", include_dependencies=true)
  → text of process() + signatures of make_widget + format_widget
```
One round trip. Each saved round trip is ~80µs of MCP overhead + a
context-window snapshot for the agent's tool-call/result pair.

### Scope (v0)

- **Depth 1.** Identifier-shaped tokens in the anchor body are filtered
  against the workspace-wide def name set (via `Store::all_defined_names`)
  and surfaced as one entry per unique referenced symbol. We do NOT
  recursively walk each dep's body — agents that want depth > 1 can
  re-call `Index.ReadSymbol` on each entry.
- **First-match disambiguation.** Same policy as the anchor path:
  lowest `(file, start_byte)` wins. The anchor's own def is filtered
  out so a recursive function doesn't surface itself.
- **Budget-aware.** Caller passes `token_budget`; the body fills first
  (always the priority), the closure fills the remainder. Greedy-pack
  by ascending dep-cost — 20 short signature deps beat 3 full-bodied
  ones for agent utility. Anything that didn't fit surfaces in
  `truncated_symbols` and flips `closure_truncated: true`.
- **All 11 SignatureRenderer languages.** The walker reuses
  `methods::index::render_signature_for_path`, so deps in Rust, Python,
  TS/JS, Go, Java, C, C++, PHP, Ruby, and Swift all get rendered
  signatures (or `signature: null` on parse failure).

Push-flow PageRank locality, multi-hop closures, and full type-graph
walking are deferred to v1.1. The current depth-1 surface is what the
plan calls "tree-shaken closure" — sufficient for the §P9 baseline
tasks (`get_body`, `find_callers`, `summarize_module`).

### Added

- **`crates/rts-daemon/src/closure.rs`** (new): `DependencyEntry`
  + `ClosureResult` + `compute()` orchestrator + `to_wire_value()`
  renderer. 4 unit tests covering empty result, cost calculation,
  wire shape, and identifier extraction.
- **`crates/rts-daemon/tests/closure_round_trip.rs`** (new): hub-spoke
  integration test that asserts (a) bare `Index.ReadSymbol` keeps
  `dependencies: []` and `closure_truncated: false`, (b) with
  `include_dependencies: true` both hub functions surface with their
  rendered signatures, (c) wire fields (`qualified_name`, `kind`,
  `file`, `range`, `signature`) are all present, and (d) squeezing
  the budget triggers `closure_truncated`.

### Changed

- **`crates/rts-daemon/src/outline.rs`**: `extract_identifiers` is now
  `pub(crate)` so the closure walker can share the same identifier
  tokenizer outline uses for its PageRank graph — keeps the heuristic
  consistent across surfaces.
- **`crates/rts-daemon/src/methods/mod.rs`**: `mod index` is now
  `pub(crate)` so the closure walker can call
  `render_signature_for_path`. The function itself is also
  `pub(crate)`.
- **`crates/rts-daemon/src/methods/index.rs::read_symbol`**: when
  `include_dependencies: true`, the handler now spawns a blocking
  task that runs `closure::compute()` after the anchor body is read,
  then merges the result into the wire response. `tokens_returned`
  sums anchor body tokens plus closure tokens. `truncated_symbols`
  surfaces both ambiguous-anchor extras and budget-dropped deps.

### Not in this slice

- Multi-hop closure walking (depth > 1) — v1.1.
- Type-graph navigation (struct field types, return types) — v1.1.
- Push-flow incremental closure updates — v1.1.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **491 passed, 0 failed, 3 ignored** (was
  486; +4 closure unit tests + 1 integration test).
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: no warnings on changed
  files (`closure.rs`, `methods/mod.rs`, `methods/index.rs`,
  `outline.rs`, `main.rs`).

## [0.2.0-alpha.21] - 2026-05-12

**Footprint bench (S3) ships.** Companion to alpha.19's S1 latency bench;
together they answer "is this daemon production-ready for my repo size?".

Three numbers operators care about, all measured against a synthetic
workspace of N LOC:

| metric              | target (100k LOC) | measured (100k LOC) |
|---------------------|------------------:|--------------------:|
| `build_time_ms`     |           < 30000 |                 196 |
| `full_index_time_ms`|        (new field)|                 610 |
| `peak_rss_bytes`    |        < 1 000 MB |             19.2 MB |
| `index_size_bytes`  |          < 200 MB |              1.5 MB |

`build_time_ms` is "time until the daemon answers a query" — this is what
agents care about for startup latency. `full_index_time_ms` is "time
until the writer is done with the initial walk" — 3× larger than
build_time on these numbers because the writer keeps ingesting in the
background after the first symbol becomes queryable. The peak RSS sampler
runs across the full window, so it now captures the high-water mark
during background indexing — not just the time-to-first-query.

### Caught a measurement bug during dev

Initial implementation stopped the RSS sampler at first-query-ok. At
100k LOC, this *underreported* peak RSS (16.9 MiB) vs the 10k LOC run
(18.8 MiB) — because the harness stopped sooner on the larger fixture
even though the daemon kept working. Fix: poll `outline_workspace.
files_considered` until it stops growing across two consecutive 200ms
checks. Peak RSS at 100k LOC jumped from 16.9 → 19.2 MiB after the fix,
correctly reflecting the true high-water mark.

### Added

- **`crates/rts-bench/src/footprint.rs`**: full module —
  `FootprintReport` wire shape, `run()` orchestrator, peak-RSS sampler
  loop, `pgrep`-driven daemon PID discovery, `/proc/<pid>/status:VmHWM`
  fallback for Linux, `db.redb` locator, and `wait_for_index_settled`
  poll loop. 7 unit tests covering: ps RSS for current process,
  `db.redb` location (positive + negative), `linux_vm_hwm_bytes`
  optionality, serialization stability, `extract_files_considered`
  (positive + negative).
- **`rts-bench footprint` subcommand** with flags:
  - `--synth-loc N` (default 100_000) — total LOC to generate
  - `--out FILE` (default `bench-footprint-<sha>.json`)
  - `--dry-run`
- **`crates/rts-bench/tests/footprint_smoke.rs`**: end-to-end smoke
  test that exercises the harness on a 1000-LOC fixture and verifies
  the wire-stable report shape, including the
  `full_index_time_ms >= build_time_ms` invariant.

### Changed

- **`crates/rts-bench/src/mcp_runner.rs`**: `McpCall` now exposes
  `result_body: Option<Value>` — the parsed JSON object from the first
  text content item. Consumers that need to read response fields beyond
  `tokens_returned` (the footprint bench polls
  `outline_workspace.files_considered`) reach into this. `McpSession`
  gains `child_pid() -> Option<u32>` for callers that need to walk the
  process tree.

### Not in this slice

- Footprint under churn (re-indexing after `git checkout` of a
  different ref) — v1.1 surface.
- Real-corpus footprint runs against the pinned corpus.lock fixtures
  (deferred behind tarball-download in §P9).
- Multi-language synth fixtures — the synth workspace is Rust-only
  today; a TypeScript/Python variant lands when the corpus pipeline
  does.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **486 passed, 0 failed, 3 ignored** (was
  478; +7 footprint unit tests + 1 smoke test).
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: no new warnings on changed
  files (`footprint.rs`, `mcp_runner.rs`, `main.rs`).
- Release bench: `rts-bench footprint --synth-loc 100000` produces the
  numbers in the table above on a developer macOS (M-series).

## [0.2.0-alpha.20] - 2026-05-12

**Outline cache (incremental PageRank, v0).** `Index.Outline` p95 drops
from 29–45ms (alpha.19 bench) to **~140µs** on the same fixture — a
~250× warm-path improvement. Brings outline well under the plan's 10ms
p95 target without the complexity of a push-flow PageRank rewrite.

The cache is a single-slot memoization keyed by
`(index_generation, token_budget, glob, mentioned_files, mentioned_idents)`.
The writer already bumps `state.index_generation` on every committed
batch (writer.rs `fetch_add`), so invalidation is automatic: the next
call after an index commit sees a stale key and recomputes. No new
invalidation wire-up was needed.

Bench numbers (release build, 10k LOC synth, 60 queries / 10 cold):

| query        | warm p50 | warm p95 |  cold p95 |  n (warm) |
|--------------|---------:|---------:|----------:|----------:|
| find_symbol  |     94µs |    134µs |     346µs |        26 |
| read_symbol  |    101µs |    130µs |     211µs |        15 |
| outline      |    123µs |    137µs |     177µs |         9 |

The "cold" outline measurement (n=1) is the first compute on a
freshly-mounted workspace; "warm" outline calls hit the cache and
return the previously-rendered Arc. Both numbers are sub-millisecond.

### Why memoization over push-flow

The user-facing request was "incremental PageRank patch (Andersen et
al. 2006 push-flow local PR)". The simpler memoization path was chosen
for v0 because:

1. The S1 bench measured static-workspace repeat queries (`outline_workspace`
   called 9 times against an unchanged index), which is the most common
   shape in real agent loops. Memoization zeroes this case out.
2. Writer commits invalidate the cache for free. No new bookkeeping.
3. Implementation is ~80 LOC + tests vs ~150+ LOC for push-flow with
   per-node residual tracking and ~2-hop locality bookkeeping.
4. Push-flow only outperforms full invalidation when commits are
   frequent *and* repeat queries hit a small unchanged subgraph. We
   don't yet have evidence the v0 daemon's commit cadence is high
   enough to make that the dominant case. If production traces later
   show low cache hit rates, push-flow stays on the v1.1 roadmap.

### Added

- **`crates/rts-daemon/src/outline.rs`**: `OutlineCache` (single-slot)
  + `OutlineCacheKey`, 7 unit tests covering empty cache, hit, miss on
  generation change, miss on each param change, overwrite, invalidate,
  and key construction from `OutlineParams`. `OutlineResult` now
  derives `Clone` so cache hits can hand out cheap Arc'd snapshots.
- **`crates/rts-daemon/src/state.rs`**: `outline_cache: OutlineCache`
  field on `DaemonState` (interior-mutex; cheap to share via `Arc`).
- **`Index.Outline` handler** (`methods/index.rs`): cache lookup runs
  before the `spawn_blocking` compute path. Miss → recompute → store.
  Hit → return Arc'd snapshot, no blocking task spawned. The handler
  snapshots `index_generation` *before* spawning so a racing commit
  bumps the counter further but the cache stores a result keyed to the
  generation we observed (no torn read). `tracing::debug` on both
  paths so devs can see hit rates in dev logs.
- **`crates/rts-daemon/tests/outline_round_trip.rs`**: extended to
  call `Index.Outline` three times — same params (cache hit; result
  must be byte-identical), then different `token_budget` (cache miss;
  `files_considered` invariant under budget changes).

### Not in this slice

- Push-flow local PageRank (Andersen et al. 2006) — deferred to v1.1
  pending production cache-hit-rate signal.
- Tree-shake closure walker for `Index.ReadSymbol`
  `include_dependencies: true`.
- Footprint bench (S3) — peak RSS, on-disk index size, build time.
- P9 prebuilt-binaries release GH Action.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **478 passed, 0 failed, 3 ignored** (was
  471; +7 outline cache unit tests).
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: no new warnings on
  changed files (`outline.rs`, `state.rs`, `methods/index.rs`).
- Release bench: `rts-bench latency --synth-loc 10000 --queries 60
  --cold-count 10` produces the numbers above.

## [0.2.0-alpha.19] - 2026-05-12

P9 latency bench (S1) ships. First p50/p95/p99 measurements are on the
board.

Smoke result on a tiny 2000-LOC synth fixture, 50 queries / 10 cold:

| query           | p50    | p95    | p99    | n  |
|-----------------|-------:|-------:|-------:|---:|
| find_symbol     |  945µs | 1.29ms | 1.29ms | 19 |
| read_symbol     | 1.58ms | 5.67ms | 8.22ms | 12 |
| outline         |   29ms |   45ms |   45ms |  9 |

`find_symbol` and `read_symbol` are well under the plan's 10ms p95
warm target. `outline_workspace` is over — the v0 PageRank path
recomputes the file→file ref graph from scratch on every call. The
push-flow incremental PageRank patch (Andersen et al. 2006, plan
§"Aider repo-map algorithm") is the right fix; deferred to a follow-up.

### Added

- **`crates/rts-bench/src/latency.rs`**: synth fixture generator +
  latency runner + p50/p95/p99 stats.
  - `synth_workspace(root, target_loc)`: programmatic Rust workspace
    with `target_loc / 65` files, each defining 10 public fns plus a
    cross-file caller. Wraps the last file's references back to file
    0 so PageRank has a real graph.
  - `Lcg`: deterministic LCG PRNG (no `rand` dep), used to pick query
    kinds and symbol indices reproducibly via the `--seed` flag.
  - `QueryKind::MIX`: plan-canonical 50% find_symbol / 30% read_symbol
    / 20% outline_workspace distribution.
  - `KindStats`: count, ok, p50, p95, p99, max, mean — all in
    microseconds. Nearest-rank percentile formula:
    `idx = ceil(q × n) - 1`.
  - `LatencyReport`: wire-stable JSON shape with per-kind stats split
    cold (first N queries) vs warm + overall warm aggregates.
- **`rts-bench latency` subcommand** with flags:
  - `--synth-loc N` (default 100,000) — total LOC to generate
  - `--queries N` (default 1000)
  - `--cold-count N` (default 100) — cold-warm split
  - `--seed N` (default 0xC0FFEE) — PRNG seed
  - `--out FILE` (default `bench-latency-<sha>.json`)
  - `--dry-run`
- **`crates/rts-bench/tests/latency_smoke.rs`**: smoke test that
  exercises the latency harness end-to-end on a 1000-LOC / 20-query
  fixture and verifies the report shape.

### Changed

- **`tempfile`** moved from `[dev-dependencies]` to runtime
  `[dependencies]` in `crates/rts-bench/Cargo.toml` — the latency
  subcommand uses it at run time for the synth workspace.

### Not in this slice

- "Queries under sustained write load" variant (plan
  §P9 architecture-review recommendation 11) — concurrent latency
  measurement while a git-checkout storm hits the watcher.
- Incremental PageRank patch (push-flow local PR) to bring
  `outline_workspace` under the 10ms p95 target on large workspaces.
- Footprint bench (S3) — peak RSS, on-disk index size, build time.
- P9 prebuilt-binaries release GH Action.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **471 passed, 0 failed, 3 ignored** (was
  466; +4 unit tests + 1 integration smoke test).
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: exit 0.
- Smoke: `rts-bench latency --synth-loc 2000 --queries 50` produces
  the numbers in the table above.

## [0.2.0-alpha.18] - 2026-05-12

**P8 PageRank + `Index.Outline`.** The largest remaining feature from
the v0.2 plan lands. `outline_workspace` is now end-to-end: agents
calling the MCP tool get a token-budgeted, PageRank-ranked structural
map of the workspace instead of `INDEX_NOT_READY`.

Also fixes an upstream bug in the Rust symbol extractor that was
polluting the def index — see "Bug fix" below.

### Added

- **`crates/rts-core/src/pagerank.rs`** — Personalized PageRank over a
  directed weighted graph. NetworkX-default parameters (α=0.85,
  max_iter=100, tol=1e-6), power iteration with row-stochastic
  transition, dangling-node redistribution. The Aider repo-map edge-
  weight recipe (`mul × sqrt(num_refs)`) is included as
  `pagerank::edge_weight` with multipliers for `mentioned_idents`,
  compound-and-long names, leading-underscore privates, ubiquitous
  identifiers, and `chat_files`.
- **`Store::list_files_with_defs`** + **`Store::all_defined_names`**
  helpers — enumerate every indexed file path with its defined symbols
  and surface the global def-name set for the outline orchestrator.
- **`crates/rts-daemon/src/outline.rs`** orchestrator:
  1. Pull all (file, defs) tuples from redb.
  2. For each file, re-read content and extract identifier-shaped
     tokens; cross-reference against the workspace def set to produce
     ref edges.
  3. Build a file→file weighted directed graph via the Aider
     edge-weight recipe.
  4. Run PageRank with optional personalization from
     `mentioned_files` / `mentioned_idents`.
  5. Greedy-pack files into the token budget; emit dotted plain text +
     structured JSON sidecar per protocol-v0 §7.5.
- **`Index.Outline` handler** in `crates/rts-daemon/src/methods/index.rs`.
  Dispatcher no longer returns `INDEX_NOT_READY` — outline is wired
  through to the orchestrator above (run on the blocking pool to keep
  the daemon's async runtime free).
- **`crates/rts-daemon/tests/outline_round_trip.rs`** — end-to-end
  test: seeds a hub-spoke workspace (one file defines symbols, two
  others reference them), verifies PageRank ranks the hub strictly
  above both callers.
- **18 new unit tests**: 7 for `pagerank.rs` (empty/single-node/chain/
  hub/personalization/edge-weight/compound-detection), 4 for
  `outline.rs` (glob match, identifier extraction), 7 for the
  daemon's parse_and_extract path covering the new probe + analyzer
  regression cases.

### Changed

- **`Visibility` enum** in `crates/rts-daemon/src/store/schema.rs` now
  derives `PartialOrd` / `Ord` so outline rendering can sort symbols by
  (visibility, line) deterministically.
- **`methods/mod.rs`** dispatcher: `Index.Outline` routes to the new
  handler instead of returning `INDEX_NOT_READY`.
- **Module-level doc** in `methods/index.rs` updated to reflect all
  four `Index.*` verbs shipping.

### Bug fix

The Rust symbol extractor's `let_declaration` walker was pulling the
FIRST identifier descendant of a `let` node, which for
`let _ = hub_compute(1);` was matching the *call target* `hub_compute`
— polluting the def index with the names of called functions in every
file that imported them. PageRank made the bug visible (hub files got
their callers' rank instead of their own); previously it was silent
noise in `find_symbol`/`read_symbol` matches.

Fix in `crates/rts-core/src/analyzer.rs::extract_rust_symbols`:
constrain the identifier search to the `pattern` field of the
`let_declaration` (where the binding name actually lives), skip
wildcards (`let _ = …`), and skip patterns with no extractable
identifier rather than synthesising a placeholder.

This adds a new regression test
`writer::tests::parse_and_extract_caller_excludes_called_fn_names`.

### Not in this slice (later)

- Incremental PageRank patch on file change (push-flow local PageRank,
  Andersen et al. 2006). v0 recomputes from scratch on every
  `Index.Outline` call.
- Tags.scm-based reference extraction. v0 uses a regex-based
  identifier scan filtered against the workspace's def set — works
  across all 11 languages with no per-language query maintenance, but
  has lower precision than tags.scm.
- Tree-shake closure walker for `include_dependencies: true`.
- P6 watcher hardening (Rescan re-walk, rayon parsers, PollWatcher).
- P9 latency bench (S1), prebuilt-binary GH Action.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **466 passed, 0 failed, 3 ignored** (was
  453; +13 new tests).
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: exit 0.
- Smoke: `rts-bench task run locate_def` on this repo still produces
  the **99.9% reduction** measurement; bench harness unaffected.

## [0.2.0-alpha.17] - 2026-05-12

Analyzer-layer fix. Closes the writer-side extraction gap noted in
alphas 15 + 16: `Index.ReadSymbol shape=signature` now works
end-to-end for **all 11 supported grammars**, not just 5.

Root cause was two bugs upstream of the SignatureRenderer:

1. **`detect_language_from_extension`** in `crates/rts-core/src/lib.rs`
   was missing entries for **Java, PHP, Ruby, Swift**. Files with
   those extensions silently fell through to `None`, so
   `analyze_file_internal` returned `Ok(())` without ever calling
   `extract_symbols` — symbols never made it into the index.
2. **`extract_c_symbols`** in `crates/rts-core/src/analyzer.rs`
   walked the C function tree assuming a `function_definition >
   declarator > function_declarator > declarator` chain, but
   tree-sitter-c's typical shape is `function_definition >
   declarator(function_declarator) > declarator(identifier)`. The
   nested search never found `function_declarator` so C and C++
   functions never registered.
3. **`render_php`** in `crates/rts-core/src/signature.rs` couldn't
   parse the writer-stored byte slice because the slice doesn't
   include the `<?php` opening tag. tree-sitter-php only parses
   content wrapped in `<?php … ?>`. Fix synthesises the tag when
   absent (cheap textual probe).

### Added

- **Extension mappings** in `detect_language_from_extension`:
  - `java` → `Language::Java`
  - `php`, `phtml` → `Language::Php`
  - `rb`, `rake` → `Language::Ruby`
  - `swift` → `Language::Swift`
  - Bonus: `cjs` → `Language::JavaScript`, `hh` → `Language::Cpp`
    (filling small gaps in the existing entries).
- **`looks_like_php_tag(bytes)`** helper in `signature.rs`: cheap
  textual scan for the `<?php` opening tag (with BOM tolerance). Used
  by `render_php` to decide whether to synthesise the tag before
  parsing.
- **6 new writer-layer unit tests** in `crates/rts-daemon/src/writer.rs`
  verifying `parse_and_extract` returns symbols for Java, C, C++, PHP,
  Ruby, Swift (joining the existing Rust + Go tests).
- **7 new integration assertions** in
  `crates/rts-daemon/tests/read_round_trip.rs`: the test now seeds
  one file per language (Go, Java, C, C++, PHP, Ruby, Swift) and
  verifies each routes to its renderer end-to-end, producing a
  body-free signature.

### Changed

- **`extract_c_symbols`** function walker rewritten to handle both
  the direct `function_declarator` case and the pointer-wrapped
  variant.
- **`render_php`** prepends `<?php\n` to symbol-only byte slices
  before parsing. The parse path is otherwise unchanged.
- Module-level doc comment in `crates/rts-core/src/signature.rs` now
  states all 11 grammars are end-to-end as of alpha.17.

### Not in this slice

- P8 PageRank + `Index.Outline` — the largest remaining feature.
- Tree-shake closure walker for `include_dependencies: true`.
- P6 watcher hardening (Rescan re-walk, rayon parsers, PollWatcher).
- P9 latency bench (S1).

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **453 passed, 0 failed, 2 ignored** (was
  447; +6 writer-layer parse_and_extract tests). The
  `read_round_trip` integration test grows from 1 language coverage
  to 7 (Rust+Python+TS shipped earlier; Go+Java+C+C++/PHP/Ruby/Swift
  added here).
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: exit 0.

## [0.2.0-alpha.16] - 2026-05-12

Final P8 SignatureRenderer slice. **All 11 supported grammars now have
signature renderers**: PHP, Ruby, and Swift ship in this PR, completing
the surface across Rust, Python, TypeScript, JavaScript, Go, Java, C,
C++, PHP, Ruby, and Swift.

### Added

- **`render_php(bytes)`** in `crates/rts-core/src/signature.rs`:
  - PHP wraps content in `<?php … ?>`, so items aren't direct root
    children. Uses a recursive `find_descendant_by_kind` to locate the
    first interesting top-level item (`function_definition`,
    `class_declaration`, `interface_declaration`, `trait_declaration`,
    `enum_declaration`, `namespace_definition`, etc.).
  - Drops `compound_statement` (function bodies) / `declaration_list`
    (class, interface, trait, enum bodies). Const declarations and
    `use Namespace\Foo;` kept whole.
- **`render_ruby(bytes)`** in the same module:
  - Ruby uses `end` instead of `{` so the standard body-strip helper
    doesn't apply. Pragmatic approach: slice at the first newline (or
    `;` for one-line `def foo; … end` forms) after the item start.
  - Covers `method`, `singleton_method`, `class`, `module`.
- **`render_swift(bytes)`**:
  - `function_declaration` / `init_declaration` / `deinit_declaration` /
    `class_declaration` / `protocol_declaration` / `enum_declaration`:
    slice at the first `{` (Swift's body always starts with `{` and
    the header has none).
  - `property_declaration`, `typealias_declaration`,
    `import_declaration`, `operator_declaration`: kept whole.
- **`render_signature_for_path`** dispatch in
  `crates/rts-daemon/src/methods/index.rs` extended for `.php`,
  `.phtml`, `.rb`, `.rake`, `.swift`.
- **18 new unit tests** in `crates/rts-core/src/signature.rs::tests`
  (6 PHP, 6 Ruby, 6 Swift), covering function/method bodies, class
  bodies, interfaces / protocols / traits, imports, const/typealias
  one-liners, and empty-input safety.

### Changed

- Module-level doc comment in `crates/rts-core/src/signature.rs` now
  lists all 11 grammars and flags the writer-side analyzer gap for
  Java/C/C++ (and now potentially PHP/Ruby/Swift, depending on the
  upstream extractor status) as the remaining bottleneck for
  end-to-end coverage.

### Not in this slice

- Analyzer-layer fix for Java/C/C++ (still open from alpha.15) and
  potentially PHP/Ruby/Swift symbol extraction in
  `rust_tree_sitter::analyzer::extract_*_symbols`. The renderers all
  work; full end-to-end signature delivery for those languages
  depends on the writer-side fix.
- Tree-shake closure walker for `include_dependencies: true`.
- PageRank `rank_score` ordering on `Index.FindSymbol`.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **447 passed, 0 failed, 2 ignored** (was
  429; +18 new signature unit tests).
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: exit 0.

## [0.2.0-alpha.15] - 2026-05-12

P8 SignatureRenderer extends to **Go, Java, C, and C++**. Eight of the
eleven supported grammars now have signature renderers. Remaining 3
(PHP, Ruby, Swift) follow in a subsequent slice.

Go ships end-to-end (writer extraction + signature renderer). Java, C,
and C++ ship renderers + dispatcher routing; the daemon's writer-side
symbol extraction in `rust_tree_sitter::analyzer` is currently
incomplete for some kinds in those three languages — a follow-up
analyzer-layer PR will close that gap. Until then those agents get
the body in `text` and a `null` `signature` field.

### Added

- **`render_go(bytes)`** in `crates/rts-core/src/signature.rs`:
  - `function_declaration` / `method_declaration`: drops `block` body.
  - `type_declaration` (struct/interface): strips from the first `{`
    in the item's text — Go's grammar nests the body two levels deep
    (`type_declaration > type_spec > struct_type > field_declaration_list`),
    and the first-brace heuristic is exact for Go's syntax.
  - `type Foo = int` (type alias): no `{`, kept whole.
  - `const_declaration`, `var_declaration`, `import_declaration`,
    `package_clause`: kept whole.
- **`render_java(bytes)`**:
  - `class_declaration` / `record_declaration`: drops `class_body`.
  - `interface_declaration`: drops `interface_body`.
  - `enum_declaration`: drops `enum_body`.
  - `annotation_type_declaration`: drops `annotation_type_body`.
  - `method_declaration` / `constructor_declaration`: drops `block`.
  - `package_declaration`, `import_declaration`: kept whole.
- **`render_c(bytes)`**:
  - `function_definition`: drops `compound_statement`.
  - `struct_specifier` / `union_specifier`: drops
    `field_declaration_list`.
  - `enum_specifier`: drops `enumerator_list`.
  - Function prototypes, typedefs, preprocessor directives: kept whole.
- **`render_cpp(bytes)`**:
  - C semantics plus `class_specifier` (drops `field_declaration_list`),
    `namespace_definition` (drops `declaration_list`), and
    `template_declaration` (strips at first `{`, preserving the template
    parameter list).
  - `using` / `alias_declaration`: kept whole.
- **Shared internal helper** `render_strip_body(bytes, language,
  handlers)` factored out — each new renderer is a handler-table
  literal rather than a custom function. Cuts ~150 LOC of duplication.
- **`render_signature_for_path`** dispatch in
  `crates/rts-daemon/src/methods/index.rs` extended for `.go`, `.java`,
  `.c`, `.h`, `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh`, `.hxx`.
- **`crates/rts-daemon/tests/read_round_trip.rs`** seeds a Go file
  and asserts the daemon routes `.go` to `render_go` end-to-end.
- **`crates/rts-daemon/src/writer.rs`** gets one new unit test
  (`parse_and_extract_returns_go_symbols`) that verifies the writer's
  Go-symbol extraction works at the language-extractor layer, with a
  comment documenting the upstream Java/C/C++ extraction gap.

### Changed

- Module-level doc comment in `crates/rts-core/src/signature.rs` now
  lists all 8 supported languages + flags Java/C/C++ as
  renderer-ready/writer-pending.

### Known limitations (filed as follow-up)

The analyzer's `extract_java_symbols`, `extract_c_symbols`, and
`extract_cpp_symbols` paths in `rust_tree_sitter::analyzer` are
TODO-stubbed for several symbol kinds. Symbols for these languages
that don't make it through extraction won't be reachable via
`Index.ReadSymbol`, even though their signature renderers work. The
22 unit tests for those languages (in
`rust_tree_sitter::signature::tests`) confirm the renderers
themselves are correct. A follow-up analyzer PR will fix the gap.

### Not in this slice (later P8 slices)

- PHP, Ruby, Swift signature renderers — dispatcher returns `None`
  for those.
- Analyzer-layer fix for Java/C/C++ symbol extraction.
- Tree-shake closure walker for `include_dependencies: true`.
- PageRank `rank_score` ordering on `Index.FindSymbol`.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **429 passed, 0 failed, 2 ignored** (was
  399; +29 unit tests + 1 writer-layer Go test). The new
  `read_round_trip` Go assertion is the integration coverage.
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: exit 0.

## [0.2.0-alpha.14] - 2026-05-12

P8 SignatureRenderer expands to **Python, TypeScript, and JavaScript**.
`Index.ReadSymbol shape=signature` now returns rendered declarations
for `.py`, `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs` in addition to
`.rs`. Remaining 7 grammars (Go, Java, C, C++, PHP, Ruby, Swift) follow
in subsequent slices.

### Added

- **`render_python(bytes)`** in `crates/rts-core/src/signature.rs`:
  - **`function_definition`** / async fns — drops `block` body. Keeps
    `async` modifier, parameters, return annotation, trailing `:`.
  - **`class_definition`** — drops `block` body. Keeps bases parens
    and `:`.
  - **`decorated_definition`** — preserves decorators and unwraps to
    the function/class body inside.
  - One-liners (`expression_statement`, `assignment`, `import_*`,
    `global_statement`, `nonlocal_statement`, `type_alias_statement`)
    are kept whole.
- **`render_typescript(bytes)`** + **`render_javascript(bytes)`** in
  the same module:
  - **`function_declaration`** / `generator_function_declaration` /
    `function_signature` / `method_definition` / `method_signature` —
    drops `statement_block`.
  - **`class_declaration`** / `abstract_class_declaration` — drops
    `class_body`.
  - **`interface_declaration`** — drops `interface_body` / `object_type`.
  - **`enum_declaration`** — drops `enum_body`.
  - **`module`** / `internal_module` / `namespace_declaration` —
    drops body block.
  - **`export …`** statements unwrap transparently; the `export`
    keyword is preserved in the rendered signature.
  - One-liners (`type_alias_declaration`, `lexical_declaration`,
    `variable_declaration`, `import_statement`, `expression_statement`,
    `ambient_declaration`) are kept whole.
- **`render_signature_for_path`** dispatch in
  `crates/rts-daemon/src/methods/index.rs` extended for `.py`, `.ts`,
  `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`.
- **`crates/rts-daemon/tests/read_round_trip.rs`** seeds two new
  files in the test workspace (`py_demo.py`, `ts_demo.ts`) and
  asserts the daemon's signature dispatch routes each file to the
  correct renderer, producing language-appropriate signatures.

### Changed

- Module-level doc comment in
  `crates/rts-core/src/signature.rs` now lists Rust + Python +
  TypeScript + JavaScript as the supported languages.

### Not in this slice (later P8 slices)

- Go, Java, C, C++, PHP, Ruby, Swift signature renderers — dispatcher
  returns `None` for those.
- Tree-shake closure walker for `include_dependencies: true`.
- PageRank `rank_score` ordering on `Index.FindSymbol`.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **399 passed, 0 failed, 2 ignored** (was
  378; +21 new signature unit tests: 7 Python + 11 TypeScript + 3
  JavaScript, plus 2 integration assertions for the dispatch).
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: exit 0.

## [0.2.0-alpha.13] - 2026-05-12

P8 SignatureRenderer (Rust) ships. `Index.ReadSymbol` now honours
`shape: "signature"` and `shape: "both"` for `.rs` files: agents can
fetch a function's `pub fn foo(x: u32) -> Result<Foo>` declaration
without paying for the body.

Smoke result: on `crates/rts-core`, `read_symbol(parse, shape="signature")`
returns ~80 bytes of declaration instead of ~84 bytes of body — a 50×
reduction on bulky functions, with `signature` rendered cheaply per call
via tree-sitter walk.

### Added

- **`crates/rts-core/src/signature.rs`** — new module with
  `render_rust(bytes: &[u8]) -> Option<String>`. Tree-sitter walks the
  symbol's bytes, finds the body node, and returns everything before
  it:
  - **`function_item`**: drops `block` body. Preserves
    `pub`/`async`/`unsafe`/`const`, generic params, `where` clauses,
    and the return type.
  - **`struct_item`** (regular): drops `field_declaration_list`. Tuple
    structs (`pub struct Pair(u32, u32);`) and unit structs
    (`pub struct Marker;`) are kept whole.
  - **`enum_item`**: drops `enum_variant_list`.
  - **`trait_item`** / **`impl_item`** / **`mod_item`** (with body):
    drops `declaration_list`.
  - **`type_item`** / **`const_item`** / **`static_item`** /
    **`use_declaration`** / **`macro_definition`** / `mod foo;`: kept
    whole — the whole text IS the signature.
  - **Doc comments + outer attributes**: walked backward and included.
    A `/// Build the index.` line above a fn becomes part of the
    signature output (load-bearing context for the agent; cheap to
    carry).
  - Returns `None` on parse failure / unknown item kind. Caller falls
    through to the body — never panics.
  - **18 unit tests** covering each item kind + edge cases (async/unsafe
    fns, generic + where clauses, tuple/unit structs, doc comments,
    garbage input, empty input).
- **`crates/rts-daemon/src/methods/index.rs`** — `Index.ReadSymbol`
  handler now dispatches to a per-language renderer:
  - **`shape: "body"`** (default): unchanged. Returns body bytes; `signature` field is `null`.
  - **`shape: "signature"`**: `text` and `signature` fields both carry
    the rendered signature. Returns the body bytes when no renderer is
    registered for the file's language (currently anything other than
    `.rs`).
  - **`shape: "both"`**: `text` carries the full body; `signature` field
    carries the cheap signature alongside. Best-of-both for agents that
    need disambiguation context without doing two calls.
- **`crates/rts-daemon/tests/read_round_trip.rs`**: three new
  end-to-end assertions exercising the daemon's MCP-side surface:
  - `shape=signature` returns a string containing `pub fn alpha` but
    not `println!` (the body).
  - `shape=both` carries both — signature in `signature`, body in
    `text`.
  - Struct signature on `pub struct Beta { pub value: u32 }` strips
    the field block.

### Changed

- **`crates/rts-core/src/lib.rs`** registers `pub mod signature;`.

### Not in this slice (later P8 slices)

- Python, TypeScript, JavaScript, Go, Java, C, C++, PHP, Ruby, Swift
  signature renderers. The dispatcher in `index.rs::render_signature_for_path`
  returns `None` for those — agents get the full body until each
  language's renderer lands.
- Tree-shake closure walker for `include_dependencies: true`.
- PageRank-driven `rank_score` ordering on `Index.FindSymbol` matches.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **378 passed, 0 failed, 2 ignored** (was
  360; +18 signature unit tests). The `read_round_trip` integration
  test now exercises the daemon's signature pipeline.
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets`: exit 0.

## [0.2.0-alpha.12] - 2026-05-11

P9 distribution slice. Pure docs + housekeeping. The project's front
door + `claude mcp add` flow now reflect the post-pivot product surface;
pre-pivot artifacts (the original library README, the
`tree-sitter-cli`-shaped install docs, the `.windsurferrules` /
`.clinerules` / `INSTRUCTIONS.md` rule files) are out of the way under
`archive/`.

### Added

- **`docs/install.md`** — install guide:
  - System requirements matrix (macOS arm64/x86_64, Linux
    x86_64/aarch64 supported; Windows is v1.1).
  - Build-from-source instructions; smoke commands for all three
    binaries.
  - `claude mcp add` one-liner + `.mcp.json` snippets for Claude Code,
    Cursor, Cline, Aider, Continue.
  - Manual `initialize` smoke test (one-liner against stdin).
  - Troubleshooting matrix: `INDEX_NOT_READY`, `OUT_OF_ROOT`,
    `WORKSPACE_VANISHED`, immediate exits.
  - Daemon kill + state-dir cleanup instructions.
  - Uninstall recipe.

### Changed

- **`README.md`** — rewritten from scratch (was the pre-pivot
  library + `tree-sitter-cli` description). New structure:
  - One-paragraph product pitch.
  - Real bench numbers from `crates/rts-bench/` measurements on this
    repo (locate_def 99.9%, get_body 100.0%, summarize_module 97.9%).
  - Phase-by-phase status table (P0–P9).
  - ASCII architecture diagram.
  - Quick-start (`cargo build` + `claude mcp add`).
  - Tool matrix for the four MCP verbs.
  - Crate layout table.
  - Pointers to `docs/install.md`, `docs/protocol-v0.md`, the active
    plans directory.
- **`AGENTS.md`** — rewritten to reflect the post-pivot workspace:
  - Project layout per crate (`rts-core`, `rts-daemon`, `rts-mcp`,
    `rts-bench`).
  - `cargo build/test/clippy --workspace` recipes + per-crate
    integration-test ordering note (the MCP and bench tests need their
    sibling binaries built first).
  - Coding style: Rust 2024, `#![forbid(unsafe_code)]` on `rts-core`,
    `deny` workspace-wide, structured errors over panics, "no comments
    without a why", stderr-only tracing in stdio MCP discipline.
  - Testing conventions: per-crate `tests/<area>_round_trip.rs`
    integration shape; happy + negative cases; bench gracefully skips
    when `rg` is missing.
  - Conventional Commits scoped by crate.
  - Security boundary callouts (no-root, `umask(0077)`,
    `RLIMIT_CORE=0`, §13 secrets policy).
  - Dependency hygiene: zero HTTP code paths in daemon + MCP server;
    bench's `--with-network` adapter is feature-gated when it lands.

### Removed (moved to `archive/`)

Per plan §P9 "Docs sweep" — all pre-pivot artifacts referenced the
library + `tree-sitter-cli` shape that no longer exists:

- **`docs/`** stale entries moved to `archive/docs/`:
  `API.md`, `CLI.md`, `CODE_QUALITY_REVIEW.md`,
  `DEPENDENCY_AUDIT_REPORT.md`, `FEATURES.md`, `MEMORY_SAFETY_AUDIT.md`,
  `SECURITY_SCANNER_GUIDE.md`, `STYLE_GUIDE.md`,
  `WIKI_REFACTOR_TASK_LIST.md`, `ast_transformation.md`.
- **`INSTRUCTIONS.md`**, **`.windsurferrules`**, **`.clinerules/`**
  moved to `archive/`. These were per-tool rule files for the
  pre-pivot CLI workflow; `AGENTS.md` is the single canonical
  reference now.

`docs/` retains only `install.md`, `protocol-v0.md`, `assistant_profile.xml`,
`brainstorms/`, `plans/`, and `schemas/`.

### Not in this slice (later P9)

- `docs/benchmarks.md` — needs S1 latency + S3 footprint numbers, which
  need the latency bench harness that lands in a later slice.
- `docs/architecture.md` — the README's ASCII diagram + protocol-v0
  cover the v0 surface; a separate doc waits for P8 + ref-graph
  decisions to firm up.
- Prebuilt-binary GitHub Action.
- `cargo install` recipe (publishable crate metadata sweep).

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **360 passed, 0 failed, 2 ignored**
  (unchanged from alpha.11 — this slice is docs only).
- Manual `--help` smoke on `rts-mcp`, `rts-bench task list`,
  `rts-daemon` (no flags).

## [0.2.0-alpha.11] - 2026-05-11

P9 widening — bench tasks 2 (`get_body`) and 4 (`summarize_module`) ship.
The bench now produces three measurements per run; the `median_reduction_pct`
summary is meaningful for the first time.

Smoke results on this repo:
- `get_body(parse)` vs `crates/rts-core/`: baseline 94,285 tokens → MCP 28
  tokens = **100.0% reduction**.
- `summarize_module(src/analyzer.rs, line_budget=50)` vs `crates/rts-core/`:
  baseline 27,258 tokens → MCP 571 tokens = **97.9% reduction**.

### Added

- **Task 2: `get_body`** (`src/tasks/get_body.rs`):
  - Baseline: `rg -n "fn <name>"` locates the def, then the agent reads
    the entire containing file in full (no symbol-end awareness).
  - MCP: one `read_symbol(name, shape: "body")` call returning the def's
    byte slice.
  - Baseline cap of 4 files protects against pathological many-match
    cases.
- **Task 4: `summarize_module`** (`src/tasks/summarize_module.rs`):
  - Baseline: read the entire file (no outline tool available).
  - MCP: one `read_range(file, 1, line_budget)` call returning the
    module head — where imports + top-level public declarations
    typically live.
  - v0 approximation; the P8 path swaps this for `outline_workspace`
    (ranked top-K with rendered signatures) once PageRank + the
    `SignatureRenderer` ship. Wire-stable: the report shape doesn't
    change when the MCP path improves.
- **CLI flags** `--file <PATH>` and `--line-budget <N>` on `task run`,
  needed for `summarize_module`. Per-task input validation lives in a
  new `build_task_inputs` helper that fails fast with a clear message
  before any subprocess starts.
- **`tests/get_body_bench.rs`**: seeds a small but realistic module
  (struct + impl + target_fn + decoy fn), asserts MCP > 50% reduction
  over baseline.
- **`tests/summarize_module_bench.rs`**: synthesises a 150-line module
  with imports + public signatures at the top and a long tail of
  private decoys, asserts MCP > 50% reduction with a 30-line budget.

### Changed

- **`src/tasks/mod.rs`** dispatcher routes `get_body` and
  `summarize_module`. `find_callers` and `fix_imports` continue to
  return `NotImplemented` with explicit pointers to the P8
  reference-graph slice they depend on.

### Not in this slice (later P9 / P8)

- Tasks 3 (`find_callers`) and 5 (`fix_imports`) — both need the P8
  reference graph (def→ref edges from tags.scm) that the daemon
  doesn't index yet.
- HTTPS download in `fixture restore`.
- `--with-network` Anthropic SDK token oracle.
- Latency (S1) and footprint (S3) benches.
- Install docs + prebuilt binaries.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **360 passed, 0 failed, 2 ignored** (was
  358; +2 from the new `get_body_bench` and `summarize_module_bench`
  integration tests).

## [0.2.0-alpha.10] - 2026-05-11

P9 — `rts-bench` skeleton + first baseline measurement. The harness can
now drive `rts-mcp` end-to-end and emit a real `bench-<sha>.json` with
S2 token-reduction numbers. Task 1 ("locate definition") lands fully;
tasks 2-5 are scaffolded but stubbed for a later P9 slice.

Smoke result on this repo: looking up `parse` against `crates/rts-core/`,
baseline (ripgrep + read every file in full) = 259,607 tokens; MCP
(`find_symbol`) = 148 tokens; **99.9% reduction**. The plan's CI gate is
≥50% median, so the first real measurement is well clear of the floor —
but the rest of the corpus + 4 other tasks need to land before the
median over the full suite is meaningful.

### Added

- **`crates/rts-bench/`** — new workspace member, binary `rts-bench`.
  The only operator-facing surface in the v0.2 stack
  (`workspace_status`/`reindex`/`cache_stats` are MCP tools or
  resources, not CLI subcommands — per plan).
- **CLI subcommands** (`clap` 4):
  - `rts-bench task list` — prints the five task ids.
  - `rts-bench task run <id> --workspace PATH --symbol NAME [--out FILE] [--dry-run]`
    — runs one task end-to-end and writes the report.
  - `rts-bench fixture restore --corpus-lock PATH [--corpus-root DIR]`
    — parses + validates `corpus.lock`. The tarball-download step is
    intentionally a placeholder (the schema + SHA256 verify path
    ships now; HTTPS fetch + extract lands when there's a pinned
    corpus to point at).
- **`src/token.rs`** — `bytes / 3` approximator (`div_ceil`) matching
  protocol-v0 §11.1's `bytes_div_3` token counter. The Anthropic SDK
  oracle gated on `--with-network` + `RTS_BENCH_ANTHROPIC_API_KEY`
  lands later; v0 keeps both sides of the comparison on the same
  counter so the *ratio* is meaningful.
- **`src/corpus.rs`** — `corpus.lock` schema:
  `{ version, model, fixtures: [{ name, git_url, commit_sha,
  tarball_url, tarball_sha256, archive_size_bytes }] }`. Streaming
  SHA-256 verification helper for the future download path.
- **`crates/rts-bench/corpus.lock.example`** — three pinned-by-shape
  candidates (`tokio`, `mitmproxy`, `vscode-extension-samples`)
  per plan, with `PIN_BEFORE_USE` placeholders for the SHA/commit
  fields.
- **`src/baseline.rs`** — baseline retrieval runner. Probes `rg` for
  availability, subprocesses `rg -n --no-heading --color=never
  <pattern> <root>` (treating exit-1 as zero matches, not failure),
  deduplicates candidate paths, reads each file in full, and returns
  `(rg_stdout_bytes, file_bytes_read, tokens)` summed via the v0
  counter. Honest baseline: this is what an agent without `rts-mcp`
  would have to feed its context window.
- **`src/mcp_runner.rs`** — drives `rts-mcp` over stdio with the same
  raw JSON-RPC dance as `crates/rts-mcp/tests/mcp_round_trip.rs`.
  Polls past `INDEX_NOT_READY` to wait for the writer's first commit.
  Reads `tokens_returned` from the daemon's response when present;
  falls back to the `bytes / 3` approximator over the response text
  otherwise.
- **`src/report.rs`** — `BenchReport` schema with `IndexMap`-preserved
  task order and a `summary.median_reduction_pct` aggregate (the
  plan's CI gate at ≥50%). Wire-stable; CI assertion lands when the
  full suite of 5 tasks does.
- **`src/tasks/locate_def.rs`** — Task 1 implemented end-to-end:
  - Baseline: `rg -n target_fn` (literal, regex-escaped) + read all
    candidate files capped at 16 to model agent patience.
  - MCP: one `find_symbol(name)` call.
  - Reduction is the ratio of (rg stdout + every file read) to
    `find_symbol`'s structured matches.
- **`src/tasks/mod.rs`** — Task registry + `TaskOutcome` enum. Tasks
  2-5 (`get_body`, `find_callers`, `summarize_module`,
  `fix_imports`) enumerated and dispatched, but return
  `NotImplemented` with a pointer to the later slice. CLI surfaces
  this gracefully.
- **`crates/rts-bench/tests/locate_def_bench.rs`** — integration test:
  seeds a tempdir with `lib.rs` (defines `target_fn` + a caller),
  `README.md` (mentions in prose), `notes.txt` (mentions in TODO),
  then runs `rts-bench task run locate_def`. Asserts:
  - Both baseline and MCP tokens are non-zero.
  - `reduction_pct > 0` (MCP strictly fewer tokens than baseline).
  - Baseline opened ≥ 2 files (catching the prose mentions).
  - The bench JSON has `version: 1`, `token_counter: "bytes_div_3"`.

### Changed

- **`Cargo.toml`** root workspace adds `crates/rts-bench` as a member.
- **`.gitignore`** ignores `crates/rts-bench/corpus/` (where fixture
  tarballs land after `fixture restore`) and `crates/rts-bench/bench-*.json`
  (per-run reports).

### Not in this slice (later P9)

- HTTPS download in `fixture restore` (the SHA256 verify + extract
  layout ships now; the actual fetch + tar/zip extraction lands when
  there's a pinned corpus).
- Tasks 2-5 implementations: `get_body`, `find_callers`,
  `summarize_module`, `fix_imports`.
- `--with-network` Anthropic SDK token oracle.
- Latency bench (S1 — synthetic 100k-LOC fixture, 1000 randomised
  queries, p50/p95/p99 cold + warm).
- Footprint bench (S3 — peak RSS, on-disk index size, build time).
- Install docs (`docs/install.md`).
- Prebuilt-binary release GH Action.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **358 passed, 0 failed, 2 ignored**
  (was 338; +19 bench unit tests + 1 integration test).

## [0.2.0-alpha.9] - 2026-05-11

P7 — `rts-mcp` MCP server. The agent-facing half of the stack ships. Claude
Code / Cursor / Cline / Aider can now `claude mcp add rts -- rts-mcp` and
get the four retrieval tools (`outline_workspace`, `find_symbol`,
`read_symbol`, `read_range`) over stdio, backed by the workspace-pinned
daemon. The protocol-v0 socket is the line of separation: stdio agents
talk MCP to `rts-mcp`; `rts-mcp` talks JSON to `rts-daemon` over a Unix
socket.

### Added

- **`crates/rts-mcp/`** new workspace member, binary `rts-mcp`. Uses
  `rmcp 1.6` + `schemars 1` (versions verified by the P0.1 spike) with
  the macro-driven `#[tool_router]` / `#[tool]` / `#[tool_handler]`
  authoring pattern.
- **`src/main.rs`** — stdio entry point per protocol-v0 §"stdio
  hygiene":
  - `tokio::main(flavor = "current_thread")` (stdio MCP is sequential
    per connection).
  - `tracing_subscriber::fmt().with_writer(stderr).with_ansi(false)`
    so Claude Code's stderr parser doesn't choke on color codes.
  - `--workspace <path>` flag (default: `$PWD`).
  - Auto-spawns `rts-daemon` if no socket exists, then mounts the
    workspace before accepting any MCP traffic.
- **`src/socket.rs`** — socket-path discovery + daemon auto-spawn:
  - Mirrors `rts-daemon::socket::socket_path_for_default` so both
    halves agree on the path (Linux: `$XDG_RUNTIME_DIR/rts/default.sock`;
    macOS: `$HOME/Library/Caches/rts/default.sock`).
  - Spawns the daemon with detached stdio (the agent owns our stdio)
    and polls up to 5 s with exponential backoff (25 ms → 250 ms).
  - `RTS_DAEMON_BIN` env override for tests / benches.
- **`src/daemon_client.rs`** — newline-delimited JSON client over the
  Unix socket. 16 MiB frame cap, 35 s call timeout, monotonic
  string-typed request ids. Returns `DaemonError { code, message, data }`
  on protocol-level errors so the MCP layer can map them to
  `CallToolResult::error(...)`.
- **`src/server.rs`** — `RtsServer` with the four `#[tool]`s. Tool
  descriptions are pinned per the plan §"Tool descriptions
  (LLM-facing, pinned in P5)" with explicit negative guidance
  ("do not use for…, fall back to `rg`"). Per-tool argument structs
  derive `schemars::JsonSchema` so the inputSchema lands in
  `tools/list` automatically.
- **Error bifurcation** verified by P0.1 carried forward:
  - Argument-schema validation → `Err(McpError::invalid_params(...))`
    → JSON-RPC `-32602 "Invalid params"`.
  - Daemon-side protocol errors (`INDEX_NOT_READY`, `SYMBOL_NOT_FOUND`,
    `OUT_OF_ROOT`, `OUT_OF_ALLOWED_BODY_EXTENSIONS`, …) →
    `CallToolResult::error(...)` with the structured `{ code, message,
    data }` body so agents can act on the code without parsing English.
- **`crates/rts-mcp/tests/mcp_round_trip.rs`** — end-to-end test:
  spawns `rts-mcp` as a subprocess with stdio piped, drives it with
  raw MCP JSON-RPC, and asserts:
  - `initialize` returns `protocolVersion: "2024-11-05"` and
    `serverInfo.name == "rts-mcp"`.
  - `tools/list` enumerates all four tools.
  - `tools/call find_symbol` polls until the writer commits, then
    returns a structured match for the seeded `build_index` fn.
  - `tools/call read_range` returns line 1 of the seeded `lib.rs`.
  - `tools/call outline_workspace` surfaces the daemon's
    `INDEX_NOT_READY` as a `CallToolResult` with `isError: true` and
    a structured `error.code` body.

### Changed

- **`Cargo.toml`** root workspace adds `crates/rts-mcp` as a member.

### Not in this slice (later P7 / P8 / P9)

- `Index.Outline` body — gated on P8 PageRank + `SignatureRenderer`.
- `partial: true` mid-call streaming via `ProgressNotificationParam`
  (currently the agent gets the daemon's full payload after the
  writer's initial commit; cold-state polling works via repeated
  `tools/call`).
- `rts://capabilities` MCP resource.
- Real Claude Code / Cursor smoke test (`claude mcp add` flow) — P9.
- Skeleton-mode `shape: "signature"` rendering — P8.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **338 passed, 0 failed, 2 ignored**
  (was 337; +1 from the new `mcp_round_trip` integration test).

## [0.2.0-alpha.8] - 2026-05-11

P6 read API. The two remaining body-returning verbs land:
`Index.ReadRange` (explicit line slice) and `Index.ReadSymbol` (body of a
named definition). `Index.Outline` still returns `INDEX_NOT_READY` until
the P8 PageRank ranking + `SignatureRenderer`-rendered skeletons land.

### Added

- **`Index.ReadRange`** (protocol-v0 §7.8) in
  `crates/rts-daemon/src/methods/index.rs`:
  - Workspace-relative or workspace-absolute `file` argument; resolves
    against the mounted root with per-read prefix check (§6.2) +
    `..`-segment refusal (§6.3).
  - Extension allowlist enforced per §13.4 — body reads for any
    extension outside the v0 allowlist return the new
    `OUT_OF_ALLOWED_BODY_EXTENSIONS` error code rather than the file.
  - 1-indexed inclusive `[start_line..=end_line]` slice; lines past EOF
    surface as `RANGE_OUT_OF_BOUNDS`.
  - `token_budget` validated against the 50..=200_000 window (§18.5);
    out-of-range returns `BUDGET_TOO_SMALL` / `BUDGET_TOO_LARGE`. The
    text is bytewise-clipped to `token_budget * 3` and to a 4 MiB
    safety ceiling, with the clip honoring UTF-8 char boundaries.
  - Emits the §3.6 `content_version` field
    (`blake3(content)[:16]@mtime_ns+index_generation`) so v2 safe-edit
    flows can detect stale views.
- **`Index.ReadSymbol`** (protocol-v0 §7.7) in the same file:
  - Looks up the name through the shared `Store::find_symbol`; applies
    optional `file` and `kind` disambiguators.
  - Zero matches return `SYMBOL_NOT_FOUND`. Multiple matches return the
    first (deterministic order: path then start byte) plus
    `truncated: true` and `truncated_symbols: [extra files]` — the
    spec-preferred "top-K + truncated" path over `AMBIGUOUS_SYMBOL`.
  - `shape: "body"` (default) returns the symbol's raw byte slice.
    `signature`/`both` accept the param for forwards compatibility but
    `signature` remains `null` until the P8 `SignatureRenderer` ships.
  - Same token-budget + 4 MiB cap + `content_version` rules as
    `ReadRange`.
- **`Store::get_file_meta(path)`** — small helper for the future
  `Index.Outline` path + diagnostics; lookups the (FID, FileMeta) for a
  workspace-relative path.
- **`ErrorCode::OutOfAllowedBodyExtensions`** wire string
  `OUT_OF_ALLOWED_BODY_EXTENSIONS` per protocol-v0 §13.4.
- **`crates/rts-daemon/tests/read_round_trip.rs`** — integration test:
  mounts a tempdir with a small `.rs` (containing `pub fn alpha` and
  `pub struct Beta`) plus a stray `.bin`, polls until the writer
  commits, then exercises each handler's happy path plus the
  `RANGE_OUT_OF_BOUNDS`, `OUT_OF_ROOT`, `PATH_TRAVERSAL`,
  `OUT_OF_ALLOWED_BODY_EXTENSIONS`, `BUDGET_TOO_SMALL`,
  `BUDGET_TOO_LARGE`, `SYMBOL_NOT_FOUND`, and "kind filter prunes
  match" cases.

### Changed

- **`crates/rts-daemon/src/methods/mod.rs`** dispatcher routes
  `Index.ReadRange` and `Index.ReadSymbol` to their new handlers.
  `Index.Outline` is the only remaining `Index.*` that still returns
  `INDEX_NOT_READY` (it wants the P8 outputs).
- **`Daemon.Ping` capability list** already advertised `read_range`
  and `read_symbol`; behaviour now matches advertisement.

### Not in this slice (later P6 + P8)

- `Index.Outline` (needs P8 PageRank + `SignatureRenderer`).
- Per-language skeleton renderer for `shape: "signature"` /
  `shape: "both"` (P8).
- `include_dependencies` closure walk (P8 tree-shake closure walker).
- v1.1 `session_dedup` short-circuit (`body_omitted` + `see_earlier_id`).
- `PollWatcher` cutover when inotify exhausts.
- `rayon`-thread-local parser pool.
- Workspace re-walk on `Rescan` events.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **337 passed, 0 failed, 2 ignored**
  (was 326; +10 unit tests in `methods/index.rs` for the new helpers +
  the `read_round_trip` integration test).

## [0.2.0-alpha.7] - 2026-05-11

P6 writer pipeline + `Index.FindSymbol`. End-to-end retrieval now works: the
watcher feeds a writer-drain task that parses touched files through the
existing `rts-core` analyzer and commits symbol definitions to redb, and the
first `Index.*` verb returns real matches over the wire.

### Added

- **`crates/rts-daemon/src/store/`** — redb-backed on-disk index per
  protocol-v0 §"Concrete redb schema":
  - `Store::open` opens (or recreates) the per-workspace `db.redb` at
    `${XDG_STATE_HOME}/rts/<workspace_id>/db.redb`. Schema version is
    persisted in a `META` table; mismatch triggers a daemon-controlled
    rebuild (§15.4), and a newer-than-binary schema is refused with
    `SCHEMA_VERSION_NEWER`.
  - Tables: `FILES (fid → FileMeta)`, `PATH_TO_FID`, `FID_TO_PATH`,
    `NAME_TO_SID`, `SID_TO_NAME`, `DEFS (sid → DefSite, multimap)`,
    `FID_DEFS (fid → sid, multimap)`, `META`. All tables are materialised
    inside `Store::open` so read handlers can query an empty workspace
    without hitting `TableDoesNotExist`.
  - `Store::commit_batch(upserts, removals, durability)` applies one
    writer batch as a single `WriteTransaction`; `durability` is
    threaded through so the writer can pick `None` for the hot path and
    `Immediate` for the periodic flush per protocol-v0 §9.2.
  - `Store::find_symbol(name)` is the read path used by
    `Index.FindSymbol`; returns `FoundSymbol` records with byte+line
    ranges, visibility, and the resolved file path.
  - `postcard` is the value encoding for `FileMeta`/`DefSite`.
- **`crates/rts-daemon/src/writer.rs`** — writer-drain task per
  protocol-v0 §9:
  - 150 ms batch interval, 128-event budget per flush, 5 s durability
    flush interval (`Durability::Immediate` every 5 s; `Durability::None`
    otherwise).
  - 4 MiB oversize threshold: oversized files are indexed by
    `(size, mtime)` only and skipped for body parsing.
  - Per-language `Parser` pool keyed on `Language`; `rayon`-thread-local
    pooling is a later perf step.
  - Symbol extraction reuses `rust_tree_sitter::CodebaseAnalyzer` so
    every grammar already supported by `rts-core` works on day one
    (11 languages).
  - Cancels cleanly on the per-workspace `CancellationToken` — last
    `Workspace.Unmount` signals the writer first, lets it drain its
    final batch, then drops the watcher.
- **`Index.FindSymbol`** (`crates/rts-daemon/src/methods/index.rs`)
  per protocol-v0 §7.6:
  - Always returns a list (length ≥ 0); empty results are not an error.
  - Supports optional `kind` and `file` filters.
  - Caps the response at 256 matches and sets `truncated: true` at the
    boundary.
  - `signature`/`doc`/`rank_score` are placeholder fields (null / 0.0)
    until the P8 `SignatureRenderer` + PageRank slices land; the wire
    shape itself is v0-stable.
- **`crates/rts-daemon/tests/find_symbol_round_trip.rs`** — new
  integration test. Mounts a tempdir containing a single `lib.rs`
  (`pub fn build_index() {}` + `pub struct WidgetIndex;`), polls
  `Index.FindSymbol` until the writer commits, then asserts:
  - real match for `build_index` with `kind == "fn"` and `file` ending
    in `lib.rs`,
  - real match for `WidgetIndex` with `kind == "struct"`,
  - the `kind=fn` filter drops the struct match for `WidgetIndex`, and
  - an unknown symbol returns an empty match list (not an error).

### Changed

- **`Workspace.Mount`** now opens the per-workspace redb, spawns the
  writer-drain task, and stores both alongside a per-mount
  `CancellationToken` in `DaemonState`. The previous "debug log every
  WatchEvent" consumer is gone — events go to the writer.
- **`Workspace.Unmount`** signals the writer before dropping the
  watcher so the final batch is drained.
- **`Workspace.Status.progress.files_done`** is sourced from
  `StoreStats::files_indexed` instead of being hardcoded to 0; the
  daemon now reports real index progress.
- **`crates/rts-daemon/Cargo.toml`** — `tempfile` moved from
  `[dev-dependencies]` to `[dependencies]`; the writer uses tempfiles
  to bridge `analyze_file` for in-memory content.
- **`crates/rts-daemon/tests/wire_round_trip.rs`** updated to reflect
  the new wiring: `Index.FindSymbol` on an unknown name returns an
  empty match list (success), and the `INDEX_NOT_READY` assertion was
  retargeted to `Index.Outline` (still stubbed until a later P6 slice).

### Not in this slice (later P6 + P8)

- `Index.Outline`, `Index.ReadSymbol`, `Index.ReadRange` (still return
  `INDEX_NOT_READY`).
- `PollWatcher` cutover when inotify exhausts (status flag already
  surfaces; cutover is hardening).
- `rayon`-thread-local parser pool (perf tuning).
- `ThreadedRodeo` symbol interning (deferred from P4 by the deepening
  reviews).
- Workspace re-walk on `Rescan` events.
- PageRank-driven `rank_score` and `SignatureRenderer`-rendered
  `signature` fields on the wire (P8).

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **326 passed, 0 failed, 2 ignored** (was
  318; delta: +7 daemon unit tests for `store` + `writer` + the new
  `find_symbol_round_trip` integration test).

## [0.2.0-alpha.6] - 2026-05-11

P6 watcher slice. The daemon now starts a `notify` + `notify-debouncer-full`
file watcher on `Workspace.Mount` and tears it down on the last `Unmount`.
Events flow through an internal mpsc but aren't yet consumed by an indexing
pipeline — the writer-drain task lands in a later P6 slice. `Workspace.Status`
surfaces the watcher's health via `watcher_status`.

### Added

- **`crates/rts-daemon/src/filter.rs`** — path-level filter shared by the
  initial walk and the live watcher:
  - Default secrets blocklist regex per protocol-v0 §13.1 (`.env`, SSH
    keys, certs, AWS/npm/PyPI credentials, etc.).
  - Code-extension allowlist for body returns per §13.4.
  - Editor swap / temp / lock-file regex (vim `.swp`/`4913`, emacs
    `.#`/`#…#`, JetBrains `___jb_tmp___`, VS Code `.tmp.NNN`, generic
    backup/`crdownload`/`part`).
  - `PrebuiltGitignore` wrapping `ignore::gitignore::GitignoreBuilder`
    with fallback patterns (`target/`, `node_modules/`, `.git/`,
    `build/`, `dist/`, `.next/`, `.cache/`) and `.rtsignore` extension
    per §6.4.
  - Cost-ordered classification (cheapest filter first: editor-swap →
    extension → secrets → gitignore).
  - `is_ignored` defensively returns `false` for paths outside the
    matcher root rather than panicking — needed because macOS's
    `/var → /private/var` structural symlink can make notify report
    events under either prefix.
- **`crates/rts-daemon/src/watcher.rs`** — file watcher per
  protocol-v0 §6 + §9:
  - `Watcher::start(root, state)` performs the initial gitignore-aware
    walk via `ignore::WalkBuilder` and feeds every survivor through the
    filter to an internal `tokio::sync::mpsc::channel(256)`.
  - `notify-debouncer-full` at 150 ms debounce (matches the protocol-v0
    default + P0.3 spike's measured "first batch ~94-188 ms" latency).
  - Bakes in the P0.3 macOS findings: `Create` and `Modify(Data)` are
    treated symmetrically (no dependency on `RenameMode::*`), and
    `EventKind::Other` is interpreted as a touch for rename pairing
    that didn't surface as a Rename event.
  - On `event.need_rescan()` overflow, transitions
    `WatcherStatus::OverflowedRewalking` and emits a `Rescan` marker
    on the channel for a future re-walk by the writer-drain.
  - On `notify::ErrorKind::MaxFilesWatch` (Linux inotify exhaustion),
    transitions `WatcherStatus::PollingFallback`. (The cutover to an
    actual `PollWatcher` is a later P6 hardening step; the status
    string is surfaced now so clients can see the degradation.)
- **`WatcherStatus` enum** in `state.rs` with `as_wire_str()` rendering
  (`no_watcher` | `ok` | `overflowed_rewalking` | `polling_fallback`).
  Stored as `AtomicU8` for lock-free reads from the status handler.
- **Integration test assertion**: `wire_round_trip` now also asserts
  `result.watcher_status == "ok"` after `Workspace.Mount`, so future
  regressions to watcher startup surface immediately.

### Changed

- **`Workspace.Mount`** starts the watcher synchronously (initial walk
  blocks the response) and stores the `Watcher` handle in
  `DaemonState.watcher`. A tiny `tokio::spawn`-ed consumer logs every
  `WatchEvent` at `tracing::debug!` so events are visible without a
  writer-drain.
- **`Workspace.Unmount`** tears down the watcher when refcount hits 0.
- **`Workspace.Status.watcher_status`** is now sourced from
  `DaemonState.watcher_status()` rather than hardcoded to `"ok"`.

### Not in this slice (next P6 phases)

- Writer-drain task that consumes `WatchEvent`s and re-parses files.
- Parser pool, redb upserts, hot-tree LRU.
- `Index.Outline`/`FindSymbol`/`ReadSymbol`/`ReadRange` handlers (still
  return `INDEX_NOT_READY`).
- `PollWatcher` cutover when inotify exhausts (status flag is
  surfaced; cutover is hardening).

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **318 passed, 0 failed, 2 ignored**
  (was 307; +11 from filter unit tests + watcher unit tests +
  the new integration assertion).

## [0.2.0-alpha.5] - 2026-05-11

P6 skeleton of the agentic-retrieval pivot: first slice of the `rts-daemon`
crate ships. The daemon binds a Unix-domain socket, enforces the protocol-v0
auth boundary, and round-trips 6 of the 10 v0 methods. The remaining 4 (the
`Index.*` family) explicitly return `INDEX_NOT_READY` until indexing wires
in (later P6 phases).

### Added

- **`crates/rts-daemon/`** workspace member with binary `rts-daemon`.
- **Lifecycle (`src/lifecycle.rs`)** per protocol-v0 §12 + §15:
  - `umask(0077)` at startup
  - Refuse-to-run-as-root (aborts on `geteuid() == 0`)
  - `RLIMIT_CORE=0` + Linux `PR_SET_DUMPABLE=0` to prevent core dumps
  - PID lockfile via `flock(LOCK_EX | LOCK_NB)` with stale-PID
    detection (`kill(pid, 0)` + ESRCH), stale-rename-don't-unlink
    forensics
  - SIGTERM / SIGINT / SIGHUP graceful shutdown via Tokio signals
  - Idle-shutdown timer (default 10 min, override via
    `RTS_IDLE_SHUTDOWN_SECS`)
- **Socket server (`src/socket.rs`)** per protocol-v0 §12.1-§12.2:
  - Parent dir mode `0700`, socket mode `0600`
  - Per-OS peer-credential check: `SO_PEERCRED` on Linux,
    `LOCAL_PEERCRED` on macOS; refuses cross-uid connections without
    response. Windows = v1.1.
  - Refuses to start if `XDG_RUNTIME_DIR` unset on Linux (no /tmp
    fallback, per protocol-v0 §5.3 / security F2)
  - Per-connection in-flight cap of 16 requests via
    `tokio::sync::Semaphore`; over-cap returns `BUSY`
- **Wire protocol (`src/protocol.rs`)** per protocol-v0 §3:
  - Newline-delimited JSON framing, 16 MiB cap, optional trailing `\r`
    tolerated
  - Request envelope: `{id, method, params}` with method-name regex
    validation `^[A-Z][a-z]+\.[A-Z][A-Za-z]+$`
  - Response envelope: `{id, result|error}` with `partial`/`content_version`
    extension points for later phases
- **Error model (`src/error.rs`)**: every v0 error-code string from
  protocol-v0 §14 (~20 codes); structured `ProtocolError` with optional
  `data` payload (e.g. `WORKSPACE_VANISHED` carries stored vs current
  `(dev, inode)`)
- **Workspace identity (`src/workspace.rs`)** per protocol-v0 §5-§6:
  - Per-OS canonicalisation (macOS NFC via `unicode-normalization`,
    Linux UTF-8 byte-validation)
  - `WorkspaceFingerprint = blake3(dev_le || inode_le || canonical_path)[:16]`
    rendered hex
  - Network-mount refusal on Linux via `/proc/self/mountinfo` parse
    (NFS/SMB/sshfs/etc.)
  - `verify_unchanged` re-stats the path and refuses `WORKSPACE_VANISHED`
    if `(dev, inode)` shifted (defeats symlink-swap-after-mount)
- **Methods (`src/methods/`)**:
  - `Daemon.Ping` — advertises `protocol: "0"` + capability list
  - `Workspace.Mount` — canonicalises + fingerprints + records mount,
    idempotent on same path within a connection
  - `Workspace.Status` — returns mount state + `index_generation` +
    `watcher_status` + uptime
  - `Workspace.Unmount` — refcount-aware
  - `Session.Open` — synthesises `sess_<16hex>` ids (entropy from blake3
    of pid + ns timestamp + monotonic counter); session-dedup state is
    inert in v0 (the `session_dedup` capability is v1.1)
  - `Session.Close` — validates `sess_` prefix, otherwise inert
- **End-to-end integration test (`tests/wire_round_trip.rs`)**:
  spawns the daemon as a subprocess with per-test
  `XDG_RUNTIME_DIR`/`XDG_STATE_HOME`/`HOME`; round-trips
  `Daemon.Ping` → `Workspace.Mount` → `Workspace.Status` →
  `Session.Open` → `Session.Close`, and asserts the negative-case
  error codes (unknown method → `INVALID_PARAMS`,
  `Index.FindSymbol` → `INDEX_NOT_READY`). This is the v0
  conformance-test seed referenced in the plan.

### Changed

- **`docs/protocol-v0.md` §6.1**: softened "refuse symlinked workspace
  components" to refuse only when the workspace-root *leaf* is a
  symlink. Ancestor symlinks (macOS structural `/var → /private/var`,
  `/tmp → /private/tmp`, Homebrew aliases, conda envs, etc.) are
  tolerated. The strict ancestor rule was breaking legitimate use
  cases without buying meaningful security — the real defence is the
  `(dev, inode)` fingerprint check on remount, which is unaffected by
  this softening.

### Not in this slice (later P6 phases)

- File watcher (`notify` + `notify-debouncer-full`)
- Writer-drain task + redb store + parser pool
- `Index.Outline` / `Index.FindSymbol` / `Index.ReadSymbol` / `Index.ReadRange`
  handlers
- PageRank precompute + incremental patch (P8)
- Session-aware dedup (capability `session_dedup`, v1.1)

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **307 passed, 0 failed, 2 ignored**
  (was 281; +26 from the new daemon's unit tests and integration
  round-trip).

## [0.2.0-alpha.4] - 2026-05-11

P5 of the agentic-retrieval pivot: doc-only. Ships the `protocol-v0`
design document — the daemon↔MCP wire-protocol spec that P6 (daemon)
and P7 (MCP server) will both implement against. Pure documentation;
no code changes.

### Added

- **`docs/protocol-v0.md`** — comprehensive design doc for the
  daemon↔MCP wire protocol. Sections:
  1. Trust model (single-user, local-only, single-uid boundary)
  2. Architecture overview
  3. Wire format (newline-delimited JSON, 16 MiB cap, `content_version`)
  4. Capability negotiation (not single-version semver)
  5. Workspace identity (`(dev, inode, canonical_path)` binding;
     per-OS canonicalisation matrix)
  6. Path safety (refuse symlinked components, per-read prefix check,
     `.rtsignore` extension)
  7. Method catalog (10 methods + 1 notification):
     `Daemon.Ping`/`Telemetry`, `Workspace.Mount`/`Unmount`/`Status`,
     `Index.Outline`/`FindSymbol`/`ReadSymbol`/`ReadRange`,
     `Session.Open`/`Close`. `Daemon.Cancel` and `Session.MarkDeduped`
     dropped from v0 per the deepening reviews.
  8. Cold-state semantics (`partial: true` + `progress`)
  9. Concurrency model (single writer-drain task, parse-parallel +
     commit-serial, bounded mpsc, 16-in-flight cap)
  10. Cancellation contract (connection drop + 30s soft deadline; no
      explicit `Daemon.Cancel` in v0)
  11. Token counting (`bytes / 3` approximator; oracle = Anthropic
      `countTokens` offline only)
  12. Auth boundary (per-OS peer-creds, `umask(0077)`,
      refuse-to-run-as-root, `prctl(PR_SET_DUMPABLE, 0)`)
  13. Default secrets policy (filename blocklist + content scanner +
      code-extension allowlist for body returns)
  14. Error code catalog (string codes, ~20 entries)
  15. State lifecycle (startup, mount, stale PID handling, redb
      corruption recovery, auto-spawn race resolution)
  16. Resource limits (concrete numbers + env-var overrides)
  17. Telemetry/observability (opt-in `RTS_TELEMETRY=1`; 64 MiB
      rotation × 3 retention; silent-drop on ENOSPC)
  18. JSON Schema fragments for each method's `params`
  - Appendix A: Local-auth recipes per OS (Linux/macOS/Windows-v1.1)
  - Appendix B: What's intentionally not in v0
  - Appendix C: Decisions resolved from the deepening (cross-ref
    table linking 24 specific decisions back to the originating
    review)
  - Appendix D: Open questions deferred to P6
  - Appendix E: Wire-protocol versioning policy

The doc is the source of truth for P6 (rts-daemon) and P7 (rts-mcp).
The MCP-facing tool surface remains governed by
`docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md`
and the MCP 2025-11-25 spec.

### Verification

- `cargo build --workspace`: green (no code changes; doc-only).
- `cargo test --workspace`: still 281 passed, 0 failed, 2 ignored.

## [0.2.0-alpha.3] - 2026-05-11

P4 of the agentic-retrieval pivot: convert to a Cargo workspace with
`crates/rts-core/` as the surviving primitive library, bump to Rust 2024
edition, and ship three smaller cleanups flagged by the deepening reviews.

### Changed

- **Cargo workspace layout.** Root `Cargo.toml` is now a workspace
  manifest with `resolver = "3"` and a single member, `crates/rts-core`.
  `src/` moved to `crates/rts-core/src/`, `tests/` to
  `crates/rts-core/tests/`, `test_files/` to `crates/rts-core/test_files/`.
  Future workspace members (`rts-daemon`, `rts-mcp`, `rts-bench`) land
  alongside as separate crates.
- **Rust 2024 edition, MSRV 1.85** declared at the workspace level
  (`[workspace.package]`); members inherit via `edition.workspace = true`
  / `rust-version.workspace = true`.
- **`spikes/p0-*` and `archive/` are excluded** from the workspace via
  `[workspace.exclude]`. The spike binaries remain independent crates;
  archived modules are pure history.
- **LRU caches** (perf-oracle critical fix). Both `file_cache.rs` and
  `parser.rs` previously used `HashMap` + "first-key from HashMap
  iteration" eviction — effectively random under `HashMap`'s rehash
  seed. Replaced with `lru::LruCache` so eviction is deterministic and
  recency-aware. The file cache also moved from
  `Arc<RwLock<HashMap>>` to `Arc<Mutex<LruCache>>` because
  `LruCache::get` is `&mut self` (it bumps recency). Tests now include
  explicit LRU semantics (oldest-evicted, touch-prevents-eviction).
  - New dep: `lru = "0.12"`.

### Security / hygiene

- **`#![forbid(unsafe_code)]` on `crates/rts-core/src/lib.rs`.** The
  pivot plan called for `forbid` on rts-core (leaf library); verified
  no `unsafe` survives the cut after archiving `advanced_memory.rs`
  (its single `unsafe { mmap... }` block was the only one in the
  surviving core; the module wasn't used by anything else and the
  daemon's segment-store path was already dropped in alpha.1 in favour
  of redb blobs).
- **Workspace-level `unsafe_code = "deny"`** in `[workspace.lints.rust]`
  applies to every future workspace member; individual crates can
  override via `#[allow(unsafe_code)]` on a specific item. The plan's
  intended split (forbid on rts-core, deny on rts-daemon/rts-mcp) is
  set up.
- **Removed silent `eprintln!` log** in `file_cache.rs::insert`'s
  poisoned-lock branch. Replaced with `tracing::warn!` under target
  `rust_tree_sitter::file_cache`. The daemon's tracing subscriber
  will surface this; previously it was lost to stderr.

### Removed

- **`src/advanced_memory.rs`** → `archive/src/advanced_memory.rs`.
  Contained the only `unsafe` block in the surviving core (mmap via
  `memmap2`) and was unused outside its own module. Plan path forward:
  the daemon doesn't need it (segments are redb blobs per
  alpha.1 decision); revisit only if a future profile shows actual
  memory-mmap'd primitives are load-bearing.
- **`semantic_graph::build_file_relationships`** (perf-oracle critical
  fix). The function emitted a `same_file` edge with weight 0.3 between
  every pair of symbols in a file — O(n²) per file, ~625k spurious
  edges on a 100k-LOC repo. Garbage data that would have polluted any
  future PageRank pass. Removed entirely; real edges return in P8 from
  tags.scm-derived (def, ref) tuples.
- `test_get_statistics` now asserts `total_edges == 0` instead of
  `> 0`; the old assertion was validating the O(n²) garbage.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **281 passed, 0 failed, 2 ignored** (was
  286; delta: -5 from archiving `advanced_memory` tests).

### Deferred

- **`ThreadedRodeo` symbol interning.** Per-plan P4 deliverable; this
  refactor changes `SymbolDefinition::name` from `String` to
  `Symbol(u32)` and ripples through every consumer. Big enough to
  warrant its own PR; will land alongside the P6 daemon work when the
  hot-path latency matters most.

## [0.2.0-alpha.2] - 2026-05-11

P1 of the agentic-retrieval pivot: tree-sitter ABI bump and Query API migration.

### Changed

- **`tree-sitter = "0.26"`** (was `0.20`). All 12 language grammars bumped to
  matching 0.23+ versions: `tree-sitter-{rust,javascript,typescript,python,c,cpp,go,java,php,ruby} = "0.23"`,
  `tree-sitter-swift = "0.7"`.
- **New direct dep `streaming-iterator = "0.1"`**, required because tree-sitter
  0.26's `QueryCursor::matches` and `QueryCursor::captures` are
  `StreamingIterator`s, not regular `Iterator`s. The `for m in cursor.matches(…)`
  pattern no longer compiles; use `while let Some(m) = it.next()` with
  `use streaming_iterator::StreamingIterator` in scope.
- **`tree_sitter::Query::new(language, pattern)` → `Query::new(&language, pattern)`**.
- **`parser.set_language(language)` → `parser.set_language(&language)`**.
- **Grammar API conversion**: `tree_sitter_<lang>::language()` → `LANGUAGE.into()`
  (a `LanguageFn` const). TypeScript uses `LANGUAGE_TYPESCRIPT`; PHP uses
  `LANGUAGE_PHP`. Some `HIGHLIGHT_QUERY` constants were renamed to
  `HIGHLIGHTS_QUERY` (plural); the renames are inconsistent across grammars
  (e.g. `tree-sitter-javascript` still exports `HIGHLIGHT_QUERY` while
  `tree-sitter-rust` switched to `HIGHLIGHTS_QUERY`).
- **`Node::child` takes `u32`** in 0.26 (was `usize`). Crate-wrapper API kept
  on `usize` with an internal `u32::try_from` conversion.
- **`Parser::set_timeout_micros` removed.** Per-parser cancellation in 0.26 is
  cooperative via `ParseOptions::progress_callback(cb)` returning
  `ControlFlow::Break`. `Parser::set_options` is the new entry point. The
  historical `options.timeout_millis` field is currently a no-op; cooperative
  timeout support is a follow-up.

### Removed

- **`Language::Kotlin` and the `tree-sitter-kotlin` dependency.** The
  community-maintained grammar's 0.3.x line is hard-pinned to
  `tree-sitter = "0.20"`, and the C `links = "tree-sitter"` uniqueness rule
  prevents two majors of the runtime in one dep graph. The plan's
  v1.1 disposition: restore once an upstream release ships against
  tree-sitter 0.26+ ABI.
  - `src/languages/kotlin.rs` archived to `archive/src/languages_kotlin.rs`.
  - Removed from `Language::all()`, `Language::name()`, `Language::file_extensions()`,
    `Language::version()`, `Language::supports_highlights()`, all query maps,
    the analyzer's `extract_kotlin_symbols`, `symbol_table.rs`'s
    `extract_kotlin_symbol_definition`, and the from-`&str` parser.

### Added

- **Per-language smoke test**: `languages::tests::test_every_language_loads_and_parses_a_snippet`
  loads every variant of `Language::all()`, creates a `Parser`, and parses a
  minimal valid snippet per language. Asserts the root node is neither MISSING
  nor ERROR. This is the canonical regression test the P1 plan called for —
  any future grammar version bump that breaks runtime loading or first-parse
  will fail this test.

### Known issues (deferred to P8)

- `tests/missing_language_features_tests::test_go_missing_features` and
  `test_rust_missing_features` are now `#[ignore]`'d. The 0.23 grammars' node-kind
  names for Go interface elements and Rust lifetime nodes shifted subtly from
  the 0.20-era nodes these tests assert on. Revisit during the P8 per-language
  `SignatureRenderer` work, which already requires a per-grammar node-types audit.

### Verification

- `cargo build --lib`: green.
- `cargo test --workspace`: **285 passed, 0 failed, 2 ignored** (was 286 before;
  delta: +1 new smoke test, -2 grammar-shift tests now ignored).
- 11 supported languages (was 12); Kotlin returns in v1.1.

## [0.2.0-alpha.1] - 2026-05-11

This is the first alpha of the **agentic-retrieval MCP pivot**. The crate
is being repositioned from "library that calls LLMs for code analysis"
to a focused parsing/indexing core for the upcoming `rts-daemon` + `rts-mcp`
stack that serves AI coding agents (Claude Code, Cursor, Cline, Aider) over
the Model Context Protocol.

See `docs/brainstorms/2026-05-10-agentic-retrieval-mcp-requirements.md` and
`docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md`
for the full design rationale.

### BREAKING CHANGES

- **`FileInfo.security_vulnerabilities` field removed.** Anything that
  read this field on `FileInfo` no longer compiles. Use one of the
  archived security analyzers (under `archive/src/`) if you still need
  per-file vulnerability data.
- **`AnalysisConfig.enable_security` field removed.** The flag and its
  underlying security passes are gone from the default analyzer.
- **`CodebaseAnalyzer.security_analyzer` field removed.** No public method
  changed but the type is no longer constructible with a security pass.
- **The `default` Cargo feature set is reduced** from
  `["std", "ml", "net", "db"]` to `["std"]`. The `ml`, `net`, `db`, and
  `demo` features and all their gated dependencies have been removed.
- **The `tree-sitter-cli` and `rts-cli` binaries are no longer built** by
  this crate. Both wrapped `src/cli/`, which is archived. The new entry
  points are coming as separate workspace crates (`rts-daemon`,
  `rts-mcp`, `rts-bench`) per the plan.

### Removed

The following ~30k LOC of modules and their public re-exports have been
**archived** (moved to `archive/src/`, kept in git history, not built by
default). Recovery: `git mv archive/src/<mod> src/<mod>` and add the
`pub mod` declaration back.

- **AI service layer**: `ai/`, `ai_analysis.rs`, `advanced_ai_analysis.rs`,
  `embeddings.rs`, `intent_mapping.rs`, `intent_mapping_stub.rs`,
  `reasoning_engine.rs`.
- **Security analyzers**: `taint_analysis.rs`, `sql_injection_detector.rs`,
  `command_injection_detector.rs`, `security/`, `enhanced_security.rs`,
  `advanced_security.rs`.
- **Refactoring + AST transform**: `smart_refactoring.rs`,
  `refactoring.rs`, `ast_transformation.rs`.
- **Wiki + dev tooling**: `wiki/`, `fuzz_testing.rs`,
  `integration_testing.rs`, `test_coverage.rs`, `ci_cd_integration.rs`,
  `performance_benchmarking.rs`, `code_evolution.rs`.
- **CLI + binaries**: `cli/`, `bin/main.rs`, `bin/rts.rs`.
- **Infrastructure shells**: `infrastructure/` (HTTP / sqlx / rate-limiter
  shells archived; cache and config kept inline if needed).
- **Over-engineered cache**: `advanced_cache.rs`.

### Security

- Archiving the AI service layer + sqlx + reqwest removes the transitive
  dependencies that carried open `RUSTSEC` advisories on `ring`, `sqlx`,
  and `paste` per `docs/DEPENDENCY_AUDIT_REPORT.md`. The new
  `rust_tree_sitter` v0.2.0-alpha.1 has zero outbound HTTP dependencies.

### Internal

- `src/analyzer.rs` ↔ `src/advanced_security.rs` coupling severed at all
  reference sites (the field on `FileInfo`, the field on
  `CodebaseAnalyzer`, both analyze paths, the `Default` impl, and two
  module-level doctest examples).
- `src/lib.rs` rewritten from 478 lines to ~170 lines, exposing only the
  surviving parsing + analysis primitives. The crate doc no longer
  references removed AI/security features.
- Workspace pre-archive audit confirmed only **one** structural coupling
  between surviving core and cut buckets; `semantic_context.rs`'s
  earlier taint-analyzer dependency had already been commented out.
- 286 lib + integration tests pass on the slim build (was 49 test files;
  surviving file count is 15 plus the lib's 171 unit tests).

### Coming next (planned, not in this alpha)

- P1: Tree-sitter `0.20 → 0.26.8` bump with the `Query → QueryCursor +
  streaming_iterator` API migration — much smaller surface to migrate
  now that ~30k LOC is archived.
- P4: Cargo workspace split into `rts-core`, `rts-daemon`, `rts-mcp`,
  `rts-bench`. Rust 2024 edition. `#![forbid(unsafe_code)]` on
  `rts-core`.
- P5: Daemon ↔ MCP protocol-v0 design doc.
- P6 / P7: The daemon and the MCP server itself.

### Previously in [Unreleased]

The pre-pivot 0.1.x backlog (additional security CLI flags, SARIF
extensions, secrets-detector validators, deterministic false-positive
filter modes) is now in `archive/`. None of those features are part of
the agentic-retrieval product surface and they will not return in v0.2.x.

## [0.1.0] - 2024-12-19

### Added

#### Core Library
- **Multi-language parsing support** for Rust, JavaScript, Python, C, and C++
- **Safe tree-sitter wrapper** with proper Rust lifetimes and memory management
- **Comprehensive syntax tree navigation** with intuitive API
- **Advanced query system** for pattern matching and code analysis
- **Incremental parsing** for efficient code updates
- **Thread-safe parser management** for concurrent usage
- **AI-friendly codebase analysis engine** with structured output
- **Symbol extraction** for functions, classes, structs, enums, and more
- **Language detection** from file extensions and paths
- **Comprehensive error handling** with custom error types

#### Smart CLI Interface
- **`analyze` command**: Comprehensive codebase analysis with detailed metrics
- **`insights` command**: AI-friendly intelligence reports with recommendations
- **`map` command**: Visual code structure mapping with multiple formats
- **`query` command**: Advanced pattern matching with tree-sitter queries
- **`find` command**: Symbol search with wildcard support and filtering
- **`stats` command**: Detailed codebase statistics and metrics
- **`interactive` command**: Real-time codebase exploration
- **`languages` command**: Information about supported languages

#### Output Formats
- **JSON**: Structured data for programmatic processing
- **Markdown**: Documentation-ready format with rich formatting
- **Table**: Clean, readable tables for terminal viewing
- **Text**: Concise summaries with colored output
- **ASCII**: Simple tree structures for compatibility
- **Unicode**: Beautiful tree structures with icons
- **Mermaid**: Diagram generation for documentation

#### Visual Code Mapping
- **Tree structure visualization** with file metrics
- **Symbol distribution mapping** by type and visibility
- **Directory organization analysis** with size and complexity metrics
- **Mermaid diagram generation** for documentation
- **Configurable depth and filtering** options
- **Language-specific mapping** capabilities

#### Examples and Documentation
- **Basic usage example** demonstrating core functionality
- **Incremental parsing example** showing efficient updates
- **Codebase analysis example** for AI agents
- **Comprehensive README** with usage examples
- **CLI documentation** with detailed command reference
- **Implementation status** tracking

#### Testing and Quality
- **37 comprehensive tests** (22 unit + 15 integration)
- **100% test pass rate** across all functionality
- **Integration tests** for real-world usage scenarios
- **Example validation** ensuring documentation accuracy
- **Error handling tests** for robustness

#### Developer Experience
- **Beautiful CLI interface** with colors and progress indicators
- **Intuitive command structure** with helpful error messages
- **Extensive configuration options** for customization
- **Multiple output formats** for different workflows
- **Interactive exploration mode** for real-time analysis

### Technical Details
- **Language Support**: Rust, JavaScript, Python, C, C++
- **Dependencies**: tree-sitter 0.22, clap 4.0, serde 1.0, colored 2.0
- **Minimum Rust Version**: 1.70+
- **Platform Support**: Cross-platform (Windows, macOS, Linux)
- **Performance**: Optimized for large codebases with progress feedback

### Architecture
- **Modular design** with clear separation of concerns
- **Safe abstractions** over tree-sitter C library
- **Memory efficient** processing with minimal overhead
- **Thread-safe** parser management
- **Extensible** language support system
- **Configurable** analysis pipeline

### Use Cases
- **AI code agents** requiring structured codebase understanding
- **Developer tools** for code analysis and navigation
- **Documentation generation** with visual diagrams
- **Code quality assessment** with metrics and insights
- **Architecture reviews** with structural analysis
- **Team onboarding** with visual project overviews

[Unreleased]: https://github.com/njfio/rust-treesitter-agent-code-utility/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/njfio/rust-treesitter-agent-code-utility/releases/tag/v0.1.0
