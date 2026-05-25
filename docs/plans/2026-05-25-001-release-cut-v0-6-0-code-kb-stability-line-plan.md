---
title: "release: Cut v0.6.0 — code KB stability line"
type: release
status: active
date: 2026-05-25
origin: docs/brainstorms/2026-05-23-v0.6-release-engineering-bundle-requirements.md
---

# release: Cut v0.6.0 — code KB stability line

## Enhancement Summary

**Deepened on:** 2026-05-25 · **Research/review agents:** best-practices-researcher, code-simplicity-reviewer, architecture-strategist, security-sentinel, agent-native-reviewer (+ repo-research-analyst, learnings-researcher, spec-flow-analyzer in the base plan).

**Key changes from the deepen pass:**
1. **Simplified 9 units → 6.** Folded the "decision-only" U3 + phantom U4 into U1/U4; merged changelog + version bump into one release-prep unit. No action lost (code-simplicity).
2. **CHANGELOG: one path, not three.** Cut the "documented alternative" and "optional curation polish." The plan's own fact settles it — fragments are the *complete* record (#102–#134), the hand-written narrative is *incomplete* (#109–#129). Roll up fragments, delete the stale narrative, done (code-simplicity).
3. **R3 wording fix (correctness).** `success_json` (`server.rs:689-692`) serializes the daemon's protocol-v0 response **verbatim** into every MCP tool body — so the response *fields the 10 tools surface today* are de-facto frozen with the tools. R3 now says "protocol-v0 may change **additively**; today's tool response fields are frozen," not "fully mutable" (architecture-strategist).
4. **Decided the H1 title** (was deferred) — change it for R4 consistency (code-simplicity).
5. **Three in-scope additions found in review:** bump the README install example `VERSION=0.5.5`→`0.6.0` (security); add a macOS browser-download quarantine note (security HIGH); document the `impact_of`/`doctor`/`telemetry` CLI↔MCP asymmetries as deliberate + add a "names frozen, additive flags not" clarifier (agent-native).
6. **Experimental-feature placement settled** — rts-mcp now, with a one-line AGENTS.md note that daemon/core experimental code declares its own feature (features don't cross the socket boundary); plus a `//! ## Feature flags` doc block (architecture + best-practices).
7. **Trimmed the verify gate** to the gap-fillers CI can't run; demoted the full local test suite to "CI is authoritative" (code-simplicity).
8. **Expanded Future Follow-ups** with concrete, sourced items: build-provenance attestation, macOS notarization + `codesign --verify` CI smoke, partial-matrix count-assertion in `release.yml`, SHA-pinning actions, and the `release-plz`/`cargo-dist`/`cargo-semver-checks` tooling migration (best-practices + security).

**New considerations discovered:** the macOS tarball's run-ability on a *browser-downloaded* (quarantined) Mac is a real gap (this session's AMFI SIGKILL was the related post-sign-mutation failure); `cargo-semver-checks` (via release-plz) would have *mechanically* forced the 0.6.0 bump decision; `impact_of` having no `rts impact` CLI twin is the natural first candidate for the new `experimental` gate post-v0.6.

---

## Overview

Cut the first real release line off the v0.6 capability arc. The 3-PR pre-pivot
cleanup (#132/#133/#134) is merged; rts-core's public surface is the minimal
facade set and the cargo-public-api gate locks it. This bundle turns "v0.6 (HEAD,
untagged)" into a tagged, framed, surface-disciplined **v0.6.0** in **one PR +
one annotated tag**:

1. **R1** — roll up `changelog.d/` fragments + bump workspace version `0.5.5 → 0.6.0`; annotated tag `v0.6.0`; push → `release.yml` builds a draft release.
2. **R2** — retire README's "Active pre-release" framing → "v0.6 — stable for daily use; pre-1.0 may still break protocol-v0 + on-disk redb."
3. **R3** — state the stability promise precisely: freeze the **user-facing surface** (10 MCP tools + 10 `rts` CLI subcommand *names*); carve out protocol-v0 (additive-only) + redb schema as pre-1.0-mutable.
4. **R4** — adopt **"code KB"** as the canonical noun, replacing "retrieval daemon" / "agentic-retrieval stack."
5. **R5** — establish a **light experimental gate**: an `experimental` Cargo feature (off by default) + one AGENTS.md paragraph.

Release engineering, not capability work. No new tools, no new subcommands, no crate/binary rename (origin: §Scope Boundaries).

> All five **product** decisions were resolved in the brainstorm (origin `Resolve Before Planning` empty). This plan resolves the five deferred **technical** questions and the failure-path gaps from the SpecFlow + review passes.

## Problem Statement

Three drifts remain (origin: §Problem Frame):
- **No release line.** `README.md:52` says "Active pre-release. Latest tag: `v0.5.5`"; ~30 merged PRs sit untagged. "Pre-release" framing invites accretion.
- **Misleading noun.** `README.md:3` says "retrieval daemon"; `rts-core/src/lib.rs:4` says "agentic-retrieval stack." PageRank, ImpactOf, doc-IDF ranking, structural grep aren't retrieval — they're knowledge-base features.
- **No surface discipline.** Nothing distinguishes "shipped + stable" from "in flight," so the next sprint can accrete stable-by-default surface.

**Audience:** prospective adopters, contributors (stable-vs-experimental signal), maintainer (forcing function against accretion).

## Proposed Solution

One PR (`release/v0.6.0`) bundling every doc/code edit **plus** the changelog
roll-up and version bump — because `release.yml:153` copies `README.md` into
every tarball, so a stale "Active pre-release" README would ship **inside** the
tagged artifact. After CI-green merge to `main`, retire build risk with a
`workflow_dispatch` dry-run against the exact merge SHA, **then** cut the
irreversible annotated tag.

## Technical Approach

### Ground truth (verified — file:line)

| Fact | Location | Implication |
|------|----------|-------------|
| Workspace version `0.5.5`, single source | `Cargo.toml:24` | One-line bump; all 4 crates inherit `version.workspace = true`. |
| All runtime version strings derive from `CARGO_PKG_VERSION` | `lib.rs:129`, `server.rs:680`, `main.rs:58`, `rts.rs:41`, `telemetry.rs:376`, `daemon/main.rs:77` | No hardcoded version strings to touch (code). README install **example** is a separate doc string — see U1. |
| `release.yml` trigger | `release.yml:40-43` `push: tags:['v*']` + `workflow_dispatch` (`dry_run` default true) | Tag → release; dispatch → reversible dry-run. |
| 3 build targets | `release.yml:67-77` | x86_64-linux-gnu, aarch64-linux-gnu, aarch64-apple-darwin. Intel-Mac + Windows excluded (`:17-25`). |
| Release is a **DRAFT** | `release.yml:179-182,222` | Maintainer flips draft→published after spot-check. |
| Auto notes **ignore CHANGELOG.md** | `release.yml:187` | Paste `## [0.6.0]` into release body before publishing. |
| Smoke test checks `--version` **name prefix only** | `release.yml:125` | CI will **not** catch a forgotten version bump → verify locally. |
| Aggregate checksums run on `success()\|\|failure()` | `release.yml:202` | Partial matrix still publishes SHA256SUMS over survivors → count assets. |
| `build-changelog.sh 0.6.0 [--dry-run]` | `scripts/build-changelog.sh:30-131` | Positional `MAJOR.MINOR.PATCH`; inserts `## [0.6.0] - <today>` after `## [Unreleased]`; concatenates fragments **sorted by filename**; **deletes** fragments; **doesn't commit**; idempotency guard refuses if `## [0.6.0]` exists. |
| public-api gate = **signatures only**, not doc text | `crates/{rts-core,rts-mcp}/tests/snapshots/public-api.txt`; nightly self-installed via `MINIMUM_NIGHTLY_RUST_VERSION` | Doc-comment noun edit won't perturb snapshots. Verify green; no `UPDATE_SNAPSHOTS` expected. |
| `rts-mcp/Cargo.toml` already has `[features]` | `default = []`, `telemetry = ["dep:ureq"]` | R5 **edits** the block (`experimental = []`), not a fresh add. |
| `telemetry` is declared **per-crate** | `rts-mcp/Cargo.toml:103` + `rts-daemon/Cargo.toml:107` | Features don't cross the rts-mcp↔rts-daemon **socket** boundary (no dep edge). Informs R5 (U2). |
| MCP responses pass through **verbatim** | `server.rs:689-692` `success_json` | Protocol-v0 *response fields* the 10 tools surface are de-facto frozen with the tools → R3 wording. |
| redb auto-rebuild keyed on version + schema | `daemon/fingerprint.rs:13-18,67-78` | v0.6.0 bump itself invalidates every index → transparent rebuild. **But** a *downgrade* across a schema bump errors `SCHEMA_VERSION_NEWER` (`daemon/methods/workspace.rs:136-146`) → README one-liner. |
| AGENTS.md: annotated tags only; never move/delete pushed tag; push/commit/CI-edits **approval-gated** | `AGENTS.md:140-145,147-160` | Tag push is the irreversible, approval-gated step. |
| No homebrew-tap automation | `.github/workflows/` (ci, fuzz-bench, real-repo-bench, release, schemas-check) | Tag will **not** fan out a formula PR. |
| Working copy = worktree on `main`; local `main` = `88aed97` (pre-release) | — | Branch from fetched `origin/main`; tag an explicit remote merge SHA, never symbolic `main`. |

### CHANGELOG resolution (single path)

`## [Unreleased]` spans `CHANGELOG.md:8-308` and is **already a complete,
theme-grouped, hand-written v0.6 narrative** (`### Added` → Retrieval surface /
Daemon lifecycle + correctness / Operability; `### Changed`; `### Fixed`)
covering **#109–#129**. Separately, `changelog.d/` holds **30 fragments**:
#102–#107, #109–#119, #121–#129, #131, and letter-placeholders **A→#133,
B→#134, C→#132** (verified via `git log`). #102–#107 appear **nowhere** in
CHANGELOG.md (genuine v0.6 work recorded only as fragments — not stale).

**Decided approach (fragments are authoritative — they're complete; the narrative isn't):**
1. `git mv` the letter fragments to numeric PR IDs so filename-sort orders them after #131, in PR order: `C-…→132-…`, `A-…→133-…`, `B-…→134-…`.
2. `scripts/build-changelog.sh 0.6.0 --dry-run`; inspect.
3. `scripts/build-changelog.sh 0.6.0` → `## [0.6.0] - 2026-05-25` from all 30 fragments; fragments deleted.
4. **Delete the stale hand-written v0.6 narrative** now sitting between the new `## [0.6.0]` and `## [0.5.5]`. Leave `## [Unreleased]` with a single `_Nothing yet._` placeholder line (Keep-a-Changelog 1.1.0 convention; avoids the "is 0.6.0 unreleased?" wart — [keepachangelog #326]). The rolled-up `## [0.6.0]` is the single source of truth.

> Never hand-create the `## [0.6.0]` header — let the script own it (its idempotency guard fires if the header pre-exists). The roll-up is reversible pre-commit via `git checkout -- CHANGELOG.md changelog.d/`.

### Implementation Units (ordered — ordering is load-bearing)

> Branch `release/v0.6.0` from a **freshly-fetched `origin/main`**. Do **U1–U2 first** (reviewable substance), then **U3** (release-prep), then the **Verify Gate**, then **U4** (PR/merge), **U5** (dry-run → tag), **U6** (verify draft → publish).

#### U1 — "code KB" noun + README reframe + frozen-surface enumeration + review-found doc fixes (R2, R3, R4)
- **Goal:** README and the rts-core preamble call rts a "code KB"; the Status section states the v0.6 promise, enumerates the frozen surface, and carves out protocol-v0 (additive) + redb (mutable, downgrade-wipe) as not-frozen; the documented CLI↔MCP asymmetries read as deliberate; review-found doc-correctness bugs fixed.
- **Files & edits:**
  - `README.md:1` — H1 "rts — Retrieval for agentic coding" → **"rts — a local code KB for agentic coding"** (decided: change for R4 consistency; the most-read line shouldn't contradict line 3).
  - `README.md:3` — "workspace-pinned local **retrieval daemon**" → "workspace-pinned **local code knowledge base (code KB)** daemon" (R4 must-change).
  - `README.md:22` — "**v0.6 (HEAD, untagged)**" → "**v0.6.0**"; keep "retrieval surface" only if it reads as the operation, else "query surface."
  - `README.md:50-58` (`## Status`) → R2 reframe + R3 promise. New text: **v0.6 — stable for daily use.** Pre-1.0 means the **wire protocol (protocol-v0) may change additively** and the **on-disk redb index may change** between minor versions (the daemon auto-rebuilds on upgrade; a *downgrade* across a schema bump needs a state-dir wipe); the **user-facing tool + CLI surface will not break without a version bump.** "Latest tag: `v0.5.5`" → "`v0.6.0`".
  - `README.md` (Status/new "Stability" block) — enumerate the **frozen surface**:
    - **10 MCP tools:** `outline_workspace`, `find_symbol`, `read_symbol`, `read_symbol_at`, `read_range`, `find_callers`, `impact_of`, `grep`, `daemon_stats`, `daemon_telemetry`
    - **10 `rts` CLI subcommands:** `mount`, `find`, `grep`, `callers`, `outline`, `read`, `stats`, `doctor`, `completions`, `telemetry`
    - **Frozen = names + argument *shapes*; additive flags within a tool/subcommand are NOT frozen** (lets CLI close flag-parity with MCP — e.g. `grep --structural` — without an experimental cycle).
    - **Deliberate CLI↔MCP asymmetries (documented, not omissions):** `impact_of` is MCP-only (CLI users get depth-1 `callers`; transitive impact is the natural first post-v0.6 `experimental` CLI subcommand — see U2); `doctor` is human/CI install tooling (agents use `daemon_telemetry` for live index health); `telemetry` enable/disable/flush is human consent-only (agents get read-only `daemon_telemetry`).
    - **NOT frozen (pre-1.0 mutable):** protocol-v0 wire format (additive changes only; the response fields today's tools surface are frozen with the tools), on-disk redb schema (auto-rebuilt on upgrade).
  - `README.md:159` (install example) — bump `VERSION=0.5.5` → `VERSION=0.6.0` (security review: stale example).
  - `README.md` (macOS install section, ~`:157-187`) — add a one-line note: a **browser-downloaded** tarball carries the quarantine xattr; clear it before first run: `xattr -dr com.apple.quarantine rts-0.6.0-aarch64-apple-darwin/` (security HIGH: un-notarized arm64 binary is Gatekeeper-blocked on the browser-download path; the `curl | tar` path is unaffected).
  - `crates/rts-core/src/lib.rs:4` — "to power the **agentic-retrieval stack**." → "to power the **local code KB**." (R4 must-change; only rts-greppable occurrence.)
- **Do NOT touch:** CHANGELOG.md "retrieval" hits (26, immutable released history); `docs/plans|ideation|brainstorms` (dated artifacts); real plan-file path links (`README.md:451`, `docs/protocol-v0.md` links).
- **Verification (U3-folded surface counts live here):**
  - `rg -n "agentic.?retrieval|retrieval stack|retrieval daemon" README.md crates/rts-core/src/lib.rs` → **0**.
  - `mcp__rts__grep --text "retrieval stack"` → **0** indexed-code hits (origin success criterion).
  - `rg -n "Active pre-release|VERSION=0.5.5" README.md` → **0**.
  - `mcp__rts__grep --text "#[tool(" --file_glob crates/rts-mcp/src/server.rs` → **10**; `rts.rs` `Cmd` enum → **10** subcommands (re-confirmed this session). All 10+10 are stable → freeze is honest (R3×R5 decision recorded in PR body).
  - README read-through: 10 tool names + 10 subcommand names + carve-out + asymmetry notes present.

#### U2 — Light experimental gate: `experimental` feature + feature-flags doc + AGENTS.md paragraph (R5)
- **Goal:** an `experimental` Cargo feature exists (off by default, compiles); the convention is documented once in AGENTS.md and once in crate docs.
- **Files & edits:**
  - `crates/rts-mcp/Cargo.toml` — **edit the existing `[features]` block**: add `experimental = []` (keep `default = []`). rts-mcp owns both governed surfaces (MCP router + `rts` CLI).
  - `crates/rts-mcp/src/` crate-level doc (`main.rs`/`server.rs` `//!`) or `lib.rs` if present — add a `//! ## Feature flags` block listing `default`, `telemetry`, `experimental` (idiomatic Rust; mirrors tokio/serde docs).
  - `AGENTS.md` — **one paragraph** (≤2 sentences, near surface/release conventions): *new MCP tools / CLI subcommands land behind `#[cfg(feature = "experimental")]` until promoted to stable in a release — no ladder, no `experimental_*` prefix, no per-feature paperwork. Daemon-side or core-side experimental code declares its own `experimental` feature in that crate (Cargo features don't cross the rts-mcp↔rts-daemon socket boundary).*
- **Approach:** **nothing to gate today** — forward-looking scaffold (origin §R5). Do NOT add a fake gated item (the theater the brainstorm rejected). The first real use will likely be `rts impact` (the documented MCP-only gap from U1).
- **Patterns to follow:** the existing `telemetry` feature (per-crate, default-OFF). AGENTS.md §427-436: `experimental` must pull nothing into the default build (it pulls nothing today).
- **Verification:**
  - `cargo build -p rts-mcp` (default) compiles.
  - `cargo build -p rts-mcp --features experimental` compiles (proves the feature is well-formed; CI never sets it).
  - `cargo tree -p rts-mcp -e features` shows `experimental` off by default, not implying `telemetry`/`ureq`.
  - AGENTS.md paragraph is ≤2 sentences (guard against bloat → reintroducing theater).

#### U3 — Release-prep: changelog roll-up + version bump (R1, parts 1+2; one commit)
- **Goal:** a complete, non-duplicated `## [0.6.0] - 2026-05-25`; `## [Unreleased]` = `_Nothing yet._`; workspace version `0.6.0`; all binaries report it.
- **Files:** `changelog.d/*` (rename A/B/C → 132/133/134, then script deletes), `CHANGELOG.md`, `Cargo.toml:24`, `Cargo.lock`.
- **Approach:** the 4-step CHANGELOG resolution above, then bump `Cargo.toml:24` `version = "0.5.5"` → `"0.6.0"` (separate edit from the script — easy to forget).
- **Verification (the gate CI won't run):**
  - `grep -c "#110" CHANGELOG.md` == **1** (no double-doc); `## [Unreleased]` body = placeholder only; all 30 PRs appear once under `## [0.6.0]`; `ls changelog.d/` = `README.md` only.
  - `cargo build --release --workspace -p rts-daemon -p rts-mcp -p rts-bench`; each `--version` (rts-daemon, rts-mcp, rts-bench, `rts`) prints `… 0.6.0`.
  - `Cargo.lock` updated + staged.

#### Verify Gate (before commit — gap-fillers CI can't run)
1. Binary `--version` == `0.6.0` (U3) — **CI smoke test only checks the name prefix**.
2. `cargo build -p rts-mcp --features experimental` compiles (U2) — **CI never builds this feature**.
3. CHANGELOG asserts (U3) — no automated gate exists for these.
4. `mcp__rts__grep`/`rg` noun + surface asserts (U1).
- *CI is authoritative on merge for the rest:* `cargo test --workspace` (incl. the signature-only public-api gate — noun edit must not perturb it; if it somehow does, `UPDATE_SNAPSHOTS=yes cargo test --workspace -- public_api` and commit, but expect green), semantic-eval gates (untouched — no rts-core symbol/corpus change), clippy (advisory pre-push baseline). Running the full local suite pre-push is optional belt-and-suspenders for a docs+version+changelog change.

#### U4 — Branch, commit, PR, merge (approval-gated push)
- Branch `release/v0.6.0` from fetched `origin/main`. Commit U1/U2/U3 as the bundled release commit (optionally a preceding `docs:` commit for the untracked origin brainstorm `docs/brainstorms/2026-05-23-…requirements.md` + this plan, so the trail ships with the release). `git push -u origin release/v0.6.0` (**approval-gated**). Open PR `release: v0.6.0 — code KB stability line`; PR body records: the H1-title change, the R3×R5 freeze decision (all 10+10 stable, `experimental` ships empty), the CHANGELOG approach, the 0.6.x-patch-compat / 0.7.0-next-break semver boundary, and the `experimental`-is-a-leaf-binary-Cargo-feature (not tokio's `--cfg`) rationale. Wait for CI green — note the public-api test self-installs nightly via rustup inside `cargo test`, so a flaky runner can fail the *merge* gate unrelated to the release. Merge to `main`.

#### U5 — Reversible dry-run, then irreversible tag (approval-gated)
1. `git fetch origin`; capture the exact `origin/main` **merge SHA**.
2. Trigger `release.yml` via **`workflow_dispatch`** (dry_run=true) against that SHA — confirm **all 3 targets build + smoke-test green**. Only place build risk is retired *reversibly*.
3. Only then: `git tag -a v0.6.0 <merge-sha> -m "Release v0.6.0 — code KB stability line"` (annotated; explicit SHA, not symbolic `main`; AGENTS.md:143).
4. `git push origin v0.6.0` (**approval-gated, irreversible** — AGENTS.md:145).

#### U6 — Verify the draft release, then publish
1. Confirm the tag-push run produced a **draft** release.
2. **Count assets = 7:** 3 tarballs (`rts-0.6.0-<target>.tar.gz`) + 3 `.sha256` + 1 `SHA256SUMS` (partial matrix would publish fewer — `--ignore-missing` would hide it from users).
3. Spot-check one tarball: 3 binaries + LICENSE-MIT/LICENSE-APACHE/README.md; **bundled README has the new code-KB framing** (not "Active pre-release"). For the macOS tarball, ideally `codesign --verify --strict` the staged binary (the session's AMFI SIGKILL was a post-sign-mutation failure).
4. **Paste the CHANGELOG `## [0.6.0]` section into the release body** (auto-notes ignore it).
5. Flip draft → published.

## Requirements Trace

| Req (origin) | Units | Verification |
|---|---|---|
| R1 cut v0.6.0 | U3, U4, U5, U6 | `## [0.6.0]` once; binaries print 0.6.0; annotated tag on merge SHA; draft → 7 assets → published |
| R2 retire "Active pre-release" | U1 | `rg "Active pre-release" README.md` → 0 |
| R3 stability promise (names+shapes frozen; flags + protocol-v0-additive + redb mutable) | U1 | README enumerates 10+10 + carve-out + asymmetries; counts match live code |
| R4 "code KB" noun | U1 | `rg`/`rts grep` "retrieval stack/daemon/agentic-retrieval" → 0 |
| R5 light experimental gate | U2 | `cargo build -p rts-mcp --features experimental` compiles; AGENTS.md + feature-flags doc present |

## System-Wide Impact

- **Interaction graph:** the tag push is the only event with a chain reaction → `release.yml` (build×3 → package → draft → aggregate checksums). No application-runtime callbacks.
- **Failure propagation:** `fail-fast: false` → one target failing still uploads others; `aggregate-checksums` publishes SHA256SUMS over survivors. Mitigation = U5 dry-run + U6 7-asset count.
- **State lifecycle:** the tag is immutable; a wrong/early tag isn't cleanly reversible (recovery = `v0.6.1`). Mitigations: explicit merge SHA, dry-run first.
- **API surface parity:** binary `--version` (Cargo.toml) and tarball name (tag-derived, `release.yml:135`) agree iff the bumped merge commit is the tagged commit.
- **Integration scenarios:** (1) tag pushed, one target fails → <7 assets → U6 catches. (2) README in a follow-up PR → stale README in tarball → prevented by one-PR rule. (3) no narrative reconciliation → #109–#129 doubled → U3 catch. (4) bump forgotten → binaries say 0.5.5, CI passes anyway → U3 local `--version` catch. (5) browser-download macOS user → quarantine kill → U1 README note.

## Acceptance Criteria

### Functional
- [ ] Annotated `v0.6.0` on `main`'s merge commit; draft with 3 tarballs + 3 sidecars + SHA256SUMS; published.
- [ ] `## [0.6.0] - 2026-05-25` covers all 30 fragment PRs once; `## [Unreleased]` = placeholder; `changelog.d/` = README.md only.
- [ ] `Cargo.toml:24` = `0.6.0`; all binaries print `0.6.0`.
- [ ] README: v0.6 promise + 10 MCP tools + 10 CLI subcommands + protocol-v0/redb carve-out + asymmetry notes; no "Active pre-release"; install example = `0.6.0`; macOS quarantine note present.
- [ ] "code KB" noun in README lead + `lib.rs:4`; `rts grep "retrieval stack"` → 0.
- [ ] `experimental` feature off by default, compiles with `--features experimental`; AGENTS.md paragraph (≤2 sentences) + `//! ## Feature flags` doc block.

### Quality Gates
- [ ] `cargo test --workspace` green (public-api signature gate unchanged).
- [ ] Semantic-eval gates green (not recalibrated — out of scope).
- [ ] Release tarball README spot-checked = new framing.

## Scope Boundaries (origin: §Scope Boundaries)
- **Not 1.0.** Pre-1.0; protocol-v0 (additive) + redb mutable.
- **No crate/binary rename.**
- **No new features / tools / subcommands** (incl. `rts impact` — deliberately deferred to the experimental gate post-v0.6).
- **No CI-config edits in this bundle** (`release.yml` changes are approval-gated and orthogonal — see Future Follow-ups).
- **No 30-day ladder / `experimental_*` prefix / per-feature paperwork.**

## Future Follow-ups (out of scope — each its own task)
- **Build-provenance attestation** (security MEDIUM, best-practices): add `actions/attest-build-provenance` to `release.yml` pointing at the existing `SHA256SUMS` (free, keyless, `id-token: write`); document `gh attestation verify` in README. Highest-leverage supply-chain upgrade.
- **macOS notarization + `codesign --verify` CI smoke** (security HIGH-ish): Developer-ID sign + `xcrun notarytool` + staple the aarch64-apple-darwin tarball (needs Apple Developer acct + CI secrets); add a macOS `codesign --verify --strict` step on the *staged* binary to catch post-sign-mutation before shipping.
- **Partial-matrix count-assertion** in `aggregate-checksums` (security MEDIUM): fail the job if `*.tar.gz` count ≠ 3 on a tag run; the `success()||failure()` workaround was for the now-removed Intel-Mac hang and currently enables a silent partial-publish.
- **SHA-pin third-party actions** (security low): pin `softprops/action-gh-release@v2` etc. to commit SHAs.
- **Release-tooling migration** (best-practices): evaluate `release-plz` (Release PR + `cargo-semver-checks` auto-bump — would *mechanically* force the 0.6.0 decision, pairs with the public-api gate) + `cargo-dist` (replaces the hand-rolled `release.yml` matrix) + `git-cliff`/`cargo-release`. Wholesale migration, separate.
- **`rts impact` CLI subcommand** (agent-native): close the MCP-only transitive-impact gap behind the new `experimental` feature — the first real exercise of the R5 gate.
- **Pre-existing debt (origin):** corpus recalibration; `rust_tree_sitter` clippy (88 errors); cargo-shear deps (20 unused); stale tree-sitter grammar version strings in `lib.rs:144-176`.

## Dependencies / Assumptions
- 3-PR cleanup arc merged (✅ #132/#133/#134).
- `build-changelog.sh`, `release.yml`, public-api gate exist + behave as tabulated (✅ verified).
- Release PR's `cargo test` CI can install the pinned nightly (rustup) for the public-api test (can flake the *merge* gate, not the tag).

## Deferred to Implementation
- **[R1] optional curation polish.** If the rolled-up `## [0.6.0]` reads poorly, re-group inline under the narrative's theme headers — normal editing judgment, not a named step.
- **[R3] minor "retrieval" usages** (e.g. `README.md:22`). Keep where it names a specific operation; soften where it's the old product noun.

## Sources & References

### Origin
- [docs/brainstorms/2026-05-23-v0.6-release-engineering-bundle-requirements.md](../brainstorms/2026-05-23-v0.6-release-engineering-bundle-requirements.md). Carried forward: full cut executed; noun = "code KB"; light experimental gate; promise = user-facing surface only (protocol-v0 + redb mutable); version v0.6.0.

### Internal References
- `Cargo.toml:24` · `scripts/build-changelog.sh:30-131` · `.github/workflows/release.yml:40-224` · `crates/rts-mcp/Cargo.toml` + `crates/rts-daemon/Cargo.toml:107` (`telemetry` per-crate precedent) · `crates/rts-mcp/src/server.rs:378-672` (10 `#[tool(`), `:689-692` (`success_json` passthrough) · `crates/rts-mcp/src/bin/rts.rs:59-158` (10 `Cmd` subcommands) · `crates/rts-core/src/lib.rs:4` · `README.md:1,3,22,50-58,159` · `crates/rts-daemon/src/fingerprint.rs:13-18,67-78`, `methods/workspace.rs:136-146` (redb rebuild/downgrade) · `docs/protocol-v0.md:78-96` (additive capability negotiation) · `AGENTS.md:140-145,392-412,427-436` · `docs/public-api-gate.md`
- Closest executed analog: [docs/plans/2026-05-22-001-refactor-pre-pivot-cleanup-and-public-surface-tightening-plan.md](2026-05-22-001-refactor-pre-pivot-cleanup-and-public-surface-tightening-plan.md)

### External References (deepen pass)
- [Cargo Book — SemVer compatibility](https://doc.rust-lang.org/cargo/reference/semver.html) (0.y.z: `y` is the breaking component) · [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) + [#326 empty-Unreleased wart](https://github.com/olivierlacan/keep-a-changelog/issues/326) · [GitHub Artifact Attestations](https://github.blog/news-insights/product-news/introducing-artifact-attestations-now-in-public-beta/) / [actions/attest-build-provenance](https://github.com/actions/attest-build-provenance) · [release-plz](https://release-plz.dev/) · [cargo-dist](https://axodotdev.github.io/cargo-dist/book/quickstart/rust.html) · [Cargo features](https://doc.rust-lang.org/cargo/reference/features.html) (additive/unification → leaf-binary feature is safe)

### Related Work
- Drift ideation survivor #3: [docs/ideation/2026-05-21-drift-remediation-ideation.md](../ideation/2026-05-21-drift-remediation-ideation.md)
- Merged: #132 (metadata + public-api gate), #133 (deletions), #134 (facade + CodebaseAnalyzer deletion)

### AI Tooling Note
Planned with Claude Opus 4.7 (1M context) via Claude Code + Compound Engineering. Code surface grounded with the live `rts` MCP daemon (`find_symbol`, `grep`, `read_symbol`); prose grounded with `rg`/`Read` (rts doesn't index markdown). Release machinery cross-verified by repo-research + learnings agents, a SpecFlow failure-path pass, and a 5-agent deepen pass (best-practices, simplicity, architecture, security, agent-native); all file:line facts re-confirmed by direct reads.
