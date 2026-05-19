---
title: Homebrew Tap for rts Distribution
type: feat
status: active
date: 2026-05-18
---

# Homebrew Tap for rts Distribution

## Overview

Release tarballs already ship via `.github/workflows/release.yml` for three
targets (x86_64-linux-gnu, aarch64-linux-gnu, aarch64-apple-darwin). The
install story stops at "download, extract, chmod, move to PATH" — every
prospective user has to follow that recipe, and the docs at
`docs/install.md:43-44` still claim Homebrew/tarballs are "P9 in flight"
when P9 is shipped for tarballs but never delivered the brew tap.

This plan closes the install-friction gap: a `njfio/homebrew-rts` tap with
an auto-bumped `Formula/rts.rb`, plus refreshed install docs.

**Scope correction:** an earlier brief framed this as "release tarballs +
brew tap." The tarballs already exist. The actual missing piece is just the
tap + formula automation.

## Problem Statement / Motivation

The Homebrew install gap is the single largest external-adoption blocker
since v0.1. Every "trying rts" thread starts with a Rust-toolchain or
manual-tarball detour. This is pure distribution work — no new code paths,
no new features, no API changes. The cost-to-value ratio is the highest of
any open workstream because the work fans out to every macOS user
attempting first install.

## Proposed Solution

**High-level pipeline:** on each `v*` tag, the release workflow (existing)
publishes signed tarballs to the GitHub Release. A new job (or `cargo-dist`
flow) computes SHA256 checksums and opens a PR against
`njfio/homebrew-rts` updating `Formula/rts.rb` with the new version and
URLs/sums. The tap repo merges the PR (manually or via auto-merge label),
and `brew install njfio/rts/rts` works end-to-end.

### Decision: cargo-dist vs hand-rolled

**Recommended: cargo-dist 0.31.0** (now branded as `dist`).

| Aspect | cargo-dist 0.31.0 | Hand-rolled bash job |
|--------|-------------------|----------------------|
| Setup cost | ~2h: `dist init`, configure tap, regenerate workflow | ~6h: write checksum + sed + git automation |
| Maintenance | Upstream handles grammar/path changes | We own every edge case |
| Formula coverage | Generates multi-arch formula with bottles | Single-binary formula only unless we extend |
| Sigstore attestations | Built in v0.27+ | Roll our own |
| Risk | Pinned version drift; less direct control | More bespoke code to debug |

cargo-dist is the default for Rust projects in 2026 (used by `ripgrep`,
`fd`, `bat`, `starship`, others). The existing
`.github/workflows/release.yml` is hand-rolled — `dist init` will replace
or augment it. Plan accommodates either swap-in or coexistence.

### Decision: tap repo location

**Recommended: separate `njfio/homebrew-rts` repo.** Homebrew convention
requires `homebrew-<tap-name>` repo naming; co-locating the formula in the
main repo means `brew tap njfio/rust_tree_sitter` which is wrong.

## Technical Approach

### Phase 1: Create tap repo (≤30 min)

- Create `njfio/homebrew-rts` (public, MIT license matching parent).
- Add `Formula/rts.rb` placeholder pointing at the latest v0.5.x release.
- Smoke test: `brew tap njfio/rts && brew install rts` works on a fresh
  macOS VM (or asahi/CI macOS runner).

### Phase 2: Wire automation (cargo-dist path)

- Run `dist init` in the worktree.
- Configure `[workspace.metadata.dist]`:
  - `installers = ["shell", "homebrew"]`
  - `tap = "njfio/homebrew-rts"`
  - `targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
                "aarch64-apple-darwin"]` (matching existing matrix)
- Provision a `HOMEBREW_TAP_TOKEN` GitHub PAT with write on the tap repo;
  add as repo secret.
- Run `dist generate` to (re)write `.github/workflows/release.yml`.
- Compare diff against current workflow; preserve any project-specific
  steps (signing, attestations).

### Phase 3: First end-to-end release

- Tag `v0.5.5` (or `v0.6.0` if grep v2 lands in same window).
- Watch workflow: tarballs publish + tap PR opens.
- Merge tap PR.
- Verify `brew install njfio/rts/rts` and `rts-mcp --version` works.

### Phase 4: Docs refresh

- Update `README.md:97-150` to lead with `brew install`.
- Rewrite `docs/install.md:43-44`:
  - Remove "P9 in flight" placeholder.
  - Section order: brew (macOS), curl-pipe-sh (Linux), tarball
    (everything else), cargo-install (devs).
- Add `docs/install.md` link from top-level README.

## Alternative Approaches Considered

| Alternative | Why rejected |
|-------------|--------------|
| **Skip Homebrew, push curl-pipe-sh harder** | macOS users heavily prefer `brew`. Adoption data on similar tools shows brew is the most-used install channel. |
| **Use Homebrew core (`homebrew-core`)** | Submission requires 75+ GitHub stars + 30 days age + stability evidence. We don't meet the bar yet. Tap is the right interim step. |
| **Hand-roll without cargo-dist** | Higher maintenance cost; reinvents what cargo-dist does well. Only worth it if cargo-dist's generated workflow conflicts irreconcilably with our signing/attestation setup. |
| **Nix flake instead** | Smaller audience than Homebrew on macOS; not mutually exclusive — can add as follow-on. |

## Acceptance Criteria

### Functional

- [ ] `njfio/homebrew-rts` repo exists, public, with `Formula/rts.rb`.
- [ ] `brew tap njfio/rts && brew install rts` succeeds on fresh macOS.
- [ ] `rts-mcp --version` reports the installed version.
- [ ] Tagging a new release auto-opens a PR against the tap.
- [ ] Existing tarball release artifacts continue to publish unchanged.

### Quality Gates

- [ ] `docs/install.md:43-44` no longer says "P9 in flight."
- [ ] README leads with `brew install` for macOS.
- [ ] Tap repo has its own README explaining the tap.
- [ ] CHANGELOG `[Unreleased]` notes the install channel.

## Success Metrics

- Time-to-first-install on macOS drops from ~5 min (download + chmod) to
  ~30s (`brew install`).
- Eliminate "how do I install this" issues on the tracker for macOS users.
- ≥1 external user reports successful `brew install` within first week of
  ship.

## Dependencies & Risks

- **Dependency:** GitHub Release artifacts must be publicly downloadable
  and have stable URL shape — confirmed by current
  `.github/workflows/release.yml`.
- **Risk:** cargo-dist's regenerated workflow may conflict with existing
  signing/attestation steps. Mitigation: review diff; selectively merge.
- **Risk:** Homebrew formula updates can fail if the tap PR isn't merged
  promptly. Mitigation: enable auto-merge on the tap repo for trusted PR
  authors (the bot account or `njfio`).
- **No new runtime dependencies.**

## Resource Requirements

- Single owner.
- ~4-6h focused work for phases 1–3.
- ~1h docs refresh in phase 4.
- One macOS device (or `macos-latest` CI runner) for smoke tests.

## Out of Scope (Non-Goals)

- `homebrew-core` submission (deferred to post-1.0).
- Linux distro packaging (apt, rpm, AUR) — separate workstream.
- Windows installer (chocolatey, winget) — separate workstream.
- Code signing or notarization beyond what Homebrew handles automatically
  via the tap.
- GPG signing of release artifacts (Sigstore attestations via cargo-dist
  cover this).

## Sources & References

### Internal

- Existing release workflow: `.github/workflows/release.yml`
- Stale docs: `docs/install.md:43-44`
- README install section: `README.md:97-150`

### External

- cargo-dist 0.31.0: <https://opensource.axo.dev/cargo-dist/>
- Homebrew tap creation: <https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap>
- release-plz (alternative version-bump tool):
  <https://release-plz.ieni.dev/>
- Sigstore + GitHub Artifact Attestations:
  <https://docs.github.com/en/actions/security-guides/using-artifact-attestations>

### Reference projects

- `ripgrep` Homebrew workflow (hand-rolled, mature)
- `starship` cargo-dist + Homebrew (cargo-dist exemplar)
- `bat` cargo-dist + Homebrew (cargo-dist exemplar)
