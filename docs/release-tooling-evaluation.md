# Release tooling evaluation + supply-chain runbook

**Date:** 2026-05-25 · **Context:** follow-ups from the v0.6.0 release (see
`docs/plans/2026-05-25-001-release-cut-v0-6-0-code-kb-stability-line-plan.md`).

This document records (1) whether to adopt automated Rust release tooling, and
(2) the runbook for the two supply-chain hardening items: build-provenance
attestation (shipped) and macOS notarization (deferred — needs maintainer
secrets).

## 1. Release tooling: keep homegrown for now; adopt `cargo-semver-checks` next

The release flow today is `scripts/build-changelog.sh` + a manual annotated tag
+ `release.yml` (3-target tarballs → draft). Evaluated alternatives:

| Tool | What it adds over today | Verdict |
|------|-------------------------|---------|
| [`release-plz`](https://release-plz.dev/) | Opens a Release PR that bumps versions, generates the changelog (via git-cliff), and runs `cargo-semver-checks` to pick the bump automatically. | **Highest-value, but defer.** It would replace `build-changelog.sh` + the manual bump wholesale — a migration, not a drop-in. Worth a dedicated spike. |
| [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks) | Mechanically detects breaking public-API changes and the required semver bump. | **Adopt next (standalone).** Pairs with the existing cargo-public-api snapshot gate; would have *mechanically* forced the 0.6.0 decision after the #132–#134 deletions instead of a human judgment call. Low integration cost: one CI job. |
| [`cargo-dist`](https://axodotdev.github.io/cargo-dist/) | Generates the cross-target build + installer + release-upload CI. | **Defer.** Overlaps what `release.yml` already does by hand; migrating is churn without new capability today. Revisit if we add installers/more targets. |
| [`git-cliff`](https://git-cliff.org/) | Commit-driven changelog generation. | **Reject for now.** Our changelog is fragment-file-driven (one fragment per PR, `changelog.d/`), which avoids the `[Unreleased]` merge-conflict churn that motivated the current scheme. git-cliff is commit-message-driven — a different model we don't need. |
| [`cargo-release`](https://github.com/crate-ci/cargo-release) | One command for bump + tag + push (+ publish). | **Optional.** Minor ergonomics over the current manual `Cargo.toml` edit + `git tag -a`; low priority. |

**Recommendation:** open a follow-up to add a `cargo-semver-checks` CI job (the
single highest-leverage, lowest-cost adoption). Treat `release-plz` adoption as
a separate, larger spike. Keep `build-changelog.sh` + `release.yml` otherwise.

## 2. Build-provenance attestation (shipped in this PR)

`release.yml`'s `aggregate-checksums` job now runs
[`actions/attest-build-provenance@v2`](https://github.com/actions/attest-build-provenance)
over `artifacts/**/*.tar.gz` (keyless Sigstore; `id-token: write` +
`attestations: write`). This adds **authenticity** on top of the existing
`SHA256SUMS` **integrity** check (a checksum file in the same release proves
nothing if an attacker can rewrite both). Users verify with:

```sh
gh attestation verify "rts-<version>-<target>.tar.gz" --repo njfio/rs-agent-code-utility
```

> First exercised on the next tagged release (the job is tag-gated; a
> `workflow_dispatch` dry-run skips `aggregate-checksums`). Validate the
> attestation appears in the draft on the next `v*` tag.

## 3. macOS notarization (deferred — requires maintainer Apple secrets)

The shipped `aarch64-apple-darwin` binaries are **ad-hoc signed** (cargo does
this at link time; `release.yml` now `codesign --verify --strict`s the staged
copies to catch strip/copy signature poisoning — the AMFI-SIGKILL class of bug).
That makes the `curl | tar` install path work, but a **browser-downloaded**
tarball carries `com.apple.quarantine` and Gatekeeper blocks an un-notarized
binary (README documents the `xattr -dr com.apple.quarantine` workaround).

Full notarization removes the need for that workaround. It is **not enabled**
because it requires an Apple Developer account ($99/yr) and CI secrets only the
maintainer can provision. Runbook to enable later:

1. **Secrets** (repo → Settings → Secrets): `APPLE_CERTIFICATE_P12` (base64 of a
   Developer ID Application cert), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`,
   `APPLE_TEAM_ID`, `APPLE_APP_SPECIFIC_PASSWORD`.
2. In the macOS build job, after building: import the cert into a temporary
   keychain, then sign with Developer ID:
   `codesign --force --options runtime --timestamp -s "Developer ID Application: <name> (<team>)" rts-daemon rts-mcp rts-bench`.
3. Zip the binaries and submit: `xcrun notarytool submit out.zip --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_SPECIFIC_PASSWORD" --wait`.
4. Staple: `xcrun stapler staple` each binary (or the tarball-bundled app), then
   re-tar.
5. Gate the whole block on the secrets being present so forks/dry-runs skip it.

Until then, the README quarantine note is the supported path for browser
downloads; the `curl | tar` path is unaffected.
