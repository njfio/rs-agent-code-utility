### Release pipeline hardening — provenance, partial-release guard, macOS signature check, Node 24

`release.yml` and the install docs gained several supply-chain and robustness
improvements (all exercised on the next tagged release):

- **Build-provenance attestation.** `aggregate-checksums` now runs
  `actions/attest-build-provenance` (keyless Sigstore/SLSA) over the release
  tarballs. Users verify authenticity with `gh attestation verify <tarball>
  --repo njfio/rs-agent-code-utility` — authenticity on top of the existing
  `SHA256SUMS` integrity check. README documents the command.
- **Partial-release guard.** `aggregate-checksums` now asserts all 3 target
  tarballs are present before publishing `SHA256SUMS`. Previously a failed build
  target (matrix is `fail-fast: false`) could publish a complete-looking
  `SHA256SUMS` over fewer than 3 tarballs that `sha256sum -c --ignore-missing`
  silently passes.
- **macOS signature check.** The build job now `codesign --verify --strict`s the
  staged Apple-Silicon binaries before tarring, catching the strip/copy
  signature-poisoning that AMFI-SIGKILLs binaries on launch.
- **Node 24 readiness.** `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` opts the workflow's
  JavaScript actions into Node.js 24 ahead of the 2026-06-02 forced migration
  off the deprecated Node 20 runtime.
- **Docs.** `docs/release-tooling-evaluation.md` records the release-tooling
  evaluation (recommend adopting `cargo-semver-checks` next; keep the homegrown
  flow otherwise) and the macOS notarization runbook (deferred — needs Apple
  Developer secrets).
