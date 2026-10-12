### Docs: README matches v0.9.0; `rts-mcp --help` names the six `verify_*` tools

The README described v0.8.0 while documenting features only main had. It now
matches what the v0.9.0 binaries ship:

- **Tools.** Sixteen, named by surface — eight lookup, six `verify_*`, two
  observability — instead of "ten". The surfaces table gains `tsr`; its token
  counts are cited to the #168 measurement, and the `verify` figure, which had
  no source, is gone.
- **Install** points at the `v0.9.0` tarballs (`rts-${VERSION}-${TARGET}.tar.gz`)
  and lists the four binaries.
- **New sections:** the `tsr` profile and inspect-record schema (#181), several
  roots on one daemon (#179: repeated `--workspace` / `RTS_MCP_ROOTS`, routing
  by path arguments, the `_root` block), `rts impact` / `rts verify` /
  `rts verify-edit`, and every environment variable the binaries read —
  including that `RTS_NO_AUTOSPAWN` is honoured by `rts` only, and that
  `rts-daemon` reads `RUST_LOG`, not `RTS_LOG`.
- **Corrected claims.** "Workspace-pinned" is gone. "Zero outbound HTTP,
  asserted in CI" now says what is true: the default builds have no HTTP client,
  the `telemetry` feature adds `ureq` to `rts-mcp`, and
  `scripts/check-daemon-http-free.sh` checks it but no workflow runs it.
  "Sub-millisecond" and "typically 99.9% less context" are replaced by the
  repository's own measurements, each cited with the version it was taken at.
- **Example output** is re-run against this repository instead of quoting line
  numbers from an older tree.

`rts-mcp --help` said the `verify` surface adds "the five check_*/verify_*
gates"; there are no `check_*` tools, and it adds six `verify_*` tools.
