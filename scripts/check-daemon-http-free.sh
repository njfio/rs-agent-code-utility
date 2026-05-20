#!/usr/bin/env bash
# Verify the default rts-daemon and rts-mcp builds link zero HTTP code
# paths, per AGENTS.md "Dependency hygiene".
#
# The v0.6 anonymous opt-in telemetry plan adds an HTTP-capable
# `flush` path to the `rts` binary, gated behind the `telemetry`
# feature on `rts-mcp` (default OFF). The daemon's `telemetry`
# feature schedules but shells out for the actual POST. This script
# asserts:
#
#  - default `cargo tree -p rts-daemon`  → no ureq/reqwest/hyper
#  - default `cargo tree -p rts-mcp`     → no ureq/reqwest/hyper
#
# It does NOT assert the `--features telemetry` builds — those are
# expected to pull in `ureq`.

set -euo pipefail

HTTP_PATTERNS='(^|[[:space:]])(ureq|reqwest|hyper|h2|isahc) v[0-9]'

check_crate() {
  local crate="$1"
  echo "checking ${crate}…"
  if cargo tree -p "${crate}" --edges normal --prefix none 2>/dev/null \
       | grep -E -q "${HTTP_PATTERNS}"; then
    echo "FAIL: HTTP crate found in default build of ${crate}:"
    cargo tree -p "${crate}" --edges normal --prefix none \
      | grep -E "${HTTP_PATTERNS}" || true
    return 1
  fi
  echo "ok: ${crate} is HTTP-free in the default feature set"
}

check_crate rts-daemon
check_crate rts-mcp
echo
echo "all default builds link zero HTTP code paths."
