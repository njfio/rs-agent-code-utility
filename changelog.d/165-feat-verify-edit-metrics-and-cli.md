### Feat: EVR/BCIR edit-quality metrics + the `rts verify-edit` CI gate

Completes verify-v0 P3: turns `Index.VerifyEdit` (the scoped pre-edit validator
landed in P3.U1) into a measurable metric and a build-gating CLI.

- **EVR / BCIR metrics** (`rts-bench verify-edit`) — runs a TOML corpus of
  proposed edit-sets (`[[edit_set]]`, each a list of `{file, content}` full
  post-edit contents) through `verify_edit` and reports two deterministic
  rates: **EVR** (Edit Validity Rate = `pass` verdicts / all edit-sets;
  `warn`/`fail` count against it) and **BCIR** (Broken-Caller Introduction Rate
  = edit-sets with a `broken_caller`/`signature_break` finding / all edit-sets).
  No LLM in the loop. Committed corpora: `corpus/verify-edit-eval-rts-core.toml`
  and the pinned self-validation fixture `corpus/verify-edit-eval-selftest.toml`
  (EVR 2/3, BCIR 1/3), asserted by an integration test against a live daemon.

- **`rts verify-edit --edits <path|->`** — the enterprise/CI pre-merge gate.
  Reads an edits JSON (`[{ "file": "...", "content": "..." }]`, full post-edit
  content) from a file or stdin (`-`), calls `Index.VerifyEdit`, prints the
  pass/warn/fail verdict + findings (`--json` passes the daemon response
  through), and maps the verdict to an exit code via **`--fail-on
  <none|warn|critical>`** (default `critical`): pass/warn → 0, fail → 2 under
  `critical`; warn/fail → 2 under `warn`; always 0 under `none` (report-only).
  Daemon/contact error or malformed edits → 3. CI usage:
  `rts verify-edit --edits pr-edits.json --fail-on critical` fails the build on
  a caller-breaking patch.
