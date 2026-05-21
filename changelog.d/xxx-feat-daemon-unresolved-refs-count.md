### Daemon: expose `unresolved_refs_count` in `Daemon.Telemetry`

PR #123 wired the real-repo CI regression bench against `tokio` / `flask` / `gin` but had to mark `unresolved_refs_count` as `Option<u64>` with a TODO note because the daemon's `Daemon.Telemetry` RPC didn't surface the counter yet. This PR closes that gap.

#### What

`crates/rts-daemon/src/store/mod.rs` gains one new helper, `Store::unresolved_refs_count() -> Result<u64, redb::Error>`, that returns the size of the `UNRESOLVED_REFS` multimap via `MultimapTable::len()` (O(1)). `crates/rts-daemon/src/methods/daemon.rs::telemetry` reads it under the same workspace-mutex acquisition that already covers `language_tag_counts()`, and emits the value as a new top-level `unresolved_refs_count: u64` field in the response. `schemas/v0/methods/Daemon.Telemetry.resp.schema.json` adds the field as required; `docs/protocol-v0.md` documents the RPC shape and the new field under a new §7.11b sub-section. Capability advertisement: `daemon_telemetry_unresolved_refs_count`.

#### Why

`unresolved_refs_count` is the metric that would have caught the PR #118 PHP `method_declaration` extractor gap early — a regression that breaks an extractor surfaces as the count jumping up for that language's fixtures. With it on the wire, PR #123's real-repo bench can drop its `Option<u64>` wrapping in a follow-up sweep.

#### Test guard

- `crates/rts-daemon/src/store/mod.rs::unresolved_refs_count_reflects_table_size` — unit test against a temp store: 0 on empty, 1 after a cross-batch unresolved ref is committed, back to 0 after the callee def lands and Pass 3 drains the deferred row.
- `crates/rts-daemon/tests/protocol_schemas.rs::unresolved_refs_count_appears_in_telemetry_response` — live RPC round-trip against the real daemon binary; asserts the field is present and well-typed.
- The existing `response_matches_schema_for_each_method` drift gate validates the live `Daemon.Telemetry` response against the updated JSON Schema, so a code-vs-schema divergence in either direction fails CI.

#### Out of scope

- No changes to the resolver logic. The count is read-only on top of existing state.
- No new RPC. The field rides in `Daemon.Telemetry`.
- The `rts-bench` `Option<u64>` wrapping cleanup is a separate sweep — this PR unblocks it but doesn't perform it (parallel agent assignment).

#### Post-deploy monitoring

No additional operational monitoring required: pure additive wire field. The schema-drift test gates accidental removal; opt-in clients (`rts-bench`'s real-repo runner) read the new field immediately, pre-v0.6 daemons continue to omit it without breaking older `rts-bench` callers.
