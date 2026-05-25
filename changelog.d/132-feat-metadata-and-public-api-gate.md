### Workspace metadata cleanup + public-API drift gate

Closes two related drift gaps surfaced during the post-24-PR cleanup pass.

#### What

1. **Workspace metadata fix.** Root `Cargo.toml`'s `[workspace.package]`
   ships real maintainer identity now:

   - `authors = ["njfio <7220+njfio@users.noreply.github.com>"]` (was
     `["Your Name <your.email@example.com>"]`)
   - `repository = "https://github.com/njfio/rs-agent-code-utility"` (was
     `"https://github.com/yourusername/rust_tree_sitter"`)

   Without this, a `cargo publish` would have shipped placeholder identity
   to crates.io.

2. **Metadata regression test (`crates/rts-core/tests/metadata.rs`).**
   Parses the workspace root `Cargo.toml` via `toml = "0.8"` (an existing
   workspace dep — no new dependency) and asserts:

   - `[workspace.package].authors` contains none of the placeholder
     fragments "Your Name", "your.email@example.com", "example.com".
   - `[workspace.package].repository` parses as a well-formed
     `https://github.com/<owner>/<name>` URL and does not contain the
     placeholder owner "yourusername".

   Parsing (not regex) avoids the workspace-inheritance fragility: crate
   manifests declare `authors.workspace = true`, which would silently
   false-pass under a regex over the per-crate manifests.

3. **Public-API drift gate (`crates/rts-core/tests/public_api.rs` +
   `crates/rts-mcp/tests/public_api.rs`).** Each test calls
   `public_api::Builder::from_rustdoc_json(...).assert_eq_or_update(...)`
   against a committed snapshot at `tests/snapshots/public-api.txt`. The
   tests run as part of `cargo test --workspace` — no new CI workflow
   file. Three new dev-deps power the gate: `public-api = "0.51"`,
   `rustdoc-json = "0.9"`, `rustup-toolchain = "0.1"`.

4. **`docs/public-api-gate.md`** documents what the gate catches, how to
   regenerate snapshots (`UPDATE_SNAPSHOTS=yes cargo test --workspace --
   public_api`), and the nightly-pinning mechanism via the
   library-exposed `public_api::MINIMUM_NIGHTLY_RUST_VERSION` constant.

#### Why

A `cargo publish` against the pre-fix metadata would have sent
placeholder identity to crates.io. The metadata test prevents future
regressions of the same shape. The public-API gate completes the
trio with PR #122 (schema drift) and PR #121 (tool-description drift):
every load-bearing surface of the workspace now has a
`cargo test`-time diff against a committed baseline.

#### Snapshot regen plan

The snapshots committed here reflect the CURRENT state of rts-core and
rts-mcp — before any post-pivot deletions land. When PR-A and PR-B
(siblings in the 3-PR refactor arc this PR is the "C" of) merge, the
rts-core snapshot needs a one-time regeneration via
`UPDATE_SNAPSHOTS=yes cargo test --workspace -- public_api`. This is
called out in the PR body so the maintainer can sequence it at merge time.

#### Out of scope

- The deletion + facade work in PR-A and PR-B (separate sibling PRs)
- Gates for `rts-daemon` (binary-only; no library surface to lock) or
  `rts-bench` (lib is internal scaffolding for the bench binary)
- A separate CI workflow file (the test runs as part of
  `cargo test --workspace` per the cargo-public-api maintainers'
  canonical recipe)

#### Quality gates

- `cargo test --workspace` — adds 3 new passing tests (2 metadata, 2
  public_api); existing suite unchanged.
- `cargo fmt --all` clean.
- `cargo clippy -p rts-daemon -p rts-mcp -p rts-bench --all-targets` clean.
- `cargo publish -p rust_tree_sitter --dry-run` succeeds with no
  placeholder-string warnings.
- Zero `unsafe` blocks added.

#### Post-deploy monitoring

No additional operational monitoring required: pure metadata + test
additions; runtime behavior unchanged. The gate becomes load-bearing
the moment it merges, but the rts-core baseline is built from current
state and will need a one-time regen when PR-A + PR-B's deletions
land.
