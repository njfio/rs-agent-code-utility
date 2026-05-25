### Version & metadata hygiene — accurate `supported_languages()`, version-agnostic telemetry golden, code-KB crate description

- **`supported_languages()` (rts-core)** now lists all 12 indexed languages with grammar versions matching the `tree-sitter-*` pins in `Cargo.toml` (previously only 7 languages, stuck at `0.21`/`0.22`); file extensions now mirror `detect_language_from_extension`.
- **Telemetry schema golden** (`telemetry_v1.golden.json`) uses a `VERSION_PLACEHOLDER` substituted from `CARGO_PKG_VERSION` (like the existing `OS_PLACEHOLDER` / `ARCH_PLACEHOLDER`), so `schema_golden_matches_fixture` no longer fails on every release version bump.
- **`rust_tree_sitter` crate description** dropped the stale "upcoming … retrieval stack" wording in favor of the current "code KB" noun.
