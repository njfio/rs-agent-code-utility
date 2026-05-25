### rts-core — cleared the clippy advisory baseline

`cargo clippy -p rust_tree_sitter --all-targets` is now warning-free. The
crate carried ~88 advisory clippy warnings (CI does not run `-D` for
rts-core, so they never failed a build). All are resolved with no runtime
behavior change:

- `assertions_on_constants` (35×, `constants.rs` tests) — compile-time
  invariant `assert!`s moved into `const { … }` blocks, so they now fail the
  build (not just the test) if a constant drifts out of range.
- `type_complexity` (2×) — the tuple return types of `RustSyntax::find_impl_blocks`
  and `PythonSyntax::find_typed_functions` are named via private (transparent)
  type aliases; the public API surface is unchanged.
- `only_used_in_recursion` (2×) — `SyntaxTree`'s private `collect_*` helpers
  no longer take an unused `&self`.
- `if_same_then_else` (2×) — merged identical C/Python declarator branches.
- `let_unit_value` + the no-op `streaming_iterator_present_check` shim and its
  dead `as _` import (`signature.rs`) removed; the dependency stays live via
  `query.rs`.
- dead `descend_for_body` (`signature.rs`) removed.
- `too_many_arguments` on the public `create_edit` constructor — site-specific
  `#[allow]` with justification; its 9 args mirror `InputEdit`'s three flattened
  `Point` fields and collapsing them would change a public signature.
