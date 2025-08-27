<?xml version="1.0" encoding="UTF-8"?>
<project-instructions version="1.0">
  <summary>
    <goal>Define enforceable project style centered on Pure TDD and Functional Programming for Rust 2021.</goal>
    <scope>Applies to library code, CLI, examples, and tests.</scope>
  </summary>

  <philosophy>
    <tdd>Always write a failing test before production code.</tdd>
    <fp>Maximize use of pure functions, immutability, and expression-oriented Rust.</fp>
  </philosophy>

  <workflow name="tdd-cycle">
    <step order="1">Write a failing unit/integration test expressing intent.</step>
    <step order="2">Write the minimal code to make the test pass.</step>
    <step order="3">Refactor for clarity and FP style with tests green.</step>
    <step order="4">Repeat; commit using Conventional Commits.</step>
  </workflow>

  <rust-functional-guidelines>
    <rule>Prefer pure functions; avoid side effects in core logic.</rule>
    <rule>Favor immutability; use immutable bindings by default.</rule>
    <rule>Use iterators and combinators (map, filter, fold) over indexed loops.</rule>
    <rule>Model effects at the edges; isolate IO and global state.</rule>
    <rule>Encode domain with types; avoid using Option/Result as control flow crutches.</rule>
    <rule>Error handling via Result<T, E>; no panics in library code.</rule>
    <rule>Prefer expression-based style; avoid early mutable state.</rule>
  </rust-functional-guidelines>

  <testing>
    <framework>cargo test (unit in modules; integration in tests/).</framework>
    <coverage>All new public APIs require tests; critical paths include edge/error cases.</coverage>
    <naming>Descriptive test names: test_language_detection, test_cli_flags, etc.</naming>
    <examples>Keep runnable examples in examples/ and ensure they compile.</examples>
  </testing>

  <tooling>
    <build>cargo build</build>
    <cli-build>cargo build --bin tree-sitter-cli</cli-build>
    <cli-run>cargo run --bin tree-sitter-cli -- --help</cli-run>
    <example-run>cargo run --example basic_usage</example-run>
    <test>cargo test</test>
    <lint>cargo clippy --all-targets --all-features</lint>
    <format>cargo fmt --all</format>
    <format-check>cargo fmt --all -- --check</format-check>
  </tooling>

  <review-checklist>
    <item>Is there a failing test that justified the change?</item>
    <item>Does the implementation prefer purity and immutability?</item>
    <item>Are errors modeled via Result with clear types?</item>
    <item>Are names and docs aligned with repo conventions?</item>
    <item>Do cargo test, clippy, and fmt pass?</item>
  </review-checklist>

  <conventions>
    <edition>Rust 2021</edition>
    <indent>4 spaces; no tabs.</indent>
    <naming>snake_case modules/funcs/vars; PascalCase types/traits; UPPER_SNAKE_CASE consts.</naming>
    <docs>Public APIs documented with rustdoc comments.</docs>
    <commits>Conventional Commits; separate refactors from features/bugfixes.</commits>
  </conventions>

  <security>
    <secrets>Do not commit secrets; use env-based config.</secrets>
    <features>Use Cargo features thoughtfully; document behavior changes.</features>
  </security>

  <recap-high-impact-items source="git-log" limit="recent">
    <item commit="81ad13c">feat: implement comprehensive memory tracking system</item>
    <item commit="5941550">feat: integrate Candle-transformers for semantic embeddings ML pipeline</item>
    <item commit="67c4d6a">feat: advanced semantic hotspot detection for O(n²)/O(n³) patterns</item>
    <item commit="bcde8a5">feat: comprehensive unit tests for core analysis modules</item>
    <item commit="54a8e12">refactor: standardize naming conventions across modules</item>
    <item commit="bbda47f">refactor: extract common analysis patterns into shared utilities</item>
    <item commit="21f2dad">feat: comprehensive NPATH complexity analysis with 100% coverage</item>
    <item commit="2738591">feat: Halstead metrics calculation with 100% coverage</item>
    <item commit="62285f6">feat: complete cognitive complexity algorithm with 100% coverage</item>
    <item commit="6fbd790">feat: comprehensive semantic context tracking for false positive reduction</item>
    <item commit="6e22365">feat: comprehensive symbol table analysis with scope-aware vuln detection</item>
    <item commit="da48770">feat: enhanced taint analysis engine with inter-procedural analysis</item>
    <item commit="5a4a7d2">feat: AST-based command injection detection with taint analysis</item>
    <item commit="32fb5a1">feat: production-ready AST-based SQL injection detection with taint analysis</item>
    <item commit="fedea9f">feat: complexity analysis with McCabe and cognitive complexity</item>
    <item commit="db3514a">feat: control flow graph construction foundation</item>
  </recap-high-impact-items>

  <acceptance>
    <definition>Change is acceptable when tests are added first, all quality gates pass, and FP rules are respected.</definition>
  </acceptance>
</project-instructions>
