Rust Guidelines

Always use safe Rust practices; avoid unsafe blocks unless justified in comments.
Prefer borrowing over ownership for efficiency in Tree-sitter node traversals.
Handle errors explicitly with Result or Option types.
Use iterators and combinators for concise and efficient code.
Avoid mutable state in core logic; isolate side effects at edges.
Prefer pure functions and immutability; use functional programming patterns.
Avoid panics in library code; handle errors gracefully.
Use RAII for resource management; prefer smart pointers over raw pointers.
Avoid cloning unless necessary; use references and borrowing where possible.
Avoid global mutable state; prefer passing dependencies explicitly.