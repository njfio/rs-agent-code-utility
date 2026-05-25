//! Build-time injection of tree-sitter grammar versions into the
//! daemon binary.
//!
//! Tree-sitter grammar crates pin their versions in `rts-core`'s
//! `Cargo.toml` but expose no runtime API for their crate version
//! (the `Language::version()` method on the C ABI returns a coarser
//! ABI version, not the crate semver). The daemon's persisted-
//! cold-mount fingerprint needs the crate semvers because a grammar
//! version bump is the load-bearing signal for "your cached parsed
//! trees may not match the current grammar."
//!
//! This `build.rs` parses `crates/rts-core/Cargo.toml` at compile
//! time, extracts every `tree-sitter-*` dependency's version, and
//! emits the sorted JSON of `(name, version)` pairs into the
//! `RTS_GRAMMAR_VERSIONS` env var so the daemon can read it via
//! `env!("RTS_GRAMMAR_VERSIONS")` at runtime.
//!
//! See `docs/plans/2026-05-18-003-feat-persisted-cold-mount-plan.md`
//! U1 for the design rationale.

use std::fs;
use std::path::Path;

fn main() {
    // The rts-core Cargo.toml is the source of truth for grammar
    // versions. If it changes, this build script needs to rerun.
    let cargo_toml_path = Path::new("../rts-core/Cargo.toml");
    println!("cargo:rerun-if-changed=../rts-core/Cargo.toml");

    let contents = fs::read_to_string(cargo_toml_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", cargo_toml_path.display()));

    let parsed: toml::Value =
        toml::from_str(&contents).unwrap_or_else(|e| panic!("parse rts-core Cargo.toml: {e}"));

    let deps = parsed
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("rts-core Cargo.toml: no [dependencies] table"));

    let mut versions: Vec<(String, String)> = Vec::new();
    for (name, dep) in deps {
        if !name.starts_with("tree-sitter") {
            continue;
        }
        // A dep can be `name = "0.23"` (a bare string) or
        // `name = { version = "0.23", features = [...] }` (a table).
        // Handle both shapes; skip anything that doesn't fit (path
        // deps, git deps — we'd want those flagged if they ever
        // appear, but for the v1 grammar set they won't).
        let version_str = match dep {
            toml::Value::String(s) => s.clone(),
            toml::Value::Table(t) => match t.get("version").and_then(toml::Value::as_str) {
                Some(s) => s.to_string(),
                None => continue,
            },
            _ => continue,
        };
        versions.push((name.clone(), version_str));
    }

    // Sort by name so the resulting env var is stable across builds
    // regardless of toml-crate iteration order.
    versions.sort_by(|a, b| a.0.cmp(&b.0));

    // Emit as a compact JSON array of [name, version] pairs. Parsing
    // it at runtime is one `serde_json::from_str` call.
    let json = encode_json(&versions);
    println!("cargo:rustc-env=RTS_GRAMMAR_VERSIONS={json}");
}

/// Hand-rolled JSON encoder for the `[[name, version], ...]` shape.
/// We avoid pulling `serde_json` into the build script so build
/// times stay minimal (the toml crate is already needed to parse
/// Cargo.toml itself).
fn encode_json(versions: &[(String, String)]) -> String {
    let mut s = String::with_capacity(versions.len() * 32);
    s.push('[');
    for (i, (name, version)) in versions.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('[');
        s.push_str(&json_quote(name));
        s.push(',');
        s.push_str(&json_quote(version));
        s.push(']');
    }
    s.push(']');
    s
}

/// Quote a string as a JSON literal. Grammar crate names and semver
/// strings never contain `\` or `"`, so the encoding is trivial; we
/// still handle them defensively in case a future grammar uses a
/// pre-release suffix with unusual characters.
fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}
