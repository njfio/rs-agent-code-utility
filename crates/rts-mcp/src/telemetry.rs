//! Anonymous, opt-in telemetry — counters and latencies only.
//!
//! Implements the wire schema, the local-only opt-in state machine, and
//! the JSON-Serialize side of the
//! `2026-05-19-003-feat-anonymous-opt-in-telemetry-plan.md` plan.
//!
//! ## Bright-line summary
//!
//! These constraints are load-bearing. Code that violates any of them
//! is wrong; tests in `tests/telemetry_privacy.rs` exist specifically
//! to catch regressions:
//!
//! 1. **Opt-in, never opt-out.** The default state is OFF. The
//!    [`is_enabled`] check honors both the on-disk flag and the
//!    presence of an install-id file; either being missing means OFF.
//! 2. **No paths, content, or symbol names.** Every map key in the
//!    payload is a `&'static str` from a hard-coded set defined in
//!    this module. Daemon-supplied per-method counters are mapped
//!    through [`method_name_to_enum`] which rejects unknown keys —
//!    a future protocol method that isn't yet enumerated here is
//!    dropped rather than forwarded.
//! 3. **No PII.** The install-id is a random UUIDv4 generated locally
//!    on first opt-in. Nothing else identifying is collected.
//! 4. **Auditable.** [`build_payload`] is the single function that
//!    produces what gets sent; `rts telemetry preview` and the (future)
//!    daemon ticker both call it. The output is byte-deterministic given
//!    the same input, so the golden-file test in
//!    `tests/fixtures/telemetry_v1.golden.json` is meaningful.
//! 5. **Easy off.** [`disable`] removes the install-id file and writes
//!    `enabled = false` to the config — both removable surfaces are
//!    cleaned up.
//!
//! ## Storage layout
//!
//! Two files under `$XDG_CONFIG_HOME/rts/` (or `~/.config/rts/` on
//! platforms without `XDG_CONFIG_HOME`):
//!
//! - `telemetry.toml` — single TOML file with `enabled = bool` and
//!   `last_ping_unix_ms = u64`. Created by `enable`/`flush`; never
//!   contains anything else.
//! - `install_id` — single line, UUIDv4 in standard hyphenated form.
//!   Created by `enable`; deleted by `disable`.
//!
//! Both files are world-readable by default; nothing inside is secret
//! (the install-id is *intentionally* a random unlinked UUID, not a
//! credential). They're scoped to the user's config dir purely for
//! XDG-correctness, not for security.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

/// Frozen wire-schema version. Bumping this is a schema change and
/// requires updating the golden file in lockstep — see the
/// `schema_golden_matches_preview` test.
pub const SCHEMA_VERSION: u32 = 1;

/// Default ingest endpoint. Placeholder — the user provisions this
/// separately. The `RTS_TELEMETRY_ENDPOINT` env var overrides it for
/// testing + air-gapped use.
pub const DEFAULT_ENDPOINT: &str = "https://telemetry.rts.dev/v1/ingest";

/// User-Agent emitted by the (feature-gated) HTTP client. Pinned at
/// build time to `CARGO_PKG_VERSION` so receiver-side traffic logs
/// stay parseable.
pub const USER_AGENT_PREFIX: &str = "rts-telemetry/";

// ─── Bounded enums (the "no user-controlled strings" boundary) ────────

/// Bounded enum of method names we forward. Mirrors the protocol-v0
/// method list as of v0.6; new methods land here in lockstep with the
/// daemon's `CallCounters` struct.
///
/// Anything outside this set is silently dropped from the payload, by
/// design — a typo in a daemon counter snapshot, a wire-version skew,
/// or any other source of unexpected strings cannot leak through the
/// receiver-side serializer.
pub const METHOD_NAMES: &[&str] = &[
    "Daemon.Ping",
    "Daemon.Stats",
    "Daemon.Cancel",
    "Daemon.Shutdown",
    "Workspace.Mount",
    "Workspace.Status",
    "Workspace.Unmount",
    "Session.Open",
    "Session.Close",
    "Index.FindSymbol",
    "Index.FindCallers",
    "Index.ImpactOf",
    "Index.ReadRange",
    "Index.ReadSymbol",
    "Index.ReadSymbolAt",
    "Index.Outline",
    "Index.Grep",
    "Index.Grep.multiline",
    "Index.Grep.structural",
    "Index.Grep.within_symbol",
];

/// Bounded enum of language identifiers we report under
/// `languages_indexed`. Mirrors the languages dispatched by
/// `crates/rts-daemon/src/language.rs::info_for_path`; expanding the
/// daemon's language set requires updating this list too (the test
/// `language_enum_covers_all_daemon_languages` would otherwise stay
/// silent — but the bounded-enum invariant prevents new strings from
/// reaching the wire).
pub const LANGUAGE_NAMES: &[&str] = &[
    "rust",
    "python",
    "typescript",
    "javascript",
    "go",
    "java",
    "c",
    "cpp",
    "php",
    "ruby",
    "swift",
    "csharp",
];

/// Bounded enum of error codes we report. Sourced from
/// `crates/rts-daemon/src/error.rs::ErrorCode`. As with method names,
/// codes outside this list are silently dropped — both forward-compat
/// (newer daemon, older receiver) and defense-in-depth (a typo or
/// fuzzed param can't smuggle a free-form string through the
/// boundary).
pub const ERROR_CODES: &[&str] = &[
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "METHOD_NOT_FOUND",
    "INTERNAL_ERROR",
    "OUT_OF_ROOT",
    "RANGE_OUT_OF_BOUNDS",
    "WORKSPACE_NOT_FOUND",
    "WORKSPACE_VANISHED",
    "WORKSPACE_MISMATCH",
    "INDEX_NOT_READY",
    "DEADLINE_EXCEEDED",
    "CANCELLED",
    "INVALID_STRUCTURAL_QUERY",
    "REGEX_TOO_COMPLEX",
    "WITHIN_SYMBOL_NOT_FOUND",
    "WITHIN_SYMBOL_TOO_MANY_DEFS",
    "TIMEOUT",
];

/// Bounded enum of workspace-size buckets. Coarser than a raw file
/// count by design: the receiver shouldn't be able to fingerprint a
/// workspace by its exact symbol count.
pub const WORKSPACE_SIZE_BUCKETS: &[&str] = &["lt_1k", "1k_to_10k", "10k_to_100k", "gt_100k"];

/// Compile-time-known target OS, as a bounded enum. Returns "linux",
/// "macos", "windows", or "unknown" — the receiver-side schema
/// validator should reject "unknown".
pub fn os_label() -> &'static str {
    // We intentionally branch at compile time so the result is a
    // `&'static str` literal — never a runtime-formatted string.
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

/// Compile-time-known target arch, as a bounded enum.
pub fn arch_label() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "unknown"
    }
}

/// Bucket a raw file count into one of the [`WORKSPACE_SIZE_BUCKETS`]
/// labels. The receiver only sees the bucket name, not the raw count.
pub fn bucket_workspace_size(files: u64) -> &'static str {
    if files < 1_000 {
        "lt_1k"
    } else if files < 10_000 {
        "1k_to_10k"
    } else if files < 100_000 {
        "10k_to_100k"
    } else {
        "gt_100k"
    }
}

/// Map a daemon-supplied method name to its bounded-enum form.
/// Returns `None` for any string outside [`METHOD_NAMES`].
pub fn method_name_to_enum(name: &str) -> Option<&'static str> {
    METHOD_NAMES.iter().copied().find(|known| *known == name)
}

/// Map a daemon-supplied error code to its bounded-enum form. Returns
/// `None` for any string outside [`ERROR_CODES`].
pub fn error_code_to_enum(code: &str) -> Option<&'static str> {
    ERROR_CODES.iter().copied().find(|known| *known == code)
}

/// Map a language identifier (lower-case keyword used by the daemon's
/// language registry) to its bounded-enum form. Returns `None` for
/// anything outside [`LANGUAGE_NAMES`].
pub fn language_to_enum(language: &str) -> Option<&'static str> {
    LANGUAGE_NAMES
        .iter()
        .copied()
        .find(|known| *known == language)
}

// ─── Wire schema ──────────────────────────────────────────────────────

/// The complete telemetry wire schema for `schema_version: 1`.
///
/// Field-stable ordering matters: the golden-file test compares
/// `serde_json::to_string_pretty` output byte-for-byte. `serde` emits
/// fields in declaration order, so this struct's field order is the
/// JSON's field order.
///
/// Adding, removing, or renaming a field requires (a) bumping
/// [`SCHEMA_VERSION`] and (b) updating the golden file in the same
/// commit. Both are enforced by tests; neither is enforced by the
/// compiler, by design — the human-readable diff is the audit log.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TelemetryPayload {
    /// Always [`SCHEMA_VERSION`]. The single integer the receiver
    /// dispatches on; never optional.
    pub schema_version: u32,

    /// Random UUIDv4 generated locally on first opt-in. Deleted by
    /// `rts telemetry disable`. The receiver hashes this with a
    /// monthly-rotating salt before persisting it, so this value is
    /// also not stable across receiver-side queries.
    pub install_id: String,

    /// Compile-time `CARGO_PKG_VERSION` of the `rts-mcp` binary that
    /// produced the payload.
    pub rts_version: String,

    /// One of "linux", "macos", "windows". Bounded enum.
    pub os: &'static str,

    /// One of "aarch64", "x86_64". Bounded enum.
    pub arch: &'static str,

    /// Daemon uptime at sample time, in hours. Lets us distinguish
    /// "user runs daemon as long-lived process" from "user starts +
    /// stops it per session" without needing a per-session counter.
    pub uptime_hours: u64,

    /// Languages observed by the daemon's per-extension dispatch.
    /// Bounded-enum subset of [`LANGUAGE_NAMES`].
    pub languages_indexed: Vec<&'static str>,

    /// Per-method call counts. Keys are bounded-enum members of
    /// [`METHOD_NAMES`]; an unknown method on input is dropped (does
    /// not appear in the payload), preserving the no-user-controlled-
    /// strings invariant on the wire.
    ///
    /// `BTreeMap` for deterministic JSON-key ordering — load-bearing
    /// for the golden-file test.
    pub method_counts: BTreeMap<&'static str, u64>,

    /// Per-method p50 latency in milliseconds. Same key constraints as
    /// `method_counts`.
    pub method_latency_p50_ms: BTreeMap<&'static str, u64>,

    /// Per-method p99 latency in milliseconds. Same key constraints
    /// as `method_counts`.
    pub method_latency_p99_ms: BTreeMap<&'static str, u64>,

    /// Per-error-code counts. Keys are bounded-enum members of
    /// [`ERROR_CODES`].
    pub error_counts: BTreeMap<&'static str, u64>,

    /// Cache-hit rate in [0.0, 1.0]. A single scalar — the receiver
    /// can't reconstruct per-request decisions.
    pub cache_hit_rate: f64,

    /// p50 of cold-walk durations in milliseconds. One value, not
    /// per-mount.
    pub cold_walk_ms_p50: u64,

    /// Bounded-enum bucket of the workspace size; see
    /// [`WORKSPACE_SIZE_BUCKETS`]. We never report the raw file
    /// count — a 47,123-file workspace and an 89,210-file workspace
    /// both report "10k_to_100k".
    pub workspace_size_bucket: &'static str,
}

/// All the inputs to [`build_payload`] in one struct so the caller
/// doesn't pass a 9-arg function. Fields are not part of the wire
/// shape — they're the *source* values that get filtered, mapped, and
/// bucketed before being placed in the [`TelemetryPayload`].
#[derive(Debug, Clone, Default)]
pub struct PayloadInputs {
    /// Daemon uptime in seconds. Bucketed into hours by `build_payload`.
    pub uptime_secs: u64,

    /// Lower-case language identifiers observed by the daemon. May
    /// contain unknown strings; only those in [`LANGUAGE_NAMES`]
    /// survive to the wire.
    pub languages_raw: Vec<String>,

    /// Method-name → call count map. Keys outside [`METHOD_NAMES`]
    /// are silently dropped.
    pub method_counts_raw: BTreeMap<String, u64>,

    /// Method-name → p50 latency map.
    pub method_latency_p50_raw: BTreeMap<String, u64>,

    /// Method-name → p99 latency map.
    pub method_latency_p99_raw: BTreeMap<String, u64>,

    /// Error-code → count map. Keys outside [`ERROR_CODES`] are
    /// silently dropped.
    pub error_counts_raw: BTreeMap<String, u64>,

    /// Cache-hit rate as a scalar in [0.0, 1.0]. Clamped by
    /// `build_payload`.
    pub cache_hit_rate: f64,

    /// p50 cold-walk duration in milliseconds.
    pub cold_walk_ms_p50: u64,

    /// Raw workspace file count. Bucketed by `build_payload`.
    pub workspace_files: u64,
}

/// Construct a [`TelemetryPayload`] from raw daemon-state inputs.
///
/// This is the single boundary where unbounded daemon-side strings
/// get filtered down to the bounded-enum subsets. If a future code
/// change ever bypasses this function and serializes
/// `TelemetryPayload` directly with attacker-controlled `&'static
/// str` values, the bright-line "no user-controlled strings"
/// invariant breaks — that's why the struct's map fields use
/// `&'static str` rather than `String`. A `String` on the wire can
/// only get there if someone explicitly leaks one.
pub fn build_payload(install_id: &str, inputs: &PayloadInputs) -> TelemetryPayload {
    let languages_indexed: Vec<&'static str> = {
        let mut s: std::collections::BTreeSet<&'static str> = Default::default();
        for raw in &inputs.languages_raw {
            if let Some(known) = language_to_enum(raw) {
                s.insert(known);
            }
        }
        s.into_iter().collect()
    };

    let method_counts = filter_method_map(&inputs.method_counts_raw);
    let method_latency_p50_ms = filter_method_map(&inputs.method_latency_p50_raw);
    let method_latency_p99_ms = filter_method_map(&inputs.method_latency_p99_raw);
    let error_counts = filter_error_map(&inputs.error_counts_raw);

    let cache_hit_rate = inputs.cache_hit_rate.clamp(0.0, 1.0);
    // Clamp NaN/Inf to 0.0 — JSON can't represent NaN.
    let cache_hit_rate = if cache_hit_rate.is_finite() {
        cache_hit_rate
    } else {
        0.0
    };

    TelemetryPayload {
        schema_version: SCHEMA_VERSION,
        install_id: install_id.to_string(),
        rts_version: env!("CARGO_PKG_VERSION").to_string(),
        os: os_label(),
        arch: arch_label(),
        uptime_hours: inputs.uptime_secs / 3_600,
        languages_indexed,
        method_counts,
        method_latency_p50_ms,
        method_latency_p99_ms,
        error_counts,
        cache_hit_rate,
        cold_walk_ms_p50: inputs.cold_walk_ms_p50,
        workspace_size_bucket: bucket_workspace_size(inputs.workspace_files),
    }
}

/// Filter an unbounded `BTreeMap<String, u64>` to a
/// `BTreeMap<&'static str, u64>` of method-name keys, dropping any
/// keys outside [`METHOD_NAMES`].
fn filter_method_map(raw: &BTreeMap<String, u64>) -> BTreeMap<&'static str, u64> {
    let mut out: BTreeMap<&'static str, u64> = BTreeMap::new();
    for (k, v) in raw {
        if let Some(known) = method_name_to_enum(k) {
            out.insert(known, *v);
        }
    }
    out
}

/// Filter an unbounded `BTreeMap<String, u64>` to a
/// `BTreeMap<&'static str, u64>` of error-code keys, dropping any
/// keys outside [`ERROR_CODES`].
fn filter_error_map(raw: &BTreeMap<String, u64>) -> BTreeMap<&'static str, u64> {
    let mut out: BTreeMap<&'static str, u64> = BTreeMap::new();
    for (k, v) in raw {
        if let Some(known) = error_code_to_enum(k) {
            out.insert(known, *v);
        }
    }
    out
}

// ─── Local state (opt-in flag + install-id) ──────────────────────────

/// On-disk config shape. Single file, two fields, no path/content.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LocalConfig {
    /// Whether telemetry is enabled. Default `false`; the binary
    /// treats an absent file as `false` too.
    #[serde(default)]
    pub enabled: bool,

    /// Unix-epoch milliseconds when the last successful flush
    /// completed. `None` if no flush has succeeded.
    #[serde(default)]
    pub last_ping_unix_ms: Option<u64>,
}

/// Compute the per-user config dir for telemetry state. Respects
/// `$XDG_CONFIG_HOME` if set; falls back to `$HOME/.config`. Doesn't
/// create the directory — `enable` does that.
///
/// The result is *not* canonicalized (e.g. doesn't follow symlinks),
/// matching XDG's intent.
pub fn config_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(xdg);
        if !p.as_os_str().is_empty() {
            return Ok(p.join("rts"));
        }
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("neither XDG_CONFIG_HOME nor HOME is set"))?;
    Ok(PathBuf::from(home).join(".config").join("rts"))
}

/// Path to the telemetry config TOML file (under `dir`).
pub fn config_path_in(dir: &Path) -> PathBuf {
    dir.join("telemetry.toml")
}

/// Path to the install-id file (under `dir`).
pub fn install_id_path_in(dir: &Path) -> PathBuf {
    dir.join("install_id")
}

/// Path to the telemetry config TOML file (default XDG-resolved dir).
pub fn config_path() -> Result<PathBuf> {
    Ok(config_path_in(&config_dir()?))
}

/// Path to the install-id file (default XDG-resolved dir).
pub fn install_id_path() -> Result<PathBuf> {
    Ok(install_id_path_in(&config_dir()?))
}

/// Read the local config from `dir`. Missing file → default
/// (`enabled = false`). The directory variant lets tests target a
/// tempdir without mutating `XDG_CONFIG_HOME` (which is `unsafe` in
/// Rust 2024).
pub fn read_config_in(dir: &Path) -> Result<LocalConfig> {
    let path = config_path_in(dir);
    if !path.exists() {
        return Ok(LocalConfig::default());
    }
    let bytes =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let cfg: LocalConfig = toml::from_str(&bytes)
        .with_context(|| format!("parse telemetry config {}", path.display()))?;
    Ok(cfg)
}

/// Read the local config from the default XDG dir.
pub fn read_config() -> Result<LocalConfig> {
    read_config_in(&config_dir()?)
}

/// Write the local config into `dir`, creating the parent dir if
/// needed.
pub fn write_config_in(dir: &Path, cfg: &LocalConfig) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create config dir {}", dir.display()))?;
    let path = config_path_in(dir);
    let text = toml::to_string(cfg).context("serialize telemetry config")?;
    std::fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Write the local config to the default XDG dir.
pub fn write_config(cfg: &LocalConfig) -> Result<()> {
    write_config_in(&config_dir()?, cfg)
}

/// Read the install-id from `dir`, returning `None` if the file is
/// missing (the canonical "telemetry not enabled" indicator).
pub fn read_install_id_in(dir: &Path) -> Result<Option<String>> {
    let path = install_id_path_in(dir);
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed))
}

/// Read the install-id from the default XDG dir.
pub fn read_install_id() -> Result<Option<String>> {
    read_install_id_in(&config_dir()?)
}

/// Write the install-id into `dir`, creating the parent dir if
/// needed. Overwrites any existing id (callers should check
/// beforehand if they want to preserve it).
pub fn write_install_id_in(dir: &Path, id: &str) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create config dir {}", dir.display()))?;
    let path = install_id_path_in(dir);
    std::fs::write(&path, format!("{id}\n"))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Write the install-id to the default XDG dir.
pub fn write_install_id(id: &str) -> Result<()> {
    write_install_id_in(&config_dir()?, id)
}

/// Combined "is telemetry actually live?" check against `dir`. Both
/// the on-disk `enabled` flag and a non-empty install-id must be
/// present; removing either disables telemetry.
pub fn is_enabled_in(dir: &Path) -> bool {
    match (read_config_in(dir), read_install_id_in(dir)) {
        (Ok(cfg), Ok(Some(_))) => cfg.enabled,
        _ => false,
    }
}

/// Combined "is telemetry actually live?" check (default XDG dir).
pub fn is_enabled() -> bool {
    match config_dir() {
        Ok(dir) => is_enabled_in(&dir),
        Err(_) => false,
    }
}

/// Generate a fresh install-id. Uses UUIDv4 via a tiny inline
/// generator to avoid pulling in the `uuid` crate for a single
/// `getrandom` call. The output shape is the standard 36-char
/// hyphenated form (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`) where
/// `y` is one of `8|9|a|b` per RFC 4122 §4.4.
pub fn generate_install_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom_bytes(&mut bytes)?;
    // Set the version (4) and variant (RFC 4122) bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format_uuid(&bytes))
}

/// Format 16 random bytes as a hyphenated UUID string.
fn format_uuid(b: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    )
}

/// Read `n` cryptographically-random bytes from the OS. On Unix this
/// reads from `/dev/urandom`; on other platforms we can pull in
/// `getrandom` later if/when the targets matter. We deliberately
/// avoid `rand::rngs::OsRng` here to keep the dependency footprint
/// minimal — the UUID generation runs once per install at most.
fn getrandom_bytes(out: &mut [u8]) -> Result<()> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")
        .context("open /dev/urandom for install-id generation")?;
    f.read_exact(out)
        .context("read random bytes from /dev/urandom")?;
    Ok(())
}

/// `rts telemetry enable` against a specific config dir.
/// Generates (or preserves) an install-id and persists `enabled =
/// true`. Idempotent: calling twice in a row is a no-op the second
/// time. Tests pass a tempdir; the default-XDG wrapper is
/// [`enable`].
pub fn enable_in(dir: &Path) -> Result<String> {
    let id = match read_install_id_in(dir)? {
        Some(existing) => existing,
        None => {
            let id = generate_install_id()?;
            write_install_id_in(dir, &id)?;
            id
        }
    };
    let mut cfg = read_config_in(dir).unwrap_or_default();
    cfg.enabled = true;
    write_config_in(dir, &cfg)?;
    Ok(id)
}

/// `rts telemetry enable` — XDG-default wrapper.
pub fn enable() -> Result<String> {
    enable_in(&config_dir()?)
}

/// `rts telemetry disable` against a specific config dir. Deletes the
/// install-id file and sets `enabled = false`. The config file is
/// preserved (with the new flag value) so we can prove on inspection
/// that telemetry has been *explicitly* disabled, as opposed to
/// "never enabled".
pub fn disable_in(dir: &Path) -> Result<()> {
    let id_path = install_id_path_in(dir);
    if id_path.exists() {
        std::fs::remove_file(&id_path).with_context(|| format!("remove {}", id_path.display()))?;
    }
    let mut cfg = read_config_in(dir).unwrap_or_default();
    cfg.enabled = false;
    write_config_in(dir, &cfg)?;
    Ok(())
}

/// `rts telemetry disable` — XDG-default wrapper.
pub fn disable() -> Result<()> {
    disable_in(&config_dir()?)
}

/// Determine the effective endpoint URL. Reads
/// `RTS_TELEMETRY_ENDPOINT` first; falls back to [`DEFAULT_ENDPOINT`].
/// This is the **only** place an endpoint is selected, so tests that
/// override the env var see the same value the (future) HTTP client
/// would see.
pub fn endpoint() -> String {
    std::env::var("RTS_TELEMETRY_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string())
}

// ─── Public observability ────────────────────────────────────────────

/// Serialize a payload to canonical-form JSON. Used by both `rts
/// telemetry preview` and the (feature-gated) flush path so the two
/// are byte-identical; the golden-file test depends on that.
pub fn payload_to_pretty_json(payload: &TelemetryPayload) -> String {
    // `to_string_pretty` emits 2-space indent and trailing newline-
    // free output, matching the golden file exactly.
    serde_json::to_string_pretty(payload).expect("TelemetryPayload always serializes cleanly")
}

/// Compact (single-line) form. Used for the wire-level POST so the
/// receiver doesn't pay deserialize overhead on indentation.
pub fn payload_to_compact_json(payload: &TelemetryPayload) -> String {
    serde_json::to_string(payload).expect("TelemetryPayload always serializes cleanly")
}

/// Render a human-friendly status line for `rts telemetry status`.
pub fn render_status(cfg: &LocalConfig, install_id: Option<&str>) -> String {
    let enabled = cfg.enabled && install_id.is_some();
    let state = if enabled { "ENABLED" } else { "DISABLED" };
    let mut lines = vec![format!("telemetry: {state}")];
    lines.push(format!("schema_version: {SCHEMA_VERSION}"));
    lines.push(format!("endpoint: {}", endpoint()));
    if let Some(id) = install_id {
        lines.push(format!("install_id: {id}"));
    } else {
        lines.push("install_id: <none>".to_string());
    }
    if let Some(ms) = cfg.last_ping_unix_ms {
        lines.push(format!("last_ping_unix_ms: {ms}"));
    } else {
        lines.push("last_ping_unix_ms: <never>".to_string());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: an isolated config dir inside a tempdir. Tests
    /// pass this path directly to the `_in` variants so we never
    /// touch the process-wide XDG_CONFIG_HOME env var (which is
    /// `unsafe` to mutate in Rust 2024 and forbidden by the
    /// workspace lint).
    fn fresh_dir() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("rts");
        (tmp, dir)
    }

    #[test]
    fn os_label_is_known() {
        let l = os_label();
        assert!(
            matches!(l, "linux" | "macos" | "windows" | "unknown"),
            "unexpected os label: {l}"
        );
    }

    #[test]
    fn arch_label_is_known() {
        let l = arch_label();
        assert!(
            matches!(l, "aarch64" | "x86_64" | "unknown"),
            "unexpected arch label: {l}"
        );
    }

    #[test]
    fn workspace_size_buckets_at_boundaries() {
        assert_eq!(bucket_workspace_size(0), "lt_1k");
        assert_eq!(bucket_workspace_size(999), "lt_1k");
        assert_eq!(bucket_workspace_size(1_000), "1k_to_10k");
        assert_eq!(bucket_workspace_size(9_999), "1k_to_10k");
        assert_eq!(bucket_workspace_size(10_000), "10k_to_100k");
        assert_eq!(bucket_workspace_size(99_999), "10k_to_100k");
        assert_eq!(bucket_workspace_size(100_000), "gt_100k");
        assert_eq!(bucket_workspace_size(1_000_000), "gt_100k");
    }

    #[test]
    fn method_name_filtering_drops_unknown_strings() {
        assert_eq!(
            method_name_to_enum("Index.FindSymbol"),
            Some("Index.FindSymbol")
        );
        assert_eq!(method_name_to_enum("Index.PathLeakAttempt"), None);
        assert_eq!(method_name_to_enum(""), None);
        // Even close-but-not-exact misses; the comparison is byte-exact.
        assert_eq!(method_name_to_enum("index.findsymbol"), None);
    }

    #[test]
    fn error_code_filtering_drops_unknown_strings() {
        assert_eq!(error_code_to_enum("TIMEOUT"), Some("TIMEOUT"));
        assert_eq!(error_code_to_enum("SOMETHING_UNDOCUMENTED"), None);
        assert_eq!(error_code_to_enum(""), None);
    }

    #[test]
    fn language_filtering_drops_unknown_strings() {
        assert_eq!(language_to_enum("rust"), Some("rust"));
        assert_eq!(language_to_enum("haskell"), None);
        // Case-sensitive — daemon's registry already lowercases.
        assert_eq!(language_to_enum("Rust"), None);
    }

    #[test]
    fn build_payload_filters_user_controlled_strings() {
        // Inputs include attacker-controlled keys; outputs must contain
        // only bounded-enum members.
        let mut method_counts_raw = BTreeMap::new();
        method_counts_raw.insert("Index.FindSymbol".to_string(), 5);
        method_counts_raw.insert("Index.SecretPath./etc/passwd".to_string(), 999);
        let mut error_counts_raw = BTreeMap::new();
        error_counts_raw.insert("TIMEOUT".to_string(), 1);
        error_counts_raw.insert("SECRET_TOKEN_abcd1234".to_string(), 1);

        let inputs = PayloadInputs {
            uptime_secs: 7_200,
            languages_raw: vec!["rust".into(), "haskell".into()],
            method_counts_raw,
            method_latency_p50_raw: BTreeMap::new(),
            method_latency_p99_raw: BTreeMap::new(),
            error_counts_raw,
            cache_hit_rate: 0.5,
            cold_walk_ms_p50: 230,
            workspace_files: 47_000,
        };

        let payload = build_payload("11111111-1111-4111-8111-111111111111", &inputs);

        // Method-name filter: bad keys dropped.
        assert_eq!(payload.method_counts.get("Index.FindSymbol"), Some(&5));
        assert!(
            !payload
                .method_counts
                .contains_key("Index.SecretPath./etc/passwd")
        );
        // Error-code filter: bad keys dropped.
        assert_eq!(payload.error_counts.get("TIMEOUT"), Some(&1));
        assert!(
            payload
                .error_counts
                .iter()
                .all(|(k, _)| !k.contains("SECRET"))
        );
        // Language filter: bad keys dropped.
        assert_eq!(payload.languages_indexed, vec!["rust"]);
        // Bucketing.
        assert_eq!(payload.workspace_size_bucket, "10k_to_100k");
        assert_eq!(payload.uptime_hours, 2);
    }

    #[test]
    fn cache_hit_rate_is_clamped() {
        let inputs = PayloadInputs {
            cache_hit_rate: 2.0,
            ..PayloadInputs::default()
        };
        let p = build_payload("id", &inputs);
        assert_eq!(p.cache_hit_rate, 1.0);

        let inputs = PayloadInputs {
            cache_hit_rate: -0.5,
            ..PayloadInputs::default()
        };
        let p = build_payload("id", &inputs);
        assert_eq!(p.cache_hit_rate, 0.0);

        let inputs = PayloadInputs {
            cache_hit_rate: f64::NAN,
            ..PayloadInputs::default()
        };
        let p = build_payload("id", &inputs);
        assert!(p.cache_hit_rate.is_finite());
    }

    #[test]
    fn install_id_shape_is_uuidv4() {
        let id = generate_install_id().expect("generate id");
        assert_eq!(id.len(), 36, "uuid length: {id}");
        // Hyphen positions.
        assert_eq!(&id[8..9], "-");
        assert_eq!(&id[13..14], "-");
        assert_eq!(&id[18..19], "-");
        assert_eq!(&id[23..24], "-");
        // Version-4 nibble.
        assert_eq!(&id[14..15], "4");
        // Variant nibble (one of 8/9/a/b).
        let v = &id[19..20];
        assert!(matches!(v, "8" | "9" | "a" | "b"), "variant: {v}");
    }

    #[test]
    fn is_enabled_default_false() {
        let (_tmp, dir) = fresh_dir();
        // No files: disabled.
        assert!(!is_enabled_in(&dir));
    }

    #[test]
    fn enable_then_status_is_enabled() {
        let (_tmp, dir) = fresh_dir();
        let id = enable_in(&dir).expect("enable");
        assert!(is_enabled_in(&dir));
        // install_id_path should now exist.
        assert!(install_id_path_in(&dir).exists());
        assert!(!id.is_empty());
    }

    #[test]
    fn disable_removes_install_id() {
        let (_tmp, dir) = fresh_dir();
        let _ = enable_in(&dir).expect("enable");
        assert!(install_id_path_in(&dir).exists());
        disable_in(&dir).expect("disable");
        assert!(!install_id_path_in(&dir).exists());
        assert!(!is_enabled_in(&dir));
    }

    #[test]
    fn enable_is_idempotent() {
        let (_tmp, dir) = fresh_dir();
        let id1 = enable_in(&dir).expect("first enable");
        let id2 = enable_in(&dir).expect("second enable");
        assert_eq!(id1, id2, "second enable must preserve install-id");
    }

    #[test]
    fn config_only_without_install_id_is_disabled() {
        let (_tmp, dir) = fresh_dir();
        write_config_in(
            &dir,
            &LocalConfig {
                enabled: true,
                last_ping_unix_ms: None,
            },
        )
        .expect("write config");
        // Config says enabled but no install-id on disk — must be
        // treated as disabled (defense in depth).
        assert!(!is_enabled_in(&dir));
    }
}
