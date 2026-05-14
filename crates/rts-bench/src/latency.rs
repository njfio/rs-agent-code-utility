//! Latency benchmark (S1) for the rts-mcp stack.
//!
//! Per plan §P9: synthetic 100k-LOC fixture, 1000 randomised queries
//! (50% find_symbol, 30% read_symbol, 20% outline_workspace), report
//! p50/p95/p99 cold and warm. The plan's exit criterion is **p95 warm
//! < 10 ms** for the daemon's hot path (excluding rts-mcp + JSON-RPC
//! overhead, which adds ~80 µs per call per the P0.1 spike).
//!
//! v0 ships the harness. Latency under sustained write load
//! (architecture review recommendation 11) lands in a follow-up.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::mcp_runner::McpSession;

/// Distribution of query kinds per plan §P9.
#[derive(Debug, Clone, Copy)]
pub enum QueryKind {
    FindSymbol,
    ReadSymbol,
    Outline,
}

impl QueryKind {
    /// Plan-canonical mix.
    pub const MIX: &'static [(QueryKind, u32)] = &[
        (QueryKind::FindSymbol, 50),
        (QueryKind::ReadSymbol, 30),
        (QueryKind::Outline, 20),
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            QueryKind::FindSymbol => "find_symbol",
            QueryKind::ReadSymbol => "read_symbol",
            QueryKind::Outline => "outline",
        }
    }
}

/// One latency measurement.
#[derive(Debug, Clone)]
pub struct Sample {
    pub kind: QueryKind,
    pub elapsed_micros: u128,
    pub ok: bool,
}

/// Synthesise a Rust workspace with `target_loc` lines of source spread
/// across files. Each file defines `funcs_per_file` public functions
/// and references one or two from the previous file — produces a chain
/// shaped like a long DAG, which gives PageRank a meaningful graph and
/// `find_symbol` plenty of names to hit.
pub fn synth_workspace(root: &Path, target_loc: usize) -> Result<Vec<String>> {
    const FUNCS_PER_FILE: usize = 10;
    const LINES_PER_FN: usize = 4;
    // Lines per file ≈ (FUNCS_PER_FILE × (LINES_PER_FN + 2)) + ~5 header
    // → 65 lines. Number of files = target_loc / 65, rounded up.
    let lines_per_file = FUNCS_PER_FILE * (LINES_PER_FN + 2) + 5;
    let file_count = target_loc.div_ceil(lines_per_file).max(2);

    let mut all_symbols: Vec<String> = Vec::with_capacity(file_count * FUNCS_PER_FILE);
    for f in 0..file_count {
        let mut src = String::new();
        src.push_str(&format!("//! Generated module {f}.\n\n"));
        for i in 0..FUNCS_PER_FILE {
            let fn_name = format!("synth_f{f}_fn{i}");
            all_symbols.push(fn_name.clone());
            src.push_str(&format!(
                "pub fn {fn_name}(x: u32) -> u32 {{\n    let _ = x + 1;\n    let _ = x.saturating_mul(2);\n    x\n}}\n\n"
            ));
        }
        // Cross-file refs: every file references the first two functions
        // of the previous file. Wraps to file_count-1 for f=0.
        let prev = (f + file_count - 1) % file_count;
        src.push_str(&format!(
            "pub fn synth_f{f}_caller() {{\n    let _ = synth_f{prev}_fn0(1);\n    let _ = synth_f{prev}_fn1(2);\n}}\n"
        ));
        all_symbols.push(format!("synth_f{f}_caller"));
        std::fs::write(root.join(format!("synth_f{f}.rs")), src)
            .with_context(|| format!("write synth_f{f}.rs"))?;
    }
    Ok(all_symbols)
}

/// Deterministic linear-congruential PRNG. We don't want a `rand`
/// dep just for latency-bench randomness; this is more than sufficient
/// for picking query kinds and symbol indices.
pub struct Lcg(u64);

impl Lcg {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        // Numerical Recipes constants.
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    pub fn pick_weighted<'a, T>(&mut self, choices: &'a [(T, u32)]) -> &'a T {
        let total: u32 = choices.iter().map(|(_, w)| *w).sum();
        let r = (self.next_u64() % total as u64) as u32;
        let mut acc: u32 = 0;
        for (item, w) in choices {
            acc += *w;
            if r < acc {
                return item;
            }
        }
        &choices.last().unwrap().0
    }

    pub fn pick_index(&mut self, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        (self.next_u64() as usize) % len
    }
}

/// Read-symbol mode for the bench mix.
///
/// `Signature` calls `read_symbol` with `shape: "signature"` and no
/// dependency walk — the historical bench default, exercises only the
/// signature renderer + redb lookup.
///
/// `BodyWithDeps` calls `read_symbol` with `shape: "body"` and
/// `include_dependencies: true` — the only path that exercises v0.3
/// U3's closure walker (the alpha.30 → v0.3 change replaced the
/// per-call parse + filter loop with one `SID_REFS_OUT` multimap
/// read). G5's spec-faithful p95 measurement requires this mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadSymbolMode {
    Signature,
    BodyWithDeps,
}

impl ReadSymbolMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ReadSymbolMode::Signature => "signature",
            ReadSymbolMode::BodyWithDeps => "body_with_deps",
        }
    }
}

/// Run the latency benchmark. Returns one `Sample` per executed query.
///
/// `read_symbol_mode` controls how the 30% read_symbol bucket is
/// executed. `Signature` is the historical default; `BodyWithDeps`
/// exercises v0.3 U3's closure walker for G5 measurement.
pub async fn run(
    session: &mut McpSession,
    symbols: &[String],
    files: &[String],
    queries: u32,
    seed: u64,
    read_symbol_mode: ReadSymbolMode,
) -> Result<Vec<Sample>> {
    let mut rng = Lcg::new(seed);
    let mut out: Vec<Sample> = Vec::with_capacity(queries as usize);
    let read_args = match read_symbol_mode {
        ReadSymbolMode::Signature => json!({ "shape": "signature" }),
        ReadSymbolMode::BodyWithDeps => {
            json!({ "shape": "body", "include_dependencies": true })
        }
    };
    for _ in 0..queries {
        let kind = *rng.pick_weighted(QueryKind::MIX);
        let sample = match kind {
            QueryKind::FindSymbol => {
                let name = &symbols[rng.pick_index(symbols.len())];
                time_call(session, kind, "find_symbol", json!({ "name": name })).await?
            }
            QueryKind::ReadSymbol => {
                let name = &symbols[rng.pick_index(symbols.len())];
                // Merge the per-call name onto the per-mode template.
                let mut args = read_args.clone();
                if let Value::Object(ref mut m) = args {
                    m.insert("name".to_string(), Value::String(name.clone()));
                }
                time_call(session, kind, "read_symbol", args).await?
            }
            QueryKind::Outline => {
                time_call(
                    session,
                    kind,
                    "outline_workspace",
                    json!({ "token_budget": 4096 }),
                )
                .await?
            }
        };
        let _ = files; // reserved for future read_range mix
        out.push(sample);
    }
    Ok(out)
}

async fn time_call(
    session: &mut McpSession,
    kind: QueryKind,
    tool: &str,
    args: Value,
) -> Result<Sample> {
    let start = Instant::now();
    let call = session.tools_call(tool, args, 0).await?;
    let elapsed = start.elapsed();
    Ok(Sample {
        kind,
        elapsed_micros: elapsed.as_micros(),
        ok: !call.is_error,
    })
}

/// Aggregated stats per query kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KindStats {
    pub count: u32,
    pub ok: u32,
    pub p50_micros: u64,
    pub p95_micros: u64,
    pub p99_micros: u64,
    pub max_micros: u64,
    pub mean_micros: u64,
}

/// Latency report shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyReport {
    pub version: u32,
    pub rts_bench_version: String,
    pub workspace_path: String,
    pub synth_loc: usize,
    pub queries: u32,
    pub cold_count: u32,
    pub seed: u64,
    /// Which `read_symbol` shape the 30% bucket exercised. Either
    /// `"signature"` (historical default) or `"body_with_deps"` (G5
    /// closure-walker mode). Stable on-the-wire field; older reports
    /// pre-v0.3.1 will deserialise with this `None` and downstream
    /// tools should treat that as `"signature"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_symbol_mode: Option<String>,
    /// Per-kind stats over warm samples (excludes the cold prefix).
    pub warm: IndexMap<String, KindStats>,
    /// Per-kind stats over the cold prefix.
    pub cold: IndexMap<String, KindStats>,
    /// Overall warm aggregates.
    pub warm_all: KindStats,
}

/// Compute `KindStats` for a slice of samples. Samples are sorted in
/// place to compute percentiles — caller owns the buffer.
fn stats_of(samples: &mut [u128]) -> KindStats {
    let count = samples.len() as u32;
    if count == 0 {
        return KindStats {
            count: 0,
            ok: 0,
            p50_micros: 0,
            p95_micros: 0,
            p99_micros: 0,
            max_micros: 0,
            mean_micros: 0,
        };
    }
    samples.sort_unstable();
    // Nearest-rank percentile: idx = ceil(q × n) − 1, clamped to range.
    // For n=100, q=0.50 → idx=49 (samples[49] from 1..=100 is 50, the
    // textbook median).
    let p = |q: f64| -> u64 {
        let n = count as f64;
        let idx = ((q * n).ceil() as usize).saturating_sub(1);
        samples[idx.min(samples.len() - 1)] as u64
    };
    let sum: u128 = samples.iter().sum();
    let mean = (sum / count as u128) as u64;
    KindStats {
        count,
        ok: count,
        p50_micros: p(0.50),
        p95_micros: p(0.95),
        p99_micros: p(0.99),
        max_micros: *samples.last().unwrap() as u64,
        mean_micros: mean,
    }
}

/// Build the wire-shape report.
pub fn build_report(
    workspace_path: &Path,
    synth_loc: usize,
    seed: u64,
    cold_count: u32,
    read_symbol_mode: ReadSymbolMode,
    samples: &[Sample],
) -> LatencyReport {
    let queries = samples.len() as u32;
    let cold = &samples[..(cold_count as usize).min(samples.len())];
    let warm = &samples[(cold_count as usize).min(samples.len())..];

    let by_kind = |bucket: &[Sample], kind: QueryKind| -> KindStats {
        // Percentiles describe response latency — they only make sense
        // over successful responses. Including error responses (e.g.
        // `SYMBOL_NOT_FOUND` returns in microseconds) silently drags
        // p50/p95/p99 downward and corrupts comparisons. The CHANGELOG
        // entry "Honest dogfooding finding — read_symbol .ok rate"
        // documents how this masked a real bench-validity issue.
        //
        // `count` still reflects the total attempted, and `ok` reports
        // how many of those succeeded. A caller seeing `ok` << `count`
        // knows the per-bucket numbers describe a small sub-sample,
        // not a corrupted mix.
        let mut bucket_samples: Vec<u128> = bucket
            .iter()
            .filter(|s| s.kind.as_str() == kind.as_str() && s.ok)
            .map(|s| s.elapsed_micros)
            .collect();
        let attempted = bucket
            .iter()
            .filter(|s| s.kind.as_str() == kind.as_str())
            .count() as u32;
        let mut stats = stats_of(&mut bucket_samples);
        stats.count = attempted;
        // `stats_of` set `stats.ok = bucket_samples.len()` already;
        // that's exactly the count of successful samples in this bucket.
        stats
    };

    let mut warm_map: IndexMap<String, KindStats> = IndexMap::new();
    let mut cold_map: IndexMap<String, KindStats> = IndexMap::new();
    for (kind, _w) in QueryKind::MIX {
        let key = kind.as_str().to_string();
        warm_map.insert(key.clone(), by_kind(warm, *kind));
        cold_map.insert(key, by_kind(cold, *kind));
    }

    // Same .ok-only invariant for the aggregate: warm_all percentiles
    // describe successful warm responses, not a mix of real responses
    // and fast errors.
    let mut all_warm: Vec<u128> = warm
        .iter()
        .filter(|s| s.ok)
        .map(|s| s.elapsed_micros)
        .collect();
    let mut warm_all = stats_of(&mut all_warm);
    warm_all.count = warm.len() as u32;

    LatencyReport {
        version: 1,
        rts_bench_version: env!("CARGO_PKG_VERSION").to_string(),
        workspace_path: workspace_path.display().to_string(),
        synth_loc,
        queries,
        cold_count,
        seed,
        read_symbol_mode: Some(read_symbol_mode.as_str().to_string()),
        warm: warm_map,
        cold: cold_map,
        warm_all,
    }
}

/// Write a `LatencyReport` to disk as pretty JSON.
pub fn write_report(path: &Path, report: &LatencyReport) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report).context("encode latency report")?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Default cold/warm split: per plan §P9, the first N queries are
/// considered "cold" while the daemon is still warming caches.
pub const DEFAULT_COLD_COUNT: u32 = 100;

/// Resolve the workspace + symbol set for a latency run. Either
/// synthesise (when `synth_loc` is given) or use an existing workspace
/// path (`target`). For a real workspace the returned `symbols` is
/// empty — the caller fills it post-mount by querying `find_symbol`
/// (since the daemon is the only thing that knows which names are
/// indexable on a workspace it doesn't synthesise).
/// Returns (workspace_root, symbols, files).
pub fn prepare_workspace(
    target: Option<&Path>,
    synth_loc: Option<usize>,
    tmp_root: &Path,
) -> Result<(PathBuf, Vec<String>, Vec<String>)> {
    match (target, synth_loc) {
        (Some(p), Some(_)) => anyhow::bail!("pass either --workspace or --synth-loc, not both"),
        (Some(p), None) => {
            let canonical = p
                .canonicalize()
                .with_context(|| format!("canonicalize {}", p.display()))?;
            if !canonical.is_dir() {
                anyhow::bail!("workspace path {} is not a directory", canonical.display());
            }
            // Symbols + files are discovered post-mount in `main.rs:
            // run_latency`. Return empty Vecs as the signal to that
            // path.
            Ok((canonical, Vec::new(), Vec::new()))
        }
        (None, Some(loc)) => {
            let ws = tmp_root.join("synth-workspace");
            std::fs::create_dir_all(&ws)?;
            let syms = synth_workspace(&ws, loc)?;
            let files: Vec<String> = std::fs::read_dir(&ws)?
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".rs"))
                .collect();
            Ok((ws, syms, files))
        }
        (None, None) => {
            anyhow::bail!("--synth-loc is required when --workspace is omitted")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synth_workspace_produces_files_and_symbols() {
        let dir = tempfile::tempdir().unwrap();
        let syms = synth_workspace(dir.path(), 1_000).unwrap();
        assert!(syms.len() > 10, "expected many symbols; got {}", syms.len());
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(entries.len() >= 2, "expected ≥2 generated files");
        // Every symbol name should appear in at least one generated file.
        let first_sym = &syms[0];
        let mut found = false;
        for e in entries {
            let e = e.unwrap();
            if e.path().extension().and_then(|x| x.to_str()) != Some("rs") {
                continue;
            }
            let content = std::fs::read_to_string(e.path()).unwrap();
            if content.contains(first_sym) {
                found = true;
                break;
            }
        }
        assert!(found, "first symbol `{first_sym}` not found in any file");
    }

    #[test]
    fn lcg_picks_weighted_in_distribution() {
        let mut rng = Lcg::new(42);
        let choices: &[(&str, u32)] = &[("a", 99), ("b", 1)];
        let mut a = 0;
        let mut b = 0;
        for _ in 0..1000 {
            match *rng.pick_weighted(choices) {
                "a" => a += 1,
                "b" => b += 1,
                _ => unreachable!(),
            }
        }
        // With weight 99:1, expect "a" ≫ "b". Allow some slack.
        assert!(a > 900, "a count {a} should be > 900");
        assert!(b < 100, "b count {b} should be < 100");
    }

    #[test]
    fn stats_of_basic_percentiles() {
        let mut s: Vec<u128> = (1..=100).collect();
        let stats = stats_of(&mut s);
        assert_eq!(stats.count, 100);
        // p50 = sample at index ceil((100-1)*0.5) = 50 → value 50.
        assert_eq!(stats.p50_micros, 50);
        // p95 ≈ index 94 → value 95.
        assert!(
            stats.p95_micros >= 94 && stats.p95_micros <= 96,
            "got {}",
            stats.p95_micros
        );
        assert_eq!(stats.p99_micros, 99);
        assert_eq!(stats.max_micros, 100);
    }

    #[test]
    fn prepare_workspace_real_path_returns_empty_symbols() {
        // Real-workspace mode: caller passes a path, we canonicalise
        // it and return an empty symbols Vec (caller fills via
        // find_symbol post-mount). Validates the v0.3.2 surface.
        let tmp = tempfile::tempdir().unwrap();
        // Make it look real: at least one file present.
        std::fs::write(tmp.path().join("dummy.rs"), "pub fn x() {}").unwrap();
        let tmp_root = tempfile::tempdir().unwrap();
        let (ws, syms, files) = prepare_workspace(Some(tmp.path()), None, tmp_root.path()).unwrap();
        assert_eq!(ws, tmp.path().canonicalize().unwrap());
        assert!(syms.is_empty(), "real-workspace path returns no symbols");
        assert!(files.is_empty(), "real-workspace path returns no files");
    }

    #[test]
    fn prepare_workspace_rejects_both_workspace_and_synth_loc() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp_root = tempfile::tempdir().unwrap();
        let err = prepare_workspace(Some(tmp.path()), Some(1_000), tmp_root.path()).unwrap_err();
        assert!(
            format!("{err}").contains("not both"),
            "expected mutual-exclusion error, got: {err}"
        );
    }

    #[test]
    fn prepare_workspace_rejects_non_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("not-a-dir.txt");
        std::fs::write(&f, "x").unwrap();
        let tmp_root = tempfile::tempdir().unwrap();
        let err = prepare_workspace(Some(&f), None, tmp_root.path()).unwrap_err();
        assert!(
            format!("{err}").contains("not a directory"),
            "expected non-directory error, got: {err}"
        );
    }

    #[test]
    fn read_symbol_mode_as_str_is_stable() {
        // The string is on-the-wire in the JSON report. Don't change
        // these without bumping the report version.
        assert_eq!(ReadSymbolMode::Signature.as_str(), "signature");
        assert_eq!(ReadSymbolMode::BodyWithDeps.as_str(), "body_with_deps");
    }

    #[test]
    fn percentiles_exclude_errored_samples() {
        // Eight samples, four genuine (1, 2, 3, 4 ms) and four
        // microsecond-fast errors (the SYMBOL_NOT_FOUND shape). The
        // pre-fix code computed percentiles over all eight and
        // reported a p50 around 500 µs — completely fictional.
        // Post-fix, percentiles describe only the four real responses.
        let real = [1_000u128, 2_000, 3_000, 4_000];
        let errs = [10u128, 12, 15, 20];
        let samples: Vec<Sample> = real
            .iter()
            .map(|&us| Sample {
                kind: QueryKind::ReadSymbol,
                elapsed_micros: us,
                ok: true,
            })
            .chain(errs.iter().map(|&us| Sample {
                kind: QueryKind::ReadSymbol,
                elapsed_micros: us,
                ok: false,
            }))
            .collect();
        let report = build_report(
            Path::new("/tmp/synth"),
            1_000,
            42,
            0, // no cold prefix — all eight are "warm"
            ReadSymbolMode::BodyWithDeps,
            &samples,
        );
        let rs = report.warm.get("read_symbol").unwrap();
        assert_eq!(rs.count, 8, "count reports attempted samples");
        assert_eq!(rs.ok, 4, "ok reports successful samples");
        // p50 over [1000, 2000, 3000, 4000] = 2000 (nearest-rank: idx
        // ceil(0.5*4)-1 = 1, value 2000). Pre-fix this was ~15 (the
        // median of all eight).
        assert_eq!(
            rs.p50_micros, 2_000,
            "p50 should describe real responses (2 ms), not be diluted \
             by SYMBOL_NOT_FOUND errors"
        );
        // p95 over [1000..=4000] = 4000 (idx ceil(0.95*4)-1 = 3).
        assert_eq!(rs.p95_micros, 4_000);
        // warm_all aggregate also follows the .ok-only rule.
        assert_eq!(report.warm_all.count, 8);
        assert_eq!(report.warm_all.ok, 4);
        assert_eq!(report.warm_all.p50_micros, 2_000);
    }

    #[test]
    fn report_records_read_symbol_mode() {
        // Build a tiny report and check the mode appears in the JSON.
        let samples = vec![Sample {
            kind: QueryKind::ReadSymbol,
            elapsed_micros: 1234,
            ok: true,
        }];
        let report = build_report(
            Path::new("/tmp/synth"),
            1_000,
            42,
            0,
            ReadSymbolMode::BodyWithDeps,
            &samples,
        );
        assert_eq!(
            report.read_symbol_mode.as_deref(),
            Some("body_with_deps"),
            "G5 deps-mode runs must record body_with_deps in the JSON report"
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["read_symbol_mode"], "body_with_deps");
    }

    #[test]
    fn stats_of_empty_is_zero() {
        let mut s: Vec<u128> = Vec::new();
        let stats = stats_of(&mut s);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.p95_micros, 0);
    }
}
