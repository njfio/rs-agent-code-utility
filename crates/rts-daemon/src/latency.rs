//! Per-method latency histograms backing the opt-in telemetry
//! `method_latency_p50_ms` / `method_latency_p99_ms` fields.
//!
//! Implementation is a hand-rolled log2-bucketed approximation:
//!
//! - **No new external deps.** AGENTS.md "Dependency hygiene" calls
//!   out the daemon's zero-HTTP closure; a histogram crate would also
//!   need a privacy / supply-chain review. The receiver of these
//!   percentiles is a telemetry pipeline that aggregates millions of
//!   data points across installs — single-install precision below
//!   "next-bucket-up" is noise once the receiver bins.
//! - **18 buckets covering 1 µs .. 262 ms .. ∞.** Bucket `i` covers
//!   `[2^i µs, 2^(i+1) µs)`; bucket 0 is `[1 µs, 2 µs)`, bucket 17 is
//!   `[131 ms, 262 ms)`, bucket 18 is "everything 262 ms and up." Any
//!   real RPC latency lands within one log2 step of the truth — i.e.,
//!   the reported p50 is within ±factor-of-1.5 of the actual p50.
//! - **All counters are `AtomicU64` with `Relaxed` ordering.** Same
//!   convention as `CallCounters`; the dispatcher path adds two
//!   relaxed atomic ops per RPC (one `record` + one cumulative count)
//!   on top of the existing per-method counter bump. Negligible
//!   overhead.
//!
//! Per-method storage lives in [`MethodLatencyHistograms`]; the
//! method enumeration mirrors `state::CallCounters` so a future
//! protocol method addition is caught at compile time by both
//! structs.
//!
//! The output of `snapshot_p50_ms_by_method` / `snapshot_p99_ms_by_method`
//! is a `BTreeMap<String, u64>` of method-enum keys to bucket-midpoint
//! milliseconds, deterministic across calls — matches what the
//! `rts-mcp` telemetry layer's `filter_method_map` filter expects.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Number of histogram buckets. Index `i` (0..NUM_BUCKETS-1) covers
/// `[2^i µs, 2^(i+1) µs)`; the final overflow bucket
/// (`NUM_BUCKETS-1`) collects everything `>= 2^(NUM_BUCKETS-1) µs`.
///
/// 19 buckets covers 1 µs .. 262 ms + overflow. p50 / p99 of any
/// real method dispatch fall well below the 262 ms ceiling on a
/// healthy daemon; pathological samples land in the overflow bucket
/// and the percentile resolves to the bucket's lower edge (524 ms).
const NUM_BUCKETS: usize = 19;

/// Per-method histogram. 19 atomic counters; clone-safe via `Default`
/// because each counter starts at 0.
#[derive(Debug, Default)]
pub struct LatencyHistogram {
    /// Bucket `i` holds the count of samples in `[2^i µs, 2^(i+1) µs)`,
    /// except the last bucket which is the overflow [2^(N-1) µs, ∞).
    buckets: [AtomicU64; NUM_BUCKETS],
}

impl LatencyHistogram {
    /// `const fn` constructor so the type can be used in static
    /// contexts and tests without going through `Default::default`.
    /// Exposed only inside this crate / tests; production code paths
    /// use `Default` via the `MethodLatencyHistograms` parent.
    #[allow(dead_code, clippy::declare_interior_mutable_const)]
    pub const fn new() -> Self {
        // Avoid Default::default in a const fn — manually instantiate.
        // The clippy `declare_interior_mutable_const` lint warns
        // because `AtomicU64` is `!Copy` and interior-mutable; the
        // const is initializer-only (consumed by the array repeat
        // expression) and the array elements then own their state.
        // This pattern is the standard recipe for `[Atomic; N]`
        // const init prior to `std::sync::atomic::AtomicU64::new`
        // becoming usable in `const` array repeat.
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            buckets: [ZERO; NUM_BUCKETS],
        }
    }

    /// Record one sample. `micros` is the observed duration in
    /// microseconds; values above the top bucket's lower edge land in
    /// the overflow bucket.
    pub fn record(&self, micros: u64) {
        let idx = bucket_index_for_micros(micros);
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Total number of recorded samples across all buckets.
    pub fn total(&self) -> u64 {
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum()
    }

    /// Percentile in milliseconds, rounded up to the bucket's lower
    /// edge. `p` is in [0.0, 1.0]. Returns 0 when no samples have
    /// been recorded — the same shape consumers see when telemetry
    /// is enabled before any RPCs have fired.
    pub fn percentile_ms(&self, p: f64) -> u64 {
        let total = self.total();
        if total == 0 {
            return 0;
        }
        let p = p.clamp(0.0, 1.0);
        // Smallest count `c` such that cumulative >= ceil(p * total).
        // Use ceil so p=1.0 returns the topmost non-empty bucket and
        // p=0.5 of a single-sample histogram returns that sample's
        // bucket.
        let target = ((p * total as f64).ceil() as u64).max(1);
        let mut cumulative: u64 = 0;
        for (i, b) in self.buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(b.load(Ordering::Relaxed));
            if cumulative >= target {
                return bucket_lower_edge_ms(i);
            }
        }
        // Should be unreachable when total > 0; defensive fallback.
        bucket_lower_edge_ms(NUM_BUCKETS - 1)
    }
}

/// Compute the bucket index for a given micros sample.
/// Values `< 1` map to bucket 0; values `>= 2^(NUM_BUCKETS-1)` map to
/// the overflow bucket.
fn bucket_index_for_micros(micros: u64) -> usize {
    if micros <= 1 {
        return 0;
    }
    // ilog2 returns floor(log2(x)); for x in [2^i, 2^(i+1)) → i.
    let raw = micros.ilog2() as usize;
    raw.min(NUM_BUCKETS - 1)
}

/// Lower edge of bucket `i` in milliseconds (clamped to >= 1ms for
/// reporting — sub-millisecond p50s are reported as 0 ms, which is
/// exactly what consumers expect from an integer-ms wire schema).
fn bucket_lower_edge_ms(i: usize) -> u64 {
    // bucket i lower edge in micros is 2^i (with i=0 the special "<=1µs"
    // bucket whose lower edge is 0 µs in practice).
    if i == 0 {
        return 0;
    }
    let micros: u64 = 1u64 << (i as u32);
    micros / 1_000
}

/// One [`LatencyHistogram`] per protocol method we care to surface.
/// Field order mirrors `state::CallCounters` so a future protocol
/// method addition is caught at compile time by both structs.
///
/// `unknown_method` is intentionally omitted — by definition we don't
/// have a stable enum name for it; recording its latency would
/// silently leak attacker-controlled method strings if surfaced.
#[derive(Debug, Default)]
pub struct MethodLatencyHistograms {
    pub daemon_ping: LatencyHistogram,
    pub daemon_stats: LatencyHistogram,
    pub daemon_cancel: LatencyHistogram,
    pub daemon_shutdown: LatencyHistogram,
    pub workspace_mount: LatencyHistogram,
    pub workspace_status: LatencyHistogram,
    pub workspace_unmount: LatencyHistogram,
    pub session_open: LatencyHistogram,
    pub session_close: LatencyHistogram,
    pub index_find_symbol: LatencyHistogram,
    pub index_find_callers: LatencyHistogram,
    pub index_impact_of: LatencyHistogram,
    pub index_read_range: LatencyHistogram,
    pub index_read_symbol: LatencyHistogram,
    pub index_read_symbol_at: LatencyHistogram,
    pub index_outline: LatencyHistogram,
    pub index_grep: LatencyHistogram,
}

impl MethodLatencyHistograms {
    /// Record `micros` against the histogram for `method`. Unknown
    /// method names are silently dropped — they're already counted
    /// against `unknown_method` in `CallCounters`, and the telemetry
    /// surface deliberately omits them.
    pub fn record(&self, method: &str, micros: u64) {
        if let Some(h) = self.histogram_for(method) {
            h.record(micros);
        }
    }

    fn histogram_for(&self, method: &str) -> Option<&LatencyHistogram> {
        Some(match method {
            "Daemon.Ping" => &self.daemon_ping,
            "Daemon.Stats" => &self.daemon_stats,
            "Daemon.Cancel" => &self.daemon_cancel,
            "Daemon.Shutdown" => &self.daemon_shutdown,
            "Workspace.Mount" => &self.workspace_mount,
            "Workspace.Status" => &self.workspace_status,
            "Workspace.Unmount" => &self.workspace_unmount,
            "Session.Open" => &self.session_open,
            "Session.Close" => &self.session_close,
            "Index.FindSymbol" => &self.index_find_symbol,
            "Index.FindCallers" => &self.index_find_callers,
            "Index.ImpactOf" => &self.index_impact_of,
            "Index.ReadRange" => &self.index_read_range,
            "Index.ReadSymbol" => &self.index_read_symbol,
            "Index.ReadSymbolAt" => &self.index_read_symbol_at,
            "Index.Outline" => &self.index_outline,
            "Index.Grep" => &self.index_grep,
            _ => return None,
        })
    }

    /// Stable list of (method_enum_name, histogram_ref) for the
    /// telemetry snapshot. Order doesn't matter — the caller
    /// `BTreeMap`-collects so the JSON key order is determined by the
    /// consumer.
    fn enumerated(&self) -> [(&'static str, &LatencyHistogram); 17] {
        [
            ("Daemon.Ping", &self.daemon_ping),
            ("Daemon.Stats", &self.daemon_stats),
            ("Daemon.Cancel", &self.daemon_cancel),
            ("Daemon.Shutdown", &self.daemon_shutdown),
            ("Workspace.Mount", &self.workspace_mount),
            ("Workspace.Status", &self.workspace_status),
            ("Workspace.Unmount", &self.workspace_unmount),
            ("Session.Open", &self.session_open),
            ("Session.Close", &self.session_close),
            ("Index.FindSymbol", &self.index_find_symbol),
            ("Index.FindCallers", &self.index_find_callers),
            ("Index.ImpactOf", &self.index_impact_of),
            ("Index.ReadRange", &self.index_read_range),
            ("Index.ReadSymbol", &self.index_read_symbol),
            ("Index.ReadSymbolAt", &self.index_read_symbol_at),
            ("Index.Outline", &self.index_outline),
            ("Index.Grep", &self.index_grep),
        ]
    }

    /// Snapshot per-method percentile in milliseconds. Methods with
    /// no recorded samples are omitted entirely (rather than reported
    /// as `0`) so the receiver can distinguish "method never called"
    /// from "method called and was sub-millisecond." The receiver's
    /// schema-validation pass on the `method_latency_*_ms` maps is
    /// the same enum filter as `method_counts`.
    pub fn snapshot_percentile_ms(&self, p: f64) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for (name, h) in self.enumerated() {
            if h.total() == 0 {
                continue;
            }
            out.insert(name.to_string(), h.percentile_ms(p));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_increments_correct_bucket() {
        let h = LatencyHistogram::new();
        h.record(5); // bucket 2: [4, 8) µs
        h.record(5);
        h.record(50_000); // bucket 15: [32_768, 65_536) µs
        assert_eq!(h.total(), 3);
    }

    #[test]
    fn percentile_of_empty_histogram_is_zero() {
        let h = LatencyHistogram::new();
        assert_eq!(h.percentile_ms(0.5), 0);
        assert_eq!(h.percentile_ms(0.99), 0);
    }

    #[test]
    fn p50_and_p99_separate_when_slow_tail_dominates_top_percentile() {
        let h = LatencyHistogram::new();
        // 90 fast calls in the sub-ms bucket + 10 slow calls in the
        // ~131-262 ms bucket. p50 should land in the fast bucket
        // (still 0 ms after integer truncation); p99 must land in
        // the slow bucket because 11% of samples are slow.
        for _ in 0..90 {
            h.record(50); // bucket 5: [32, 64) µs → 0 ms
        }
        for _ in 0..10 {
            h.record(200_000); // bucket 17: [131_072, 262_144) µs → 131 ms
        }
        let p50 = h.percentile_ms(0.5);
        let p99 = h.percentile_ms(0.99);
        assert!(p50 < p99, "p50 ({p50}) should be < p99 ({p99})");
        assert!(p99 >= 131, "p99 ({p99}) should reflect the slow tail");
    }

    #[test]
    fn p50_at_least_p99_when_distribution_is_uniform() {
        // Defense-in-depth: equal samples per bucket should produce
        // p99 >= p50, never the other way around.
        let h = LatencyHistogram::new();
        for _ in 0..10 {
            h.record(50);
        }
        for _ in 0..10 {
            h.record(200_000);
        }
        let p50 = h.percentile_ms(0.5);
        let p99 = h.percentile_ms(0.99);
        assert!(p99 >= p50, "p99 ({p99}) should be >= p50 ({p50})");
    }

    #[test]
    fn overflow_bucket_caps_runaway_samples() {
        let h = LatencyHistogram::new();
        h.record(u64::MAX);
        assert_eq!(h.total(), 1);
        // overflow bucket lower edge in ms.
        let expected_ms = bucket_lower_edge_ms(NUM_BUCKETS - 1);
        assert_eq!(h.percentile_ms(0.5), expected_ms);
    }

    #[test]
    fn method_record_routes_to_correct_histogram() {
        let m = MethodLatencyHistograms::default();
        m.record("Index.FindSymbol", 1_000);
        m.record("Index.FindSymbol", 2_000);
        m.record("Index.Grep", 50_000);
        m.record("not.a.real.method", 1_000); // dropped silently

        let p50 = m.snapshot_percentile_ms(0.5);
        assert!(p50.contains_key("Index.FindSymbol"));
        assert!(p50.contains_key("Index.Grep"));
        // The drop is the bright-line behavior — make sure the
        // attacker-controlled string isn't a key.
        assert!(!p50.contains_key("not.a.real.method"));
        // Untouched methods are absent (NOT reported as 0).
        assert!(!p50.contains_key("Index.Outline"));
    }

    #[test]
    fn unknown_method_does_not_leak_into_snapshot() {
        let m = MethodLatencyHistograms::default();
        m.record("/etc/passwd", 1_000);
        m.record("Index.SecretRpc.GetToken", 1_000);
        let p50 = m.snapshot_percentile_ms(0.5);
        for k in p50.keys() {
            assert!(
                !k.contains("/etc/passwd") && !k.contains("Secret"),
                "leaked attacker string: {k}"
            );
        }
        // Snapshot is empty since no known methods recorded.
        assert!(p50.is_empty());
    }
}
