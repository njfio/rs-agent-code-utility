//! Hallucination-metric harness (verify-v0 P1.U5).
//!
//! Measures, with **no LLM**, how often agent-emitted code references
//! symbols / imports that don't exist, and how often call sites mismatch
//! the real signature. The pipeline is fully deterministic:
//!
//! 1. Parse each agent snippet with rts's own tree-sitter extractor
//!    ([`rust_tree_sitter::extract_references`], F3) to turn it into the
//!    symbols / imports / call-arities it *uses*.
//! 2. Check each reference against the live index via the verify tools
//!    (`Index.VerifySymbol` / `Index.VerifyImport` / `Index.VerifySignature`,
//!    surfaced through `rts-mcp` as `verify_symbol` / `verify_import` /
//!    `verify_signature`).
//! 3. Aggregate into rates with **honest denominators**: every metric
//!    excludes `indeterminate` references from its denominator and reports
//!    the count it excluded, so coverage is always visible and a rate can
//!    never be cherry-picked by silently dropping the undecidable cases.
//!
//! ## Metrics
//!
//! - **SHR** (Symbol Hallucination Rate) = `not_found symbol refs /
//!   decidable symbol refs`. **RGR** (Reference Grounding Rate) = `1 − SHR`.
//! - **IHR** (Import Hallucination Rate) = `unresolved imports / decidable
//!   imports`.
//! - **SMR** (Signature Mismatch Rate) = `mismatched call sites / decidable
//!   call sites`. A call site is decidable only when the callee exists AND
//!   `verify_signature` did not return `indeterminate`.
//!
//! Snippets in languages without F3 support (anything but Rust / TS /
//! Python) contribute to [`HallucinationReport::unsupported_language_refs`],
//! never to any rate.
//!
//! ## Testability
//!
//! The pure aggregation math ([`Metric::from_resolutions`] /
//! [`build_report`]) operates over already-collected [`Resolution`] values
//! and needs no daemon. The [`VerifyOracle`] trait abstracts the live
//! verify calls so the integration path uses the real daemon while unit
//! tests feed canned resolutions.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use rust_tree_sitter::{Language, RefKind, Reference, extract_references, supports_references};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// The three decidability outcomes a verify call can produce, mirroring
/// `rust_tree_sitter::Resolution`'s frozen wire strings. Re-declared here
/// (rather than reusing the core enum) so the bench's report shape stays
/// independent of the core type and serializes the snake_case strings the
/// other bench reports use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// The reference resolved to exactly one definition (or, for a
    /// signature, matched it). Counts toward the denominator, not the
    /// numerator.
    Exact,
    /// The reference provably has no matching definition (or, for a
    /// signature, mismatched). Counts toward BOTH numerator and
    /// denominator.
    NotFound,
    /// Could not be decided statically (ambiguous overload, macro /
    /// dynamic dispatch, unsupported signature, unresolved multi-segment
    /// import). EXCLUDED from the denominator; counted separately.
    Indeterminate,
}

impl Resolution {
    /// Parse the `resolution` field of a verify-tool response body.
    /// Unknown / missing strings are treated as `Indeterminate` — the
    /// honest default (never manufacture a false `not_found`).
    pub fn from_wire(s: Option<&str>) -> Self {
        match s {
            Some("exact") => Resolution::Exact,
            Some("not_found") => Resolution::NotFound,
            _ => Resolution::Indeterminate,
        }
    }
}

/// One metric's tally: an honest numerator / denominator pair plus the
/// count of indeterminate references it excluded.
///
/// `rate` is `numerator / denominator`, or `None` when the denominator is
/// zero (nothing was decidable) — never `NaN`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metric {
    /// Decidable references that resolved to `not_found` (hallucinations).
    pub numerator: u64,
    /// Decidable references (exact + not_found). Excludes indeterminate.
    pub denominator: u64,
    /// `numerator / denominator`, or `null` when `denominator == 0`.
    pub rate: Option<f64>,
    /// References excluded from `denominator` because they were
    /// `indeterminate`. Surfaced so coverage is always visible.
    pub indeterminate_excluded: u64,
}

impl Metric {
    /// Aggregate a metric from an iterator of per-reference resolutions.
    pub fn from_resolutions(resolutions: impl IntoIterator<Item = Resolution>) -> Self {
        let mut numerator = 0u64;
        let mut denominator = 0u64;
        let mut indeterminate_excluded = 0u64;
        for r in resolutions {
            match r {
                Resolution::NotFound => {
                    numerator += 1;
                    denominator += 1;
                }
                Resolution::Exact => {
                    denominator += 1;
                }
                Resolution::Indeterminate => {
                    indeterminate_excluded += 1;
                }
            }
        }
        let rate = if denominator == 0 {
            None
        } else {
            Some(numerator as f64 / denominator as f64)
        };
        Metric {
            numerator,
            denominator,
            rate,
            indeterminate_excluded,
        }
    }

    /// The grounding rate `1 − rate`, or `None` when nothing was
    /// decidable. Used to surface RGR (= 1 − SHR) alongside SHR.
    pub fn grounding_rate(&self) -> Option<f64> {
        self.rate.map(|r| 1.0 - r)
    }
}

/// Versioned hallucination report. Same conventions as the other bench
/// reports: a `version` field, a `rts_bench_version` echo, serde-derived,
/// deterministic field order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HallucinationReport {
    /// Schema version for this report payload.
    pub version: u32,
    /// `rts-bench` package version (correlates historical diffs with
    /// extractor / metric changes).
    pub rts_bench_version: String,
    /// Workspace the references were checked against.
    pub workspace_path: String,
    /// Corpus file the snippets came from.
    pub corpus_path: String,
    /// Number of corpus snippets processed.
    pub snippet_count: usize,
    /// Symbol Hallucination Rate. `rate` = SHR; `1 − rate` = RGR.
    pub shr: Metric,
    /// Reference Grounding Rate (`1 − SHR`), or `null` when SHR is `null`.
    /// Surfaced as a top-level field so consumers don't have to recompute.
    pub rgr: Option<f64>,
    /// Import Hallucination Rate.
    pub ihr: Metric,
    /// Signature Mismatch Rate. NOTE (v0): a "mismatch" here is **arity-only**.
    /// F3 extracts a call site's argument count (`call_arity`) but not the
    /// caller's parameter names/types, so the bench claims only `{arity}` and
    /// `verify_signature` can flag an arity difference but not a param-order or
    /// return-shape one. The rate never *falsely* reports a mismatch; it is
    /// just narrower than the daemon's full `verify_signature` diff surface.
    pub smr: Metric,
    /// References in snippets whose language has no F3 reference-extraction
    /// support (anything but Rust / TS / Python). These contribute to no
    /// rate; counted here so unsupported-language coverage is visible.
    pub unsupported_language_refs: u64,
    /// Languages that actually contributed extracted references, sorted
    /// for determinism. (lowercased: `rust`, `typescript`, `python`.)
    pub languages_covered: Vec<String>,
}

/// Build a [`HallucinationReport`] from the per-reference resolutions of
/// each metric. Pure aggregation — no daemon, no IO.
#[allow(clippy::too_many_arguments)]
pub fn build_report(
    rts_bench_version: &str,
    workspace_path: &str,
    corpus_path: &str,
    snippet_count: usize,
    symbol_resolutions: impl IntoIterator<Item = Resolution>,
    import_resolutions: impl IntoIterator<Item = Resolution>,
    signature_resolutions: impl IntoIterator<Item = Resolution>,
    unsupported_language_refs: u64,
    languages_covered: BTreeSet<String>,
) -> HallucinationReport {
    let shr = Metric::from_resolutions(symbol_resolutions);
    let rgr = shr.grounding_rate();
    let ihr = Metric::from_resolutions(import_resolutions);
    let smr = Metric::from_resolutions(signature_resolutions);
    HallucinationReport {
        version: 1,
        rts_bench_version: rts_bench_version.to_string(),
        workspace_path: workspace_path.to_string(),
        corpus_path: corpus_path.to_string(),
        snippet_count,
        shr,
        rgr,
        ihr,
        smr,
        unsupported_language_refs,
        languages_covered: languages_covered.into_iter().collect(),
    }
}

// ---------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------

/// Parsed verify-eval corpus. Mirrors the semantic-eval TOML shape: a
/// pinned `version` plus a `[[snippet]]` array.
#[derive(Debug, Clone, Deserialize)]
pub struct Corpus {
    #[allow(dead_code)]
    pub version: u32,
    #[serde(rename = "snippet")]
    pub snippets: Vec<CorpusSnippet>,
}

/// One agent-emitted code snippet plus the language it's written in.
#[derive(Debug, Clone, Deserialize)]
pub struct CorpusSnippet {
    /// Free-text label for the snippet (what the fixture is exercising).
    /// Optional; only used in the human-readable summary.
    #[serde(default)]
    pub name: String,
    /// Language string (`rust`, `typescript`, `python`, …). Parsed via
    /// `rust_tree_sitter::Language::from_str`.
    pub lang: String,
    /// The agent-emitted code to analyze.
    pub code: String,
}

/// Load and parse a TOML verify-eval corpus.
pub fn load_corpus(path: &Path) -> Result<Corpus> {
    let bytes =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let parsed: Corpus = toml::from_str(&bytes)
        .with_context(|| format!("parse {} as verify corpus TOML", path.display()))?;
    Ok(parsed)
}

// ---------------------------------------------------------------------
// Edit corpus (EVR / BCIR)
// ---------------------------------------------------------------------

/// Parsed verify-EDIT-eval corpus. Mirrors the snippet-corpus TOML shape:
/// a pinned `version` plus an `[[edit_set]]` array, where each entry is a
/// whole proposed patch (a list of `[file, content]` edits) with a KNOWN
/// expected verdict the self-validation fixture pins.
#[derive(Debug, Clone, Deserialize)]
pub struct EditCorpus {
    #[allow(dead_code)]
    pub version: u32,
    #[serde(rename = "edit_set")]
    pub edit_sets: Vec<CorpusEditSet>,
}

/// One proposed edit-set: a label, the list of `{file, content}` edits
/// (full post-edit content), and the verdict the fixture expects. The
/// expected fields are advisory metadata for the human summary / a future
/// grader — the measured EVR / BCIR are computed from the LIVE daemon
/// verdict, never from these.
#[derive(Debug, Clone, Deserialize)]
pub struct CorpusEditSet {
    /// Free-text label for the edit-set (what it exercises).
    #[serde(default)]
    pub name: String,
    /// The proposed edits — each `{file, content}` carries the full
    /// post-edit content of `file`.
    pub edits: Vec<CorpusEdit>,
    /// Expected verdict (`pass` | `warn` | `fail`). Advisory — surfaced
    /// in the summary so a drift is visible; not used in aggregation.
    #[serde(default)]
    pub expected_verdict: Option<String>,
}

/// One proposed file edit inside a [`CorpusEditSet`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CorpusEdit {
    /// Workspace-relative file path.
    pub file: String,
    /// The COMPLETE new content of `file` after the edit.
    pub content: String,
}

impl CorpusEditSet {
    /// The `edits` array as the JSON the daemon's `Index.VerifyEdit`
    /// expects: `[{ "file": …, "content": … }]`.
    pub fn edits_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.edits).unwrap_or_else(|_| json!([]))
    }
}

/// Load and parse a TOML verify-EDIT-eval corpus.
pub fn load_edit_corpus(path: &Path) -> Result<EditCorpus> {
    let bytes =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let parsed: EditCorpus = toml::from_str(&bytes)
        .with_context(|| format!("parse {} as verify-edit corpus TOML", path.display()))?;
    Ok(parsed)
}

// ---------------------------------------------------------------------
// Verify oracle
// ---------------------------------------------------------------------

/// The outcome of one `verify_edit` call: the verdict string plus the
/// distinct finding kinds the daemon reported. Kept deliberately small —
/// the edit metrics (EVR / BCIR) only need the verdict and whether a
/// caller-breaking kind appeared, not the full finding payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditVerdict {
    /// `pass` | `warn` | `fail` (frozen wire strings). An unknown /
    /// missing verdict is treated as `fail` by the aggregator (an
    /// undecodable verdict is never counted as a clean pass).
    pub verdict: String,
    /// The distinct `kind` strings across `findings[]`
    /// (`broken_caller`, `signature_break`, `dangling_ref`,
    /// `new_symbol`, …). Used to decide BCIR membership.
    pub finding_kinds: BTreeSet<String>,
}

impl EditVerdict {
    /// True when the verdict reads as a clean `pass` (the EVR numerator
    /// criterion). `warn` and `fail` — and any unknown verdict — count
    /// AGAINST EVR.
    pub fn is_pass(&self) -> bool {
        self.verdict == "pass"
    }

    /// True when any finding kind is caller-breaking (`broken_caller`
    /// or `signature_break`) — the BCIR numerator criterion.
    pub fn introduces_broken_caller(&self) -> bool {
        self.finding_kinds.contains("broken_caller")
            || self.finding_kinds.contains("signature_break")
    }

    /// Build an [`EditVerdict`] from a raw `Index.VerifyEdit` response
    /// body. Missing `verdict` → `"fail"` (honest default — never read
    /// an undecodable body as a pass). Missing/empty `findings` → no
    /// kinds.
    pub fn from_body(body: &serde_json::Value) -> Self {
        let verdict = body
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("fail")
            .to_string();
        let finding_kinds = body
            .get("findings")
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| f.get("kind").and_then(|k| k.as_str()))
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();
        EditVerdict {
            verdict,
            finding_kinds,
        }
    }
}

/// Abstracts the live verify calls so the aggregation pipeline can run
/// against the real daemon in production and canned answers in tests.
///
/// Each per-reference method returns the [`Resolution`] for one
/// reference; [`verify_edit`](VerifyOracle::verify_edit) returns the
/// [`EditVerdict`] for one whole edit-set. The pure math never sees the
/// daemon; this trait is the only seam that does.
#[allow(async_fn_in_trait)]
pub trait VerifyOracle {
    /// `verify_symbol(name)` → resolution.
    async fn verify_symbol(&mut self, name: &str) -> Result<Resolution>;
    /// `verify_import(path)` → resolution.
    async fn verify_import(&mut self, path: &str) -> Result<Resolution>;
    /// `verify_signature(name, claimed{arity})` → resolution.
    ///
    /// A `match:true` exact result maps to [`Resolution::Exact`]; a
    /// `match:false` exact result maps to [`Resolution::NotFound`] (a
    /// *mismatch* is the SMR hallucination); `not_found`/`indeterminate`
    /// map straight through. The callee-existence gate is applied by the
    /// driver (a call site is only decidable when the callee exists), so
    /// this method just reports the signature outcome.
    async fn verify_signature(&mut self, name: &str, arity: u32) -> Result<Resolution>;
    /// `verify_edit(edits)` → the verdict + finding kinds for one
    /// proposed edit-set. `edits` is the `[{file, content}]` array
    /// (full post-edit content) forwarded verbatim to the daemon's
    /// `Index.VerifyEdit`.
    async fn verify_edit(&mut self, edits: &serde_json::Value) -> Result<EditVerdict>;
}

/// Live [`VerifyOracle`] backed by an `McpSession` talking to the real
/// `rts-mcp` + daemon. Calls the `verify_symbol` / `verify_import` /
/// `verify_signature` MCP tools (which forward to `Index.Verify*`).
pub struct SessionOracle<'a> {
    session: &'a mut crate::mcp_runner::McpSession,
    /// INDEX_NOT_READY retry budget per call — shared with the rest of
    /// the bench so cold mounts don't skew results.
    retries: u32,
}

impl<'a> SessionOracle<'a> {
    pub fn new(session: &'a mut crate::mcp_runner::McpSession) -> Self {
        Self {
            session,
            retries: 30,
        }
    }

    /// Extract the `resolution` string from a verify-tool response body.
    fn resolution_of(call: &crate::mcp_runner::McpCall) -> Resolution {
        let res = call
            .result_body
            .as_ref()
            .and_then(|b| b.get("resolution"))
            .and_then(|r| r.as_str());
        Resolution::from_wire(res)
    }
}

impl VerifyOracle for SessionOracle<'_> {
    async fn verify_symbol(&mut self, name: &str) -> Result<Resolution> {
        let call = self
            .session
            .tools_call("verify_symbol", json!({ "name": name }), self.retries)
            .await
            .context("verify_symbol call")?;
        Ok(Self::resolution_of(&call))
    }

    async fn verify_import(&mut self, path: &str) -> Result<Resolution> {
        let call = self
            .session
            .tools_call("verify_import", json!({ "path": path }), self.retries)
            .await
            .context("verify_import call")?;
        Ok(Self::resolution_of(&call))
    }

    async fn verify_signature(&mut self, name: &str, arity: u32) -> Result<Resolution> {
        let call = self
            .session
            .tools_call(
                "verify_signature",
                json!({ "name": name, "claimed": { "arity": arity } }),
                self.retries,
            )
            .await
            .context("verify_signature call")?;
        let body = call.result_body.clone().unwrap_or_default();
        let resolution = Resolution::from_wire(body.get("resolution").and_then(|r| r.as_str()));
        // On an exact resolution the `match` field decides hallucination:
        // a mismatch (`match:false`) is the SMR numerator.
        Ok(match resolution {
            Resolution::Exact => match body.get("match").and_then(|m| m.as_bool()) {
                Some(true) => Resolution::Exact,
                Some(false) => Resolution::NotFound,
                // Exact resolution but no `match` field — treat as
                // undecidable rather than invent a verdict.
                None => Resolution::Indeterminate,
            },
            other => other,
        })
    }

    async fn verify_edit(&mut self, edits: &serde_json::Value) -> Result<EditVerdict> {
        let call = self
            .session
            .tools_call("verify_edit", json!({ "edits": edits }), self.retries)
            .await
            .context("verify_edit call")?;
        let body = call.result_body.clone().unwrap_or_default();
        Ok(EditVerdict::from_body(&body))
    }
}

// ---------------------------------------------------------------------
// Driver: snippet → references → resolutions
// ---------------------------------------------------------------------

/// Per-snippet accumulator of resolutions, kept separate per metric so
/// `build_report` can aggregate each honestly.
#[derive(Debug, Default)]
pub struct Resolutions {
    pub symbol: Vec<Resolution>,
    pub import: Vec<Resolution>,
    pub signature: Vec<Resolution>,
    pub unsupported_language_refs: u64,
    pub languages_covered: BTreeSet<String>,
}

/// Route one snippet's references through the oracle and append the
/// outcomes to `acc`. Pure routing logic; all daemon contact is via the
/// oracle, so this is unit-testable with a stub.
///
/// Routing:
/// - `Import` → `verify_import(qualified || name)` → IHR.
/// - `Type` / `Path` → `verify_symbol(name)` → SHR.
/// - `Call` → `verify_symbol(name)` → SHR, AND, when the symbol exists
///   (`exact`), `verify_signature(name, call_arity)` → SMR. A call whose
///   callee is `not_found`/`indeterminate` contributes to SHR only; its
///   call site is NOT decidable for SMR (no callee to compare against),
///   so it never enters the SMR denominator.
async fn resolve_snippet<O: VerifyOracle>(
    oracle: &mut O,
    lang: Language,
    code: &str,
    acc: &mut Resolutions,
) -> Result<()> {
    if !supports_references(lang) {
        // Should be screened before calling, but be defensive: count
        // every reference-shaped token as unsupported rather than parse
        // with an extractor that returns `[]`.
        return Ok(());
    }
    let refs: Vec<Reference> = extract_references(code.as_bytes(), lang);
    if !refs.is_empty() {
        acc.languages_covered
            .insert(lang.to_string().to_lowercase());
    }
    for r in refs {
        match r.kind {
            RefKind::Import => {
                let path = r.qualified.as_deref().unwrap_or(&r.name);
                acc.import.push(oracle.verify_import(path).await?);
            }
            RefKind::Type | RefKind::Path => {
                acc.symbol.push(oracle.verify_symbol(&r.name).await?);
            }
            RefKind::Call => {
                let sym = oracle.verify_symbol(&r.name).await?;
                acc.symbol.push(sym);
                // SMR gate: only verify the signature when the callee
                // exists. A non-existent callee has no signature to
                // mismatch, so the call site isn't decidable for SMR.
                if sym == Resolution::Exact {
                    if let Some(arity) = r.call_arity {
                        acc.signature
                            .push(oracle.verify_signature(&r.name, arity).await?);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Run the full corpus through the oracle and accumulate resolutions.
///
/// Supported-language snippets (Rust / TS / Python) are parsed with F3
/// and routed through the oracle. Snippets we can't parse for references —
/// a known-but-unsupported language (e.g. Go) OR an unknown `lang` string —
/// contribute to no rate; their non-blank line count is added to
/// `unsupported_language_refs` as a coarse, honest "we couldn't look at
/// this" signal that keeps the uncovered surface visible in the report. A
/// single mislabelled snippet must never abort measuring the whole corpus.
pub async fn run_corpus<O: VerifyOracle>(oracle: &mut O, corpus: &Corpus) -> Result<Resolutions> {
    let mut acc = Resolutions::default();
    for snip in &corpus.snippets {
        // An unknown language string is treated as unsupported, not fatal.
        match snip.lang.parse::<Language>() {
            Ok(lang) if supports_references(lang) => {
                resolve_snippet(oracle, lang, &snip.code, &mut acc).await?;
            }
            _ => {
                acc.unsupported_language_refs +=
                    snip.code.lines().filter(|l| !l.trim().is_empty()).count() as u64;
            }
        }
    }
    Ok(acc)
}

/// Build a [`HallucinationReport`] from a completed [`Resolutions`].
pub fn report_from_resolutions(
    rts_bench_version: &str,
    workspace_path: &str,
    corpus_path: &str,
    snippet_count: usize,
    acc: Resolutions,
) -> HallucinationReport {
    build_report(
        rts_bench_version,
        workspace_path,
        corpus_path,
        snippet_count,
        acc.symbol,
        acc.import,
        acc.signature,
        acc.unsupported_language_refs,
        acc.languages_covered,
    )
}

// ---------------------------------------------------------------------
// Edit metrics: EVR / BCIR
// ---------------------------------------------------------------------

/// A simple fraction over the edit corpus: `numerator / denominator`,
/// with `rate = None` when the corpus is empty (never `NaN`). Same
/// honest-denominator convention as [`Metric`], but every edit-set is
/// always decidable (a verdict always comes back), so there is no
/// excluded-indeterminate bucket here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditRate {
    /// Edit-sets matching the metric's criterion.
    pub numerator: u64,
    /// Total edit-sets considered.
    pub denominator: u64,
    /// `numerator / denominator`, or `null` when `denominator == 0`.
    pub rate: Option<f64>,
}

impl EditRate {
    fn new(numerator: u64, denominator: u64) -> Self {
        let rate = if denominator == 0 {
            None
        } else {
            Some(numerator as f64 / denominator as f64)
        };
        EditRate {
            numerator,
            denominator,
            rate,
        }
    }
}

/// Versioned edit-quality report. EVR (Edit Validity Rate) and BCIR
/// (Broken-Caller Introduction Rate) over a corpus of proposed edit-sets.
///
/// - **EVR** = fraction of edit-sets whose `verify_edit` verdict is
///   `pass`. `warn` / `fail` (and any undecodable verdict) count against
///   it.
/// - **BCIR** = fraction of edit-sets whose findings include ≥1
///   `broken_caller` or `signature_break`. The complement of "clean of
///   caller breaks" — higher is worse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditQualityReport {
    /// Schema version for this report payload.
    pub version: u32,
    /// `rts-bench` package version.
    pub rts_bench_version: String,
    /// Workspace the edits were validated against.
    pub workspace_path: String,
    /// Corpus file the edit-sets came from.
    pub corpus_path: String,
    /// Number of corpus edit-sets processed.
    pub edit_set_count: usize,
    /// Edit Validity Rate: `pass` verdicts / all edit-sets.
    pub evr: EditRate,
    /// Broken-Caller Introduction Rate: edit-sets with ≥1
    /// `broken_caller`/`signature_break` finding / all edit-sets.
    pub bcir: EditRate,
}

/// Aggregate EVR / BCIR from an iterator of per-edit-set [`EditVerdict`]s.
/// Pure math — no daemon, no IO.
pub fn build_edit_report(
    rts_bench_version: &str,
    workspace_path: &str,
    corpus_path: &str,
    verdicts: impl IntoIterator<Item = EditVerdict>,
) -> EditQualityReport {
    let mut total = 0u64;
    let mut passes = 0u64;
    let mut broken = 0u64;
    for v in verdicts {
        total += 1;
        if v.is_pass() {
            passes += 1;
        }
        if v.introduces_broken_caller() {
            broken += 1;
        }
    }
    EditQualityReport {
        version: 1,
        rts_bench_version: rts_bench_version.to_string(),
        workspace_path: workspace_path.to_string(),
        corpus_path: corpus_path.to_string(),
        edit_set_count: total as usize,
        evr: EditRate::new(passes, total),
        bcir: EditRate::new(broken, total),
    }
}

/// Run an edit corpus through the oracle, calling `verify_edit` once per
/// edit-set and collecting the verdicts. A single failed RPC aborts the
/// run (unlike snippet metrics, an edit-set has no honest "skip" — a
/// missing verdict would silently shrink the denominator).
pub async fn run_edit_corpus<O: VerifyOracle>(
    oracle: &mut O,
    corpus: &EditCorpus,
) -> Result<Vec<EditVerdict>> {
    let mut out = Vec::with_capacity(corpus.edit_sets.len());
    for set in &corpus.edit_sets {
        let edits = set.edits_json();
        out.push(oracle.verify_edit(&edits).await?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn metric_basic_shr_excludes_indeterminate() {
        // 3 exact + 2 not_found + 1 indeterminate ⇒ SHR = 2/5 = 0.4,
        // denominator = 5, indeterminate_excluded = 1.
        let m = Metric::from_resolutions([
            Resolution::Exact,
            Resolution::Exact,
            Resolution::Exact,
            Resolution::NotFound,
            Resolution::NotFound,
            Resolution::Indeterminate,
        ]);
        assert_eq!(m.numerator, 2);
        assert_eq!(m.denominator, 5);
        assert_eq!(m.indeterminate_excluded, 1);
        assert_eq!(m.rate, Some(0.4));
        // RGR = 1 − 0.4 = 0.6.
        assert_eq!(m.grounding_rate(), Some(0.6));
    }

    #[test]
    fn metric_empty_denominator_is_none_not_nan() {
        // Only indeterminate refs ⇒ nothing decidable. rate must be
        // None (null in JSON), never NaN.
        let m = Metric::from_resolutions([Resolution::Indeterminate, Resolution::Indeterminate]);
        assert_eq!(m.numerator, 0);
        assert_eq!(m.denominator, 0);
        assert_eq!(m.indeterminate_excluded, 2);
        assert_eq!(m.rate, None);
        assert_eq!(m.grounding_rate(), None);
        // And a fully-empty input is also None, not NaN.
        let empty = Metric::from_resolutions([]);
        assert_eq!(empty.rate, None);
    }

    #[test]
    fn metric_all_exact_is_zero_rate() {
        let m = Metric::from_resolutions([Resolution::Exact, Resolution::Exact]);
        assert_eq!(m.rate, Some(0.0));
        assert_eq!(m.grounding_rate(), Some(1.0));
        assert_eq!(m.indeterminate_excluded, 0);
    }

    #[test]
    fn resolution_from_wire_defaults_unknown_to_indeterminate() {
        assert_eq!(Resolution::from_wire(Some("exact")), Resolution::Exact);
        assert_eq!(
            Resolution::from_wire(Some("not_found")),
            Resolution::NotFound
        );
        assert_eq!(
            Resolution::from_wire(Some("indeterminate")),
            Resolution::Indeterminate
        );
        // Unknown / missing → indeterminate (never a false not_found).
        assert_eq!(
            Resolution::from_wire(Some("wat")),
            Resolution::Indeterminate
        );
        assert_eq!(Resolution::from_wire(None), Resolution::Indeterminate);
    }

    #[test]
    fn build_report_wires_all_metrics_and_rgr() {
        let mut langs = BTreeSet::new();
        langs.insert("rust".to_string());
        let report = build_report(
            "0.0.0-test",
            "/ws",
            "/corpus.toml",
            4,
            // SHR: 3 exact + 2 not_found + 1 indeterminate ⇒ 2/5.
            [
                Resolution::Exact,
                Resolution::Exact,
                Resolution::Exact,
                Resolution::NotFound,
                Resolution::NotFound,
                Resolution::Indeterminate,
            ],
            // IHR: 1 exact + 1 not_found ⇒ 1/2.
            [Resolution::Exact, Resolution::NotFound],
            // SMR: 2 exact + 0 not_found + 1 indeterminate ⇒ 0/2.
            [
                Resolution::Exact,
                Resolution::Exact,
                Resolution::Indeterminate,
            ],
            7,
            langs,
        );
        assert_eq!(report.version, 1);
        assert_eq!(report.snippet_count, 4);
        assert_eq!(report.shr.rate, Some(0.4));
        assert_eq!(report.rgr, Some(0.6));
        assert_eq!(report.ihr.rate, Some(0.5));
        assert_eq!(report.smr.rate, Some(0.0));
        assert_eq!(report.smr.indeterminate_excluded, 1);
        assert_eq!(report.unsupported_language_refs, 7);
        assert_eq!(report.languages_covered, vec!["rust".to_string()]);
    }

    #[test]
    fn report_serializes_null_rate_as_json_null() {
        let report = build_report(
            "0.0.0-test",
            "/ws",
            "/c.toml",
            1,
            [Resolution::Indeterminate],
            [],
            [],
            0,
            BTreeSet::new(),
        );
        let json = serde_json::to_value(&report).unwrap();
        // rate must serialize as JSON null, not NaN (which isn't valid JSON).
        assert!(json["shr"]["rate"].is_null());
        assert!(json["rgr"].is_null());
        assert!(json["ihr"]["rate"].is_null());
    }

    // ---- routing tests against a stub oracle ----

    /// Canned-answer oracle keyed by symbol/path name. Names not in the
    /// map resolve to `Indeterminate` (so a test only has to declare the
    /// names it cares about). Signature answers are keyed separately.
    struct StubOracle {
        symbols: HashMap<String, Resolution>,
        imports: HashMap<String, Resolution>,
        signatures: HashMap<String, Resolution>,
        /// Canned `verify_edit` verdicts, returned in order. Each call
        /// pops the next. A panic on exhaustion makes a miscounted test
        /// loud instead of silently reusing a stale verdict.
        edit_verdicts: Vec<EditVerdict>,
    }

    impl StubOracle {
        fn empty() -> Self {
            StubOracle {
                symbols: HashMap::new(),
                imports: HashMap::new(),
                signatures: HashMap::new(),
                edit_verdicts: Vec::new(),
            }
        }
    }

    impl VerifyOracle for StubOracle {
        async fn verify_symbol(&mut self, name: &str) -> Result<Resolution> {
            Ok(self
                .symbols
                .get(name)
                .copied()
                .unwrap_or(Resolution::Indeterminate))
        }
        async fn verify_import(&mut self, path: &str) -> Result<Resolution> {
            Ok(self
                .imports
                .get(path)
                .copied()
                .unwrap_or(Resolution::Indeterminate))
        }
        async fn verify_signature(&mut self, name: &str, _arity: u32) -> Result<Resolution> {
            Ok(self
                .signatures
                .get(name)
                .copied()
                .unwrap_or(Resolution::Indeterminate))
        }
        async fn verify_edit(&mut self, _edits: &serde_json::Value) -> Result<EditVerdict> {
            if self.edit_verdicts.is_empty() {
                anyhow::bail!("StubOracle.verify_edit called more times than canned verdicts");
            }
            Ok(self.edit_verdicts.remove(0))
        }
    }

    fn verdict(v: &str, kinds: &[&str]) -> EditVerdict {
        EditVerdict {
            verdict: v.to_string(),
            finding_kinds: kinds.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        // The routing futures never yield to the runtime (the stub is
        // synchronous), so a minimal executor that polls once suffices —
        // but use tokio's current-thread runtime to be safe.
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn routing_call_resolves_symbol_then_signature_when_callee_exists() {
        let mut oracle = StubOracle {
            symbols: HashMap::from([("make_thing".to_string(), Resolution::Exact)]),
            imports: HashMap::new(),
            signatures: HashMap::from([("make_thing".to_string(), Resolution::NotFound)]),
            edit_verdicts: Vec::new(),
        };
        let mut acc = Resolutions::default();
        block_on(resolve_snippet(
            &mut oracle,
            Language::Rust,
            "fn caller() { let _ = make_thing(1, 2); }",
            &mut acc,
        ))
        .unwrap();
        // The call contributes to SHR (callee exists → Exact) AND, because
        // the callee exists, to SMR (signature mismatch → NotFound).
        assert_eq!(acc.symbol, vec![Resolution::Exact]);
        assert_eq!(acc.signature, vec![Resolution::NotFound]);
        assert!(acc.languages_covered.contains("rust"));
    }

    #[test]
    fn routing_call_skips_signature_when_callee_absent() {
        // Callee is not_found → SHR gets the not_found, but SMR is NOT
        // touched (no callee to compare a signature against). This is the
        // honest denominator: a hallucinated call isn't a signature
        // mismatch, it's a symbol hallucination.
        let mut oracle = StubOracle {
            symbols: HashMap::from([("invented".to_string(), Resolution::NotFound)]),
            imports: HashMap::new(),
            signatures: HashMap::from([("invented".to_string(), Resolution::NotFound)]),
            edit_verdicts: Vec::new(),
        };
        let mut acc = Resolutions::default();
        block_on(resolve_snippet(
            &mut oracle,
            Language::Rust,
            "fn caller() { invented(1); }",
            &mut acc,
        ))
        .unwrap();
        assert_eq!(acc.symbol, vec![Resolution::NotFound]);
        assert!(
            acc.signature.is_empty(),
            "absent callee must not enter the SMR denominator; got {:?}",
            acc.signature
        );
    }

    #[test]
    fn routing_import_goes_to_ihr() {
        let mut oracle = StubOracle {
            symbols: HashMap::new(),
            imports: HashMap::from([("std::collections::HashMap".to_string(), Resolution::Exact)]),
            signatures: HashMap::new(),
            edit_verdicts: Vec::new(),
        };
        let mut acc = Resolutions::default();
        block_on(resolve_snippet(
            &mut oracle,
            Language::Rust,
            "use std::collections::HashMap;",
            &mut acc,
        ))
        .unwrap();
        assert_eq!(acc.import, vec![Resolution::Exact]);
        assert!(acc.symbol.is_empty());
    }

    #[test]
    fn run_corpus_counts_unsupported_language_refs() {
        let corpus = Corpus {
            version: 1,
            snippets: vec![CorpusSnippet {
                name: "go-snippet".into(),
                lang: "go".into(),
                code: "package main\nfunc main() {\n  foo()\n}\n".into(),
            }],
        };
        let mut oracle = StubOracle {
            symbols: HashMap::new(),
            imports: HashMap::new(),
            signatures: HashMap::new(),
            edit_verdicts: Vec::new(),
        };
        let acc = block_on(run_corpus(&mut oracle, &corpus)).unwrap();
        // Go has no F3 support → no decidable refs, 4 non-blank lines
        // counted as unsupported.
        assert!(acc.symbol.is_empty());
        assert_eq!(acc.unsupported_language_refs, 4);
        assert!(acc.languages_covered.is_empty());
    }

    #[test]
    fn run_corpus_treats_unknown_language_as_unsupported_not_fatal() {
        // A mislabelled `lang` must not abort the whole corpus run — it falls
        // into the unsupported bucket like a known-but-unsupported language.
        let corpus = Corpus {
            version: 1,
            snippets: vec![CorpusSnippet {
                name: "typo".into(),
                lang: "cobol".into(),
                code: "IDENTIFICATION DIVISION.\nPROGRAM-ID. X.\n".into(),
            }],
        };
        let mut oracle = StubOracle {
            symbols: HashMap::new(),
            imports: HashMap::new(),
            signatures: HashMap::new(),
            edit_verdicts: Vec::new(),
        };
        let acc =
            block_on(run_corpus(&mut oracle, &corpus)).expect("must not abort on unknown lang");
        assert!(acc.symbol.is_empty());
        assert_eq!(acc.unsupported_language_refs, 2);
    }

    // ---- EVR / BCIR aggregation (edit metrics) ----

    #[test]
    fn edit_verdict_from_body_defaults_missing_verdict_to_fail() {
        // No `verdict` field → fail (never a false pass), no kinds.
        let v = EditVerdict::from_body(&json!({}));
        assert_eq!(v.verdict, "fail");
        assert!(!v.is_pass());
        assert!(v.finding_kinds.is_empty());

        // A pass with a new_symbol finding: is_pass true, no broken caller.
        let v = EditVerdict::from_body(&json!({
            "verdict": "pass",
            "findings": [{ "kind": "new_symbol", "symbol": "brand_new" }],
        }));
        assert!(v.is_pass());
        assert!(!v.introduces_broken_caller());

        // A fail with a broken_caller: not a pass, IS a broken caller.
        let v = EditVerdict::from_body(&json!({
            "verdict": "fail",
            "findings": [{ "kind": "broken_caller", "symbol": "target" }],
        }));
        assert!(!v.is_pass());
        assert!(v.introduces_broken_caller());

        // signature_break also counts toward BCIR.
        let v = EditVerdict::from_body(&json!({
            "verdict": "fail",
            "findings": [{ "kind": "signature_break", "symbol": "target" }],
        }));
        assert!(v.introduces_broken_caller());
    }

    #[test]
    fn build_edit_report_evr_bcir_numerator_denominator() {
        // 4 edit-sets: 2 pass (one with a benign new_symbol), 1 warn,
        // 1 fail-with-broken_caller.
        //   EVR  = passes / total      = 2 / 4 = 0.5
        //   BCIR = caller-breaks / total = 1 / 4 = 0.25
        let verdicts = vec![
            verdict("pass", &[]),
            verdict("pass", &["new_symbol"]),
            verdict("warn", &["dangling_ref"]),
            verdict("fail", &["broken_caller"]),
        ];
        let report = build_edit_report("0.0.0-test", "/ws", "/c.toml", verdicts);
        assert_eq!(report.version, 1);
        assert_eq!(report.edit_set_count, 4);
        assert_eq!(report.evr.numerator, 2);
        assert_eq!(report.evr.denominator, 4);
        assert_eq!(report.evr.rate, Some(0.5));
        assert_eq!(report.bcir.numerator, 1);
        assert_eq!(report.bcir.denominator, 4);
        assert_eq!(report.bcir.rate, Some(0.25));
    }

    #[test]
    fn build_edit_report_signature_break_counts_toward_bcir() {
        // A `fail` driven by a signature_break (not broken_caller) still
        // lands in BCIR — both kinds are caller-breaking.
        let verdicts = vec![verdict("fail", &["signature_break"])];
        let report = build_edit_report("0.0.0-test", "/ws", "/c.toml", verdicts);
        assert_eq!(report.evr.rate, Some(0.0));
        assert_eq!(report.bcir.numerator, 1);
        assert_eq!(report.bcir.rate, Some(1.0));
    }

    #[test]
    fn build_edit_report_empty_corpus_is_none_not_nan() {
        let report = build_edit_report("0.0.0-test", "/ws", "/c.toml", []);
        assert_eq!(report.edit_set_count, 0);
        assert_eq!(report.evr.rate, None);
        assert_eq!(report.bcir.rate, None);
        // And serializes as JSON null, never NaN.
        let j = serde_json::to_value(&report).unwrap();
        assert!(j["evr"]["rate"].is_null());
        assert!(j["bcir"]["rate"].is_null());
    }

    #[test]
    fn run_edit_corpus_calls_verify_edit_per_set_in_order() {
        // Two edit-sets; the stub returns a canned verdict per call.
        // run_edit_corpus must preserve order and emit one verdict each.
        let corpus = EditCorpus {
            version: 1,
            edit_sets: vec![
                CorpusEditSet {
                    name: "breaking".into(),
                    edits: vec![CorpusEdit {
                        file: "hub.rs".into(),
                        content: "pub fn unrelated() {}\n".into(),
                    }],
                    expected_verdict: Some("fail".into()),
                },
                CorpusEditSet {
                    name: "safe".into(),
                    edits: vec![CorpusEdit {
                        file: "hub.rs".into(),
                        content: "pub fn target(x: u32) -> u32 { x }\npub fn extra() {}\n".into(),
                    }],
                    expected_verdict: Some("pass".into()),
                },
            ],
        };
        let mut oracle = StubOracle::empty();
        oracle.edit_verdicts = vec![
            verdict("fail", &["broken_caller"]),
            verdict("pass", &["new_symbol"]),
        ];
        let verdicts = block_on(run_edit_corpus(&mut oracle, &corpus)).unwrap();
        assert_eq!(verdicts.len(), 2);
        assert_eq!(verdicts[0].verdict, "fail");
        assert!(verdicts[0].introduces_broken_caller());
        assert_eq!(verdicts[1].verdict, "pass");

        // And the report over those verdicts: EVR=1/2, BCIR=1/2.
        let report = build_edit_report("0.0.0-test", "/ws", "/c.toml", verdicts);
        assert_eq!(report.evr.rate, Some(0.5));
        assert_eq!(report.bcir.rate, Some(0.5));
    }

    #[test]
    fn corpus_edit_set_edits_json_matches_daemon_shape() {
        let set = CorpusEditSet {
            name: "x".into(),
            edits: vec![CorpusEdit {
                file: "a.rs".into(),
                content: "fn a() {}\n".into(),
            }],
            expected_verdict: None,
        };
        let j = set.edits_json();
        assert_eq!(j[0]["file"], "a.rs");
        assert_eq!(j[0]["content"], "fn a() {}\n");
    }
}
