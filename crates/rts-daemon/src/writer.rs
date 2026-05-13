//! Writer-drain task: consumes `WatchEvent`s from the watcher, re-parses the
//! affected files, and commits batched upserts/removals into the redb store.
//!
//! Per protocol-v0 §9.2: **single writer task, parse-parallel + commit-serial**.
//! The simpler v0 shape here is single-threaded parse + single-threaded commit;
//! the rayon-fanned-out parse path is a P6 hardening optimisation (gated on
//! the P0.2 spike numbers — single-threaded commits already commit 100 files
//! in 12.8 ms at `Durability::None`).
//!
//! The task batches events with the same cadence as the watcher's debouncer
//! (150 ms) plus an N-event budget (128 events / commit). A periodic
//! `Durability::Immediate` flush every 5 seconds drains the kernel cache to
//! disk; the hot path uses `Durability::None` per the redb-storage spike's
//! recommendation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use redb::Durability;
use rust_tree_sitter::{Language, Symbol};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::state::DaemonState;
use crate::store::{
    DefSite, FileBatchEntry, FileBatchRemoval, FileMeta, ParseStatus, Store, SymbolKind,
};
use crate::watcher::WatchEvent;

/// Per-batch commit timer. Matches the watcher's debounce window so events
/// arriving in a burst land in one transaction.
const BATCH_FLUSH_INTERVAL: Duration = Duration::from_millis(150);

/// Periodic durability anchor. Per protocol-v0 §9.2 / P0.2 spike: hot path
/// uses `Durability::None`, this empty commit forces an fsync every 5 s.
const DURABILITY_FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Max events to accumulate in a single batch before forcing a flush, even
/// if the timer hasn't fired yet. Bounds peak memory under a `git checkout`
/// storm. Matches the protocol-v0 §16 / `notify` mpsc depth.
const BATCH_SIZE_BUDGET: usize = 128;

/// Files larger than this are tagged `oversize=true` and indexed by metadata
/// only — body reads and symbol extraction are skipped. Per protocol-v0 §16.
const OVERSIZE_THRESHOLD_BYTES: u64 = 4 * 1024 * 1024;

/// Spawn the writer-drain task. Returns a `JoinHandle` so the caller can
/// observe orderly termination (or panics).
pub fn spawn(
    rx: mpsc::Receiver<WatchEvent>,
    store: Arc<Store>,
    state: Arc<DaemonState>,
    cancel: CancellationToken,
    workspace_root: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run(rx, store, state, cancel, workspace_root).await {
            error!(error = %e, "writer task ended with error");
        } else {
            info!("writer task exited cleanly");
        }
    })
}

async fn run(
    mut rx: mpsc::Receiver<WatchEvent>,
    store: Arc<Store>,
    state: Arc<DaemonState>,
    cancel: CancellationToken,
    workspace_root: PathBuf,
) -> anyhow::Result<()> {
    let parsers = ParserPool::new();
    let mut upserts: HashMap<PathBuf, ()> = HashMap::new(); // de-dup within a batch
    let mut removals: HashMap<PathBuf, ()> = HashMap::new();
    let mut last_durability_flush = Instant::now();
    let mut flush_timer = tokio::time::interval(BATCH_FLUSH_INTERVAL);
    flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!("writer cancelled; draining final batch");
                let _ = flush(
                    &store,
                    &state,
                    &parsers,
                    &workspace_root,
                    &mut upserts,
                    &mut removals,
                    Durability::Immediate,
                );
                return Ok(());
            }
            event = rx.recv() => {
                match event {
                    Some(WatchEvent::Touched { path, .. }) => {
                        // Latest event for a path wins; remove any pending removal.
                        removals.remove(&path);
                        upserts.insert(path, ());
                        if upserts.len() + removals.len() >= BATCH_SIZE_BUDGET {
                            let dur = pick_durability(&mut last_durability_flush);
                            let _ = flush(
                                &store,
                                &state,
                                &parsers,
                                &workspace_root,
                                &mut upserts,
                                &mut removals,
                                dur,
                            );
                        }
                    }
                    Some(WatchEvent::Removed { path }) => {
                        // Removal supersedes any pending upsert.
                        upserts.remove(&path);
                        removals.insert(path, ());
                        if upserts.len() + removals.len() >= BATCH_SIZE_BUDGET {
                            let dur = pick_durability(&mut last_durability_flush);
                            let _ = flush(
                                &store,
                                &state,
                                &parsers,
                                &workspace_root,
                                &mut upserts,
                                &mut removals,
                                dur,
                            );
                        }
                    }
                    Some(WatchEvent::Rescan) => {
                        // Kernel watch buffer overflowed; index state may be
                        // stale. Drain the current batch first so we don't
                        // mix pre-overflow events with the rewalk's results,
                        // then run a fresh walk + orphan detection against
                        // the store. This is the recovery path P6 ships.
                        info!("writer received rescan signal; running re-walk");
                        let _ = flush(
                            &store,
                            &state,
                            &parsers,
                            &workspace_root,
                            &mut upserts,
                            &mut removals,
                            Durability::Immediate,
                        );
                        match rescan_and_reconcile(
                            &workspace_root,
                            &store,
                            &mut upserts,
                            &mut removals,
                        ) {
                            Ok(stats) => info!(
                                target: "rts_daemon::writer",
                                touched = stats.touched,
                                orphans = stats.orphans,
                                "rescan reconciled with on-disk truth"
                            ),
                            Err(e) => warn!(error = %e, "rescan reconciliation failed"),
                        }
                        // Force a flush so the post-rescan state lands
                        // durably and the watcher_status flip back to Ok
                        // reflects committed truth.
                        let _ = flush(
                            &store,
                            &state,
                            &parsers,
                            &workspace_root,
                            &mut upserts,
                            &mut removals,
                            Durability::Immediate,
                        );
                        state.set_watcher_status(crate::state::WatcherStatus::Ok);
                    }
                    None => {
                        // Channel closed.
                        let _ = flush(
                            &store,
                            &state,
                            &parsers,
                            &workspace_root,
                            &mut upserts,
                            &mut removals,
                            Durability::Immediate,
                        );
                        return Ok(());
                    }
                }
            }
            _ = flush_timer.tick() => {
                if !upserts.is_empty() || !removals.is_empty() {
                    let dur = pick_durability(&mut last_durability_flush);
                    let _ = flush(
                        &store,
                        &state,
                        &parsers,
                        &workspace_root,
                        &mut upserts,
                        &mut removals,
                        dur,
                    );
                }
            }
        }
    }
}

fn pick_durability(last_flush: &mut Instant) -> Durability {
    if last_flush.elapsed() >= DURABILITY_FLUSH_INTERVAL {
        *last_flush = Instant::now();
        Durability::Immediate
    } else {
        Durability::None
    }
}

fn flush(
    store: &Arc<Store>,
    state: &Arc<DaemonState>,
    parsers: &ParserPool,
    workspace_root: &Path,
    upserts: &mut HashMap<PathBuf, ()>,
    removals: &mut HashMap<PathBuf, ()>,
    durability: Durability,
) -> anyhow::Result<()> {
    if upserts.is_empty() && removals.is_empty() {
        return Ok(());
    }

    // Fan parses out across rayon's pool. The parse step is the heavy
    // work in a flush (tree-sitter parse + symbol extraction +
    // tempfile-driven analyzer call), and `ParserPool::parse_and_extract`
    // is safe to call concurrently — the per-language parser cache
    // entry is short-locked just to seed-if-vacant, and the actual
    // parse uses a fresh local `CodebaseAnalyzer` per call.
    use rayon::prelude::*;
    let paths: Vec<PathBuf> = upserts.drain().map(|(p, _)| p).collect();
    let results: Vec<(PathBuf, Result<FileBatchEntry, ParseRejected>)> = paths
        .into_par_iter()
        .map(|p| {
            let r = parse_and_extract(parsers, workspace_root, &p);
            (p, r)
        })
        .collect();
    let mut batch: Vec<FileBatchEntry> = Vec::with_capacity(results.len());
    for (path, result) in results {
        match result {
            Ok(entry) => batch.push(entry),
            Err(ParseRejected::IoMissing) => {
                // File vanished between event and parse. Treat as removal.
                removals.insert(path, ());
            }
            Err(other) => {
                debug!(path = %path.display(), reason = ?other, "skipped during parse");
            }
        }
    }
    // The store keys files by workspace-relative paths (upserts go
    // through parse_and_extract which strips the prefix). Watcher
    // events ship absolute paths, and our in-process queues key by
    // absolute. Rebase here so the store lookup actually finds the
    // file. Caught by the P6 integration test on alpha.25 — prior to
    // the test the delete path was silently a no-op for the
    // absolute-vs-relative mismatch.
    let removal_vec: Vec<FileBatchRemoval> = removals
        .drain()
        .map(|(path, _)| {
            let rel = path
                .strip_prefix(workspace_root)
                .map(|p| p.to_path_buf())
                .unwrap_or(path);
            FileBatchRemoval { path: rel }
        })
        .collect();

    let upserted = store.commit_batch(batch, removal_vec, durability)?;
    if upserted > 0 {
        state
            .index_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(())
}

/// Summary of one rescan reconciliation pass. Surfaced in tracing so
/// operators reviewing overflow incidents can see whether the rewalk
/// found churn or just confirmed quiet.
#[derive(Debug, Default)]
struct RescanStats {
    /// Number of on-disk files queued for re-parse.
    touched: u64,
    /// Number of indexed files that no longer exist on disk (orphans
    /// from the overflow window).
    orphans: u64,
}

/// Re-walk the workspace, queue every on-disk file as a `Touched`-style
/// upsert, and queue index-resident files that no longer exist on disk
/// as removals. Called from the writer's `WatchEvent::Rescan` arm.
///
/// This is the correctness backbone of P6 watcher hardening: when the
/// kernel watch buffer overflows during a `git checkout` storm, we
/// can't trust the event stream alone — files may have been created,
/// modified, or deleted while events were being dropped. The rewalk
/// reconciles the index against on-disk truth.
fn rescan_and_reconcile(
    workspace_root: &Path,
    store: &Arc<Store>,
    upserts: &mut HashMap<PathBuf, ()>,
    removals: &mut HashMap<PathBuf, ()>,
) -> anyhow::Result<RescanStats> {
    let gitignore = crate::filter::PrebuiltGitignore::build(workspace_root)
        .map_err(|e| anyhow::anyhow!("rebuild gitignore: {e}"))?;

    // Walk the workspace once and collect the *current* set of paths
    // that pass the v0 filter. We use the same WalkBuilder shape as
    // the initial walk so behaviour stays identical.
    let mut on_disk: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let walker = ignore::WalkBuilder::new(workspace_root)
        .standard_filters(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .ignore(true)
        .add_custom_ignore_filename(".rtsignore")
        .follow_links(false)
        .build();
    let mut touched_count: u64 = 0;
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "rescan walk error; continuing");
                continue;
            }
        };
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.into_path();
        match crate::filter::classify(&path, &gitignore) {
            crate::filter::FilterDecision::IndexFull
            | crate::filter::FilterDecision::IndexSignatureOnly => {
                on_disk.insert(path.clone());
                // Removal supersession: if a path was queued for removal
                // before the rescan but re-appeared, the rescan wins.
                removals.remove(&path);
                upserts.insert(path, ());
                touched_count = touched_count.saturating_add(1);
            }
            crate::filter::FilterDecision::Skip(_) => {}
        }
    }

    // Orphan detection: anything in the store that's no longer on disk
    // (per the walk above) is queued for removal. `list_files_with_defs`
    // returns workspace-relative paths; we rebase to absolute for the
    // store comparison.
    let indexed = store
        .list_files_with_defs()
        .map_err(|e| anyhow::anyhow!("list_files_with_defs: {e:#}"))?;
    let mut orphan_count: u64 = 0;
    for f in &indexed {
        let abs = workspace_root.join(&f.path);
        if !on_disk.contains(&abs) {
            // Don't override an upsert that came in during the rescan
            // itself — that would be a race we can't recover from.
            upserts.remove(&abs);
            removals.insert(abs, ());
            orphan_count = orphan_count.saturating_add(1);
        }
    }

    Ok(RescanStats {
        touched: touched_count,
        orphans: orphan_count,
    })
}

#[derive(Debug)]
enum ParseRejected {
    IoMissing,
    Oversize,
    UnsupportedLanguage,
    OutOfRoot,
    ParseFailed(String),
}

fn parse_and_extract(
    parsers: &ParserPool,
    workspace_root: &Path,
    abs_path: &Path,
) -> Result<FileBatchEntry, ParseRejected> {
    // Re-check the path is under root. The watcher emits absolute paths that
    // we already filtered, but a stale event after a directory move could
    // sneak past. (Per protocol-v0 §6.2: re-canonicalise on every read.)
    if !abs_path.starts_with(workspace_root) {
        return Err(ParseRejected::OutOfRoot);
    }

    let meta_io = match std::fs::metadata(abs_path) {
        Ok(m) => m,
        Err(_) => return Err(ParseRejected::IoMissing),
    };
    let mtime_ns = meta_io
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0)
        });
    let size = meta_io.len();
    let rel_path = abs_path.strip_prefix(workspace_root).unwrap_or(abs_path);

    if size > OVERSIZE_THRESHOLD_BYTES {
        let h = blake3::hash(format!("oversize:{}:{}", abs_path.display(), size).as_bytes()).into();
        return Ok(FileBatchEntry {
            path: rel_path.to_path_buf(),
            meta: FileMeta {
                content_hash: h,
                mtime_ns,
                lang: 0,
                parse_status: ParseStatus::Partial,
                oversize: true,
            },
            defs: Vec::new(),
        });
    }

    // Dispatch via the central registry. The path is absolute at this
    // point but `info_for_path` only inspects the extension, so it
    // doesn't matter whether the workspace-relative or absolute form
    // is passed.
    let language = match abs_path
        .to_str()
        .and_then(crate::language::info_for_path)
        .map(|info| info.language)
    {
        Some(l) => l,
        None => return Err(ParseRejected::UnsupportedLanguage),
    };

    let content = match std::fs::read_to_string(abs_path) {
        Ok(s) => s,
        Err(_) => return Err(ParseRejected::IoMissing),
    };
    let content_hash: [u8; 32] = blake3::hash(content.as_bytes()).into();

    let symbols = match parsers.parse_and_extract(language, &content) {
        Ok(s) => s,
        Err(e) => {
            warn!(path = %abs_path.display(), error = %e, "parse failed");
            // Still record the file so re-saves can clear the failure.
            return Ok(FileBatchEntry {
                path: rel_path.to_path_buf(),
                meta: FileMeta {
                    content_hash,
                    mtime_ns,
                    lang: lang_tag(language),
                    parse_status: ParseStatus::Failed,
                    oversize: false,
                },
                defs: Vec::new(),
            });
        }
    };

    let defs = symbols
        .into_iter()
        .filter_map(|sym| symbol_to_def(&sym, &content))
        .collect();

    Ok(FileBatchEntry {
        path: rel_path.to_path_buf(),
        meta: FileMeta {
            content_hash,
            mtime_ns,
            lang: lang_tag(language),
            parse_status: ParseStatus::Ok,
            oversize: false,
        },
        defs,
    })
}

fn symbol_to_def(sym: &Symbol, content: &str) -> Option<(String, DefSite, SymbolKind)> {
    if sym.name.is_empty() {
        return None;
    }
    let kind = SymbolKind::from_str_loose(&sym.kind);
    let (start_byte, end_byte) = line_col_to_byte_range(content, sym);

    Some((
        sym.name.clone(),
        DefSite {
            fid: 0, // set inside commit_batch once the file id is known
            start: start_byte,
            end: end_byte,
            start_line: sym.start_line as u32,
            end_line: sym.end_line as u32,
            visibility: crate::store::schema::Visibility::from_str_loose(&sym.visibility),
            kind,
        },
        kind,
    ))
}

/// Translate a 1-based `(line, col)` range to byte offsets in `content`.
/// Imprecise for ranges that span CRLF newlines (treats them as `\n` for the
/// purposes of byte counting) — acceptable for v0; the per-language
/// SignatureRenderer in P8 will get this from tree-sitter directly.
fn line_col_to_byte_range(content: &str, sym: &Symbol) -> (u32, u32) {
    let bytes = content.as_bytes();
    let mut line_starts: Vec<usize> = vec![0];
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            line_starts.push(i + 1);
        }
    }
    let line_start = |line_1based: usize| -> usize {
        if line_1based == 0 || line_1based > line_starts.len() {
            return bytes.len();
        }
        line_starts[line_1based - 1]
    };
    let start = (line_start(sym.start_line) + sym.start_column).min(bytes.len()) as u32;
    let end = (line_start(sym.end_line) + sym.end_column).min(bytes.len()) as u32;
    let end = end.max(start);
    (start, end)
}

/// Stable numeric tag for each `Language` variant — stored in `FileMeta.lang`
/// so future schema readers can recognise the language without coupling to
/// `Language`'s enum discriminant order.
fn lang_tag(language: Language) -> u8 {
    match language {
        Language::Rust => 1,
        Language::JavaScript => 2,
        Language::TypeScript => 3,
        Language::Python => 4,
        Language::C => 5,
        Language::Cpp => 6,
        Language::Go => 7,
        Language::Java => 8,
        Language::Php => 9,
        Language::Ruby => 10,
        Language::Swift => 11,
    }
}

/// Per-call parser facade. v0 created a fresh `CodebaseAnalyzer` per
/// call and round-tripped the content through a tempfile via
/// `analyzer.analyze_file`; the alpha.29 perf reviewer audit (H1)
/// flagged that as the writer's biggest hot-path waste — tree-sitter
/// accepts content directly through `analyze_content`, no tempfile
/// or re-read needed.
///
/// The type is kept around (vs an inline call) for two reasons:
///
/// 1. The writer's `flush()` rayon `into_par_iter().map(...)` closure
///    captures `&ParserPool` (originally for the mutex-protected
///    parser cache). Keeping the type lets us extend it later with
///    rayon-thread-local analyzer storage, when/if benches show that
///    `CodebaseAnalyzer::new()` per call is itself measurable.
/// 2. Tests in the writer module exercise this surface via
///    `ParserPool::new().parse_and_extract(...)`.
struct ParserPool;

impl ParserPool {
    fn new() -> Self {
        Self
    }

    /// Parse `content` for `language` and return the extracted symbols.
    ///
    /// Bypasses the filesystem entirely — content goes straight into
    /// `CodebaseAnalyzer::analyze_content`, which parses with
    /// tree-sitter and runs the per-language symbol extractor. No
    /// tempfile, no disk round-trip.
    fn parse_and_extract(&self, language: Language, content: &str) -> anyhow::Result<Vec<Symbol>> {
        use rust_tree_sitter::CodebaseAnalyzer;
        let mut analyzer = CodebaseAnalyzer::new()?;
        Ok(analyzer.analyze_content(content, language)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_extract_returns_rust_symbols() {
        let pool = ParserPool::new();
        let src = "pub fn hello() {}\npub struct World;\n";
        let syms = pool.parse_and_extract(Language::Rust, src).unwrap();
        assert!(
            syms.iter().any(|s| s.name == "hello"),
            "expected `hello` in {syms:?}"
        );
    }

    #[test]
    fn parse_and_extract_caller_excludes_called_fn_names() {
        // Probe for the bug where the analyzer was reporting referenced
        // function names as defined symbols in the referring file.
        let pool = ParserPool::new();
        let src =
            "pub fn caller_a_one() {\n    let _ = hub_compute(1);\n    let _ = hub_format(2);\n}\n";
        let syms = pool.parse_and_extract(Language::Rust, src).unwrap();
        let names: Vec<_> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"caller_a_one"),
            "expected `caller_a_one` in {names:?}"
        );
        assert!(
            !names.contains(&"hub_compute"),
            "`hub_compute` is a CALL, not a def, should not appear; got {names:?}"
        );
        assert!(
            !names.contains(&"hub_format"),
            "`hub_format` is a CALL, not a def, should not appear; got {names:?}"
        );
    }

    /// **Known issue**: as of `0.2.0-alpha.15` the analyzer's
    /// `extract_java_symbols` / `extract_c_symbols` / `extract_cpp_symbols`
    /// paths return empty when called via the writer's tempfile route
    /// (the `extract_*_symbols` methods in `rust_tree_sitter::analyzer`
    /// are TODO-stubbed for these languages). The SignatureRenderer for
    /// these languages works (covered by 22 unit tests in
    /// `rust_tree_sitter::signature::tests`), but they won't get
    /// signature-rendered through `Index.ReadSymbol` until the writer's
    /// upstream extraction is fixed in a follow-up PR. Go works.
    #[test]
    fn parse_and_extract_returns_go_symbols() {
        let pool = ParserPool::new();
        let src = "package demo\n\nfunc GoTarget(name string) int { return len(name) }\n";
        let syms = pool.parse_and_extract(Language::Go, src).unwrap();
        let names: Vec<_> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"GoTarget"),
            "expected `GoTarget` in symbols; got {names:?}"
        );
    }

    #[test]
    fn parse_and_extract_returns_java_symbols() {
        let pool = ParserPool::new();
        let src = "package demo;\n\npublic class JavaTarget {\n    public int compute(int x) { return x + 1; }\n}\n";
        let syms = pool.parse_and_extract(Language::Java, src).unwrap();
        let names: Vec<_> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"JavaTarget"),
            "expected `JavaTarget` in symbols; got {names:?}"
        );
    }

    #[test]
    fn parse_and_extract_returns_c_symbols() {
        let pool = ParserPool::new();
        let src = "int c_target(int a, int b) { return a + b; }\n";
        let syms = pool.parse_and_extract(Language::C, src).unwrap();
        let names: Vec<_> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"c_target"),
            "expected `c_target` in symbols; got {names:?}"
        );
    }

    #[test]
    fn parse_and_extract_returns_cpp_symbols() {
        let pool = ParserPool::new();
        let src = "int cpp_target(int a, int b) { return a + b; }\n";
        let syms = pool.parse_and_extract(Language::Cpp, src).unwrap();
        let names: Vec<_> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"cpp_target"),
            "expected `cpp_target` in symbols; got {names:?}"
        );
    }

    #[test]
    fn parse_and_extract_returns_php_symbols() {
        let pool = ParserPool::new();
        let src = "<?php\nfunction phpTarget($a, $b) { return $a + $b; }\n";
        let syms = pool.parse_and_extract(Language::Php, src).unwrap();
        let names: Vec<_> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"phpTarget"),
            "expected `phpTarget` in symbols; got {names:?}"
        );
    }

    #[test]
    fn parse_and_extract_returns_ruby_symbols() {
        let pool = ParserPool::new();
        let src = "def ruby_target(name)\n  name.length\nend\n";
        let syms = pool.parse_and_extract(Language::Ruby, src).unwrap();
        let names: Vec<_> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"ruby_target"),
            "expected `ruby_target` in symbols; got {names:?}"
        );
    }

    #[test]
    fn parse_and_extract_returns_swift_symbols() {
        let pool = ParserPool::new();
        let src = "func swiftTarget(_ a: Int, _ b: Int) -> Int { return a + b }\n";
        let syms = pool.parse_and_extract(Language::Swift, src).unwrap();
        let names: Vec<_> = syms.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"swiftTarget"),
            "expected `swiftTarget` in symbols; got {names:?}"
        );
    }

    #[test]
    fn line_col_translation_is_consistent_with_str_bytes() {
        let content = "abc\ndef\nghij\n";
        let sym = Symbol {
            name: "x".into(),
            kind: "fn".into(),
            start_line: 2,
            end_line: 3,
            start_column: 1,
            end_column: 3,
            visibility: "public".into(),
            documentation: None,
        };
        let (start, end) = line_col_to_byte_range(content, &sym);
        // Line 2 starts at byte 4; col 1 → byte 5.
        // Line 3 starts at byte 8; col 3 → byte 11.
        assert_eq!(start, 5);
        assert_eq!(end, 11);
    }

    /// Build a store seeded with one indexed file. Returns (store, root).
    /// The seeded file is `seeded.rs` with a `pub fn seeded()` symbol.
    fn seed_store_with_one_file() -> (Arc<Store>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        // Drop state_dir on store-builder return; redb file already opened.
        let _ = state_dir;

        std::fs::write(
            tmp.path().join("seeded.rs"),
            "pub fn seeded() -> u32 { 1 }\n",
        )
        .unwrap();

        // Open a fresh store (not on disk in any tracked location — just
        // a tempfile for the redb file).
        let db_path = tmp.path().join("_index").join("db.redb");
        std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let store = Arc::new(Store::open(&db_path).unwrap());

        // Seed via parse_and_extract + commit_batch, mirroring the
        // writer's normal flow.
        let parsers = ParserPool::new();
        let abs = tmp.path().join("seeded.rs");
        let entry = parse_and_extract(&parsers, tmp.path(), &abs).expect("parse seed");
        store
            .commit_batch(vec![entry], vec![], redb::Durability::Immediate)
            .expect("commit seed");
        (store, tmp)
    }

    #[test]
    fn rescan_queues_orphan_for_removal_when_file_vanishes() {
        let (store, tmp) = seed_store_with_one_file();
        // Sanity: the seeded symbol is queryable.
        assert!(
            !store.find_symbol("seeded").unwrap().is_empty(),
            "seed should be in the store"
        );

        // Make the file disappear. The watcher didn't see it (we never
        // started one); the rescan path is responsible for catching up.
        std::fs::remove_file(tmp.path().join("seeded.rs")).unwrap();

        let mut upserts: HashMap<PathBuf, ()> = HashMap::new();
        let mut removals: HashMap<PathBuf, ()> = HashMap::new();
        let stats = rescan_and_reconcile(tmp.path(), &store, &mut upserts, &mut removals)
            .expect("reconcile");

        assert_eq!(stats.touched, 0, "no on-disk files left");
        assert_eq!(stats.orphans, 1, "the vanished file should be one orphan");
        assert_eq!(removals.len(), 1, "removals should have the orphan path");
        assert!(
            upserts.is_empty(),
            "no upserts when there are no on-disk files"
        );
    }

    #[test]
    fn rescan_picks_up_new_files_added_outside_event_stream() {
        let (store, tmp) = seed_store_with_one_file();
        // A file that arrived while we were "deaf" to events.
        std::fs::write(
            tmp.path().join("late.rs"),
            "pub fn arrived_late() -> u32 { 7 }\n",
        )
        .unwrap();

        let mut upserts: HashMap<PathBuf, ()> = HashMap::new();
        let mut removals: HashMap<PathBuf, ()> = HashMap::new();
        let stats = rescan_and_reconcile(tmp.path(), &store, &mut upserts, &mut removals)
            .expect("reconcile");

        // Both files are present, neither orphaned.
        assert_eq!(stats.touched, 2, "two on-disk files now");
        assert_eq!(stats.orphans, 0);
        assert_eq!(upserts.len(), 2);
        assert!(removals.is_empty());
        // Both absolute paths should be queued.
        let queued_basenames: std::collections::HashSet<_> = upserts
            .keys()
            .map(|p| p.file_name().unwrap().to_owned())
            .collect();
        assert!(queued_basenames.contains(std::ffi::OsStr::new("seeded.rs")));
        assert!(queued_basenames.contains(std::ffi::OsStr::new("late.rs")));
    }

    #[test]
    fn rescan_supersedes_pending_removal_when_file_reappears() {
        let (store, tmp) = seed_store_with_one_file();

        // Pre-queue a removal (as if some event said "seeded.rs is gone"),
        // then run the rescan. The file is *still on disk*, so the
        // rescan should win and the removal should be cleared.
        let abs_seeded = tmp.path().join("seeded.rs");
        let mut upserts: HashMap<PathBuf, ()> = HashMap::new();
        let mut removals: HashMap<PathBuf, ()> = HashMap::new();
        removals.insert(abs_seeded.clone(), ());

        let stats = rescan_and_reconcile(tmp.path(), &store, &mut upserts, &mut removals)
            .expect("reconcile");
        assert_eq!(stats.touched, 1);
        assert_eq!(stats.orphans, 0);
        assert!(
            !removals.contains_key(&abs_seeded),
            "stale removal should be cleared by the rescan upsert; got {removals:?}"
        );
        assert!(upserts.contains_key(&abs_seeded));
    }
}
