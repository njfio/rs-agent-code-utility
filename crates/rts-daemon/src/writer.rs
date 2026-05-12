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
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use redb::Durability;
use rust_tree_sitter::{Language, Parser, Symbol};
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
                        // Surface to status; the actual rewalk is the watcher's
                        // job. We currently just log; the writer's redb state is
                        // self-consistent as soon as the watcher catches up.
                        info!("writer received rescan signal");
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

    let mut batch: Vec<FileBatchEntry> = Vec::with_capacity(upserts.len());
    for (path, _) in upserts.drain() {
        match parse_and_extract(parsers, workspace_root, &path) {
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
    let removal_vec: Vec<FileBatchRemoval> = removals
        .drain()
        .map(|(path, _)| FileBatchRemoval { path })
        .collect();

    let upserted = store.commit_batch(batch, removal_vec, durability)?;
    if upserted > 0 {
        state
            .index_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(())
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

    let language = match detect_language_from_path(abs_path) {
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

fn detect_language_from_path(path: &Path) -> Option<Language> {
    let ext = path.extension().and_then(|e| e.to_str())?;
    rust_tree_sitter::detect_language_from_extension(ext)
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

/// Per-language `Parser` cache. tree-sitter `Parser` is not `Sync` for
/// concurrent parses (P0.3 finding); we lock per language so single-writer
/// flushes serialise fine. The rayon thread-local refinement is a later
/// P6 perf step.
struct ParserPool {
    by_lang: Mutex<HashMap<Language, Parser>>,
}

impl ParserPool {
    fn new() -> Self {
        Self {
            by_lang: Mutex::new(HashMap::new()),
        }
    }

    /// Parse `content` for `language` and return the extracted symbols via
    /// the per-language extractor from rts-core's `CodebaseAnalyzer`.
    fn parse_and_extract(&self, language: Language, content: &str) -> anyhow::Result<Vec<Symbol>> {
        // Borrow / create a `Parser` for this language. We use a single
        // `CodebaseAnalyzer` per call to keep its `&mut self` contract local;
        // the analyzer's symbol-extraction methods are pure functions of the
        // tree + content, so this is cheap.
        use rust_tree_sitter::CodebaseAnalyzer;

        // Trigger the parser-pool insert so the lock is held only for the
        // brief check; the actual parse uses a fresh local analyzer per call.
        {
            let mut pool = self
                .by_lang
                .lock()
                .map_err(|e| anyhow::anyhow!("parser pool poisoned: {e}"))?;
            if let std::collections::hash_map::Entry::Vacant(e) = pool.entry(language) {
                e.insert(Parser::new(language)?);
            }
        }

        let mut analyzer = CodebaseAnalyzer::new()?;
        let tmp = tempfile::NamedTempFile::new()
            .map_err(|e| anyhow::anyhow!("could not create tempfile for parse: {e}"))?;
        // Suffix the tempfile so analyzer's extension-based language detection
        // routes to the right extractor. NamedTempFile doesn't easily let us
        // pick the suffix, so we manually rename inside its dir.
        let target = tmp.path().with_extension(default_extension(language));
        std::fs::write(&target, content)?;
        let result = analyzer.analyze_file(&target)?;
        let _ = std::fs::remove_file(&target);
        let symbols = result
            .files
            .into_iter()
            .flat_map(|f| f.symbols.into_iter())
            .collect();
        Ok(symbols)
    }
}

fn default_extension(language: Language) -> &'static str {
    match language {
        Language::Rust => "rs",
        Language::JavaScript => "js",
        Language::TypeScript => "ts",
        Language::Python => "py",
        Language::C => "c",
        Language::Cpp => "cpp",
        Language::Go => "go",
        Language::Java => "java",
        Language::Php => "php",
        Language::Ruby => "rb",
        Language::Swift => "swift",
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
}
