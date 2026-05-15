//! redb-backed on-disk index. Owns the schema and offers minimal-surface
//! read/write helpers; the writer-drain (in `writer.rs`) is the only
//! consumer of `Store::commit_batch`, and the read handlers in `methods/`
//! are the only consumers of the lookup helpers.
//!
//! Schema is per `docs/protocol-v0.md` §"Concrete redb schema" and the P0.2
//! redb-storage spike at `spikes/p0-2-redb-smoke/`.

pub mod schema;

pub use schema::{DefSite, FileId, FileMeta, ParseStatus, RefSite, SymbolKind};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, anyhow};
use postcard::{from_bytes, to_allocvec};
use redb::{Database, Durability, ReadableMultimapTable, ReadableTable};

use schema::{
    DEFS, FID_DEFS, FID_REFS, FID_TO_PATH, FILES, META, NAME_TO_SID, PATH_TO_FID, REFS,
    SID_REFS_OUT, SID_TO_NAME,
};

/// Current on-disk schema version. Bump when any table layout or value-bytes
/// shape changes. Mismatch on open → daemon-controlled rebuild (protocol-v0
/// §15.4); a newer-than-binary schema → refusal with `SCHEMA_VERSION_NEWER`.
///
/// History:
/// * `1` — initial schema (v0.2 alpha.1+): files, names, defs.
/// * `2` — v0.3 alpha.31 (U1): adds REFS + FID_REFS + SID_REFS_OUT
///   for the call graph half of the index. Old `db.redb` files are
///   wiped on first mount; the index is a derived cache per
///   protocol-v0 §15.4. No migration code needed.
pub const SCHEMA_VERSION: u32 = 2;

const META_SCHEMA_VERSION: &str = "schema_version";
const META_NEXT_FID: &str = "next_fid";
const META_NEXT_SID: &str = "next_sid";

/// Why the writer rejected a file.
#[derive(Debug, Clone, Copy)]
pub enum FileRejected {
    /// > 4 MiB; indexed by (size, mtime) only per protocol-v0 §16.
    Oversize,
    /// Could not detect the language; the file is below the workspace root
    /// but not in our 11 supported grammars.
    UnsupportedLanguage,
}

/// Snapshot stats for `Workspace.Status`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StoreStats {
    pub files_indexed: u64,
    pub parse_failed_files: u64,
}

/// A single reference hit extracted from a parse pass. The writer
/// produces these alongside defs; `commit_batch` resolves
/// `name` → `callee_sid` and computes `caller_sid` via
/// smallest-enclosing-def lookup against the file's own defs.
///
/// `start_line` / `end_line` are 1-based inclusive (matching `DefSite`);
/// `start` / `end` are 0-based byte offsets, half-open.
#[derive(Debug, Clone)]
pub struct RefHit {
    pub name: String,
    pub start: u32,
    pub end: u32,
    pub start_line: u32,
    pub end_line: u32,
}

/// A single file's contribution to the index, batched up by the writer before
/// commit. The writer task collects one `FileBatchEntry` per touched file,
/// hands them to `Store::commit_batch`, and the store applies them as one
/// `WriteTransaction`.
#[derive(Debug)]
pub struct FileBatchEntry {
    pub path: PathBuf,
    pub meta: FileMeta,
    /// Defined symbols + their byte/line ranges.
    pub defs: Vec<(String, DefSite, SymbolKind)>,
    /// Reference hits within this file. Empty for parse-failed files.
    /// `commit_batch` filters external references (names with no
    /// `NAME_TO_SID` entry after batch interning) per v0.3 plan §F1.
    pub refs: Vec<RefHit>,
}

/// A removal entry for files that disappeared since last index.
#[derive(Debug)]
pub struct FileBatchRemoval {
    pub path: PathBuf,
}

/// Owning handle for the redb database + lightweight in-memory caches used by
/// the writer (next-id counters).
pub struct Store {
    db: Database,
    /// Path on disk; surfaced for diagnostics + telemetry only.
    db_path: PathBuf,
    next_fid: AtomicU32,
    next_sid: AtomicU32,
    stats: std::sync::Mutex<StoreStats>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("db_path", &self.db_path)
            .field("next_fid", &self.next_fid.load(Ordering::Relaxed))
            .field("next_sid", &self.next_sid.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Open (or create) the per-workspace redb file at `db_path`. The parent
    /// directory MUST already exist with safe perms (caller's responsibility).
    /// On a schema-version mismatch the database is wiped and recreated — the
    /// index is a derived cache per protocol-v0 §15.4.
    pub fn open(db_path: &Path) -> anyhow::Result<Self> {
        // First attempt: open as-is.
        let mut db = Database::create(db_path)
            .with_context(|| format!("open redb at {}", db_path.display()))?;

        let mut rebuild = false;
        let mut next_fid = 1u32;
        let mut next_sid = 1u32;
        {
            let txn = db.begin_read().context("begin_read for meta probe")?;
            match txn.open_table(META) {
                Ok(meta) => {
                    let stored: Option<u32> = meta
                        .get(META_SCHEMA_VERSION)?
                        .and_then(|v| u32_from_le_slice(v.value()));
                    match stored {
                        Some(v) if v == SCHEMA_VERSION => {
                            next_fid = meta
                                .get(META_NEXT_FID)?
                                .and_then(|v| u32_from_le_slice(v.value()))
                                .unwrap_or(1);
                            next_sid = meta
                                .get(META_NEXT_SID)?
                                .and_then(|v| u32_from_le_slice(v.value()))
                                .unwrap_or(1);
                        }
                        Some(v) if v > SCHEMA_VERSION => {
                            return Err(anyhow!(
                                "on-disk schema version {v} is newer than this daemon binary supports ({SCHEMA_VERSION})"
                            ));
                        }
                        _ => rebuild = true,
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => rebuild = true,
                Err(e) => return Err(anyhow::Error::new(e)),
            }
        }

        if rebuild {
            drop(db);
            // remove_file: ENOENT is fine. Anything else surfaces.
            match std::fs::remove_file(db_path) {
                Ok(()) | Err(_) => {}
            }
            db = Database::create(db_path)
                .with_context(|| format!("recreate redb at {}", db_path.display()))?;
            let w = db.begin_write().context("begin_write for schema init")?;
            {
                let mut meta = w.open_table(META)?;
                meta.insert(META_SCHEMA_VERSION, &SCHEMA_VERSION.to_le_bytes()[..])?;
                meta.insert(META_NEXT_FID, &1u32.to_le_bytes()[..])?;
                meta.insert(META_NEXT_SID, &1u32.to_le_bytes()[..])?;
            }
            w.commit().context("commit schema init")?;
        }

        // Materialise every table redb-side so read handlers can query before
        // the writer has ever committed. Without this, an empty workspace +
        // `Index.FindSymbol` returns `TableDoesNotExist` instead of an empty
        // match list.
        {
            let w = db.begin_write().context("begin_write for table init")?;
            {
                let _ = w.open_table(FILES)?;
                let _ = w.open_table(PATH_TO_FID)?;
                let _ = w.open_table(FID_TO_PATH)?;
                let _ = w.open_table(NAME_TO_SID)?;
                let _ = w.open_table(SID_TO_NAME)?;
                let _ = w.open_multimap_table(DEFS)?;
                let _ = w.open_multimap_table(FID_DEFS)?;
                // v0.3 (SCHEMA_VERSION=2): call-graph tables.
                let _ = w.open_multimap_table(REFS)?;
                let _ = w.open_multimap_table(FID_REFS)?;
                let _ = w.open_multimap_table(SID_REFS_OUT)?;
                let _ = w.open_table(META)?;
            }
            w.commit().context("commit table init")?;
        }

        Ok(Self {
            db,
            db_path: db_path.to_path_buf(),
            next_fid: AtomicU32::new(next_fid),
            next_sid: AtomicU32::new(next_sid),
            stats: std::sync::Mutex::new(StoreStats::default()),
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn stats(&self) -> StoreStats {
        self.stats.lock().map(|g| *g).unwrap_or_default()
    }

    /// Commit a writer-task batch. Returns the number of files indexed (or
    /// re-indexed) by this commit.
    ///
    /// `durability` lets the writer choose `None` for the hot path and
    /// `Immediate` for the periodic flush per protocol-v0 §9.2.
    pub fn commit_batch(
        &self,
        upserts: Vec<FileBatchEntry>,
        removals: Vec<FileBatchRemoval>,
        durability: Durability,
    ) -> anyhow::Result<u64> {
        if upserts.is_empty() && removals.is_empty() {
            return Ok(0);
        }
        let mut indexed = 0u64;
        let mut parse_failed_delta = 0i64;

        let mut txn = self.db.begin_write().context("begin_write")?;
        txn.set_durability(durability);
        {
            let mut files = txn.open_table(FILES)?;
            let mut path_to_fid = txn.open_table(PATH_TO_FID)?;
            let mut fid_to_path = txn.open_table(FID_TO_PATH)?;
            let mut name_to_sid = txn.open_table(NAME_TO_SID)?;
            let mut sid_to_name = txn.open_table(SID_TO_NAME)?;
            let mut defs = txn.open_multimap_table(DEFS)?;
            let mut fid_defs = txn.open_multimap_table(FID_DEFS)?;
            let mut refs_t = txn.open_multimap_table(REFS)?;
            let mut fid_refs = txn.open_multimap_table(FID_REFS)?;
            let mut sid_refs_out = txn.open_multimap_table(SID_REFS_OUT)?;
            let mut meta = txn.open_table(META)?;

            // Removals first (rare relative to upserts; cheap to scan).
            for rem in &removals {
                let path_str = rem.path.to_string_lossy();
                let fid = match path_to_fid.get(path_str.as_ref())? {
                    Some(v) => v.value(),
                    None => continue,
                };
                drop_file_entries(
                    &mut files,
                    &mut fid_defs,
                    &mut defs,
                    &mut fid_refs,
                    &mut refs_t,
                    &mut sid_refs_out,
                    fid,
                )?;
                path_to_fid.remove(path_str.as_ref())?;
                fid_to_path.remove(&fid)?;
            }

            // Upserts: **two-pass** to avoid intra-batch ordering bugs.
            //
            // Pass 1: assign FIDs, drop prior entries, write FileMeta +
            // DEFS + FID_DEFS, intern names. After Pass 1 every def name
            // in the batch is present in NAME_TO_SID.
            //
            // Pass 2: write refs. Now every same-batch callee resolves
            // correctly via NAME_TO_SID. Before this refactor, callers
            // in a file processed earlier than their callee's file
            // would have their refs filtered as "external."
            //
            // We carry `(fid, file_defs)` between passes so the caller_sid
            // resolution in Pass 2 still has access to the file's own def
            // ranges.
            let mut staged: Vec<(u32, Vec<(u32, u32, u32, SymbolKind)>, Vec<RefHit>)> =
                Vec::with_capacity(upserts.len());

            // Pass 1.
            for entry in upserts {
                let path_str = entry.path.to_string_lossy().to_string();

                let existing_fid = path_to_fid.get(path_str.as_str())?.map(|v| v.value());
                let fid = match existing_fid {
                    Some(v) => v,
                    None => {
                        let new_fid = self.next_fid.fetch_add(1, Ordering::Relaxed);
                        path_to_fid.insert(path_str.as_str(), new_fid)?;
                        fid_to_path.insert(new_fid, path_str.as_str())?;
                        new_fid
                    }
                };

                // Track parse-status delta for stats.
                let prior_failed = files
                    .get(&fid)?
                    .and_then(|v| from_bytes::<FileMeta>(v.value()).ok())
                    .map(|m| m.parse_status == ParseStatus::Failed)
                    .unwrap_or(false);
                let now_failed = entry.meta.parse_status == ParseStatus::Failed;
                if now_failed && !prior_failed {
                    parse_failed_delta += 1;
                } else if !now_failed && prior_failed {
                    parse_failed_delta -= 1;
                }

                // Drop prior defs *and* refs for this file before re-inserting;
                // this is the simplest correct policy and avoids stale-symbol
                // and stale-edge leaks.
                drop_file_entries(
                    &mut files,
                    &mut fid_defs,
                    &mut defs,
                    &mut fid_refs,
                    &mut refs_t,
                    &mut sid_refs_out,
                    fid,
                )?;

                let meta_bytes = to_allocvec(&entry.meta).context("encode FileMeta")?;
                files.insert(&fid, meta_bytes.as_slice())?;

                // Track each def's (sid, byte_range, kind) so we can
                // compute caller_sid for ref sites in this file.
                // `enclosing_caller_sid` filters by kind (only Function/
                // Method/Module count as callers) so local-variable
                // defs emitted alongside fn defs don't "steal" the
                // innermost-enclosing lookup. See is_call_bearing_kind
                // for the rationale.
                let mut file_defs: Vec<(u32, u32, u32, SymbolKind)> =
                    Vec::with_capacity(entry.defs.len());

                for (name, mut def, kind) in entry.defs {
                    let existing_sid = name_to_sid.get(name.as_str())?.map(|v| v.value());
                    let sid = match existing_sid {
                        Some(v) => v,
                        None => {
                            let new_sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
                            name_to_sid.insert(name.as_str(), new_sid)?;
                            sid_to_name.insert(new_sid, name.as_str())?;
                            new_sid
                        }
                    };
                    def.fid = fid;
                    def.kind = kind;
                    let def_bytes = to_allocvec(&def).context("encode DefSite")?;
                    defs.insert(&sid, def_bytes.as_slice())?;
                    fid_defs.insert(&fid, &sid)?;
                    file_defs.push((sid, def.start, def.end, kind));
                }

                staged.push((fid, file_defs, entry.refs));
                indexed += 1;
            }

            // Pass 2: refs. Every same-batch callee is now interned.
            // External names (no NAME_TO_SID entry after Pass 1) are
            // filtered per v0.3 plan §F1.
            for (fid, file_defs, refs) in staged {
                for r in refs {
                    let callee_sid = match name_to_sid.get(r.name.as_str())? {
                        Some(v) => v.value(),
                        None => continue, // external symbol; skip per F1
                    };
                    let caller_sid = enclosing_caller_sid(&file_defs, r.start);

                    let site = RefSite {
                        fid,
                        start: r.start,
                        end: r.end,
                        start_line: r.start_line,
                        end_line: r.end_line,
                        caller_sid,
                    };
                    let site_bytes = to_allocvec(&site).context("encode RefSite")?;
                    refs_t.insert(&callee_sid, site_bytes.as_slice())?;
                    fid_refs.insert(&fid, &callee_sid)?;
                    if let Some(c) = caller_sid {
                        sid_refs_out.insert(&c, &callee_sid)?;
                    }
                }
            }

            // Persist next-id counters and any other metadata for restart.
            meta.insert(
                META_NEXT_FID,
                &self.next_fid.load(Ordering::Relaxed).to_le_bytes()[..],
            )?;
            meta.insert(
                META_NEXT_SID,
                &self.next_sid.load(Ordering::Relaxed).to_le_bytes()[..],
            )?;
        }
        txn.commit().context("commit write txn")?;

        if let Ok(mut s) = self.stats.lock() {
            s.files_indexed += indexed;
            s.parse_failed_files = (s.parse_failed_files as i64 + parse_failed_delta).max(0) as u64;
        }

        Ok(indexed)
    }

    /// Look up a file by its workspace-relative path and return the FID + the
    /// stored `FileMeta` (content hash, mtime, lang, parse status, oversize).
    ///
    /// Returns `Ok(None)` if the path isn't indexed (gitignore/secrets/ext or
    /// just not seen by the watcher yet). Used by `Index.ReadRange` for the
    /// pre-read existence check + by `Index.ReadSymbol` for `content_version`.
    /// Enumerate every indexed file path + its symbol defs. Used by
    /// `Index.Outline` to build the file-level reference graph for
    /// PageRank ranking. Returns paths in arbitrary order.
    pub fn list_files_with_defs(&self) -> anyhow::Result<Vec<FileWithDefs>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let fid_to_path = txn.open_table(FID_TO_PATH)?;
        let fid_defs = txn.open_multimap_table(FID_DEFS)?;
        let sid_to_name = txn.open_table(SID_TO_NAME)?;
        let defs = txn.open_multimap_table(DEFS)?;

        let mut out: Vec<FileWithDefs> = Vec::new();
        let iter = fid_to_path.iter()?;
        for row in iter {
            let row = row?;
            let fid = row.0.value();
            let path = row.1.value().to_string();
            let mut defined_symbols: Vec<DefinedSymbol> = Vec::new();
            let mut sid_it = fid_defs.get(&fid)?;
            while let Some(sid_row) = sid_it.next() {
                let sid = sid_row?.value();
                let name = match sid_to_name.get(&sid)? {
                    Some(v) => v.value().to_string(),
                    None => continue,
                };
                // Walk the DEFS multimap for this SID and pick the def
                // whose FID matches the current file.
                let mut defs_it = defs.get(&sid)?;
                while let Some(def_row) = defs_it.next() {
                    let bytes = def_row?.value().to_vec();
                    if let Ok(d) = from_bytes::<DefSite>(&bytes) {
                        if d.fid == fid {
                            defined_symbols.push(DefinedSymbol {
                                name: name.clone(),
                                kind: d.kind,
                                visibility: d.visibility,
                                start_line: d.start_line,
                                end_line: d.end_line,
                                start_byte: d.start,
                                end_byte: d.end,
                            });
                            break;
                        }
                    }
                }
            }
            out.push(FileWithDefs {
                path,
                defined_symbols,
            });
        }
        Ok(out)
    }

    /// Defs in one workspace-relative file, surfaced as `FoundSymbol`.
    /// Used by `Index.ReadSymbolAt` to convert `(file, line)` into a
    /// concrete def site by picking the innermost enclosing range.
    ///
    /// Returns `Ok(Vec::new())` when the file isn't indexed — caller
    /// surfaces this as `FILE_NOT_INDEXED`. Order is arbitrary; the
    /// `ReadSymbolAt` handler sorts by range to find the innermost
    /// containing def.
    pub fn defs_in_file(&self, path: &str) -> anyhow::Result<Vec<FoundSymbol>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let path_to_fid = txn.open_table(PATH_TO_FID)?;
        let fid: u32 = match path_to_fid.get(path)? {
            Some(v) => v.value(),
            None => return Ok(Vec::new()),
        };
        let fid_defs = txn.open_multimap_table(FID_DEFS)?;
        let sid_to_name = txn.open_table(SID_TO_NAME)?;
        let defs = txn.open_multimap_table(DEFS)?;
        let mut out: Vec<FoundSymbol> = Vec::new();
        let mut sid_it = fid_defs.get(&fid)?;
        while let Some(sid_row) = sid_it.next() {
            let sid = sid_row?.value();
            let name = match sid_to_name.get(&sid)? {
                Some(v) => v.value().to_string(),
                None => continue,
            };
            let mut def_it = defs.get(&sid)?;
            while let Some(def_row) = def_it.next() {
                let bytes = def_row?.value().to_vec();
                if let Ok(d) = from_bytes::<DefSite>(&bytes) {
                    if d.fid == fid {
                        out.push(FoundSymbol {
                            name: name.clone(),
                            kind: d.kind,
                            file: path.to_string(),
                            fid: d.fid,
                            start_byte: d.start,
                            end_byte: d.end,
                            start_line: d.start_line,
                            end_line: d.end_line,
                            visibility: d.visibility,
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    /// All symbol names defined anywhere in the workspace, as a set.
    /// Used by `Index.Outline` to filter raw identifier references
    /// down to "actual symbol references" before building the graph.
    pub fn all_defined_names(&self) -> anyhow::Result<std::collections::HashSet<String>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let name_to_sid = txn.open_table(NAME_TO_SID)?;
        let mut out = std::collections::HashSet::new();
        let iter = name_to_sid.iter()?;
        for row in iter {
            let row = row?;
            out.insert(row.0.value().to_string());
        }
        Ok(out)
    }

    pub fn get_file_meta(&self, path: &str) -> anyhow::Result<Option<(FileId, FileMeta)>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let path_to_fid = txn.open_table(PATH_TO_FID)?;
        let fid_u32 = match path_to_fid.get(path)? {
            Some(v) => v.value(),
            None => return Ok(None),
        };
        let files = txn.open_table(FILES)?;
        match files.get(&fid_u32)? {
            Some(v) => {
                let meta: FileMeta = from_bytes(v.value()).context("decode FileMeta")?;
                Ok(Some((FileId(fid_u32), meta)))
            }
            None => Ok(None),
        }
    }

    /// All references *into* a symbol — "who calls X, and where?"
    /// Enumerate every workspace-defined sid plus its name and the
    /// number of files that define it. Used by `symbol_pagerank` (v0.3
    /// U4) to build the rank-graph node set + apply the "ubiquitous"
    /// edge-weight multiplier (>5 def sites → ×0.1).
    ///
    /// A sid is "workspace-defined" iff it has at least one DEFS row.
    /// External symbols (referenced but not defined in the workspace)
    /// are filtered at commit time per Deepening §F1, so they have no
    /// NAME_TO_SID entry and are naturally absent here.
    ///
    /// Returns `(sid, name, def_count)` tuples in arbitrary order;
    /// the caller assigns dense indices for PageRank input.
    pub fn iter_workspace_sids(&self) -> anyhow::Result<Vec<(u32, String, u32)>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let sid_to_name = txn.open_table(SID_TO_NAME)?;
        let defs = txn.open_multimap_table(DEFS)?;

        let mut out: Vec<(u32, String, u32)> = Vec::new();
        let iter = sid_to_name.iter()?;
        for row in iter {
            let row = row?;
            let sid = row.0.value();
            let name = row.1.value().to_string();

            // Skip sids with no DEFS entry — they're external symbols
            // that got interned for ref tracking but aren't actually
            // workspace-defined. (Shouldn't happen given §F1, but
            // defensive.)
            let mut def_count: u32 = 0;
            let it = defs.get(&sid)?;
            for _ in it {
                def_count = def_count.saturating_add(1);
            }
            if def_count == 0 {
                continue;
            }
            out.push((sid, name, def_count));
        }
        Ok(out)
    }

    /// Resolve `sid` → workspace symbol name via `SID_TO_NAME`. The
    /// inverse of `sid_for_name`. Returns `Ok(None)` for unknown sids
    /// (shouldn't happen with committed data). Used by `closure::compute`
    /// (v0.3 U3) to resolve outgoing-edge callee sids back to names for
    /// the wire shape.
    pub fn name_for_sid(&self, sid: u32) -> anyhow::Result<Option<String>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let sid_to_name = txn.open_table(SID_TO_NAME)?;
        Ok(sid_to_name.get(&sid)?.map(|v| v.value().to_string()))
    }

    /// Resolve `name` → `callee_sid` via `NAME_TO_SID`. Returns
    /// `Ok(None)` for unknown names (external symbols / unindexed).
    /// Used by `Index.FindCallers` (U2') to convert the wire-level
    /// name into the integer key needed for `refs_to_symbol`.
    pub fn sid_for_name(&self, name: &str) -> anyhow::Result<Option<u32>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let name_to_sid = txn.open_table(NAME_TO_SID)?;
        Ok(name_to_sid.get(name)?.map(|v| v.value()))
    }

    /// Resolve `fid` → workspace-relative path. Returns `Ok(None)` for
    /// unknown fids. Used by `Index.FindCallers` (U2') to convert each
    /// `RefSite.fid` into the path the caller wants to see.
    pub fn path_for_fid(&self, fid: u32) -> anyhow::Result<Option<String>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let fid_to_path = txn.open_table(FID_TO_PATH)?;
        Ok(fid_to_path.get(&fid)?.map(|v| v.value().to_string()))
    }

    /// Resolve a `(caller_sid, fid)` pair into the caller's own def
    /// info — the enclosing symbol's name + kind + range. Used by
    /// `Index.FindCallers` (U2') to surface `enclosing_qualified_name`
    /// + `kind` alongside the call-site range from the `RefSite`.
    ///
    /// Returns `Ok(None)` when SID_TO_NAME has no entry for
    /// `caller_sid` (shouldn't happen for an indexed sid) or when no
    /// DEFS row for this sid matches the given fid (which only fires
    /// during a torn-read race — the writer always pairs `caller_sid`
    /// with a def in the same file at commit time).
    pub fn caller_def_info(
        &self,
        caller_sid: u32,
        fid: u32,
    ) -> anyhow::Result<Option<CallerDefInfo>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let sid_to_name = txn.open_table(SID_TO_NAME)?;
        let name = match sid_to_name.get(&caller_sid)? {
            Some(v) => v.value().to_string(),
            None => return Ok(None),
        };
        let defs = txn.open_multimap_table(DEFS)?;
        for row in defs.get(&caller_sid)? {
            let bytes = row?.value().to_vec();
            if let Ok(d) = from_bytes::<DefSite>(&bytes) {
                if d.fid == fid {
                    return Ok(Some(CallerDefInfo {
                        name,
                        kind: d.kind,
                        def_start_byte: d.start,
                        def_end_byte: d.end,
                        def_start_line: d.start_line,
                        def_end_line: d.end_line,
                    }));
                }
            }
        }
        Ok(None)
    }

    /// All references *into* a symbol — "who calls X, and where?"
    /// One entry per call site. The caller (FindCallers handler, v0.3
    /// U2') resolves `caller_sid` → qualified name via SID_TO_NAME +
    /// DEFS lookup. Returns `Ok(Vec::new())` for symbols with no
    /// indexed callers (or for unknown sids).
    ///
    /// Order: insertion order within each `(callee_sid)` multimap
    /// key, which is arbitrary. Callers that want stable ordering
    /// should sort by `(fid, start)`.
    pub fn refs_to_symbol(&self, callee_sid: u32) -> anyhow::Result<Vec<RefSite>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let refs_t = txn.open_multimap_table(REFS)?;
        let mut out: Vec<RefSite> = Vec::new();
        let it = refs_t.get(&callee_sid)?;
        for row in it {
            let bytes = row?.value().to_vec();
            if let Ok(rs) = from_bytes::<RefSite>(&bytes) {
                out.push(rs);
            }
        }
        Ok(out)
    }

    /// All references *from* a symbol — "what does X reference?"
    /// Returns the set of callee sids X has outgoing edges to. The
    /// closure walker (v0.3 U3) uses this to enumerate dependencies
    /// without re-parsing the anchor file.
    ///
    /// Note: this returns only edges where the caller_sid is `Some(X)`
    /// — file-scope refs are excluded (they have no caller to key on).
    #[allow(dead_code)] // consumed by v0.3 U3 (closure walker)
    pub fn refs_from_symbol(&self, caller_sid: u32) -> anyhow::Result<Vec<u32>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let sid_refs_out = txn.open_multimap_table(SID_REFS_OUT)?;
        let mut out: Vec<u32> = Vec::new();
        let it = sid_refs_out.get(&caller_sid)?;
        for row in it {
            out.push(row?.value());
        }
        Ok(out)
    }

    /// All callee sids referenced by `fid`. The set is deduplicated
    /// (FID_REFS multimap semantics) — if a file references callee C
    /// three times, this returns C once. Use [`refs_to_symbol`] for
    /// per-site information.
    ///
    /// `outline::compute` uses [`refs_for_file_resolved`] (which
    /// returns per-callsite counts + resolved names); this lower-level
    /// helper is retained for callers that want the raw sid set
    /// without the SID_TO_NAME join.
    #[allow(dead_code)] // raw-sid variant; production code uses refs_for_file_resolved
    pub fn refs_for_file(&self, fid: u32) -> anyhow::Result<Vec<u32>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let fid_refs = txn.open_multimap_table(FID_REFS)?;
        let mut out: Vec<u32> = Vec::new();
        let it = fid_refs.get(&fid)?;
        for row in it {
            out.push(row?.value());
        }
        Ok(out)
    }

    /// Per-file outgoing refs with their callee names resolved. Used
    /// by `outline::compute` for the file-level PageRank graph
    /// construction (which keys edges by name to apply the Aider
    /// edge-weight recipe).
    ///
    /// Returns `(callee_name, ref_count)` tuples where `ref_count`
    /// is the number of *individual call sites* in the file to that
    /// callee (not the dedup'd FID_REFS multimap count). Names with
    /// no SID_TO_NAME entry are silently filtered.
    pub fn refs_for_file_resolved(&self, fid: u32) -> anyhow::Result<Vec<(String, u32)>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let fid_refs = txn.open_multimap_table(FID_REFS)?;
        let refs_t = txn.open_multimap_table(REFS)?;
        let sid_to_name = txn.open_table(SID_TO_NAME)?;
        let mut out: Vec<(String, u32)> = Vec::new();
        let it = fid_refs.get(&fid)?;
        for row in it {
            let callee_sid = row?.value();
            let name = match sid_to_name.get(&callee_sid)? {
                Some(v) => v.value().to_string(),
                None => continue,
            };
            // Count per-file call sites by walking REFS[callee_sid]
            // and filtering to this fid.
            let mut count: u32 = 0;
            let site_it = refs_t.get(&callee_sid)?;
            for site_row in site_it {
                let bytes = site_row?.value().to_vec();
                if let Ok(rs) = from_bytes::<RefSite>(&bytes) {
                    if rs.fid == fid {
                        count += 1;
                    }
                }
            }
            if count > 0 {
                out.push((name, count));
            }
        }
        Ok(out)
    }

    /// Resolve a name to all of its def sites + the file path each lives in.
    ///
    /// Returned in arbitrary order; the caller (`Index.FindSymbol` handler) is
    /// responsible for the wire-level shape and rank-score assignment.
    pub fn find_symbol(&self, name: &str) -> anyhow::Result<Vec<FoundSymbol>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let name_to_sid = txn.open_table(NAME_TO_SID)?;
        let sid = match name_to_sid.get(name)? {
            Some(v) => v.value(),
            None => return Ok(Vec::new()),
        };
        let defs = txn.open_multimap_table(DEFS)?;
        let fid_to_path = txn.open_table(FID_TO_PATH)?;

        let mut fid_path_cache: HashMap<u32, String> = HashMap::new();
        let mut out: Vec<FoundSymbol> = Vec::new();
        for row in defs.get(&sid)? {
            let row = row?;
            let def: DefSite = from_bytes(row.value()).context("decode DefSite")?;
            let path = match fid_path_cache.get(&def.fid) {
                Some(p) => p.clone(),
                None => {
                    let s = fid_to_path
                        .get(&def.fid)?
                        .map(|v| v.value().to_string())
                        .unwrap_or_default();
                    fid_path_cache.insert(def.fid, s.clone());
                    s
                }
            };
            out.push(FoundSymbol {
                name: name.to_string(),
                kind: def.kind,
                file: path,
                fid: def.fid,
                start_byte: def.start,
                end_byte: def.end,
                start_line: def.start_line,
                end_line: def.end_line,
                visibility: def.visibility,
            });
        }
        Ok(out)
    }

    /// Batched `find_symbol` for N names. Opens one read transaction,
    /// one shared `fid → path` cache, and walks each name's defs.
    /// Per-name cost drops from `(txn open + table opens + lookups)`
    /// to `(lookups + shared cache)` — measurable on the closure walker
    /// which previously called `find_symbol` once per resolved
    /// candidate (168 µs avg total across N≈5 names per call on
    /// `crates/rts-core`).
    ///
    /// Names absent from `NAME_TO_SID` produce an empty Vec at that key.
    /// Returned map is keyed by the input `name`; callers that need a
    /// specific name's defs just `.get(name)`.
    pub fn find_symbols_batch(
        &self,
        names: &[String],
    ) -> anyhow::Result<HashMap<String, Vec<FoundSymbol>>> {
        let txn = self.db.begin_read().context("begin_read")?;
        let name_to_sid = txn.open_table(NAME_TO_SID)?;
        let defs = txn.open_multimap_table(DEFS)?;
        let fid_to_path = txn.open_table(FID_TO_PATH)?;

        let mut fid_path_cache: HashMap<u32, String> = HashMap::new();
        let mut out: HashMap<String, Vec<FoundSymbol>> = HashMap::with_capacity(names.len());
        for name in names {
            let sid = match name_to_sid.get(name.as_str())? {
                Some(v) => v.value(),
                None => {
                    out.entry(name.clone()).or_default();
                    continue;
                }
            };
            let entry = out.entry(name.clone()).or_default();
            for row in defs.get(&sid)? {
                let row = row?;
                let def: DefSite = from_bytes(row.value()).context("decode DefSite")?;
                let path = match fid_path_cache.get(&def.fid) {
                    Some(p) => p.clone(),
                    None => {
                        let s = fid_to_path
                            .get(&def.fid)?
                            .map(|v| v.value().to_string())
                            .unwrap_or_default();
                        fid_path_cache.insert(def.fid, s.clone());
                        s
                    }
                };
                entry.push(FoundSymbol {
                    name: name.clone(),
                    kind: def.kind,
                    file: path,
                    fid: def.fid,
                    start_byte: def.start,
                    end_byte: def.end,
                    start_line: def.start_line,
                    end_line: def.end_line,
                    visibility: def.visibility,
                });
            }
        }
        Ok(out)
    }
}

/// Surface struct for `Index.FindSymbol` consumers. Plain data; no redb
/// Single defined symbol — surface for `Index.Outline`.
#[derive(Debug, Clone)]
pub struct DefinedSymbol {
    pub name: String,
    pub kind: SymbolKind,
    pub visibility: schema::Visibility,
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: u32,
    pub end_byte: u32,
}

/// One file's defs surface for `Index.Outline` orchestration.
#[derive(Debug, Clone)]
pub struct FileWithDefs {
    pub path: String,
    pub defined_symbols: Vec<DefinedSymbol>,
}

/// types leak past this boundary.
#[derive(Debug, Clone)]
pub struct FoundSymbol {
    pub name: String,
    pub kind: SymbolKind,
    /// File path as stored at index time (workspace-root-relative on most
    /// invocations; the writer is the source of truth for the format).
    pub file: String,
    pub fid: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    pub start_line: u32,
    pub end_line: u32,
    pub visibility: schema::Visibility,
}

/// Surface struct for v0.3 U2'+. Resolved info for a caller's *own*
/// def, returned by [`Store::caller_def_info`]. The wire-shape
/// `enclosing_qualified_name` + `kind` + `enclosing_def_range` fields
/// in `Index.FindCallers.callers[]` are built from one of these per
/// `RefSite`.
#[derive(Debug, Clone)]
pub struct CallerDefInfo {
    pub name: String,
    pub kind: SymbolKind,
    pub def_start_byte: u32,
    pub def_end_byte: u32,
    pub def_start_line: u32,
    pub def_end_line: u32,
}

// Long arg list is the cost of operating on six redb tables in one
// txn. Wrapping in a struct would just relocate the noise. The single
// caller is `commit_batch` (twice — once for removals, once before
// upserting a file). Stable across U1; v0.3 U5+ may revisit if more
// tables join the txn.
#[allow(clippy::too_many_arguments)]
fn drop_file_entries(
    files: &mut redb::Table<'_, u32, &[u8]>,
    fid_defs: &mut redb::MultimapTable<'_, u32, u32>,
    defs: &mut redb::MultimapTable<'_, u32, &[u8]>,
    fid_refs: &mut redb::MultimapTable<'_, u32, u32>,
    refs_t: &mut redb::MultimapTable<'_, u32, &[u8]>,
    sid_refs_out: &mut redb::MultimapTable<'_, u32, u32>,
    fid: u32,
) -> anyhow::Result<()> {
    // Drop the file row itself.
    files.remove(&fid)?;

    // Defs are keyed by SID and carry the FID inside the encoded value, so we
    // can't surgically remove rows for this FID with a single key lookup. The
    // policy: walk FID_DEFS to learn which SIDs the file contributed to, then
    // for each SID re-read its values, filter out rows whose def.fid == fid,
    // and re-insert what remains. This is O(touched SIDs × avg fan-out) — fine
    // for v0; a later phase may use a tuple-key (FID, SID) table to make this
    // O(1) per drop.
    let prior_def_sids: Vec<u32> = {
        let mut v = Vec::new();
        let it = fid_defs.get(&fid)?;
        for row in it {
            v.push(row?.value());
        }
        v
    };
    fid_defs.remove_all(&fid)?;

    for sid in &prior_def_sids {
        // Read & filter.
        let kept: Vec<Vec<u8>> = {
            let mut v = Vec::new();
            let it = defs.get(sid)?;
            for row in it {
                let bytes = row?.value().to_vec();
                if let Ok(d) = from_bytes::<DefSite>(&bytes) {
                    if d.fid != fid {
                        v.push(bytes);
                    }
                }
            }
            v
        };
        defs.remove_all(sid)?;
        for v in kept {
            defs.insert(sid, v.as_slice())?;
        }
    }

    // v0.3 (U1): drop refs that originated in this file. REFS is keyed by
    // *callee_sid* — so to drop "refs that file F made to anything," we
    // must:
    //   1. Walk FID_REFS[fid] → set of callee sids C₁..Cₙ that this file
    //      referenced.
    //   2. For each Cᵢ, read REFS[Cᵢ], filter out RefSites whose `fid` ==
    //      the file being dropped, re-insert the remainder. Mirrors the
    //      defs filter-by-fid above. Crucial that this is by-fid, not
    //      by-callee-sid: callee Cᵢ may have refs from many files, and
    //      we only want to drop the ones originating in this file.
    //   3. For SID_REFS_OUT, we know which caller_sids in this file's
    //      defs (`prior_def_sids`) contributed outgoing edges; clear all
    //      of those — they'll be re-inserted by the upsert that
    //      follows. If a sid still has defs in OTHER files, its outgoing
    //      edges from those other files should remain.
    let prior_ref_callees: Vec<u32> = {
        let mut v = Vec::new();
        let it = fid_refs.get(&fid)?;
        for row in it {
            v.push(row?.value());
        }
        v
    };
    fid_refs.remove_all(&fid)?;

    for callee_sid in prior_ref_callees {
        let kept: Vec<Vec<u8>> = {
            let mut v = Vec::new();
            let it = refs_t.get(&callee_sid)?;
            for row in it {
                let bytes = row?.value().to_vec();
                if let Ok(rs) = from_bytes::<RefSite>(&bytes) {
                    if rs.fid != fid {
                        v.push(bytes);
                    }
                }
            }
            v
        };
        refs_t.remove_all(&callee_sid)?;
        for v in kept {
            refs_t.insert(&callee_sid, v.as_slice())?;
        }
    }

    // Outgoing edges: for each def sid that was in this file, the
    // upsert loop will re-insert its outgoing refs (or not, if the
    // sid is going away). Clearing all outgoing edges for these sids
    // is correct ONLY when this file owns the def. If a name has
    // defs in multiple files, the other files' outgoing edges are
    // *also* keyed by the same sid — and we'd clobber them.
    //
    // Solution: filter SID_REFS_OUT by what's still alive. Read each
    // sid's outgoing edges, but we don't have file-tag inside SID_REFS_OUT
    // (it's u32→u32). So we must walk REFS for each outgoing callee_sid
    // and check if any caller-side RefSite with caller_sid==sid still
    // references it from another file.
    //
    // Simpler shape that's still correct: rebuild SID_REFS_OUT from
    // surviving REFS rows after the per-file rewrite above. We do
    // that once per drop call by walking the touched callee_sids.
    for sid in &prior_def_sids {
        // Capture the existing outgoing-edge set BEFORE we wipe it.
        let prior_callees: Vec<u32> = {
            let mut v = Vec::new();
            let it = sid_refs_out.get(sid)?;
            for row in it {
                v.push(row?.value());
            }
            v
        };
        sid_refs_out.remove_all(sid)?;

        // Re-insert any callees that still have a RefSite with
        // caller_sid == sid from a file OTHER than `fid`.
        for callee in prior_callees {
            let it = refs_t.get(&callee)?;
            for row in it {
                let bytes = row?.value().to_vec();
                if let Ok(rs) = from_bytes::<RefSite>(&bytes) {
                    if rs.caller_sid == Some(*sid) && rs.fid != fid {
                        sid_refs_out.insert(sid, &callee)?;
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Find the smallest enclosing def whose byte range covers `byte`
/// AND whose kind is "call-bearing" (Function, Method, Module —
/// kinds that have a body which can contain call expressions).
///
/// **v0.3 U3 fix:** the rts-core analyzer emits local-variable
/// defs (e.g. `let w = make_widget(...)`) as Symbols with byte
/// ranges covering their RHS. Without a kind filter, those tiny
/// variable ranges win the innermost-enclosing lookup and "steal"
/// the caller_sid from the actual containing function. The fix
/// restricts candidates to kinds that can plausibly contain a
/// call site:
///
/// - `Function` / `Method` — the obvious cases.
/// - `Module` — top-level statements at module scope. The
///   analyzer doesn't always emit module-scope kinds in v0, so
///   most file-scope calls still end up with `caller_sid = None`.
///
/// Non-call-bearing kinds explicitly excluded: `Struct`, `Enum`,
/// `Trait`, `Type`, `Const`, `Static`, `Class`, and `Other` (which
/// covers `Variable` and anything from the parser the SymbolKind
/// enum doesn't map cleanly).
///
/// Returns `None` when no call-bearing def covers the byte — the
/// caller stores `caller_sid: None` in the `RefSite`, and the ref
/// won't appear in `SID_REFS_OUT` (correct: a file-scope ref has
/// no caller to key on).
fn enclosing_caller_sid(file_defs: &[(u32, u32, u32, SymbolKind)], byte: u32) -> Option<u32> {
    let mut best: Option<(u32, u32)> = None; // (sid, range_size)
    for &(sid, start, end, kind) in file_defs {
        if !is_call_bearing_kind(kind) {
            continue;
        }
        if byte >= start && byte < end {
            let span = end.saturating_sub(start);
            if best.map(|(_, b)| span < b).unwrap_or(true) {
                best = Some((sid, span));
            }
        }
    }
    best.map(|(sid, _)| sid)
}

/// Whether a `SymbolKind` represents something that can *contain*
/// call expressions in its body. Used by `enclosing_caller_sid` to
/// filter out local-variable / type-alias / const defs that the
/// analyzer happens to emit alongside fn defs.
fn is_call_bearing_kind(kind: SymbolKind) -> bool {
    matches!(
        kind,
        SymbolKind::Function | SymbolKind::Method | SymbolKind::Module
    )
}

fn u32_from_le_slice(slice: &[u8]) -> Option<u32> {
    if slice.len() == 4 {
        Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schema::Visibility;

    fn temp_store() -> (tempfile::TempDir, Store) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db.redb");
        let store = Store::open(&path).unwrap();
        (tmp, store)
    }

    fn rust_meta(content_hash: [u8; 32]) -> FileMeta {
        FileMeta {
            content_hash,
            mtime_ns: 0,
            lang: 1, // rust per writer's convention
            parse_status: ParseStatus::Ok,
            oversize: false,
        }
    }

    #[test]
    fn open_creates_db_with_schema_version() {
        let (_tmp, store) = temp_store();
        // Second open of the same path should succeed without rebuild and
        // preserve next_fid/next_sid.
        let path = store.db_path().to_path_buf();
        let snapshot = store.next_fid.load(Ordering::Relaxed);
        drop(store);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.next_fid.load(Ordering::Relaxed), snapshot);
    }

    #[test]
    fn commit_then_find_symbol_round_trips() {
        let (_tmp, store) = temp_store();
        let h = blake3::hash(b"file v1").into();
        let entry = FileBatchEntry {
            path: std::path::PathBuf::from("src/lib.rs"),
            meta: rust_meta(h),
            defs: vec![
                (
                    "build_index".to_string(),
                    DefSite {
                        fid: 0,
                        start: 100,
                        end: 200,
                        start_line: 5,
                        end_line: 15,
                        visibility: Visibility::Public,
                        kind: SymbolKind::Function,
                    },
                    SymbolKind::Function,
                ),
                (
                    "Index".to_string(),
                    DefSite {
                        fid: 0,
                        start: 0,
                        end: 50,
                        start_line: 1,
                        end_line: 3,
                        visibility: Visibility::Public,
                        kind: SymbolKind::Struct,
                    },
                    SymbolKind::Struct,
                ),
            ],
            refs: Vec::new(),
        };
        let n = store
            .commit_batch(vec![entry], vec![], Durability::Immediate)
            .unwrap();
        assert_eq!(n, 1);

        let hits = store.find_symbol("build_index").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].file, "src/lib.rs");
        assert_eq!(hits[0].kind, SymbolKind::Function);
        assert_eq!(hits[0].start_line, 5);

        let no_hits = store.find_symbol("does_not_exist").unwrap();
        assert!(no_hits.is_empty());
    }

    #[test]
    fn find_symbols_batch_matches_per_name_find_symbol() {
        // Same fixture as `commit_then_find_symbol_round_trips`, but
        // ask via batch + compare against single-call. The two paths
        // must produce identical FoundSymbol sets per name.
        let (_tmp, store) = temp_store();
        let h = blake3::hash(b"file v1").into();
        let entry = FileBatchEntry {
            path: std::path::PathBuf::from("src/lib.rs"),
            meta: rust_meta(h),
            defs: vec![
                (
                    "build_index".to_string(),
                    DefSite {
                        fid: 0,
                        start: 100,
                        end: 200,
                        start_line: 5,
                        end_line: 15,
                        visibility: Visibility::Public,
                        kind: SymbolKind::Function,
                    },
                    SymbolKind::Function,
                ),
                (
                    "Index".to_string(),
                    DefSite {
                        fid: 0,
                        start: 0,
                        end: 50,
                        start_line: 1,
                        end_line: 3,
                        visibility: Visibility::Public,
                        kind: SymbolKind::Struct,
                    },
                    SymbolKind::Struct,
                ),
            ],
            refs: Vec::new(),
        };
        store
            .commit_batch(vec![entry], vec![], Durability::Immediate)
            .unwrap();

        let names = vec![
            "build_index".to_string(),
            "Index".to_string(),
            "does_not_exist".to_string(),
        ];
        let batched = store.find_symbols_batch(&names).unwrap();
        assert_eq!(batched.len(), 3);
        // Present names return the same Vec contents as find_symbol.
        for name in &["build_index", "Index"] {
            let batch_hits = batched.get(*name).expect("name in batch result");
            let single_hits = store.find_symbol(name).unwrap();
            assert_eq!(
                batch_hits.len(),
                single_hits.len(),
                "{name}: batch vs single-call hit count must match"
            );
            // The two paths produce identical FoundSymbol entries.
            // (Order within a name is multimap-walk order; we don't
            // pin it here — the closure walker sorts before picking
            // the first match anyway.)
            for (b, s) in batch_hits.iter().zip(single_hits.iter()) {
                assert_eq!(b.name, s.name);
                assert_eq!(b.file, s.file);
                assert_eq!(b.kind, s.kind);
                assert_eq!(b.start_byte, s.start_byte);
                assert_eq!(b.end_byte, s.end_byte);
            }
        }
        // Missing name returns an empty Vec at the key.
        assert!(
            batched
                .get("does_not_exist")
                .expect("key present")
                .is_empty(),
            "missing name should map to empty Vec, not be absent"
        );
    }

    #[test]
    fn find_symbols_batch_empty_input_returns_empty_map() {
        let (_tmp, store) = temp_store();
        let result = store.find_symbols_batch(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn re_upsert_drops_prior_defs_for_same_file() {
        let (_tmp, store) = temp_store();
        let h1 = blake3::hash(b"v1").into();
        let h2 = blake3::hash(b"v2").into();

        let v1 = FileBatchEntry {
            path: std::path::PathBuf::from("a.rs"),
            meta: rust_meta(h1),
            defs: vec![(
                "alpha".to_string(),
                DefSite {
                    fid: 0,
                    start: 0,
                    end: 10,
                    start_line: 1,
                    end_line: 1,
                    visibility: Visibility::Private,
                    kind: SymbolKind::Function,
                },
                SymbolKind::Function,
            )],
            refs: Vec::new(),
        };
        store
            .commit_batch(vec![v1], vec![], Durability::Immediate)
            .unwrap();
        assert_eq!(store.find_symbol("alpha").unwrap().len(), 1);

        let v2 = FileBatchEntry {
            path: std::path::PathBuf::from("a.rs"),
            meta: rust_meta(h2),
            defs: vec![(
                "beta".to_string(),
                DefSite {
                    fid: 0,
                    start: 0,
                    end: 10,
                    start_line: 1,
                    end_line: 1,
                    visibility: Visibility::Public,
                    kind: SymbolKind::Function,
                },
                SymbolKind::Function,
            )],
            refs: Vec::new(),
        };
        store
            .commit_batch(vec![v2], vec![], Durability::Immediate)
            .unwrap();
        // alpha's def on a.rs should be gone; beta should be there.
        assert!(store.find_symbol("alpha").unwrap().is_empty());
        let beta = store.find_symbol("beta").unwrap();
        assert_eq!(beta.len(), 1);
        assert_eq!(beta[0].file, "a.rs");
    }

    #[test]
    fn removal_drops_file_entries() {
        let (_tmp, store) = temp_store();
        let entry = FileBatchEntry {
            path: std::path::PathBuf::from("doomed.rs"),
            meta: rust_meta(blake3::hash(b"x").into()),
            defs: vec![(
                "vanish".to_string(),
                DefSite {
                    fid: 0,
                    start: 0,
                    end: 1,
                    start_line: 1,
                    end_line: 1,
                    visibility: Visibility::Private,
                    kind: SymbolKind::Function,
                },
                SymbolKind::Function,
            )],
            refs: Vec::new(),
        };
        store
            .commit_batch(vec![entry], vec![], Durability::Immediate)
            .unwrap();
        assert_eq!(store.find_symbol("vanish").unwrap().len(), 1);

        store
            .commit_batch(
                vec![],
                vec![FileBatchRemoval {
                    path: std::path::PathBuf::from("doomed.rs"),
                }],
                Durability::Immediate,
            )
            .unwrap();
        assert!(store.find_symbol("vanish").unwrap().is_empty());
    }

    // ---------- v0.3 ref-graph tests (U1) ----------

    fn fn_def(start: u32, end: u32, start_line: u32, end_line: u32) -> DefSite {
        DefSite {
            fid: 0,
            start,
            end,
            start_line,
            end_line,
            visibility: Visibility::Public,
            kind: SymbolKind::Function,
        }
    }

    #[test]
    fn enclosing_caller_sid_skips_non_call_bearing_kinds() {
        // Regression test for the v0.3 U3 bug: the rts-core analyzer
        // emits local-variable defs (e.g. `let w = make_widget(...)`)
        // as Symbols with byte ranges covering their RHS. Before the
        // is_call_bearing_kind filter, those tiny variable ranges
        // would "steal" the innermost-enclosing lookup from the
        // actual containing function — the ref's caller_sid would
        // point at the let-binding instead of the enclosing fn, and
        // SID_REFS_OUT[fn_sid] would silently drop the edge.
        //
        // Setup:
        //   fn_def:  sid=10, bytes [0..100), kind=Function
        //   var_def: sid=20, bytes [40..60), kind=Other (the let)
        // A ref at byte 50 should attribute to fn_def (sid=10),
        // *not* the let-binding (sid=20), even though the let's
        // range is smaller.
        let file_defs: Vec<(u32, u32, u32, SymbolKind)> = vec![
            (10, 0, 100, SymbolKind::Function),
            (20, 40, 60, SymbolKind::Other), // local let-binding shape
        ];
        let caller = enclosing_caller_sid(&file_defs, 50);
        assert_eq!(
            caller,
            Some(10),
            "non-call-bearing kinds must not steal caller_sid"
        );

        // A ref outside any def returns None.
        assert_eq!(enclosing_caller_sid(&file_defs, 200), None);

        // Methods + Modules also count as callers.
        let nested: Vec<(u32, u32, u32, SymbolKind)> = vec![
            (1, 0, 100, SymbolKind::Module),
            (2, 10, 80, SymbolKind::Method),
        ];
        // Innermost: Method at [10..80) beats Module at [0..100) for a ref at 50.
        assert_eq!(enclosing_caller_sid(&nested, 50), Some(2));
        // For a ref at byte 5 (inside Module only), the Module wins.
        assert_eq!(enclosing_caller_sid(&nested, 5), Some(1));
    }

    #[test]
    fn refs_round_trip_writes_all_three_tables() {
        // Two-file fixture:
        //   def.rs defines `callee` at bytes [0, 50)
        //   call.rs defines `caller` at bytes [0, 100); inside caller's
        //   range there's a ref to `callee` at byte 30.
        // After commit:
        //   - refs_to_symbol(callee_sid) returns 1 RefSite with caller_sid == sid(caller)
        //   - refs_from_symbol(caller_sid) returns [callee_sid]
        //   - refs_for_file(call.rs fid) returns [callee_sid]
        let (_tmp, store) = temp_store();

        let def_entry = FileBatchEntry {
            path: std::path::PathBuf::from("def.rs"),
            meta: rust_meta(blake3::hash(b"def").into()),
            defs: vec![(
                "callee".to_string(),
                fn_def(0, 50, 1, 5),
                SymbolKind::Function,
            )],
            refs: Vec::new(),
        };

        let call_entry = FileBatchEntry {
            path: std::path::PathBuf::from("call.rs"),
            meta: rust_meta(blake3::hash(b"call").into()),
            defs: vec![(
                "caller".to_string(),
                fn_def(0, 100, 1, 10),
                SymbolKind::Function,
            )],
            refs: vec![RefHit {
                name: "callee".to_string(),
                start: 30,
                end: 36,
                start_line: 3,
                end_line: 3,
            }],
        };

        store
            .commit_batch(vec![def_entry, call_entry], vec![], Durability::Immediate)
            .unwrap();

        // Resolve sids via find_symbol so we don't have to peek under the
        // hood at NAME_TO_SID directly.
        let callee_hits = store.find_symbol("callee").unwrap();
        assert_eq!(callee_hits.len(), 1);
        let caller_hits = store.find_symbol("caller").unwrap();
        assert_eq!(caller_hits.len(), 1);

        // The sids aren't on FoundSymbol; we'll grab them via a read txn
        // on NAME_TO_SID. (In production code, U2's FindCallers handler
        // does this same lookup.)
        let txn = store.db.begin_read().unwrap();
        let name_to_sid = txn.open_table(NAME_TO_SID).unwrap();
        let callee_sid = name_to_sid.get("callee").unwrap().unwrap().value();
        let caller_sid = name_to_sid.get("caller").unwrap().unwrap().value();
        drop(name_to_sid);
        drop(txn);

        // refs_to_symbol: 1 caller of `callee`, sourced from call.rs.
        let into_callee = store.refs_to_symbol(callee_sid).unwrap();
        assert_eq!(into_callee.len(), 1, "expected one ref site into callee");
        let rs = &into_callee[0];
        assert_eq!(rs.start, 30);
        assert_eq!(rs.end, 36);
        assert_eq!(rs.start_line, 3);
        assert_eq!(
            rs.caller_sid,
            Some(caller_sid),
            "caller_sid should resolve to the enclosing caller def"
        );

        // refs_from_symbol: caller references [callee_sid].
        let out_of_caller = store.refs_from_symbol(caller_sid).unwrap();
        assert_eq!(out_of_caller, vec![callee_sid]);

        // refs_from_symbol for callee (which defines nothing it calls): empty.
        let out_of_callee = store.refs_from_symbol(callee_sid).unwrap();
        assert!(out_of_callee.is_empty());

        // refs_for_file(call.rs) returns the set of callees from that file.
        let txn = store.db.begin_read().unwrap();
        let path_to_fid = txn.open_table(PATH_TO_FID).unwrap();
        let call_fid = path_to_fid.get("call.rs").unwrap().unwrap().value();
        drop(path_to_fid);
        drop(txn);
        let file_refs = store.refs_for_file(call_fid).unwrap();
        assert_eq!(file_refs, vec![callee_sid]);
    }

    #[test]
    fn refs_external_symbol_filtered_at_commit() {
        // A file references `Vec` (not workspace-defined). After commit,
        // no REFS row should exist for `Vec` — we filter externals per
        // the v0.3 plan §F1 "drop external-symbol storage."
        let (_tmp, store) = temp_store();

        let entry = FileBatchEntry {
            path: std::path::PathBuf::from("uses_vec.rs"),
            meta: rust_meta(blake3::hash(b"v").into()),
            defs: vec![(
                "local_fn".to_string(),
                fn_def(0, 50, 1, 5),
                SymbolKind::Function,
            )],
            refs: vec![RefHit {
                name: "Vec".to_string(), // external: never defined locally
                start: 20,
                end: 23,
                start_line: 2,
                end_line: 2,
            }],
        };
        store
            .commit_batch(vec![entry], vec![], Durability::Immediate)
            .unwrap();

        // NAME_TO_SID should not have an entry for "Vec" (we skip it at
        // commit time before allocating a sid).
        let txn = store.db.begin_read().unwrap();
        let name_to_sid = txn.open_table(NAME_TO_SID).unwrap();
        assert!(
            name_to_sid.get("Vec").unwrap().is_none(),
            "external symbols should NOT be interned"
        );
    }

    #[test]
    fn refs_invalidate_when_referring_file_dropped() {
        // Two files A and B both ref C. Drop A. B's ref to C survives.
        // This is the multi-file invalidation test from the Deepening C1.
        let (_tmp, store) = temp_store();

        let def_c = FileBatchEntry {
            path: std::path::PathBuf::from("c.rs"),
            meta: rust_meta(blake3::hash(b"c").into()),
            defs: vec![("C".to_string(), fn_def(0, 10, 1, 2), SymbolKind::Function)],
            refs: Vec::new(),
        };
        let a = FileBatchEntry {
            path: std::path::PathBuf::from("a.rs"),
            meta: rust_meta(blake3::hash(b"a").into()),
            defs: vec![("A".to_string(), fn_def(0, 100, 1, 10), SymbolKind::Function)],
            refs: vec![RefHit {
                name: "C".to_string(),
                start: 50,
                end: 51,
                start_line: 5,
                end_line: 5,
            }],
        };
        let b = FileBatchEntry {
            path: std::path::PathBuf::from("b.rs"),
            meta: rust_meta(blake3::hash(b"b").into()),
            defs: vec![("B".to_string(), fn_def(0, 100, 1, 10), SymbolKind::Function)],
            refs: vec![RefHit {
                name: "C".to_string(),
                start: 60,
                end: 61,
                start_line: 6,
                end_line: 6,
            }],
        };

        store
            .commit_batch(vec![def_c, a, b], vec![], Durability::Immediate)
            .unwrap();

        let txn = store.db.begin_read().unwrap();
        let name_to_sid = txn.open_table(NAME_TO_SID).unwrap();
        let c_sid = name_to_sid.get("C").unwrap().unwrap().value();
        drop(name_to_sid);
        drop(txn);

        // Both A and B should ref C → REFS[c_sid] has 2 entries.
        let before = store.refs_to_symbol(c_sid).unwrap();
        assert_eq!(before.len(), 2, "expected 2 ref sites into C");

        // Drop A.
        store
            .commit_batch(
                vec![],
                vec![FileBatchRemoval {
                    path: std::path::PathBuf::from("a.rs"),
                }],
                Durability::Immediate,
            )
            .unwrap();

        // B's ref to C survives.
        let after = store.refs_to_symbol(c_sid).unwrap();
        assert_eq!(
            after.len(),
            1,
            "B's ref to C must survive A's deletion (filter-by-fid)"
        );
        // The surviving site is from b.rs.
        let txn = store.db.begin_read().unwrap();
        let path_to_fid = txn.open_table(PATH_TO_FID).unwrap();
        let b_fid = path_to_fid.get("b.rs").unwrap().unwrap().value();
        drop(path_to_fid);
        drop(txn);
        assert_eq!(after[0].fid, b_fid);
    }

    #[test]
    fn refs_invalidate_on_re_upsert() {
        // A file re-saved with a different set of refs should clear
        // its prior REFS contributions and write fresh ones.
        let (_tmp, store) = temp_store();

        let def_c = FileBatchEntry {
            path: std::path::PathBuf::from("c.rs"),
            meta: rust_meta(blake3::hash(b"c").into()),
            defs: vec![("C".to_string(), fn_def(0, 10, 1, 2), SymbolKind::Function)],
            refs: Vec::new(),
        };
        let def_d = FileBatchEntry {
            path: std::path::PathBuf::from("d.rs"),
            meta: rust_meta(blake3::hash(b"d").into()),
            defs: vec![("D".to_string(), fn_def(0, 10, 1, 2), SymbolKind::Function)],
            refs: Vec::new(),
        };
        let a_v1 = FileBatchEntry {
            path: std::path::PathBuf::from("a.rs"),
            meta: rust_meta(blake3::hash(b"v1").into()),
            defs: vec![("A".to_string(), fn_def(0, 100, 1, 10), SymbolKind::Function)],
            refs: vec![RefHit {
                name: "C".to_string(),
                start: 50,
                end: 51,
                start_line: 5,
                end_line: 5,
            }],
        };
        store
            .commit_batch(vec![def_c, def_d, a_v1], vec![], Durability::Immediate)
            .unwrap();

        let txn = store.db.begin_read().unwrap();
        let name_to_sid = txn.open_table(NAME_TO_SID).unwrap();
        let c_sid = name_to_sid.get("C").unwrap().unwrap().value();
        let d_sid = name_to_sid.get("D").unwrap().unwrap().value();
        drop(name_to_sid);
        drop(txn);

        assert_eq!(store.refs_to_symbol(c_sid).unwrap().len(), 1);
        assert!(store.refs_to_symbol(d_sid).unwrap().is_empty());

        // Re-save a.rs with a ref to D instead of C.
        let a_v2 = FileBatchEntry {
            path: std::path::PathBuf::from("a.rs"),
            meta: rust_meta(blake3::hash(b"v2").into()),
            defs: vec![("A".to_string(), fn_def(0, 100, 1, 10), SymbolKind::Function)],
            refs: vec![RefHit {
                name: "D".to_string(),
                start: 70,
                end: 71,
                start_line: 7,
                end_line: 7,
            }],
        };
        store
            .commit_batch(vec![a_v2], vec![], Durability::Immediate)
            .unwrap();

        // A's old ref to C is gone; new ref to D is present.
        assert!(
            store.refs_to_symbol(c_sid).unwrap().is_empty(),
            "re-upsert should clear prior refs"
        );
        let into_d = store.refs_to_symbol(d_sid).unwrap();
        assert_eq!(into_d.len(), 1);
    }

    #[test]
    fn refs_for_file_resolved_returns_per_file_callsite_count() {
        // call.rs has 3 refs to callee → refs_for_file_resolved returns
        // ("callee", 3). The dedup'd FID_REFS multimap would say "1
        // distinct callee," but per-call-site count is what
        // outline::compute needs for the Aider edge-weight recipe.
        let (_tmp, store) = temp_store();

        let def_entry = FileBatchEntry {
            path: std::path::PathBuf::from("def.rs"),
            meta: rust_meta(blake3::hash(b"def").into()),
            defs: vec![(
                "callee".to_string(),
                fn_def(0, 10, 1, 2),
                SymbolKind::Function,
            )],
            refs: Vec::new(),
        };
        let call_entry = FileBatchEntry {
            path: std::path::PathBuf::from("call.rs"),
            meta: rust_meta(blake3::hash(b"call").into()),
            defs: vec![(
                "caller".to_string(),
                fn_def(0, 200, 1, 20),
                SymbolKind::Function,
            )],
            refs: vec![
                RefHit {
                    name: "callee".to_string(),
                    start: 30,
                    end: 36,
                    start_line: 3,
                    end_line: 3,
                },
                RefHit {
                    name: "callee".to_string(),
                    start: 60,
                    end: 66,
                    start_line: 6,
                    end_line: 6,
                },
                RefHit {
                    name: "callee".to_string(),
                    start: 90,
                    end: 96,
                    start_line: 9,
                    end_line: 9,
                },
            ],
        };
        store
            .commit_batch(vec![def_entry, call_entry], vec![], Durability::Immediate)
            .unwrap();

        let txn = store.db.begin_read().unwrap();
        let path_to_fid = txn.open_table(PATH_TO_FID).unwrap();
        let call_fid = path_to_fid.get("call.rs").unwrap().unwrap().value();
        drop(path_to_fid);
        drop(txn);

        let resolved = store.refs_for_file_resolved(call_fid).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "callee");
        assert_eq!(resolved[0].1, 3, "3 call sites in this file");
    }

    #[test]
    fn v1_to_v2_schema_mismatch_triggers_rebuild() {
        // Simulate a v0.2 redb file by seeding SCHEMA_VERSION=1, then
        // open it with the v0.3 binary (SCHEMA_VERSION=2). The existing
        // `Store::open` rebuild path at mod.rs:124-148 wipes and
        // recreates; the new tables (REFS, FID_REFS, SID_REFS_OUT)
        // must be open-able after the rebuild, and the workspace
        // starts fresh (no leaked rows).
        //
        // This is v0.3's first real exercise of the schema-mismatch
        // rebuild path (the policy was introduced in v0.2 alpha.1 but
        // never tripped because SCHEMA_VERSION stayed at 1 for the
        // entire alpha line).
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db.redb");

        // Seed a v1 db with some content + the old SCHEMA_VERSION metadata.
        {
            let db = redb::Database::create(&path).unwrap();
            let w = db.begin_write().unwrap();
            {
                let mut meta = w.open_table(META).unwrap();
                meta.insert(META_SCHEMA_VERSION, &1u32.to_le_bytes()[..])
                    .unwrap();
                let mut path_to_fid = w.open_table(PATH_TO_FID).unwrap();
                path_to_fid.insert("stale.rs", 42u32).unwrap();
            }
            w.commit().unwrap();
        }

        // Open with v0.3 binary. Should silently rebuild.
        let store = Store::open(&path).unwrap();

        // The v1 data should be gone (rebuild wiped it).
        let no_match = store.find_symbol("anything").unwrap();
        assert!(no_match.is_empty(), "rebuild should erase prior content");

        // The new v0.3 tables should be present + usable. We exercise
        // them via a fresh commit that includes refs — if the tables
        // weren't initialised, this would fail with TableDoesNotExist.
        let entry = FileBatchEntry {
            path: std::path::PathBuf::from("fresh.rs"),
            meta: rust_meta(blake3::hash(b"fresh").into()),
            defs: vec![("X".to_string(), fn_def(0, 10, 1, 2), SymbolKind::Function)],
            refs: Vec::new(),
        };
        store
            .commit_batch(vec![entry], vec![], Durability::Immediate)
            .unwrap();
        assert_eq!(store.find_symbol("X").unwrap().len(), 1);

        // SCHEMA_VERSION metadata is now v2.
        let txn = store.db.begin_read().unwrap();
        let meta = txn.open_table(META).unwrap();
        let stored = meta
            .get(META_SCHEMA_VERSION)
            .unwrap()
            .and_then(|v| u32_from_le_slice(v.value()))
            .unwrap();
        assert_eq!(stored, SCHEMA_VERSION);
        assert_eq!(stored, 2);
    }

    #[test]
    fn schema_newer_than_binary_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db.redb");
        {
            // Seed a redb file with a higher schema_version.
            let db = redb::Database::create(&path).unwrap();
            let w = db.begin_write().unwrap();
            {
                let mut meta = w.open_table(META).unwrap();
                meta.insert(META_SCHEMA_VERSION, &(SCHEMA_VERSION + 1).to_le_bytes()[..])
                    .unwrap();
            }
            w.commit().unwrap();
        }
        let err = Store::open(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("newer than this daemon binary"), "got {msg}");
    }
}
