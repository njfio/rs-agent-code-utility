//! redb-backed on-disk index. Owns the schema and offers minimal-surface
//! read/write helpers; the writer-drain (in `writer.rs`) is the only
//! consumer of `Store::commit_batch`, and the read handlers in `methods/`
//! are the only consumers of the lookup helpers.
//!
//! Schema is per `docs/protocol-v0.md` §"Concrete redb schema" and the P0.2
//! redb-storage spike at `spikes/p0-2-redb-smoke/`.

pub mod schema;

pub use schema::{DefSite, FileId, FileMeta, ParseStatus, SymbolId, SymbolKind};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, anyhow};
use postcard::{from_bytes, to_allocvec};
use redb::{Database, Durability, ReadableMultimapTable, ReadableTable};

use schema::{
    DEFS, FILES, FID_TO_PATH, FID_DEFS, META, NAME_TO_SID, PATH_TO_FID, SID_TO_NAME,
};

/// Current on-disk schema version. Bump when any table layout or value-bytes
/// shape changes. Mismatch on open → daemon-controlled rebuild (protocol-v0
/// §15.4); a newer-than-binary schema → refusal with `SCHEMA_VERSION_NEWER`.
pub const SCHEMA_VERSION: u32 = 1;

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
            let mut meta = txn.open_table(META)?;

            // Removals first (rare relative to upserts; cheap to scan).
            for rem in &removals {
                let path_str = rem.path.to_string_lossy();
                let fid = match path_to_fid.get(path_str.as_ref())? {
                    Some(v) => v.value(),
                    None => continue,
                };
                drop_file_entries(&mut files, &mut fid_defs, &mut defs, fid)?;
                path_to_fid.remove(path_str.as_ref())?;
                fid_to_path.remove(&fid)?;
            }

            // Upserts.
            for entry in upserts {
                let path_str = entry.path.to_string_lossy().to_string();

                let existing_fid = path_to_fid
                    .get(path_str.as_str())?
                    .map(|v| v.value());
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

                // Drop prior defs for this file before re-inserting; this is the
                // simplest correct policy and avoids stale-symbol leaks.
                drop_file_entries(&mut files, &mut fid_defs, &mut defs, fid)?;

                let meta_bytes = to_allocvec(&entry.meta).context("encode FileMeta")?;
                files.insert(&fid, meta_bytes.as_slice())?;

                for (name, mut def, kind) in entry.defs {
                    let existing_sid = name_to_sid
                        .get(name.as_str())?
                        .map(|v| v.value());
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
                }

                indexed += 1;
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
}

/// Surface struct for `Index.FindSymbol` consumers. Plain data; no redb
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

fn drop_file_entries(
    files: &mut redb::Table<'_, u32, &[u8]>,
    fid_defs: &mut redb::MultimapTable<'_, u32, u32>,
    defs: &mut redb::MultimapTable<'_, u32, &[u8]>,
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
    let prior_sids: Vec<u32> = {
        let mut v = Vec::new();
        let mut it = fid_defs.get(&fid)?;
        while let Some(row) = it.next() {
            v.push(row?.value());
        }
        v
    };
    fid_defs.remove_all(&fid)?;

    for sid in prior_sids {
        // Read & filter.
        let kept: Vec<Vec<u8>> = {
            let mut v = Vec::new();
            let mut it = defs.get(&sid)?;
            while let Some(row) = it.next() {
                let bytes = row?.value().to_vec();
                if let Ok(d) = from_bytes::<DefSite>(&bytes) {
                    if d.fid != fid {
                        v.push(bytes);
                    }
                }
            }
            v
        };
        defs.remove_all(&sid)?;
        for v in kept {
            defs.insert(&sid, v.as_slice())?;
        }
    }
    Ok(())
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
                meta.insert(
                    META_SCHEMA_VERSION,
                    &(SCHEMA_VERSION + 1).to_le_bytes()[..],
                )
                .unwrap();
            }
            w.commit().unwrap();
        }
        let err = Store::open(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("newer than this daemon binary"),
            "got {msg}"
        );
    }
}
