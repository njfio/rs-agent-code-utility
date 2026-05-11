//! P0.2 spike: redb storage smoke for the daemon's on-disk index.
//!
//! Validates the plan's proposed schema and measures:
//!  - Index build time on a synthetic ~10k-LOC fixture (~500 files × ~25 defs × ~3 refs)
//!  - On-disk size after build
//!  - Point-lookup latency, two variants:
//!      (a) open-a-new-ReadTransaction-per-query (naive)
//!      (b) reuse one long-lived ReadTransaction across many queries (perf oracle's optimization)
//!  - Single batched WriteTransaction throughput re-upserting 100 files
//!
//! The plan's S1 target is p95 warm query < 10ms end-to-end (includes MCP+socket overhead).
//! redb point-lookup alone should be well under that — sub-millisecond is the bar here.

use std::{
    hint::black_box,
    time::Instant,
};

use anyhow::{Context, Result};
use postcard::{from_bytes, to_allocvec};
use redb::{
    Database, Durability, MultimapTableDefinition, ReadableTable, ReadableMultimapTable,
    TableDefinition,
};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

// ---------- Schema (matches the plan's §Concrete redb schema) ----------

const FILES: TableDefinition<u32, &[u8]> = TableDefinition::new("files");
const PATH_TO_FID: TableDefinition<&str, u32> = TableDefinition::new("path_to_fid");
const FID_TO_PATH: TableDefinition<u32, &str> = TableDefinition::new("fid_to_path");
const NAME_TO_SID: TableDefinition<&str, u32> = TableDefinition::new("name_to_sid");
const SID_TO_NAME: TableDefinition<u32, &str> = TableDefinition::new("sid_to_name");
const DEFS: MultimapTableDefinition<u32, &[u8]> = MultimapTableDefinition::new("defs");
const REFS: MultimapTableDefinition<u32, &[u8]> = MultimapTableDefinition::new("refs");
const FID_DEFS: MultimapTableDefinition<u32, u32> = MultimapTableDefinition::new("fid_defs");
const SKELETONS: TableDefinition<u32, &[u8]> = TableDefinition::new("skeletons");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileMeta {
    content_hash: [u8; 32],
    mtime_ns: i64,
    lang: u8,
    parse_status: u8,
    oversize: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct DefSite {
    fid: u32,
    start: u32,
    end: u32,
    kind: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct RefSite {
    fid: u32,
    start: u32,
    end: u32,
}

// ---------- Synthetic corpus ----------

const NUM_FILES: u32 = 500;
const SYMS_PER_FILE: u32 = 25;
const REFS_PER_SYM: u32 = 3;

fn gen_path(fid: u32) -> String {
    let dir = fid / 50;
    format!("src/module_{dir:03}/file_{fid:04}.rs")
}

fn gen_symbol_name(fid: u32, idx: u32) -> String {
    // Mix of locally-unique and globally-shared names so we exercise multimap fanout.
    let g = match idx % 5 {
        0 => "new",
        1 => "from",
        2 => "into",
        3 => "default",
        _ => "build",
    };
    if idx % 5 == 0 {
        // Some names collide across files (multimap key with many values).
        g.to_string()
    } else {
        format!("{g}_{fid}_{idx}")
    }
}

// ---------- Build (one batched transaction over the whole corpus) ----------

fn build_index(db: &Database, durability: Durability) -> Result<BuildStats> {
    let mut total_def_rows: u64 = 0;
    let mut total_ref_rows: u64 = 0;
    let mut total_skel_bytes: u64 = 0;
    let mut unique_names: u32 = 0;

    let started = Instant::now();
    let txn = db.begin_write().context("begin_write")?;
    let mut txn = txn;
    txn.set_durability(durability);
    {
        let mut files = txn.open_table(FILES)?;
        let mut path_to_fid = txn.open_table(PATH_TO_FID)?;
        let mut fid_to_path = txn.open_table(FID_TO_PATH)?;
        let mut name_to_sid = txn.open_table(NAME_TO_SID)?;
        let mut sid_to_name = txn.open_table(SID_TO_NAME)?;
        let mut defs = txn.open_multimap_table(DEFS)?;
        let mut refs = txn.open_multimap_table(REFS)?;
        let mut fid_defs = txn.open_multimap_table(FID_DEFS)?;
        let mut skeletons = txn.open_table(SKELETONS)?;

        let mut next_sid: u32 = 1;

        for fid in 0..NUM_FILES {
            let path = gen_path(fid);
            path_to_fid.insert(path.as_str(), fid)?;
            fid_to_path.insert(fid, path.as_str())?;

            let meta = FileMeta {
                content_hash: blake3::hash(path.as_bytes()).into(),
                mtime_ns: 0,
                lang: 1, // pretend rust
                parse_status: 0,
                oversize: false,
            };
            let meta_bytes = to_allocvec(&meta)?;
            files.insert(fid, meta_bytes.as_slice())?;

            // Synthetic skeleton blob (~120 bytes per file).
            let skel = format!("// skeleton for fid={fid}\nfn placeholder() {{}}\n").into_bytes();
            total_skel_bytes += skel.len() as u64;
            skeletons.insert(fid, skel.as_slice())?;

            for idx in 0..SYMS_PER_FILE {
                let name = gen_symbol_name(fid, idx);
                let existing = name_to_sid.get(name.as_str())?.map(|v| v.value());
                let sid = match existing {
                    Some(v) => v,
                    None => {
                        let s = next_sid;
                        next_sid += 1;
                        unique_names += 1;
                        name_to_sid.insert(name.as_str(), s)?;
                        sid_to_name.insert(s, name.as_str())?;
                        s
                    }
                };

                let def = DefSite {
                    fid,
                    start: idx * 100,
                    end: idx * 100 + 80,
                    kind: 1,
                };
                let def_bytes = to_allocvec(&def)?;
                defs.insert(sid, def_bytes.as_slice())?;
                fid_defs.insert(fid, sid)?;
                total_def_rows += 1;

                for r in 0..REFS_PER_SYM {
                    let ref_site = RefSite {
                        fid: (fid + r) % NUM_FILES,
                        start: r * 50,
                        end: r * 50 + 20,
                    };
                    let rb = to_allocvec(&ref_site)?;
                    refs.insert(sid, rb.as_slice())?;
                    total_ref_rows += 1;
                }
            }
        }

        let mut meta_table = txn.open_table(META)?;
        meta_table.insert("schema_version", &1u32.to_le_bytes()[..])?;
        meta_table.insert("next_sid", &next_sid.to_le_bytes()[..])?;
    }
    txn.commit()?;
    let elapsed = started.elapsed();
    Ok(BuildStats {
        elapsed,
        total_def_rows,
        total_ref_rows,
        total_skel_bytes,
        unique_names,
    })
}

struct BuildStats {
    elapsed: std::time::Duration,
    total_def_rows: u64,
    total_ref_rows: u64,
    total_skel_bytes: u64,
    unique_names: u32,
}

// ---------- Lookup benchmarks ----------

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

/// Variant (a): open a fresh ReadTransaction every query.
fn bench_lookup_fresh_txn(db: &Database, queries: &[String], iters: usize) -> Result<Vec<u64>> {
    let mut samples = Vec::with_capacity(iters);
    for i in 0..iters {
        let name = &queries[i % queries.len()];
        let started = Instant::now();
        let txn = db.begin_read()?;
        let n2s = txn.open_table(NAME_TO_SID)?;
        let sid_handle = n2s.get(name.as_str())?;
        if let Some(sid_h) = sid_handle {
            let sid = sid_h.value();
            let defs = txn.open_multimap_table(DEFS)?;
            let mut iter = defs.get(&sid)?;
            // Drain to be fair — production code reads at least the first.
            let mut count = 0;
            while let Some(d) = iter.next() {
                let bytes = d?;
                let _: DefSite = from_bytes(bytes.value())?;
                count += 1;
                if count > 16 {
                    break;
                }
            }
            black_box(count);
        }
        samples.push(started.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    Ok(samples)
}

/// Variant (b): one ReadTransaction reused across all queries. The perf oracle's recommendation.
fn bench_lookup_shared_txn(db: &Database, queries: &[String], iters: usize) -> Result<Vec<u64>> {
    let txn = db.begin_read()?;
    let n2s = txn.open_table(NAME_TO_SID)?;
    let defs = txn.open_multimap_table(DEFS)?;

    let mut samples = Vec::with_capacity(iters);
    for i in 0..iters {
        let name = &queries[i % queries.len()];
        let started = Instant::now();
        if let Some(sid_h) = n2s.get(name.as_str())? {
            let sid = sid_h.value();
            let mut iter = defs.get(&sid)?;
            let mut count = 0;
            while let Some(d) = iter.next() {
                let bytes = d?;
                let _: DefSite = from_bytes(bytes.value())?;
                count += 1;
                if count > 16 {
                    break;
                }
            }
            black_box(count);
        }
        samples.push(started.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    Ok(samples)
}

/// Single batched WriteTransaction re-upserting 100 files (delete prior def/ref rows, re-insert).
fn bench_batched_write(db: &Database, durability: Durability) -> Result<u128> {
    let started = Instant::now();
    let txn = db.begin_write()?;
    let mut txn = txn;
    txn.set_durability(durability);
    {
        let mut files = txn.open_table(FILES)?;
        let mut defs = txn.open_multimap_table(DEFS)?;
        let mut refs = txn.open_multimap_table(REFS)?;
        let mut fid_defs = txn.open_multimap_table(FID_DEFS)?;
        let mut skeletons = txn.open_table(SKELETONS)?;

        // For 100 files, invalidate prior defs/refs via FID_DEFS lookup, then re-upsert.
        for fid in 0..100u32 {
            // Collect prior SIDs so we can drop their def/ref rows for this fid.
            let prior_sids: Vec<u32> = {
                let mut v = Vec::new();
                let mut it = fid_defs.get(&fid)?;
                while let Some(e) = it.next() {
                    v.push(e?.value());
                }
                v
            };
            for sid in &prior_sids {
                // Remove this file's def rows for sid. We don't know the exact value bytes,
                // so we remove_all by sid then re-insert all other files' defs. In production
                // the daemon stores (fid, sid) -> DefSite as the primary key instead. For the
                // smoke we approximate by simply re-inserting; the multimap will grow.
                let _ = sid;
            }
            fid_defs.remove_all(&fid)?;

            // Upsert file meta.
            let meta = FileMeta {
                content_hash: blake3::hash(format!("v2-fid-{fid}").as_bytes()).into(),
                mtime_ns: 1,
                lang: 1,
                parse_status: 0,
                oversize: false,
            };
            files.insert(fid, to_allocvec(&meta)?.as_slice())?;

            let skel = format!("// v2 skeleton fid={fid}\n").into_bytes();
            skeletons.insert(fid, skel.as_slice())?;

            for idx in 0..SYMS_PER_FILE {
                let name = gen_symbol_name(fid, idx);
                // Resolve sid via NAME_TO_SID (read+insert-if-missing inside the same txn).
                // For the smoke, assume all names already exist from the initial build.
                let n2s = txn.open_table(NAME_TO_SID)?;
                let sid = n2s.get(name.as_str())?.map(|v| v.value()).unwrap_or(0);
                drop(n2s);

                if sid != 0 {
                    let def = DefSite {
                        fid,
                        start: idx * 100,
                        end: idx * 100 + 90,
                        kind: 2,
                    };
                    defs.insert(sid, to_allocvec(&def)?.as_slice())?;
                    fid_defs.insert(fid, sid)?;
                    for r in 0..REFS_PER_SYM {
                        let rs = RefSite {
                            fid: (fid + r) % NUM_FILES,
                            start: r * 60,
                            end: r * 60 + 20,
                        };
                        refs.insert(sid, to_allocvec(&rs)?.as_slice())?;
                    }
                }
            }
        }
    }
    txn.commit()?;
    Ok(started.elapsed().as_micros())
}

fn on_disk_size(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn main() -> Result<()> {
    println!("# redb 4.x smoke — schema-shaped point-lookup + batched-write benchmark");
    println!("redb={}", redb::Database::create("/tmp/_rts_redb_version_probe").map(|_| "ok").unwrap_or("err"));
    let _ = std::fs::remove_file("/tmp/_rts_redb_version_probe");

    let tmp = TempDir::new()?;
    let db_path = tmp.path().join("smoke.redb");
    let db = Database::create(&db_path)?;

    // Build the full ~10k-LOC fixture in one transaction.
    let stats = build_index(&db, Durability::Immediate)?;
    let disk = on_disk_size(&db_path);
    println!(
        "[build] files={} unique_names={} def_rows={} ref_rows={} skel_bytes={} elapsed={:?} on_disk={:.2} MiB",
        NUM_FILES,
        stats.unique_names,
        stats.total_def_rows,
        stats.total_ref_rows,
        stats.total_skel_bytes,
        stats.elapsed,
        disk as f64 / (1024.0 * 1024.0),
    );

    // Sample 10k name queries against the index. Mix of frequent (shared) and unique names.
    let mut queries = Vec::with_capacity(10_000);
    for i in 0..10_000u32 {
        let fid = (i % NUM_FILES) as u32;
        let idx = (i / 17) % SYMS_PER_FILE;
        queries.push(gen_symbol_name(fid, idx));
    }

    // Variant (a): fresh ReadTransaction per query.
    let samples_a = bench_lookup_fresh_txn(&db, &queries, 10_000)?;
    println!(
        "[lookup-fresh-txn] n=10000 p50={}µs p95={}µs p99={}µs max={}µs",
        percentile(&samples_a, 0.50) / 1_000,
        percentile(&samples_a, 0.95) / 1_000,
        percentile(&samples_a, 0.99) / 1_000,
        samples_a.last().copied().unwrap_or(0) / 1_000,
    );
    println!(
        "[lookup-fresh-txn-ns] p50={}ns p95={}ns p99={}ns",
        percentile(&samples_a, 0.50),
        percentile(&samples_a, 0.95),
        percentile(&samples_a, 0.99),
    );

    // Variant (b): shared ReadTransaction across all queries (perf oracle's recommendation).
    let samples_b = bench_lookup_shared_txn(&db, &queries, 10_000)?;
    println!(
        "[lookup-shared-txn] n=10000 p50={}ns p95={}ns p99={}ns max={}ns",
        percentile(&samples_b, 0.50),
        percentile(&samples_b, 0.95),
        percentile(&samples_b, 0.99),
        samples_b.last().copied().unwrap_or(0),
    );

    // Batched write throughput.
    let write_us = bench_batched_write(&db, Durability::Immediate)?;
    println!("[batched-write-immediate] 100_files_one_txn={}µs ({:.2} ms)", write_us, write_us as f64 / 1000.0);

    let write_us_eventual = bench_batched_write(&db, Durability::None)?;
    println!("[batched-write-none] 100_files_one_txn={}µs ({:.2} ms)", write_us_eventual, write_us_eventual as f64 / 1000.0);

    let disk_after = on_disk_size(&db_path);
    println!("[disk] after_writes={:.2} MiB (growth: {:.2} MiB)", disk_after as f64 / (1024.0 * 1024.0), (disk_after as f64 - disk as f64) / (1024.0 * 1024.0));

    println!("DONE");
    Ok(())
}
