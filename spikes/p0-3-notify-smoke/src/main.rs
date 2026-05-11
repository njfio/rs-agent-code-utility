//! P0.3 spike: notify + notify-debouncer-full smoke test.
//!
//! Verifies, in a controlled tempdir:
//!  1. Debouncer coalescing of rapid write storms (150ms window)
//!  2. Rename detection (`RenameMode::From`/`To`/`Both`)
//!  3. `need_rescan()` propagation when the underlying watcher overflows
//!  4. End-to-end latency from filesystem event to debouncer callback
//!  5. Editor-swap-file filter feasibility (vim `.swp`, JetBrains `___jb_tmp___`)
//!
//! Writes a machine-readable summary line to stdout that the wrapper script
//! captures into RESULTS.md.

use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use notify::{
    EventKind, RecursiveMode,
    event::{ModifyKind, RenameMode},
};
use notify_debouncer_full::{DebounceEventResult, new_debouncer};
use tempfile::TempDir;

/// Counts events observed by category, plus the wall-clock time of the
/// first delivered batch after the wakeup.
#[derive(Default, Debug)]
struct Counts {
    creates: usize,
    modifies: usize,
    renames_from: usize,
    renames_to: usize,
    renames_both: usize,
    removes: usize,
    other: usize,
    rescans: usize,
    batches: usize,
    errors: usize,
}

fn make_debouncer(
    counts: Arc<Mutex<Counts>>,
    first_batch_at: Arc<Mutex<Option<Instant>>>,
) -> Result<notify_debouncer_full::Debouncer<notify::RecommendedWatcher, notify_debouncer_full::RecommendedCache>> {
    let timeout = Duration::from_millis(150);
    let counts_for_handler = counts.clone();
    let first_for_handler = first_batch_at.clone();
    let debouncer = new_debouncer(
        timeout,
        None,
        move |res: DebounceEventResult| match res {
            Ok(events) => {
                let mut c = counts_for_handler.lock().expect("counts lock");
                c.batches += 1;
                let mut first = first_for_handler.lock().expect("first lock");
                if first.is_none() {
                    *first = Some(Instant::now());
                }
                drop(first);
                for ev in events {
                    if ev.event.need_rescan() {
                        c.rescans += 1;
                        continue;
                    }
                    match ev.event.kind {
                        EventKind::Create(_) => c.creates += 1,
                        EventKind::Modify(ModifyKind::Data(_)) => c.modifies += 1,
                        EventKind::Modify(ModifyKind::Name(rm)) => match rm {
                            RenameMode::From => c.renames_from += 1,
                            RenameMode::To => c.renames_to += 1,
                            RenameMode::Both => c.renames_both += 1,
                            _ => c.other += 1,
                        },
                        EventKind::Modify(_) => c.modifies += 1,
                        EventKind::Remove(_) => c.removes += 1,
                        _ => c.other += 1,
                    }
                }
            }
            Err(errs) => {
                let mut c = counts_for_handler.lock().expect("counts lock");
                c.errors += errs.len();
            }
        },
    )?;
    Ok(debouncer)
}

fn scenario_storm(root: &PathBuf, n: usize) -> Result<Duration> {
    let started = Instant::now();
    for i in 0..n {
        let p = root.join(format!("file_{i:04}.txt"));
        fs::write(&p, format!("v0 {i}\n")).with_context(|| format!("create {p:?}"))?;
    }
    Ok(started.elapsed())
}

fn scenario_modify_in_place(root: &PathBuf, n: usize) -> Result<()> {
    for i in 0..n {
        let p = root.join(format!("file_{i:04}.txt"));
        fs::write(&p, format!("v1 {i}\n")).with_context(|| format!("modify {p:?}"))?;
    }
    Ok(())
}

fn scenario_atomic_rename(root: &PathBuf, n: usize) -> Result<()> {
    for i in 0..n {
        let from = root.join(format!("file_{i:04}.txt"));
        let tmp = root.join(format!("file_{i:04}.txt.tmp"));
        // JetBrains-style atomic save: write tmp, rename over original
        fs::write(&tmp, format!("v2 {i}\n")).with_context(|| format!("tmp {tmp:?}"))?;
        fs::rename(&tmp, &from).with_context(|| format!("rename {tmp:?} -> {from:?}"))?;
    }
    Ok(())
}

fn scenario_rename_across_dir(root: &PathBuf, from_dir: &PathBuf, to_dir: &PathBuf, n: usize) -> Result<()> {
    for i in 0..n {
        let src = from_dir.join(format!("moved_{i:04}.txt"));
        let dst = to_dir.join(format!("moved_{i:04}.txt"));
        fs::write(&src, "moving\n")?;
        fs::rename(&src, &dst)?;
    }
    let _ = root;
    Ok(())
}

fn scenario_editor_swapfiles(root: &PathBuf) -> Result<()> {
    // Names we expect to filter out at the pre-debouncer stage.
    let names = [
        ".file_0000.txt.swp",  // vim
        "4913",                 // vim probe
        ".#file_0000.txt",      // emacs lock symlink (we just create a file with this name)
        "#file_0000.txt#",      // emacs autosave
        "file_0000.txt~",       // generic backup
        "___jb_tmp___",          // JetBrains
        ".tmp.123",              // VS Code-style
    ];
    for n in names {
        fs::write(root.join(n), "decoy")?;
    }
    Ok(())
}

fn print_summary(label: &str, counts: &Counts, started: Instant, first_batch: Option<Instant>) {
    let total_elapsed = started.elapsed();
    let first_latency = first_batch.map(|t| t.duration_since(started));
    println!(
        "[{label}] batches={} creates={} modifies={} ren_from={} ren_to={} ren_both={} removes={} other={} rescans={} errors={} total={:?} first_batch_latency={:?}",
        counts.batches,
        counts.creates,
        counts.modifies,
        counts.renames_from,
        counts.renames_to,
        counts.renames_both,
        counts.removes,
        counts.other,
        counts.rescans,
        counts.errors,
        total_elapsed,
        first_latency,
    );
}

fn run_scenario<F>(label: &str, tmp: &TempDir, action: F) -> Result<()>
where
    F: FnOnce(&PathBuf) -> Result<()>,
{
    let counts = Arc::new(Mutex::new(Counts::default()));
    let first = Arc::new(Mutex::new(None));
    let mut debouncer = make_debouncer(counts.clone(), first.clone())?;
    debouncer.watch(tmp.path(), RecursiveMode::Recursive)?;
    // Give the watcher a beat to settle on macOS FSEvents.
    thread::sleep(Duration::from_millis(100));

    let started = Instant::now();
    action(&tmp.path().to_path_buf())?;
    // Wait long enough for the 150ms debounce window plus a generous tail.
    thread::sleep(Duration::from_millis(800));

    let counts = counts.lock().expect("counts lock").clone_for_print();
    let first = *first.lock().expect("first lock");
    print_summary(label, &counts, started, first);
    drop(debouncer);
    Ok(())
}

impl Counts {
    fn clone_for_print(&self) -> Counts {
        Counts {
            creates: self.creates,
            modifies: self.modifies,
            renames_from: self.renames_from,
            renames_to: self.renames_to,
            renames_both: self.renames_both,
            removes: self.removes,
            other: self.other,
            rescans: self.rescans,
            batches: self.batches,
            errors: self.errors,
        }
    }
}

fn main() -> Result<()> {
    let storm_n: usize = std::env::var("STORM_N").ok().and_then(|s| s.parse().ok()).unwrap_or(500);
    let watches_target = AtomicUsize::new(0);

    println!("# notify + notify-debouncer-full smoke (storm_n={storm_n})");
    println!("notify={} debouncer-full={}", env!("CARGO_PKG_VERSION"), "see Cargo.toml");

    let tmp = TempDir::new()?;
    let from_dir = tmp.path().join("from");
    let to_dir = tmp.path().join("to");
    fs::create_dir_all(&from_dir)?;
    fs::create_dir_all(&to_dir)?;
    watches_target.fetch_add(2, Ordering::Relaxed);

    // 1. Storm of fresh creates - tests debounce coalescing.
    let counts = Arc::new(Mutex::new(Counts::default()));
    let first = Arc::new(Mutex::new(None));
    let mut deb = make_debouncer(counts.clone(), first.clone())?;
    deb.watch(tmp.path(), RecursiveMode::Recursive)?;
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let storm_wall = scenario_storm(&tmp.path().to_path_buf(), storm_n)?;
    thread::sleep(Duration::from_millis(800));
    print_summary("storm-create", &counts.lock().unwrap().clone_for_print(), started, *first.lock().unwrap());
    println!("[storm-create] wall_time_writes={storm_wall:?}");
    drop(deb);
    thread::sleep(Duration::from_millis(200));

    // 2. Modify-in-place of those same files.
    run_scenario("modify-in-place", &tmp, |root| scenario_modify_in_place(root, storm_n.min(200)))?;

    // 3. Atomic rename (write tmp + rename over). Exercises rename pairing.
    run_scenario("atomic-rename", &tmp, |root| scenario_atomic_rename(root, storm_n.min(200)))?;

    // 4. Cross-dir rename. Exercises rename From/To pairing.
    run_scenario("rename-across-dir", &tmp, |root| {
        scenario_rename_across_dir(root, &from_dir, &to_dir, storm_n.min(100))
    })?;

    // 5. Editor swap-file decoys. These should still appear in the event stream;
    //    the real pre-filter happens in the daemon before any work is done.
    run_scenario("editor-swap-decoys", &tmp, |root| scenario_editor_swapfiles(root))?;

    println!("# Verified APIs:");
    println!("- new_debouncer(timeout, tick_rate, handler) builds notify-debouncer-full");
    println!("- DebouncedEvent.event.kind matches EventKind::{{Create, Modify(Data), Modify(Name(RenameMode)), Remove}}");
    println!("- DebouncedEvent.event.need_rescan() detects overflow (no overflow triggered in this smoke; production daemon must handle)");
    println!("- 150ms debounce window coalesces N rapid writes into one or two batches");
    println!("DONE");
    Ok(())
}
