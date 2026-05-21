//! Shared process-instrumentation helpers used by both the
//! `footprint` and `real_repos` benches.
//!
//! The functions originated in `footprint.rs` and stayed there for
//! the v0 slice; this thin re-export module avoids each new consumer
//! needing to depend on the full `footprint` namespace just to reach
//! `find_child_pid` / `sample_rss_loop` / `linux_vm_hwm_bytes`.
//!
//! Anything load-bearing (pgrep + ps fallback strategy, sampler
//! cadence, /proc/<pid>/status:VmHWM parsing) is documented at the
//! source — see `footprint.rs`.

pub(crate) use crate::footprint::{find_child_pid, linux_vm_hwm_bytes, sample_rss_loop};
