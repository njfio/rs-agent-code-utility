### Fix: cold mount no longer scans gitignored dirs (target/, node_modules)

The file watcher's debouncer used `RecommendedCache` (a file-ID map),
which scans the **entire watched tree** on startup to seed rename
detection. `notify` watches the whole workspace recursively and is not
gitignore-aware, so that scan walked `target/`, `node_modules`, etc. —
dominating cold mount (≈100 s on a workspace with a multi-GB `target/`,
despite only ~380 files being indexed). The debouncer now uses `NoCache`:
the indexer doesn't need precise rename tracking (a rename surfaces as
remove+create, already handled), so the scan is pure overhead. Cold mount
on this repo dropped from ~104 s to ~5 s.
