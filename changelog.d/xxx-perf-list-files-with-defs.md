### Perf: `outline` no longer re-walks the DEFS multimap per file

`Store::list_files_with_defs` (the enumeration behind `Index.Outline`)
was O(files × defs-per-name): for every `(file, symbol)` it re-scanned
the whole `DEFS` multimap for that name to find the matching file. On a
5000-file workspace this took ~121 s. It now makes a single pass over
`DEFS`, bucketing each definition into its file by `fid` — O(total
defs). Same output (one symbol per name per file, all files listed),
dramatically faster cold `outline`.
