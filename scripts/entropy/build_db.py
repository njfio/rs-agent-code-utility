#!/usr/bin/env python3
"""Compile .entropy/events/*.jsonl -> .entropy/ledger.db (idempotent)."""
import json, sqlite3, sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
EVENTS, DB = ROOT / ".entropy/events", ROOT / ".entropy/ledger.db"

DDL = """
CREATE TABLE IF NOT EXISTS tasks (
  session_id TEXT PRIMARY KEY, repo TEXT, branch TEXT,
  started_at TEXT, ended_at TEXT, base_rev TEXT, head_rev TEXT,
  lines_added INT, lines_removed INT, files_touched INT,
  tokens_out INT, context_peak INT, turns INT);
CREATE TABLE IF NOT EXISTS gate_events (
  ts TEXT, repo TEXT, branch TEXT, net INT, added INT, removed INT,
  warn INT, block INT, action TEXT, override_reason TEXT, session_id TEXT,
  PRIMARY KEY (ts, repo, branch, action));
CREATE TABLE IF NOT EXISTS retrieval (
  session_id TEXT, symbol_id TEXT, name TEXT, path TEXT,
  rank INT, score REAL, used INT, match_kind TEXT,
  PRIMARY KEY (session_id, symbol_id));
CREATE TABLE IF NOT EXISTS snapshots (
  week TEXT PRIMARY KEY, month TEXT, rev TEXT, loc INT, symbols INT,
  dup_pct REAL, clone_clusters INT, mean_fan_in REAL, mean_fan_out REAL,
  deps_direct INT, deps_transitive INT);
"""

INSERT = {
 "task": ("INSERT OR REPLACE INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
   ["session_id","repo","branch","started_at","ended_at","base_rev","head_rev",
    "lines_added","lines_removed","files_touched","tokens_out","context_peak","turns"]),
 "gate": ("INSERT OR REPLACE INTO gate_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
   ["ts","repo","branch","net","added","removed","warn","block","action",
    "override_reason","session_id"]),
 "retrieval": ("INSERT OR REPLACE INTO retrieval VALUES (?,?,?,?,?,?,?,?)",
   ["session_id","symbol_id","name","path","rank","score","used","match_kind"]),
 "snapshot": ("INSERT OR REPLACE INTO snapshots VALUES (?,?,?,?,?,?,?,?,?,?,?)",
   ["week","month","rev","loc","symbols","dup_pct","clone_clusters","mean_fan_in",
    "mean_fan_out","deps_direct","deps_transitive"]),
}

con = sqlite3.connect(DB); con.executescript(DDL)
n = 0
for f in sorted(EVENTS.glob("*.jsonl")):
    for line in f.read_text().splitlines():
        if not line.strip(): continue
        try: ev = json.loads(line)
        except json.JSONDecodeError: continue
        spec = INSERT.get(ev.get("t"))
        if not spec: continue
        sql, cols = spec
        con.execute(sql, [ev.get(c) for c in cols]); n += 1
con.commit()
print(f"ledger: {n} events -> {DB}")
