#!/usr/bin/env python3
"""Normalize a jscpd JSON report into the entropy clusters shape (spec §7.2).

Test: tests/test_normalizer.sh   Fixture: fixtures/jscpd-report.sample.json

CONTRACT
  argv[1] = path to a jscpd JSON report
  stdout  = one JSON object:
    { "dup_pct":  <statistics.total.percentage from the report>,
      "clusters": [ { "cluster_id":   <md5 hex of the shared `fragment`>,
                      "mass_tokens":  <max `tokens` across the group's pairs>,
                      "sites":        [ {"path", "start_line", "end_line"} ... ],
                      "spread_files": <count of distinct paths in sites>,
                      "score":        <mass_tokens * spread_files> } ... ] }
RULES
  - group duplicate pairs by identical `fragment` string
  - sites = union of firstFile/secondFile across the group,
    deduped by (path, start); start/end map from jscpd `start`/`end`
  - clusters sorted by score descending
  - exit 0 on success; nonzero with a stderr message on malformed input
"""
import hashlib
import json
import sys


def main() -> int:
    try:
        with open(sys.argv[1], "rb") as fh:
            report = json.load(fh)
        dup_pct = report["statistics"]["total"]["percentage"]
        groups: dict[str, dict] = {}
        for dup in report["duplicates"]:
            g = groups.setdefault(dup["fragment"], {"mass_tokens": 0, "sites": {}})
            g["mass_tokens"] = max(g["mass_tokens"], dup["tokens"])
            for side in ("firstFile", "secondFile"):
                f = dup[side]
                g["sites"].setdefault((f["name"], f["start"]), {
                    "path": f["name"],
                    "start_line": f["start"],
                    "end_line": f["end"],
                })
        clusters = []
        for fragment, g in groups.items():
            sites = list(g["sites"].values())
            spread = len({s["path"] for s in sites})
            clusters.append({
                "cluster_id": hashlib.md5(fragment.encode()).hexdigest(),
                "mass_tokens": g["mass_tokens"],
                "sites": sites,
                "spread_files": spread,
                "score": g["mass_tokens"] * spread,
            })
        clusters.sort(key=lambda c: -c["score"])
        json.dump({"dup_pct": dup_pct, "clusters": clusters}, sys.stdout)
        print()
    except Exception as exc:  # malformed input, missing argv, bad shape
        print(f"jscpd_to_clusters: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
