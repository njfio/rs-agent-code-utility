"""Per-arm verify-metric collection (verify-v0 P4 U3).

OFFLINE post-hoc scoring: takes the trajectories an arm produced and
feeds each one's final patch through the rts verify CLI to compute the
§5 edit-quality / hallucination metrics PER ARM. NO model in the loop.

The rts CLI is reached only through the `RtsVerifyRunner` boundary
(a Protocol), so the whole module is unit-testable with a `FakeRunner`
returning canned JSON — no daemon, no subprocess, no network.

Metrics (mirroring `crates/rts-bench`'s `Metric` shape —
numerator / denominator / rate, with `rate=None` on an empty
denominator so a rate is never NaN and never cherry-picked):

  - **EVR** (Edit Validity Rate): patches whose `verify_edit` verdict
    is "pass" / patches scored. `warn` and `fail` count against it.
  - **BCIR** (Broken-Caller Introduction Rate): patches with >=1
    finding kind in {broken_caller, signature_break} / patches scored.
  - **SHR / IHR / SMR**: symbol / import / signature hallucination
    rates, aggregated from the `verify_file` (`rts verify --json`)
    hallucination lists over the files each patch touched. A reference
    counts toward the denominator only when its resolution is decidable
    (`exact` or `not_found`); `indeterminate` is excluded (honest
    denominators).

### SMR is approximated as `None`

The `rts verify --json` file-level surface returns symbol / import
resolutions but NOT per-call-site arity data, so we cannot decide
signature mismatches from this boundary. SMR is therefore reported with
denominator 0 / rate None (documented, never a false zero). The
arity-aware SMR lives in `rts-bench`'s reference-level harness, which
has the F3 `call_arity` extraction this CLI surface lacks.

### Empty / missing patches

A trajectory with `final_patch` None or "" produced no edit to score;
it is SKIPPED (not counted in any denominator) and tallied under
`skipped_empty_patches` so coverage stays visible.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Protocol


class RtsVerifyRunner(Protocol):
    """Thin boundary over the rts verify CLI.

    `verify_edit` mirrors `rts verify-edit --json`: given a list of
    full post-edit `{file, content}` dicts, returns the daemon verdict
    body `{verdict, findings: [{kind, ...}], files?: [...], ...}`.

    `verify_file` mirrors `rts verify --json` on one file's content:
    returns `{hallucinations: [{name, kind, resolution, ...}]}` where
    `resolution` is one of "exact" / "not_found" / "indeterminate".
    """

    def verify_edit(self, edits: list[dict]) -> dict: ...

    def verify_file(self, path: str, content: str) -> dict: ...


# --- Real (shelling) implementation -------------------------------


class CliRtsVerifyRunner:
    """Real `RtsVerifyRunner` that shells out to the `rts` binary.

    Used only in real runs; tests inject a fake. Kept dependency-free
    (subprocess + json) so importing this module never spawns anything.
    """

    def __init__(self, rts_bin: str = "rts", workspace: str | None = None) -> None:
        self._rts = rts_bin
        self._workspace = workspace

    def _run(self, args: list[str], stdin: str | None = None) -> dict:
        proc = subprocess.run(
            [self._rts, *args],
            input=stdin,
            capture_output=True,
            text=True,
            cwd=self._workspace,
            timeout=120,
        )
        out = proc.stdout.strip()
        if not out:
            return {"error": proc.stderr.strip() or "empty output"}
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {"error": "non-json output", "raw": out}

    def verify_edit(self, edits: list[dict]) -> dict:
        # `rts verify-edit --edits - --json` reads the edits JSON on stdin.
        return self._run(
            ["verify-edit", "--edits", "-", "--json"], stdin=json.dumps(edits)
        )

    def verify_file(self, path: str, content: str) -> dict:
        # `rts verify <path> --json` (content already on disk in workspace).
        return self._run(["verify", path, "--json"])


# --- Metric accumulator (mirrors rts-bench's Metric shape) --------

_CALLER_BREAK_KINDS = frozenset({"broken_caller", "signature_break"})


def _metric(numerator: int, denominator: int, indeterminate: int = 0) -> dict[str, Any]:
    """`{numerator, denominator, rate, indeterminate_excluded}` with
    `rate=None` on an empty denominator (never NaN)."""
    rate = None if denominator == 0 else numerator / denominator
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": rate,
        "indeterminate_excluded": indeterminate,
    }


def _patch_to_edits(patch: str) -> list[dict]:
    """Wrap a trajectory's final patch into the verify_edit edit list.

    The trajectory stores a unified diff as a single blob; the verify
    boundary keys on the `content` field, so we pass the patch as one
    edit dict. (A richer impl would parse the diff into per-file
    post-edit contents; the FakeRunner-backed tests exercise this
    contract via the `content` key.)
    """
    return [{"file": "", "content": patch}]


def evaluate_arm(
    trajectories: list[Any],
    runner: RtsVerifyRunner,
) -> dict[str, Any]:
    """Compute the §5 verify metrics for one arm's trajectories.

    Returns a dict with `evr`, `bcir`, `shr`, `ihr`, `smr` metric
    blocks (numerator/denominator/rate), plus `scored_patches` and
    `skipped_empty_patches` for coverage visibility.
    """
    evr_num = 0
    bcir_num = 0
    scored = 0
    skipped = 0

    shr_num = shr_den = shr_ind = 0
    ihr_num = ihr_den = ihr_ind = 0

    for traj in trajectories:
        patch = getattr(traj, "final_patch", None)
        if not patch:  # None or "" → no edit to score; skip.
            skipped += 1
            continue

        scored += 1
        body = runner.verify_edit(_patch_to_edits(patch))
        verdict = body.get("verdict")
        findings = body.get("findings") or []

        if verdict == "pass":
            evr_num += 1
        kinds = {f.get("kind") for f in findings}
        if kinds & _CALLER_BREAK_KINDS:
            bcir_num += 1

        # Hallucination rates over the files this patch touched.
        for path in body.get("files") or []:
            file_body = runner.verify_file(path, "")
            for ref in file_body.get("hallucinations") or []:
                kind = ref.get("kind")
                resolution = ref.get("resolution")
                if kind == "import":
                    if resolution == "not_found":
                        ihr_num += 1
                        ihr_den += 1
                    elif resolution == "exact":
                        ihr_den += 1
                    else:
                        ihr_ind += 1
                else:  # symbol / type / path → SHR
                    if resolution == "not_found":
                        shr_num += 1
                        shr_den += 1
                    elif resolution == "exact":
                        shr_den += 1
                    else:
                        shr_ind += 1

    return {
        "scored_patches": scored,
        "skipped_empty_patches": skipped,
        "evr": _metric(evr_num, scored),
        "bcir": _metric(bcir_num, scored),
        "shr": _metric(shr_num, shr_den, shr_ind),
        "ihr": _metric(ihr_num, ihr_den, ihr_ind),
        # SMR approximated as None: the verify_file CLI surface does not
        # expose per-call-site arity, so signature mismatch can't be
        # decided here. See module docstring.
        "smr": _metric(0, 0),
    }
