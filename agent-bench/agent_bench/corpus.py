"""Corpus loading — Task records from a checked-in JSON or a dataset id.

Two sources, one entry point:

  - A checked-in JSON corpus (e.g. `corpus/swe-bench-lite-smoke.json`):
    `load_corpus(path)` parses the file directly.
  - A dataset id (e.g. `princeton-nlp/SWE-bench_Lite`) behind the
    `CorpusLoader` boundary: `load_corpus(id, loader=...)`. The real
    loader pulls from HuggingFace; tests inject a `FakeLoader` so NO
    network is touched in the suite.

Required fields are validated up front with a clear `ValueError` so a
malformed corpus fails fast (not deep inside the run loop). `limit`
truncates deterministically (first N, in file order). The corpus
version rides on the returned list as `.corpus_version`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, runtime_checkable

from .run import Task

# Fields a corpus row MUST carry. `gold_patch` is optional (Docker eval
# only; the agent never sees it). `repo_dir` is populated at run time by
# isolation.prepare_task, so it is NOT required in the corpus.
_REQUIRED_FIELDS = ("instance_id", "repo", "base_commit", "problem_statement")


@runtime_checkable
class CorpusLoader(Protocol):
    """Boundary over a dataset source (e.g. HuggingFace).

    `load(source)` returns `(corpus_version, rows)` where `rows` is a
    list of task dicts. Real impl hits HuggingFace; the test fake returns
    canned rows so the suite never reaches the network.
    """

    def load(self, source: str) -> tuple[str, list[dict]]: ...


class TaskList(list):
    """A list of `Task` that also carries the corpus version.

    Subclassing list keeps call sites simple (`for t in tasks`) while
    letting the run loop record which corpus snapshot produced a result.
    """

    corpus_version: str = ""


# --- Real (HuggingFace) loader ------------------------------------


class HuggingFaceLoader:
    """Real `CorpusLoader` that pulls a split from HuggingFace `datasets`.

    Imports `datasets` lazily so importing this module never drags in the
    heavy dependency (and so the test suite, which injects a fake, never
    touches HF). Used only in real runs.
    """

    def __init__(self, split: str = "test") -> None:
        self._split = split

    def load(self, source: str) -> tuple[str, list[dict]]:
        from datasets import load_dataset  # lazy: real-run only

        ds = load_dataset(source, split=self._split)
        rows = [dict(r) for r in ds]
        version = f"{source}@{self._split}"
        return (version, rows)


# --- Validation + coercion ----------------------------------------


def _row_to_task(row: dict, *, index: int) -> Task:
    """Validate a corpus row and build a frozen `Task`.

    Raises `ValueError` naming the first missing required field so a
    malformed corpus fails fast and legibly.
    """
    if not isinstance(row, dict):
        raise ValueError(f"corpus row {index} is not an object: {row!r}")
    for field_name in _REQUIRED_FIELDS:
        if field_name not in row or row[field_name] in (None, ""):
            raise ValueError(
                f"corpus row {index} ({row.get('instance_id', '?')}) is "
                f"missing required field {field_name!r}"
            )
    return Task(
        instance_id=str(row["instance_id"]),
        repo=str(row["repo"]),
        base_commit=str(row["base_commit"]),
        problem_statement=str(row["problem_statement"]),
        # repo_dir is a placeholder; isolation.prepare_task overwrites it.
        repo_dir=Path("<unmaterialized>"),
        gold_patch=str(row.get("gold_patch", "")),
    )


def _rows_to_tasks(rows: list[dict], version: str, limit: int | None) -> TaskList:
    if limit is not None:
        rows = rows[:limit]
    tasks = TaskList(_row_to_task(r, index=i) for i, r in enumerate(rows))
    tasks.corpus_version = version
    return tasks


# --- Entry point --------------------------------------------------


def load_corpus(
    source: str | Path,
    *,
    limit: int | None = None,
    loader: CorpusLoader | None = None,
) -> TaskList:
    """Load tasks from a JSON corpus path OR a dataset id via `loader`.

    - When `loader` is None, `source` is a path to a checked-in JSON
      corpus (`{"name": ..., "tasks": [...]}`); the version is the
      corpus `name`.
    - When `loader` is given, `source` is a dataset id passed to
      `loader.load(...)`, which returns `(corpus_version, rows)`.

    `limit` keeps the first N rows in file/dataset order (deterministic).
    Malformed rows raise `ValueError`.
    """
    if loader is not None:
        version, rows = loader.load(str(source))
        return _rows_to_tasks(rows, version, limit)

    path = Path(source)
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError(
            f"corpus {path} must be a JSON object with a 'tasks' list, "
            f"got {type(raw).__name__}"
        )
    rows = raw.get("tasks")
    if not isinstance(rows, list):
        raise ValueError(f"corpus {path} has no 'tasks' list")
    version = str(raw.get("name", path.stem))
    return _rows_to_tasks(rows, version, limit)
