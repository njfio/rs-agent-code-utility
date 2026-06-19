"""Tests for corpus loading (U2).

`load_corpus` loads Task records from a checked-in JSON corpus OR from a
dataset id behind a `loader` boundary (the HF path, faked here — NO
network). It validates required fields, truncates deterministically via
`limit`, and carries `corpus_version`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bench.corpus import CorpusLoader, load_corpus
from agent_bench.run import Task

SMOKE = Path(__file__).resolve().parent.parent / "corpus" / "swe-bench-lite-smoke.json"


class TestLoadFromJson:
    def test_loads_smoke_corpus(self) -> None:
        tasks = load_corpus(SMOKE)
        assert len(tasks) == 4
        assert all(isinstance(t, Task) for t in tasks)
        ids = [t.instance_id for t in tasks]
        assert "django__django-11099" in ids
        # Fields carried through.
        first = tasks[0]
        assert first.repo == "django/django"
        assert first.problem_statement

    def test_limit_truncates_deterministically(self) -> None:
        two = load_corpus(SMOKE, limit=2)
        assert len(two) == 2
        # Deterministic: same first two as the unlimited load, in order.
        full = load_corpus(SMOKE)
        assert [t.instance_id for t in two] == [t.instance_id for t in full[:2]]

    def test_carries_corpus_version(self) -> None:
        tasks = load_corpus(SMOKE)
        # corpus_version is attached as an attribute on the returned list
        # wrapper OR accessible via load_corpus return; we expose it on
        # each Task is not desired (Task is frozen + shared), so the
        # version rides on the list object.
        assert getattr(tasks, "corpus_version", None) == "swe-bench-lite-smoke"

    def test_malformed_missing_field_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text(
            json.dumps(
                {
                    "name": "broken",
                    "tasks": [{"instance_id": "x", "repo": "a/b"}],  # missing fields
                }
            )
        )
        with pytest.raises(ValueError, match="base_commit"):
            load_corpus(bad)

    def test_malformed_not_a_dict_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps([1, 2, 3]))
        with pytest.raises(ValueError):
            load_corpus(bad)


class FakeLoader:
    """Canned CorpusLoader — returns task dicts without touching HF."""

    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows
        self.requested: list[str] = []

    def load(self, source: str) -> tuple[str, list[dict]]:
        self.requested.append(source)
        return ("fake-dataset-v1", list(self.rows))


class TestLoadViaLoader:
    def test_fake_loader_returns_canned_tasks(self) -> None:
        loader = FakeLoader(
            rows=[
                {
                    "instance_id": "fake__1",
                    "repo": "fake/repo",
                    "base_commit": "abc",
                    "problem_statement": "do it",
                    "gold_patch": "",
                },
                {
                    "instance_id": "fake__2",
                    "repo": "fake/repo",
                    "base_commit": "def",
                    "problem_statement": "do it again",
                },
            ]
        )
        tasks = load_corpus("princeton-nlp/SWE-bench_Lite", loader=loader)
        assert loader.requested == ["princeton-nlp/SWE-bench_Lite"]
        assert [t.instance_id for t in tasks] == ["fake__1", "fake__2"]
        assert getattr(tasks, "corpus_version", None) == "fake-dataset-v1"

    def test_loader_path_respects_limit(self) -> None:
        loader = FakeLoader(
            rows=[
                {
                    "instance_id": f"fake__{i}",
                    "repo": "fake/repo",
                    "base_commit": "c",
                    "problem_statement": "p",
                }
                for i in range(5)
            ]
        )
        tasks = load_corpus("ds", loader=loader, limit=2)
        assert [t.instance_id for t in tasks] == ["fake__0", "fake__1"]

    def test_loader_malformed_raises(self) -> None:
        loader = FakeLoader(rows=[{"instance_id": "x"}])
        with pytest.raises(ValueError):
            load_corpus("ds", loader=loader)


def test_corpus_loader_protocol_importable() -> None:
    assert CorpusLoader is not None
