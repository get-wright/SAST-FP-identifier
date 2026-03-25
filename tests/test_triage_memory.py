"""Tests for local reviewer overrides and triage memories."""

import json

from src.core.triage_memory import TriageMemoryStore


def test_find_memories_prefers_repo_scope_over_framework_scope(tmp_path):
    data_dir = tmp_path / "triage_data"
    data_dir.mkdir()
    (data_dir / "memories.json").write_text(json.dumps({
        "version": 1,
        "memories": [
            {
                "id": "framework-memory",
                "scope": "framework",
                "framework": "django",
                "rule": "sql-injection",
                "guidance": "Django ORM usually mitigates raw SQL findings unless raw() or cursor() is used.",
            },
            {
                "id": "repo-memory",
                "scope": "repo",
                "repo_url": "https://github.com/u/r",
                "rule": "sql-injection",
                "guidance": "This repo has a legacy safe_sql wrapper; check for it before marking false positive.",
            },
        ],
    }))

    store = TriageMemoryStore(str(data_dir))
    memories = store.find_memories(
        repo_url="https://github.com/u/r",
        framework="django",
        rule="sql-injection",
    )

    assert [m.id for m in memories] == ["repo-memory", "framework-memory"]


def test_find_override_matches_repo_and_fingerprint(tmp_path):
    data_dir = tmp_path / "triage_data"
    data_dir.mkdir()
    (data_dir / "overrides.json").write_text(json.dumps({
        "version": 1,
        "overrides": [
            {
                "id": "override-1",
                "repo_url": "https://github.com/u/r",
                "fingerprint": "fp1",
                "verdict": "false_positive",
                "confidence": 1.0,
                "reasoning": "Reviewed by security: constant string only.",
            },
        ],
    }))

    store = TriageMemoryStore(str(data_dir))
    override = store.find_override("https://github.com/u/r", "fp1")

    assert override is not None
    assert override.id == "override-1"
    assert override.verdict == "false_positive"
