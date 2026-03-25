"""Tests for index registry."""

import pytest
from src.graph.index_registry import IndexRegistry


@pytest.fixture
def registry(tmp_path):
    return IndexRegistry(str(tmp_path / "index_registry.json"))


def test_empty_registry_returns_none(registry):
    assert registry.get("nonexistent") is None


def test_set_and_get(registry):
    registry.set("user_repo", {
        "repo_path": "/tmp/repo",
        "last_commit_sha": "abc123",
        "definition_count": 100,
        "languages": ["python"],
    })
    entry = registry.get("user_repo")
    assert entry is not None
    assert entry["last_commit_sha"] == "abc123"


def test_update_existing(registry):
    registry.set("user_repo", {"last_commit_sha": "abc123", "repo_path": "/tmp/repo"})
    registry.set("user_repo", {"last_commit_sha": "def456", "repo_path": "/tmp/repo"})
    entry = registry.get("user_repo")
    assert entry["last_commit_sha"] == "def456"


def test_needs_reindex_no_entry(registry):
    assert registry.needs_reindex("user_repo", "abc123") is True


def test_needs_reindex_same_sha(registry):
    registry.set("user_repo", {"last_commit_sha": "abc123", "repo_path": "/tmp"})
    assert registry.needs_reindex("user_repo", "abc123") is False


def test_needs_reindex_different_sha(registry):
    registry.set("user_repo", {"last_commit_sha": "abc123", "repo_path": "/tmp"})
    assert registry.needs_reindex("user_repo", "def456") is True


def test_persistence(tmp_path):
    path = str(tmp_path / "reg.json")
    r1 = IndexRegistry(path)
    r1.set("repo", {"last_commit_sha": "abc", "repo_path": "/tmp"})
    r2 = IndexRegistry(path)
    assert r2.get("repo")["last_commit_sha"] == "abc"
