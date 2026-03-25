"""Tests for result cache."""

import json
import pytest
from src.core.cache import ResultCache


@pytest.fixture
def cache(tmp_path):
    return ResultCache(cache_dir=str(tmp_path / "cache"), ttl_hours=1)


def test_miss_returns_none(cache):
    assert cache.get("repo", "sha", "file.py", "fp_hash") is None


def test_set_and_get(cache):
    data = [{"finding_index": 0, "verdict": "false_positive"}]
    cache.set("repo", "sha", "file.py", "fp_hash", data)
    result = cache.get("repo", "sha", "file.py", "fp_hash")
    assert result == data


def test_different_sha_misses(cache):
    cache.set("repo", "sha1", "file.py", "fp_hash", [{"x": 1}])
    assert cache.get("repo", "sha2", "file.py", "fp_hash") is None


def test_disabled_cache():
    cache = ResultCache(cache_dir="/tmp/x", enabled=False)
    cache.set("r", "s", "f", "h", [{"x": 1}])
    assert cache.get("r", "s", "f", "h") is None


def test_set_and_get_with_contexts(cache):
    verdicts = [{"finding_index": 0, "verdict": "false_positive"}]
    contexts = {
        "0": {
            "enclosing_function": "applyDark",
            "callers": [{"file": "sidepanel.js", "line": 42, "function": "init"}],
            "callees": ["updateIframeStyles"],
            "imports": [],
            "source": "gkg",
        }
    }

    cache.set_with_contexts("repo", "sha", "file.js", "fp_hash", verdicts, contexts)

    cached_verdicts, cached_contexts = cache.get_with_contexts("repo", "sha", "file.js", "fp_hash")
    assert cached_verdicts == verdicts
    assert cached_contexts == contexts


def test_get_with_contexts_supports_legacy_cache_entries(cache):
    path = cache._cache_path("repo", "sha", "file.py", "fp_hash")
    path.write_text(json.dumps({"ts": 9999999999, "verdicts": [{"finding_index": 0}]}))

    verdicts, contexts = cache.get_with_contexts("repo", "sha", "file.py", "fp_hash")
    assert verdicts == [{"finding_index": 0}]
    assert contexts == {}
