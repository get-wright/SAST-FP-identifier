"""Tests for repo handler."""

import os
import pytest
from pathlib import Path
from src.repo.handler import RepoHandler


@pytest.fixture
def tmp_cache(tmp_path):
    return str(tmp_path / "repos_cache")


def test_local_path_returned_as_is(tmp_cache):
    handler = RepoHandler(cache_dir=tmp_cache)
    result = handler.clone(".")
    assert result == "."


def test_clone_creates_cache_dir(tmp_cache):
    handler = RepoHandler(cache_dir=tmp_cache)
    assert Path(tmp_cache).exists()


def test_get_repo_name_from_url():
    handler = RepoHandler(cache_dir="/tmp/test")
    assert handler._get_repo_name("https://github.com/user/repo") == "user_repo"
    assert handler._get_repo_name("https://github.com/user/repo.git") == "user_repo"


def test_get_head_sha(tmp_path):
    """Test getting HEAD SHA from a real git repo."""
    os.system(f"cd {tmp_path} && git init && git commit --allow-empty -m 'init'")
    handler = RepoHandler(cache_dir=str(tmp_path))
    sha = handler.get_head_sha(str(tmp_path))
    assert sha is not None
    assert len(sha) == 40


def test_validate_repo_url_rejects_file():
    handler = RepoHandler(
        cache_dir="/tmp/test",
        allowed_domains=["github.com"],
    )
    with pytest.raises(ValueError):
        handler.validate_url("file:///etc/passwd")


def test_validate_repo_url_rejects_bad_domain():
    handler = RepoHandler(
        cache_dir="/tmp/test",
        allowed_domains=["github.com"],
    )
    with pytest.raises(ValueError):
        handler.validate_url("https://evil.com/repo")
