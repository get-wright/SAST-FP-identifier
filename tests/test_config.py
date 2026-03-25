"""Tests for configuration loading."""

import pytest
from src.config import Settings


def test_settings_loads_defaults():
    s = Settings()
    assert s.HOST == "0.0.0.0"
    assert s.PORT == 8000
    assert s.API_KEY == "changeme"
    assert s.LLM_API_KEY == ""
    assert s.LLM_TEMPERATURE == 0.3
    assert s.FP_CONFIDENCE_THRESHOLD == 0.8
    assert s.SHALLOW_CLONE is True
    assert "github.com" in s.ALLOWED_REPO_DOMAINS


def test_settings_accepts_overrides():
    s = Settings(API_KEY="custom", LLM_API_KEY="my-key")
    assert s.API_KEY == "custom"
    assert s.LLM_API_KEY == "my-key"


def test_repo_url_validation_accepts_https():
    s = Settings()
    assert s.validate_repo_url("https://github.com/user/repo") is True


def test_repo_url_validation_rejects_file():
    s = Settings()
    with pytest.raises(ValueError, match="https://"):
        s.validate_repo_url("file:///etc/passwd")


def test_repo_url_validation_rejects_unlisted_domain():
    s = Settings()
    with pytest.raises(ValueError, match="Domain"):
        s.validate_repo_url("https://evil.com/repo")
