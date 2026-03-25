"""Tests for graph manager — uses mocks since gkg may not be installed."""

import pytest
from unittest.mock import AsyncMock, patch
from src.graph.manager import GraphManager


@pytest.fixture
def manager(tmp_path):
    return GraphManager(
        gkg_path="gkg",
        server_port=27495,
        registry_path=str(tmp_path / "registry.json"),
    )


@pytest.mark.asyncio
async def test_ensure_index_and_server_indexes_then_starts(manager):
    """First-time index: CLI index → start server."""
    with patch.object(manager, "is_available", return_value=True), \
         patch.object(manager, "_is_server_running", side_effect=[False, True]), \
         patch.object(manager, "_run_gkg_index", new_callable=AsyncMock, return_value=True), \
         patch.object(manager, "_start_server", new_callable=AsyncMock, return_value=True), \
         patch.object(manager._registry, "needs_reindex", return_value=True), \
         patch.object(manager._registry, "set"):
        result = await manager.ensure_index_and_server("/tmp/repo", "user_repo", "abc123")
        assert result is True
        manager._run_gkg_index.assert_called_once_with("/tmp/repo")
        manager._start_server.assert_called_once()


@pytest.mark.asyncio
async def test_ensure_index_and_server_skips_if_up_to_date(manager):
    """Already indexed with same SHA — just ensure server is running."""
    with patch.object(manager, "is_available", return_value=True), \
         patch.object(manager, "_is_server_running", return_value=True), \
         patch.object(manager, "_run_gkg_index", new_callable=AsyncMock) as mock_idx, \
         patch.object(manager._registry, "needs_reindex", return_value=False):
        result = await manager.ensure_index_and_server("/tmp/repo", "user_repo", "abc123")
        assert result is True
        mock_idx.assert_not_called()


@pytest.mark.asyncio
async def test_ensure_index_and_server_reindexes_via_mcp(manager):
    """Server running + SHA changed → re-index via MCP."""
    with patch.object(manager, "is_available", return_value=True), \
         patch.object(manager, "_is_server_running", return_value=True), \
         patch.object(manager.client, "index_project", new_callable=AsyncMock, return_value={}), \
         patch.object(manager._registry, "needs_reindex", return_value=True), \
         patch.object(manager._registry, "set"):
        result = await manager.ensure_index_and_server("/tmp/repo", "user_repo", "abc123")
        assert result is True
        manager.client.index_project.assert_called_once_with("/tmp/repo")


@pytest.mark.asyncio
async def test_ensure_index_disabled_when_gkg_not_available(manager):
    with patch.object(manager, "is_available", return_value=False):
        result = await manager.ensure_index_and_server("/tmp/repo", "user_repo", "abc123")
        assert result is False


def test_is_available_false_when_gkg_not_found(manager):
    with patch("shutil.which", return_value=None):
        assert manager.is_available() is False


def test_is_available_true_when_gkg_found(manager):
    with patch("shutil.which", return_value="/usr/bin/gkg"):
        assert manager.is_available() is True
