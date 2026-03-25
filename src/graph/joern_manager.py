"""CPG lifecycle manager for Joern."""

from __future__ import annotations

import logging
import os

import httpx

from src.graph.index_registry import IndexRegistry
from src.graph.joern_client import JoernClient

logger = logging.getLogger(__name__)


class JoernManager:
    """Manages Joern CPG import lifecycle with index-state tracking."""

    def __init__(
        self,
        joern_url: str,
        import_timeout: int,
        query_timeout: int,
        registry_path: str,
        analyzer_repo_prefix: str = "/app/repos_cache",
        joern_repo_prefix: str = "/repos",
    ) -> None:
        self.analyzer_repo_prefix = analyzer_repo_prefix.rstrip("/")
        self.joern_repo_prefix = joern_repo_prefix.rstrip("/")
        self._client = JoernClient(
            base_url=joern_url,
            import_timeout=import_timeout,
            query_timeout=query_timeout,
        )
        self._registry = IndexRegistry(registry_path)

    @property
    def client(self) -> JoernClient:
        """Expose the underlying JoernClient."""
        return self._client

    def is_available(self) -> bool:
        """Return True if Joern server is reachable (synchronous check)."""
        try:
            resp = httpx.get(self._client.base_url, timeout=5)
            return resp.status_code < 500
        except Exception:
            return False

    async def ensure_cpg(self, repo_path: str, commit_sha: str) -> bool:
        """Ensure a CPG exists for the repo at the given commit SHA.

        Uses the registry to skip re-import when the SHA has not changed.
        Returns True if the CPG is ready (existing or freshly imported).
        """
        repo_key = f"joern_{os.path.basename(repo_path.rstrip('/'))}"

        if not self._registry.needs_reindex(repo_key, commit_sha):
            logger.info("Joern CPG up-to-date for %s at %s", repo_key, commit_sha[:8])
            return True

        joern_path = self.translate_path(repo_path)
        logger.info("Importing CPG for %s (joern path: %s)", repo_key, joern_path)

        success = await self._client.import_code(joern_path)
        if not success:
            logger.error("Joern importCode failed for %s", repo_key)
            return False

        self._registry.set(repo_key, {
            "repo_path": joern_path,
            "last_commit_sha": commit_sha,
        })
        return True

    def translate_path(self, analyzer_path: str) -> str:
        """Translate analyzer-side repo path to Joern-container path.

        Example: /app/repos_cache/org_repo → /repos/org_repo
        """
        norm = analyzer_path.rstrip("/")
        if norm.startswith(self.analyzer_repo_prefix):
            suffix = norm[len(self.analyzer_repo_prefix):]
            return self.joern_repo_prefix + suffix
        return norm
