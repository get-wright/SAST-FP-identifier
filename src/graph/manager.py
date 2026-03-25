"""gkg server lifecycle and index management.

gkg requires: index first (CLI), then start server, then query via MCP.
The CLI `gkg index` fails if the server is already running.
For re-indexing when the server is up, use MCP `index_project` tool.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
from typing import Optional

from src.graph.index_registry import IndexRegistry
from src.graph.mcp_client import GkgMCPClient

logger = logging.getLogger(__name__)


class GraphManager:
    def __init__(
        self,
        gkg_path: str = "gkg",
        server_port: int = 27495,
        enable_reindexing: bool = True,
        index_timeout: int = 300,
        registry_path: str = "./index_registry.json",
    ):
        self._gkg_path = gkg_path
        self._server_port = server_port
        self._enable_reindexing = enable_reindexing
        self._index_timeout = index_timeout
        self._registry = IndexRegistry(registry_path)
        self._index_lock = asyncio.Lock()
        self.client = GkgMCPClient(
            base_url=f"http://localhost:{server_port}",
        )

    def is_available(self) -> bool:
        """Check if gkg binary is on PATH."""
        return shutil.which(self._gkg_path) is not None

    async def ensure_index_and_server(
        self, repo_path: str, repo_key: str, commit_sha: str
    ) -> bool:
        """Index repo and ensure server is running.

        Correct order:
        - If first time: stop server (if running) → CLI index → start server
        - If re-index (SHA changed, server running): MCP index_project
        - If up-to-date: ensure server is running
        """
        if not self.is_available():
            logger.warning("gkg not found — graph features disabled")
            return False

        abs_path = os.path.abspath(repo_path)

        async with self._index_lock:
            if not self._registry.needs_reindex(repo_key, commit_sha):
                logger.info("Index up-to-date for %s at %s", repo_key, commit_sha[:8])
                was_running = self._is_server_running()
                if not was_running:
                    await self._start_server()
                    if not self._is_server_running():
                        return False
                    # Fresh server needs project registration
                    logger.info("Registering project %s with freshly started server", repo_key)
                    try:
                        await self.client.index_project(abs_path)
                    except Exception as e:
                        logger.warning("MCP project registration failed: %s", e)
                return self._is_server_running()

            server_running = self._is_server_running()

            if server_running:
                # Server is up — use MCP to re-index
                logger.info("Re-indexing %s via MCP (server running)", repo_key)
                try:
                    await self.client.index_project(abs_path)
                    self._registry.set(repo_key, {
                        "repo_path": abs_path,
                        "last_commit_sha": commit_sha,
                    })
                    return True
                except Exception as e:
                    logger.warning("MCP re-index failed: %s — stopping server for CLI index", e)
                    await self._stop_server()
                    server_running = False

            # Server not running — use CLI index then start server
            logger.info("Indexing %s via CLI", repo_key)
            success = await self._run_gkg_index(abs_path)
            if not success:
                logger.error("gkg CLI index failed for %s", repo_key)
                return False

            self._registry.set(repo_key, {
                "repo_path": abs_path,
                "last_commit_sha": commit_sha,
            })

            # Start server after indexing
            logger.info("Starting gkg server after indexing")
            await self._start_server()
            if not self._is_server_running():
                logger.error("gkg server failed to start")
                return False

            # Register project with the running server — the server doesn't
            # automatically know about CLI-indexed projects.
            logger.info("Registering project %s with gkg server via MCP", repo_key)
            try:
                await self.client.index_project(abs_path)
            except Exception as e:
                logger.warning("MCP project registration failed: %s — server may not have project data", e)

            return True

    def _is_server_running(self) -> bool:
        """Check if gkg server is responding."""
        import httpx
        try:
            resp = httpx.get(
                f"http://localhost:{self._server_port}/",
                timeout=2,
            )
            return resp.status_code < 500
        except Exception:
            return False

    async def _start_server(self) -> bool:
        """Start gkg server in detached mode."""
        cmd = [self._gkg_path, "server", "start", "--detached"]
        if self._enable_reindexing:
            cmd.append("--enable-reindexing")

        logger.info("Starting gkg server: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.wait(), timeout=10)
            await asyncio.sleep(1)
            return self._is_server_running()
        except Exception as e:
            logger.error("Failed to start gkg server: %s", e)
            return False

    async def _stop_server(self) -> None:
        """Stop gkg server."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self._gkg_path, "server", "stop",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            await asyncio.sleep(0.5)
        except Exception as e:
            logger.warning("Failed to stop gkg server: %s", e)

    async def _run_gkg_index(self, repo_path: str) -> bool:
        """Run `gkg index <path>` as subprocess (server must NOT be running)."""
        cmd = [self._gkg_path, "index", repo_path]
        logger.info("Running gkg index: %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._index_timeout
            )
            if proc.returncode == 0:
                logger.info("gkg index completed for %s", repo_path)
                return True
            logger.error("gkg index failed: %s", stderr.decode())
            return False
        except asyncio.TimeoutError:
            logger.error("gkg index timed out after %ds", self._index_timeout)
            proc.kill()
            return False
        except Exception as e:
            logger.error("gkg index error: %s", e)
            return False

    async def shutdown(self) -> None:
        """Stop the gkg server."""
        if not self.is_available():
            return
        await self._stop_server()
