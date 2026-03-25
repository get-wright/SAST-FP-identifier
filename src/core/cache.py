"""File-based result cache keyed by (repo, commit, file, fingerprints_hash)."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ResultCache:
    def __init__(self, cache_dir: str = "./cache", ttl_hours: int = 24, enabled: bool = True):
        self._dir = Path(cache_dir)
        self._ttl_seconds = ttl_hours * 3600
        self._enabled = enabled
        if enabled:
            self._dir.mkdir(parents=True, exist_ok=True)

    def get(self, repo: str, sha: str, file: str, fp_hash: str) -> Optional[list[dict]]:
        if not self._enabled:
            return None
        path = self._cache_path(repo, sha, file, fp_hash)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            if time.time() - data.get("ts", 0) > self._ttl_seconds:
                path.unlink(missing_ok=True)
                return None
            return data["verdicts"]
        except Exception:
            return None

    def set(self, repo: str, sha: str, file: str, fp_hash: str, verdicts: list[dict]) -> None:
        if not self._enabled:
            return
        path = self._cache_path(repo, sha, file, fp_hash)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"ts": time.time(), "verdicts": verdicts}))

    def get_with_contexts(
        self,
        repo: str,
        sha: str,
        file: str,
        fp_hash: str,
    ) -> tuple[Optional[list[dict]], dict[str, dict]]:
        if not self._enabled:
            return None, {}

        path = self._cache_path(repo, sha, file, fp_hash)
        if not path.exists():
            return None, {}

        try:
            data = json.loads(path.read_text())
            if time.time() - data.get("ts", 0) > self._ttl_seconds:
                path.unlink(missing_ok=True)
                return None, {}
            return data["verdicts"], data.get("contexts", {})
        except Exception:
            return None, {}

    def set_with_contexts(
        self,
        repo: str,
        sha: str,
        file: str,
        fp_hash: str,
        verdicts: list[dict],
        contexts: dict[str, dict],
    ) -> None:
        if not self._enabled:
            return
        path = self._cache_path(repo, sha, file, fp_hash)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"ts": time.time(), "verdicts": verdicts, "contexts": contexts}))

    def _cache_path(self, repo: str, sha: str, file: str, fp_hash: str) -> Path:
        key = hashlib.sha256(f"{repo}:{sha}:{file}:{fp_hash}".encode()).hexdigest()[:32]
        return self._dir / f"{key}.json"
