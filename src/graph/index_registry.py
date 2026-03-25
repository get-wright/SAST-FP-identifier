"""File-locked JSON registry for gkg index state."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from filelock import FileLock

logger = logging.getLogger(__name__)


class IndexRegistry:
    def __init__(self, path: str = "./index_registry.json"):
        self._path = Path(path)
        self._lock_path = Path(f"{path}.lock")

    def get(self, repo_key: str) -> Optional[dict[str, Any]]:
        data = self._read()
        return data.get(repo_key)

    def set(self, repo_key: str, entry: dict[str, Any]) -> None:
        with FileLock(self._lock_path):
            data = self._read()
            entry["indexed_at"] = datetime.now(timezone.utc).isoformat()
            data[repo_key] = entry
            self._write(data)

    def needs_reindex(self, repo_key: str, current_sha: str) -> bool:
        entry = self.get(repo_key)
        if entry is None:
            return True
        return entry.get("last_commit_sha") != current_sha

    def _read(self) -> dict:
        if not self._path.exists():
            return {}
        try:
            return json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _write(self, data: dict) -> None:
        self._path.write_text(json.dumps(data, indent=2))
