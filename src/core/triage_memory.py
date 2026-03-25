"""Local file-backed reviewer overrides and triage memories."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class ReviewerOverride:
    id: str
    repo_url: str
    fingerprint: str
    verdict: str
    confidence: float = 1.0
    reasoning: str = ""


@dataclass(frozen=True)
class TriageMemory:
    id: str
    scope: str
    repo_url: Optional[str]
    framework: Optional[str]
    rule: str
    guidance: str


class TriageMemoryStore:
    def __init__(self, data_dir: str = "./triage_data"):
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._overrides_path = self._dir / "overrides.json"
        self._memories_path = self._dir / "memories.json"

    def find_override(self, repo_url: str, fingerprint: str) -> ReviewerOverride | None:
        for entry in self._load_overrides():
            if entry.repo_url == repo_url and entry.fingerprint == fingerprint:
                return entry
        return None

    def find_memories(
        self,
        repo_url: str,
        framework: Optional[str],
        rule: str,
    ) -> list[TriageMemory]:
        framework_lower = (framework or "").lower()
        rule_lower = rule.lower()
        repo_matches: list[TriageMemory] = []
        framework_matches: list[TriageMemory] = []

        for entry in self._load_memories():
            if entry.rule.lower() != rule_lower:
                continue
            if entry.scope == "repo" and entry.repo_url == repo_url:
                repo_matches.append(entry)
            elif entry.scope == "framework" and (entry.framework or "").lower() == framework_lower:
                framework_matches.append(entry)

        return repo_matches + framework_matches

    def policy_hash(
        self,
        repo_url: str,
        framework: Optional[str],
        findings: list[Any],
    ) -> str:
        entries: list[dict[str, Any]] = []
        for finding in findings:
            override = self.find_override(repo_url, finding.fingerprint)
            if override:
                entries.append({"type": "override", **asdict(override)})
            for memory in self.find_memories(repo_url, framework, finding.check_id):
                entries.append({"type": "memory", **asdict(memory)})

        if not entries:
            return "no-triage-data"

        payload = json.dumps(entries, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def _load_overrides(self) -> list[ReviewerOverride]:
        raw_entries = self._load_json_list(self._overrides_path, "overrides")
        items: list[ReviewerOverride] = []
        for entry in raw_entries:
            if not isinstance(entry, dict):
                continue
            verdict = entry.get("verdict", "uncertain")
            if verdict not in ("true_positive", "false_positive", "uncertain"):
                continue
            items.append(ReviewerOverride(
                id=str(entry.get("id", "")),
                repo_url=str(entry.get("repo_url", "")),
                fingerprint=str(entry.get("fingerprint", "")),
                verdict=verdict,
                confidence=float(entry.get("confidence", 1.0)),
                reasoning=str(entry.get("reasoning", "")),
            ))
        return items

    def _load_memories(self) -> list[TriageMemory]:
        raw_entries = self._load_json_list(self._memories_path, "memories")
        items: list[TriageMemory] = []
        for entry in raw_entries:
            if not isinstance(entry, dict):
                continue
            scope = entry.get("scope", "")
            if scope not in ("repo", "framework"):
                continue
            rule = str(entry.get("rule", "")).strip()
            guidance = str(entry.get("guidance", "")).strip()
            if not rule or not guidance:
                continue
            items.append(TriageMemory(
                id=str(entry.get("id", "")),
                scope=scope,
                repo_url=entry.get("repo_url"),
                framework=entry.get("framework"),
                rule=rule,
                guidance=guidance,
            ))
        return items

    def _load_json_list(self, path: Path, key: str) -> list[Any]:
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text())
        except Exception:
            return []
        values = payload.get(key, [])
        return values if isinstance(values, list) else []
