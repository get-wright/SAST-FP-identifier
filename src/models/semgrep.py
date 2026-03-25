"""Semgrep JSON output models."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel


class SemgrepFinding(BaseModel):
    """Single finding from Semgrep JSON results[]."""

    check_id: str
    path: str
    start: dict[str, int]  # {line, col, offset?}
    end: dict[str, int]
    extra: dict[str, Any]

    @property
    def start_line(self) -> int:
        return self.start["line"]

    @property
    def end_line(self) -> int:
        return self.end["line"]

    @property
    def fingerprint(self) -> str:
        return self.extra.get("fingerprint", "")

    @property
    def severity(self) -> str:
        return self.extra.get("severity", "INFO")

    @property
    def message(self) -> str:
        return self.extra.get("message", "")

    @property
    def lines(self) -> str:
        return self.extra.get("lines", "")

    @property
    def metadata(self) -> dict:
        return self.extra.get("metadata", {})

    @property
    def is_ignored(self) -> bool:
        return self.extra.get("is_ignored", False)


class SemgrepOutput(BaseModel):
    """Top-level Semgrep --json output."""

    version: str = ""
    results: list[SemgrepFinding] = []
    errors: list[dict] = []
    paths: dict[str, Any] = {}


def parse_semgrep_json(
    data: dict,
    filter_ignored: bool = True,
    max_findings: int | None = None,
) -> list[SemgrepFinding]:
    """Parse raw Semgrep JSON dict into Finding models.

    Args:
        data: Raw Semgrep JSON output dict.
        filter_ignored: Skip findings with nosemgrep suppression.
        max_findings: Cap number of findings processed.

    Returns:
        List of SemgrepFinding models.
    """
    output = SemgrepOutput.model_validate(data)
    findings = output.results

    if filter_ignored:
        findings = [f for f in findings if not f.is_ignored]

    if max_findings and len(findings) > max_findings:
        findings = findings[:max_findings]

    return findings
