"""Analysis output models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from pydantic import BaseModel, Field


@dataclass
class CallerInfo:
    """A function that calls the vulnerable function."""

    file: str
    line: int
    function: str
    context: str = ""


# --- Taint models: canonical home is src/taint/models.py ---
# Re-exported here for backward compatibility.
from src.taint.models import (
    FlowStep,
    SanitizerInfo,
    InferredSinkSource,
    CrossFileHop,
    TaintFlow,
    GuardInfo,
    AccessPath,
)


@dataclass
class FindingContext:
    """Rich context gathered for a single finding."""

    code_snippet: str
    enclosing_function: str
    function_body: str
    callers: list[CallerInfo] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    related_definitions: list[str] = field(default_factory=list)
    source: str = "unknown"  # "joern" or "gkg" or "tree_sitter"
    taint_reachable: Optional[bool] = None
    taint_sanitized: Optional[bool] = None
    taint_path: list[str] = field(default_factory=list)
    taint_sanitizers: list[str] = field(default_factory=list)
    taint_flow: Optional[TaintFlow] = None


class FindingVerdict(BaseModel):
    """LLM verdict for a single finding."""

    finding_index: int
    fingerprint: str = ""
    verdict: str = "uncertain"  # "true_positive", "false_positive", "uncertain"
    confidence: float = 0.0
    reasoning: str = ""
    remediation_code: Optional[str] = None
    remediation_explanation: Optional[str] = None
    status: str = "ok"  # "ok", "error", "parse_error"
    decision_source: str = "llm"  # "llm" or "human_override"
    applied_memory_ids: list[str] = Field(default_factory=list)
    dataflow_analysis: Optional[str] = None
    flow_steps: list[dict] = Field(
        default_factory=list
    )  # [{label, location, code, explanation}]
    override_id: Optional[str] = None

    def classification(self, threshold: float = 0.8) -> str:
        """Three-state classification with confidence threshold."""
        if self.verdict == "uncertain" or self.confidence < threshold:
            return "uncertain"
        return self.verdict


@dataclass
class FileGroupResult:
    """Analysis result for all findings in one file."""

    file_path: str
    verdicts: list[FindingVerdict] = field(default_factory=list)
    contexts: dict[int, FindingContext] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class AnalysisResult:
    """Complete analysis result."""

    repo_url: str
    commit_sha: str
    file_groups: list[FileGroupResult] = field(default_factory=list)
    commit_sha_mismatch: bool = False
    gkg_available: bool = True
    joern_available: bool = False
    sbom_profile: Optional[dict] = None  # serialized RepoProfile
    warnings: list[str] = field(default_factory=list)
