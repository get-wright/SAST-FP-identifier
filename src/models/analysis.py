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


@dataclass
class FlowStep:
    """One step in a taint flow trace."""

    variable: str
    line: int
    expression: str
    kind: str  # "source" | "parameter" | "assignment" | "call_result" | "return" | "sink"

    def to_dict(self) -> dict:
        return {"variable": self.variable, "line": self.line, "expression": self.expression, "kind": self.kind}


@dataclass
class SanitizerInfo:
    """A sanitizer found in the taint path."""

    name: str
    line: int
    cwe_categories: list[str]
    conditional: bool
    verified: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name, "line": self.line, "cwe_categories": self.cwe_categories,
            "conditional": self.conditional, "verified": self.verified,
        }


@dataclass
class InferredSinkSource:
    """Sink/source inferred from finding metadata when rule lacks explicit taint mode."""

    sink_expression: str
    sink_type: str  # "sql_query" | "command_exec" | "html_output" | "file_path" | "generic"
    expected_sources: list[str]
    inferred_from: str  # "cwe" | "rule_id" | "code_pattern" | "heuristic"

    def to_dict(self) -> dict:
        return {
            "sink_expression": self.sink_expression, "sink_type": self.sink_type,
            "expected_sources": self.expected_sources, "inferred_from": self.inferred_from,
        }


@dataclass
class CrossFileHop:
    """A cross-file resolution step in the taint chain."""

    callee: str
    file: str
    line: int
    action: str  # "propagates" | "sanitizes" | "transforms" | "unknown"
    sub_flow: Optional[TaintFlow] = None

    def to_dict(self) -> dict:
        return {
            "callee": self.callee, "file": self.file, "line": self.line,
            "action": self.action,
            "sub_flow": self.sub_flow.to_dict() if self.sub_flow else None,
        }


@dataclass
class TaintFlow:
    """Complete taint flow trace for a single finding."""

    path: list[FlowStep]
    sanitizers: list[SanitizerInfo] = field(default_factory=list)
    unresolved_calls: list[str] = field(default_factory=list)
    cross_file_hops: list[CrossFileHop] = field(default_factory=list)
    confidence_factors: list[str] = field(default_factory=list)
    inferred: Optional[InferredSinkSource] = None

    @property
    def source(self) -> FlowStep:
        return self.path[0]

    @property
    def sink(self) -> FlowStep:
        return self.path[-1]

    def to_dict(self) -> dict:
        return {
            "path": [s.to_dict() for s in self.path],
            "sanitizers": [s.to_dict() for s in self.sanitizers],
            "unresolved_calls": self.unresolved_calls,
            "cross_file_hops": [h.to_dict() for h in self.cross_file_hops],
            "confidence_factors": self.confidence_factors,
            "inferred": self.inferred.to_dict() if self.inferred else None,
        }


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
