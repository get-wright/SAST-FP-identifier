"""Pydantic output schemas for LLM structured output."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class FlowStep(BaseModel):
    """One step in a data flow trace."""
    label: Literal["source", "propagation", "sanitizer", "sink"] = Field(
        description="Role of this step: source (data origin), propagation (intermediate transform), sanitizer (security check), sink (dangerous operation)"
    )
    location: str = Field(description="file:line or function name, e.g. 'sw.py:308' or 'request.args.get()'")
    code: str = Field(description="The code expression at this step, e.g. 'url = request.args.get(\"url\")' or 'hashlib.md5(url.encode())'")
    explanation: str = Field(description="Brief explanation of what happens at this step, e.g. 'User input enters via query parameter'")


class StepAnnotation(BaseModel):
    """LLM explanation for a grounded flow step."""
    step_index: int = Field(description="1-based index matching the grounded step position")
    explanation: str = Field(description="Brief explanation of what happens at this step")


class GapStep(BaseModel):
    """LLM-generated step to fill a gap in the grounded trace."""
    label: Literal["source", "propagation", "sanitizer", "sink"] = Field(description="Role of this gap step")
    location: str = Field(description="file:line")
    code: str = Field(description="The code expression")
    explanation: str = Field(description="What happens at this step")
    after_step: int = Field(description="Insert after this grounded step index (0 = before first)")


class VerdictOutput(BaseModel):
    """Single-pass verdict with dataflow analysis."""
    finding_index: int
    reasoning: str = Field(description="3-5 sentence natural paragraph explaining why this is/isn't a vulnerability")
    dataflow_analysis: str = Field(description="Paragraph tracing data flow, or 'Not applicable' for config findings")
    step_annotations: list[StepAnnotation] = Field(default_factory=list, description="Explanations for grounded flow steps, keyed by 1-based index")
    gap_steps: list[GapStep] = Field(default_factory=list, description="LLM-generated steps to fill gaps in the grounded trace")
    flow_steps: list[FlowStep] = Field(default_factory=list, description="Structured data flow steps from source to sink. Empty list for config/non-dataflow findings.")
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(description="0.0 to 1.0")
    remediation_code: Optional[str] = None
    remediation_explanation: Optional[str] = None


class VerdictOutputBatch(BaseModel):
    """Batch of verdicts for a file group."""
    verdicts: list[VerdictOutput]


class DataflowResult(BaseModel):
    """Stage 1: dataflow analysis only (no verdict)."""
    finding_index: int
    dataflow_analysis: str = Field(description="Paragraph tracing data movement from source to sink")
    step_annotations: list[StepAnnotation] = Field(default_factory=list, description="Explanations for grounded flow steps, keyed by 1-based index")
    gap_steps: list[GapStep] = Field(default_factory=list, description="LLM-generated steps to fill gaps in the grounded trace")
    flow_steps: list[FlowStep] = Field(default_factory=list, description="Structured data flow steps from source to sink. Empty list for config/non-dataflow findings.")
    flow_complete: bool = Field(description="True if full source-to-sink path is traceable")
    gaps: list[str] = Field(default_factory=list, description="What context is missing")


class DataflowBatch(BaseModel):
    """Batch of Stage 1 dataflow results."""
    results: list[DataflowResult]


class VerdictOnlyOutput(BaseModel):
    """Stage 2: verdict without dataflow (merged with Stage 1 later)."""
    finding_index: int
    reasoning: str = Field(description="3-5 sentence natural paragraph")
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(description="0.0 to 1.0")
    remediation_code: Optional[str] = None
    remediation_explanation: Optional[str] = None


class VerdictOnlyBatch(BaseModel):
    """Batch of Stage 2 verdict results."""
    verdicts: list[VerdictOnlyOutput]
