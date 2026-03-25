"""Pydantic output schemas for LLM structured output."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class VerdictOutput(BaseModel):
    """Single-pass verdict with dataflow analysis."""
    finding_index: int
    reasoning: str = Field(description="3-5 sentence natural paragraph explaining why this is/isn't a vulnerability")
    dataflow_analysis: str = Field(description="Paragraph tracing data flow, or 'Not applicable' for config findings")
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(ge=0.0, le=1.0)
    remediation_code: Optional[str] = None
    remediation_explanation: Optional[str] = None


class VerdictOutputBatch(BaseModel):
    """Batch of verdicts for a file group."""
    verdicts: list[VerdictOutput]


class DataflowResult(BaseModel):
    """Stage 1: dataflow analysis only (no verdict)."""
    finding_index: int
    dataflow_analysis: str = Field(description="Paragraph tracing data movement from source to sink")
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
    confidence: float = Field(ge=0.0, le=1.0)
    remediation_code: Optional[str] = None
    remediation_explanation: Optional[str] = None


class VerdictOnlyBatch(BaseModel):
    """Batch of Stage 2 verdict results."""
    verdicts: list[VerdictOnlyOutput]
