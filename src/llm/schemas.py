"""Pydantic output schemas for LLM structured output."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class VerdictOutput(BaseModel):
    """Single finding verdict — matches current LLM output format."""
    finding_index: int
    reasoning: str = Field(description="Security analysis reasoning")
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(ge=0.0, le=1.0)
    remediation_code: Optional[str] = None
    remediation_explanation: Optional[str] = None


class VerdictOutputBatch(BaseModel):
    """Batch of verdicts for a file group."""
    verdicts: list[VerdictOutput]
