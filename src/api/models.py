"""API request/response models."""

from typing import Any, Optional
from pydantic import BaseModel, Field


class LLMOverride(BaseModel):
    """Optional per-request LLM provider override."""

    provider: str = Field(..., description="Provider name: fpt_cloud, openai, or anthropic")
    api_key: str = Field(..., description="LLM API key")
    model: Optional[str] = Field(None, description="Model name (uses provider default if omitted)")
    base_url: Optional[str] = Field(None, description="Custom base URL for OpenAI-compatible APIs")
    is_reasoning_model: bool = Field(False, description="Use higher token budget for reasoning models (o1, o3, gpt-oss, DeepSeek-R1)")


class AnalyzeRequest(BaseModel):
    repo_url: str = Field(..., description="Repository HTTPS URL")
    semgrep_json: dict[str, Any] = Field(..., description="Raw Semgrep --json output")
    commit_sha: Optional[str] = Field(None, description="Expected commit SHA (optional)")
    git_token: Optional[str] = Field(None, description="OAuth/PAT token for private repo access")
    llm_override: Optional[LLMOverride] = Field(None, description="Override the server's default LLM provider")


class AnalyzeResponse(BaseModel):
    annotated_json: dict[str, Any]
    markdown_summary: str
    warnings: list[str] = []
    sbom_profile: Optional[dict[str, Any]] = None
