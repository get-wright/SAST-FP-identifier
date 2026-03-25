"""API route handlers."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from src.api.models import AnalyzeRequest, AnalyzeResponse
from src.core.orchestrator import Orchestrator
from src.llm.provider import create_provider
from src.reports.annotated_json import build_annotated_json
from src.reports.markdown_summary import build_markdown_summary

# Default models per provider (used when model is not specified in override)
_DEFAULT_MODELS = {
    "fpt_cloud": "GLM-4.5",
    "openai": "gpt-4.1",
    "anthropic": "claude-sonnet-4-6",
    "openrouter": "anthropic/claude-sonnet-4-6",
}


def _build_llm_override(request: AnalyzeRequest):
    """Create a per-request LLM provider from override fields, or return None."""
    ovr = request.llm_override
    if not ovr:
        return None, None
    model = ovr.model or _DEFAULT_MODELS.get(ovr.provider, "")
    provider = create_provider(
        ovr.provider, ovr.api_key, model, ovr.base_url,
        is_reasoning_model=ovr.is_reasoning_model,
    )
    return provider, ovr.provider

logger = logging.getLogger(__name__)

router = APIRouter()
_STREAM_HEARTBEAT_SECONDS = 10.0

_orchestrator: Orchestrator | None = None


def set_orchestrator(orch: Orchestrator) -> None:
    global _orchestrator
    _orchestrator = orch


def get_orchestrator() -> Orchestrator:
    if _orchestrator is None:
        raise RuntimeError("Orchestrator not initialized")
    return _orchestrator


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "Semgrep False-Positive Analyzer"}


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    orch = get_orchestrator()

    try:
        orch._repo.validate_url(request.repo_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    llm_override, provider_name = _build_llm_override(request)

    try:
        result = await orch.analyze(
            repo_url=request.repo_url,
            semgrep_json=request.semgrep_json,
            commit_sha=request.commit_sha,
            git_token=request.git_token,
            llm_override=llm_override,
        )
    except Exception as e:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")

    verdicts_by_file = {
        fg.file_path: fg.verdicts for fg in result.file_groups
    }
    contexts_by_file = {
        fg.file_path: fg.contexts for fg in result.file_groups if fg.contexts
    }
    annotated = build_annotated_json(
        request.semgrep_json, verdicts_by_file,
        result.commit_sha, provider_name or orch._llm_provider_name,
        contexts_by_file=contexts_by_file,
    )
    markdown = build_markdown_summary(result)

    return AnalyzeResponse(
        annotated_json=annotated,
        markdown_summary=markdown,
        warnings=result.warnings,
        sbom_profile=result.sbom_profile,
    )


@router.post("/analyze/stream")
async def analyze_stream(request: AnalyzeRequest):
    orch = get_orchestrator()

    try:
        orch._repo.validate_url(request.repo_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    llm_override, provider_name = _build_llm_override(request)

    async def event_generator():
        queue: asyncio.Queue[dict] = asyncio.Queue()
        trace_events: list[dict] = []

        async def on_step(event):
            trace_events.append(event)
            await queue.put(event)

        async def run_analysis():
            return await orch.analyze(
                repo_url=request.repo_url,
                semgrep_json=request.semgrep_json,
                commit_sha=request.commit_sha,
                git_token=request.git_token,
                llm_override=llm_override,
                on_step=on_step,
            )

        task = asyncio.create_task(run_analysis())

        # Yield trace events as they arrive
        while True:
            if task.done() and queue.empty():
                break
            try:
                evt = await asyncio.wait_for(
                    queue.get(), timeout=_STREAM_HEARTBEAT_SECONDS
                )
            except asyncio.TimeoutError:
                yield _sse_comment("keep-alive")
                continue
            yield _sse(evt)

        # Get result (raises if orchestrator failed)
        try:
            result = await task
        except Exception as e:
            logger.exception("Analysis failed")
            yield _sse({"step": "error", "status": "error", "message": str(e), "progress": 0})
            return

        verdicts_by_file = {fg.file_path: fg.verdicts for fg in result.file_groups}
        contexts_by_file = {
            fg.file_path: fg.contexts for fg in result.file_groups if fg.contexts
        }
        annotated = build_annotated_json(
            request.semgrep_json, verdicts_by_file,
            result.commit_sha, provider_name or orch._llm_provider_name,
            contexts_by_file=contexts_by_file,
        )
        markdown = build_markdown_summary(result)

        yield _sse({
            "step": "done", "status": "completed", "progress": 100,
            "result": {
                "annotated_json": annotated,
                "markdown_summary": markdown,
                "warnings": result.warnings,
                "sbom_profile": result.sbom_profile,
                "trace_events": trace_events,
            },
        })

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _sse_comment(message: str) -> str:
    return f": {message}\n\n"
