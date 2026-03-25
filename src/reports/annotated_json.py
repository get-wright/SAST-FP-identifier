"""Build annotated Semgrep JSON with x_fp_analysis per finding."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any, Optional

from src.models.analysis import FindingContext, FindingVerdict


def build_annotated_json(
    original: dict[str, Any],
    verdicts_by_file: dict[str, list[FindingVerdict]],
    commit_sha: str,
    llm_provider: str,
    contexts_by_file: Optional[dict[str, dict[int, FindingContext]]] = None,
) -> dict[str, Any]:
    """Inject x_fp_analysis into each finding's extra dict.

    Matches verdicts to findings by fingerprint within each file group.
    Unmatched findings get a placeholder with confidence=0.0.
    """
    output = copy.deepcopy(original)

    for finding in output.get("results", []):
        path = finding.get("path", "")
        fingerprint = finding.get("extra", {}).get("fingerprint", "")
        verdicts = verdicts_by_file.get(path, [])

        matched = _match_verdict(verdicts, fingerprint)

        if matched:
            analysis = {
                "verdict": matched.verdict,
                "classification": matched.classification(),
                "confidence": matched.confidence,
                "reasoning": matched.reasoning,
                "remediation_code": matched.remediation_code,
                "remediation_explanation": matched.remediation_explanation,
                "decision_source": matched.decision_source,
                "applied_memory_ids": matched.applied_memory_ids,
                "override_id": matched.override_id,
                "dataflow_analysis": matched.dataflow_analysis,
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
                "commit_sha": commit_sha,
                "llm_provider": llm_provider,
                "status": matched.status,
            }

            gc = _find_graph_context(contexts_by_file, path, verdicts, fingerprint)
            if gc is not None:
                analysis["graph_context"] = gc

            finding["extra"]["x_fp_analysis"] = analysis
        else:
            finding["extra"]["x_fp_analysis"] = {
                "verdict": "uncertain",
                "classification": "uncertain",
                "confidence": 0.0,
                "reasoning": "",
                "remediation_code": None,
                "remediation_explanation": None,
                "decision_source": "none",
                "applied_memory_ids": [],
                "override_id": None,
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
                "commit_sha": commit_sha,
                "llm_provider": llm_provider,
                "status": "no_verdict",
            }

    return output


def _match_verdict(
    verdicts: list[FindingVerdict], fingerprint: str
) -> FindingVerdict | None:
    for v in verdicts:
        if v.fingerprint == fingerprint:
            return v
    return None


def _find_graph_context(
    contexts_by_file: Optional[dict[str, dict[int, FindingContext]]],
    path: str,
    verdicts: list[FindingVerdict],
    fingerprint: str,
) -> dict | None:
    """Look up FindingContext for this finding and serialize to graph_context dict."""
    if not contexts_by_file:
        return None

    file_contexts = contexts_by_file.get(path)
    if not file_contexts:
        return None

    matched_verdict = _match_verdict(verdicts, fingerprint)
    if matched_verdict is None:
        return None

    ctx = file_contexts.get(matched_verdict.finding_index)
    if ctx is None:
        return None

    gc = {
        "enclosing_function": ctx.enclosing_function or None,
        "callers": [
            {"file": c.file, "line": c.line, "function": c.function, "context": c.context}
            for c in ctx.callers
        ],
        "callees": ctx.callees,
        "imports": ctx.imports,
        "source": ctx.source,
    }
    if ctx.taint_reachable is not None:
        gc["taint_reachable"] = ctx.taint_reachable
        gc["taint_sanitized"] = ctx.taint_sanitized
        gc["taint_path"] = ctx.taint_path
        gc["taint_sanitizers"] = ctx.taint_sanitizers
    return gc
