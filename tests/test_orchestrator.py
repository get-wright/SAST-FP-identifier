"""Tests for orchestrator — mocks external dependencies."""

import asyncio
import json

import pytest
from unittest.mock import AsyncMock, patch
from src.core.orchestrator import Orchestrator
from src.models.analysis import CallerInfo, FindingContext, FindingVerdict
from src.models.semgrep import parse_semgrep_json


SAMPLE_SEMGREP = {
    "version": "1.1.0",
    "results": [
        {
            "check_id": "sql-injection",
            "path": "app.py",
            "start": {"line": 10, "col": 1},
            "end": {"line": 10, "col": 30},
            "extra": {
                "message": "SQL injection", "severity": "HIGH",
                "fingerprint": "fp1", "lines": "q = f'SELECT...'",
                "metadata": {}, "is_ignored": False,
            },
        },
    ],
    "errors": [],
    "paths": {"scanned": ["app.py"], "skipped": []},
}


@pytest.fixture
def orchestrator(tmp_path):
    return Orchestrator(
        repos_cache_dir=str(tmp_path / "repos"),
        cache_dir=str(tmp_path / "cache"),
        triage_data_dir=str(tmp_path / "triage_data"),
        registry_path=str(tmp_path / "reg.json"),
        llm_provider="fpt_cloud",
        llm_api_key="test",
        llm_model="test",
        llm_base_url="http://test",
    )


@pytest.mark.asyncio
async def test_groups_findings_by_file(orchestrator):
    groups = orchestrator._group_findings(SAMPLE_SEMGREP)
    assert "app.py" in groups
    assert len(groups["app.py"]) == 1


@pytest.mark.asyncio
async def test_filters_ignored_findings(orchestrator):
    data = {
        **SAMPLE_SEMGREP,
        "results": [
            {**SAMPLE_SEMGREP["results"][0]},
            {**SAMPLE_SEMGREP["results"][0], "extra": {
                **SAMPLE_SEMGREP["results"][0]["extra"], "is_ignored": True,
            }},
        ],
    }
    groups = orchestrator._group_findings(data)
    assert len(groups["app.py"]) == 1


@pytest.mark.asyncio
async def test_analyze_returns_result(orchestrator):
    """Full pipeline with mocked externals."""
    mock_verdict = FindingVerdict(
        finding_index=0, fingerprint="fp1",
        verdict="true_positive", confidence=0.9, reasoning="Vulnerable",
    )

    with patch.object(orchestrator._repo, "clone", return_value="/tmp/repo"), \
         patch.object(orchestrator._repo, "get_head_sha", return_value="abc123"), \
         patch.object(orchestrator._graph, "ensure_index_and_server", new_callable=AsyncMock, return_value=False), \
         patch.object(orchestrator._graph, "is_available", return_value=False), \
         patch.object(orchestrator, "_analyze_file_group", new_callable=AsyncMock, return_value=[mock_verdict]):
        result = await orchestrator.analyze("https://github.com/u/r", SAMPLE_SEMGREP)

    assert result.commit_sha == "abc123"
    assert len(result.file_groups) == 1
    # Confidence adjusted based on evidence quality (tree-sitter only)
    # Raw 0.9 with evidence penalty applied — should be lower than raw
    assert result.file_groups[0].verdicts[0].confidence < 0.9


@pytest.mark.asyncio
async def test_process_file_group_preserves_cached_contexts(orchestrator):
    findings = parse_semgrep_json(SAMPLE_SEMGREP)
    verdict = FindingVerdict(
        finding_index=0,
        fingerprint="fp1",
        verdict="true_positive",
        confidence=0.9,
        reasoning="Vulnerable",
    )
    contexts = {
        "0": {
            "code_snippet": "query = f'SELECT...'",
            "enclosing_function": "index",
            "function_body": "def index(): ...",
            "callers": [{"file": "routes.py", "line": 12, "function": "dispatch", "context": "dispatch()"}],
            "callees": ["execute"],
            "imports": ["sqlite3"],
            "related_definitions": [],
            "source": "gkg",
        }
    }
    orchestrator._cache.set_with_contexts(
        "https://github.com/u/r",
        "abc123",
        "app.py",
        orchestrator._fingerprints_hash(findings),
        [verdict.model_dump()],
        contexts,
    )

    result = await orchestrator._process_file_group(
        "app.py",
        findings,
        enricher=AsyncMock(),
        repo_map="",
        commit_sha="abc123",
        repo_url="https://github.com/u/r",
    )

    assert result.verdicts[0].fingerprint == "fp1"
    assert result.contexts[0] == FindingContext(
        code_snippet="query = f'SELECT...'",
        enclosing_function="index",
        function_body="def index(): ...",
        callers=[CallerInfo(file="routes.py", line=12, function="dispatch", context="dispatch()")],
        callees=["execute"],
        imports=["sqlite3"],
        related_definitions=[],
        source="gkg",
    )


@pytest.mark.asyncio
async def test_analyze_emits_trace_events(orchestrator):
    """on_step callback receives trace events with timing."""
    mock_verdict = FindingVerdict(
        finding_index=0, fingerprint="fp1",
        verdict="true_positive", confidence=0.9, reasoning="Vulnerable",
    )

    trace_events = []

    async def on_step(event):
        trace_events.append(event)

    with patch.object(orchestrator._repo, "clone", return_value="/tmp/repo"), \
         patch.object(orchestrator._repo, "get_head_sha", return_value="abc123"), \
         patch.object(orchestrator._graph, "ensure_index_and_server", new_callable=AsyncMock, return_value=False), \
         patch.object(orchestrator._graph, "is_available", return_value=False), \
         patch.object(orchestrator, "_analyze_file_group", new_callable=AsyncMock, return_value=[mock_verdict]):
        result = await orchestrator.analyze(
            "https://github.com/u/r", SAMPLE_SEMGREP, on_step=on_step,
        )

    assert len(trace_events) > 0
    for evt in trace_events:
        assert evt["trace"] is True
        assert "step" in evt
        assert "status" in evt
    steps = [e["step"] for e in trace_events]
    assert "repo_clone" in steps
    assert "gkg_check" in steps


@pytest.mark.asyncio
async def test_analyze_emits_in_progress_trace_for_long_setup_steps(orchestrator):
    """Long setup steps should emit in-progress traces before they complete."""
    mock_verdict = FindingVerdict(
        finding_index=0, fingerprint="fp1",
        verdict="true_positive", confidence=0.9, reasoning="Vulnerable",
    )

    trace_events = []

    async def on_step(event):
        trace_events.append(event)

    def slow_clone(*args, **kwargs):
        import time
        time.sleep(0.05)
        return "/tmp/repo"

    async def slow_ensure(*args, **kwargs):
        await asyncio.sleep(0.05)
        return False

    with patch.object(orchestrator._repo, "clone", side_effect=slow_clone), \
         patch.object(orchestrator._repo, "get_head_sha", return_value="abc123"), \
         patch.object(orchestrator._graph, "ensure_index_and_server", side_effect=slow_ensure), \
         patch.object(orchestrator._graph, "is_available", return_value=True), \
         patch.object(orchestrator, "_analyze_file_group", new_callable=AsyncMock, return_value=[mock_verdict]):
        await orchestrator.analyze(
            "https://github.com/u/r", SAMPLE_SEMGREP, on_step=on_step,
        )

    repo_clone_statuses = [e["status"] for e in trace_events if e["step"] == "repo_clone"]
    gkg_index_statuses = [e["status"] for e in trace_events if e["step"] == "gkg_index"]
    assert repo_clone_statuses[:2] == ["in_progress", "completed"]
    assert gkg_index_statuses[:2] == ["in_progress", "error"]


@pytest.mark.asyncio
async def test_process_file_group_applies_reviewer_override(orchestrator, tmp_path):
    triage_dir = tmp_path / "triage_data"
    triage_dir.mkdir(exist_ok=True)
    (triage_dir / "overrides.json").write_text(json.dumps({
        "version": 1,
        "overrides": [
            {
                "id": "override-1",
                "repo_url": "https://github.com/u/r",
                "fingerprint": "fp1",
                "verdict": "false_positive",
                "confidence": 1.0,
                "reasoning": "Human reviewer confirmed the input is a fixed constant.",
            },
        ],
    }))

    findings = parse_semgrep_json(SAMPLE_SEMGREP)
    contexts = {
        0: FindingContext(
            code_snippet="q = f'SELECT...'",
            enclosing_function="index",
            function_body="def index(): ...",
            callers=[],
            callees=["execute"],
            imports=["sqlite3"],
            related_definitions=[],
            source="tree_sitter",
        ),
    }

    with patch.object(orchestrator, "_analyze_file_group", new_callable=AsyncMock, return_value=[
        FindingVerdict(
            finding_index=0,
            fingerprint="fp1",
            verdict="true_positive",
            confidence=0.91,
            reasoning="LLM says vulnerable",
        )
    ]):
        result = await orchestrator._process_file_group(
            "app.py",
            findings,
            enricher=AsyncMock(enrich=AsyncMock(return_value=contexts[0])),
            repo_map="",
            commit_sha="abc123",
            repo_url="https://github.com/u/r",
        )

    verdict = result.verdicts[0]
    assert verdict.verdict == "false_positive"
    assert verdict.confidence == 1.0
    assert verdict.reasoning == "Human reviewer confirmed the input is a fixed constant."
    assert verdict.decision_source == "human_override"
    assert verdict.override_id == "override-1"


@pytest.mark.asyncio
async def test_process_file_group_does_not_use_stale_cache_when_override_changes(orchestrator, tmp_path):
    findings = parse_semgrep_json(SAMPLE_SEMGREP)
    fp_hash = orchestrator._fingerprints_hash(findings)
    orchestrator._cache.set_with_contexts(
        "https://github.com/u/r",
        "abc123",
        "app.py",
        fp_hash,
        [
            FindingVerdict(
                finding_index=0,
                fingerprint="fp1",
                verdict="true_positive",
                confidence=0.95,
                reasoning="Cached LLM verdict",
            ).model_dump()
        ],
        {
            "0": {
                "code_snippet": "query = f'SELECT...'",
                "enclosing_function": "index",
                "function_body": "def index(): ...",
                "callers": [],
                "callees": ["execute"],
                "imports": ["sqlite3"],
                "related_definitions": [],
                "source": "tree_sitter",
            }
        },
    )

    triage_dir = tmp_path / "triage_data"
    triage_dir.mkdir(exist_ok=True)
    (triage_dir / "overrides.json").write_text(json.dumps({
        "version": 1,
        "overrides": [
            {
                "id": "override-2",
                "repo_url": "https://github.com/u/r",
                "fingerprint": "fp1",
                "verdict": "false_positive",
                "confidence": 1.0,
                "reasoning": "Override changed after cached result was written.",
            },
        ],
    }))

    with patch.object(orchestrator, "_analyze_file_group", new_callable=AsyncMock, return_value=[
        FindingVerdict(
            finding_index=0,
            fingerprint="fp1",
            verdict="true_positive",
            confidence=0.91,
            reasoning="Fresh LLM verdict",
        )
    ]) as mock_analyze:
        result = await orchestrator._process_file_group(
            "app.py",
            findings,
            enricher=AsyncMock(enrich=AsyncMock(return_value=FindingContext(
                code_snippet="q = f'SELECT...'",
                enclosing_function="index",
                function_body="def index(): ...",
                callers=[],
                callees=["execute"],
                imports=["sqlite3"],
                related_definitions=[],
                source="tree_sitter",
            ))),
            repo_map="",
            commit_sha="abc123",
            repo_url="https://github.com/u/r",
        )

    assert mock_analyze.await_count == 1
    verdict = result.verdicts[0]
    assert verdict.verdict == "false_positive"
    assert verdict.override_id == "override-2"


def test_taint_flow_boosts_evidence_score():
    from src.core.orchestrator import _base_evidence
    from src.models.analysis import FindingContext, FlowStep, TaintFlow

    flow = TaintFlow(
        path=[
            FlowStep(variable="x", line=1, expression="param", kind="parameter"),
            FlowStep(variable="x", line=2, expression="eval(x)", kind="sink"),
        ],
        sanitizers=[],
        unresolved_calls=[],
        cross_file_hops=[],
        confidence_factors=["Direct source to sink with no sanitizer"],
        inferred=None,
    )
    ctx = FindingContext(
        code_snippet="eval(x)", enclosing_function="f", function_body="def f(x): eval(x)",
        taint_flow=flow,
    )
    score = _base_evidence(ctx, "app.py")
    assert score >= 0.80


def test_taint_flow_sanitizer_lowers_evidence():
    from src.core.orchestrator import _base_evidence
    from src.models.analysis import FindingContext, FlowStep, SanitizerInfo, TaintFlow

    flow = TaintFlow(
        path=[
            FlowStep(variable="x", line=1, expression="param", kind="parameter"),
            FlowStep(variable="x", line=2, expression="safe = escape(x)", kind="call_result"),
            FlowStep(variable="safe", line=3, expression="output(safe)", kind="sink"),
        ],
        sanitizers=[SanitizerInfo(name="escape", line=2, cwe_categories=["CWE-79"], conditional=False, verified=True)],
        unresolved_calls=[],
        cross_file_hops=[],
        confidence_factors=[],
        inferred=None,
    )
    ctx = FindingContext(
        code_snippet="output(safe)", enclosing_function="f", function_body="...",
        taint_flow=flow,
    )
    score = _base_evidence(ctx, "app.py")
    assert score <= 0.70
