"""Tests for API endpoints."""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport
from src.api.app import create_app
from src.models.analysis import AnalysisResult, CallerInfo, FileGroupResult, FindingContext, FindingVerdict


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_analyze_with_auth(client):
    mock_result = AnalysisResult(
        repo_url="https://github.com/u/r",
        commit_sha="abc",
        file_groups=[],
    )
    with patch("src.api.routes.get_orchestrator") as mock_orch:
        mock_orch.return_value.analyze = AsyncMock(return_value=mock_result)
        mock_orch.return_value._repo.validate_url = lambda x: None
        mock_orch.return_value._llm_provider_name = "fpt_cloud"
        resp = await client.post(
            "/analyze",
            json={
                "repo_url": "https://github.com/u/r",
                "semgrep_json": {"version": "1", "results": [], "errors": [], "paths": {}},
            },
        )
    assert resp.status_code == 200
    assert "annotated_json" in resp.json()
    assert "markdown_summary" in resp.json()


@pytest.mark.asyncio
async def test_analyze_includes_graph_context_in_annotated_json(client):
    mock_result = AnalysisResult(
        repo_url="https://github.com/u/r",
        commit_sha="abc",
        file_groups=[
            FileGroupResult(
                file_path="app.py",
                verdicts=[
                    FindingVerdict(
                        finding_index=0,
                        fingerprint="fp1",
                        verdict="true_positive",
                        confidence=0.91,
                        reasoning="Vulnerable path remains reachable",
                    )
                ],
                contexts={
                    0: FindingContext(
                        code_snippet="query = f'SELECT ...'",
                        enclosing_function="index",
                        function_body="def index(): ...",
                        callers=[
                            CallerInfo(
                                file="routes.py",
                                line=12,
                                function="dispatch",
                                context="dispatch()",
                            )
                        ],
                        callees=["execute"],
                        imports=["sqlite3"],
                        source="gkg",
                    )
                },
            )
        ],
    )
    with patch("src.api.routes.get_orchestrator") as mock_orch:
        mock_orch.return_value.analyze = AsyncMock(return_value=mock_result)
        mock_orch.return_value._repo.validate_url = lambda x: None
        mock_orch.return_value._llm_provider_name = "fpt_cloud"
        resp = await client.post(
            "/analyze",
            json={
                "repo_url": "https://github.com/u/r",
                "semgrep_json": {
                    "version": "1",
                    "results": [
                        {
                            "check_id": "sql-injection",
                            "path": "app.py",
                            "start": {"line": 10, "col": 1},
                            "end": {"line": 10, "col": 20},
                            "extra": {
                                "message": "SQL injection",
                                "severity": "HIGH",
                                "fingerprint": "fp1",
                                "lines": "query = f'SELECT ...'",
                            },
                        }
                    ],
                    "errors": [],
                    "paths": {"scanned": ["app.py"], "skipped": []},
                },
            },
        )

    assert resp.status_code == 200
    graph_context = resp.json()["annotated_json"]["results"][0]["extra"]["x_fp_analysis"]["graph_context"]
    assert graph_context == {
        "enclosing_function": "index",
        "callers": [{"file": "routes.py", "line": 12, "function": "dispatch", "context": "dispatch()"}],
        "callees": ["execute"],
        "imports": ["sqlite3"],
        "source": "gkg",
    }


@pytest.mark.asyncio
async def test_middleware_exempts_non_analyze_paths(client):
    """Non-analyze paths should not require API key."""
    resp = await client.get("/health")
    assert resp.status_code == 200

    resp = await client.get("/docs")
    assert resp.status_code != 401


@pytest.mark.asyncio
async def test_analyze_validates_body(client):
    resp = await client.post(
        "/analyze",
        json={"repo_url": "not-a-url"},
        headers={"X-API-Key": "test-key"},
    )
    assert resp.status_code == 422 or resp.status_code == 400


@pytest.mark.asyncio
async def test_analyze_stream_sends_keepalive_during_idle_wait(client):
    mock_result = AnalysisResult(
        repo_url="https://github.com/u/r",
        commit_sha="abc",
        file_groups=[],
    )

    async def slow_analyze(**kwargs):
        await asyncio.sleep(0.03)
        return mock_result

    with patch("src.api.routes.get_orchestrator") as mock_orch, \
         patch("src.api.routes._STREAM_HEARTBEAT_SECONDS", 0.01):
        mock_orch.return_value.analyze = AsyncMock(side_effect=slow_analyze)
        mock_orch.return_value._repo.validate_url = lambda x: None
        mock_orch.return_value._llm_provider_name = "fpt_cloud"

        resp = await client.post(
            "/analyze/stream",
            json={
                "repo_url": "https://github.com/u/r",
                "semgrep_json": {"version": "1", "results": [], "errors": [], "paths": {}},
            },
        )

    assert resp.status_code == 200
    assert ": keep-alive" in resp.text
    assert '"step": "done"' in resp.text
