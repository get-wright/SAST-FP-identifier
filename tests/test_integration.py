"""Smoke test — full pipeline with mocked LLM and gkg."""

import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport
from src.api.app import create_app
from src.api.routes import set_orchestrator
from src.core.orchestrator import Orchestrator


SEMGREP_JSON = {
    "version": "1.1.0",
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected",
            "path": "app.py",
            "start": {"line": 2, "col": 1},
            "end": {"line": 2, "col": 20},
            "extra": {
                "message": "exec usage detected",
                "severity": "WARNING",
                "fingerprint": "smoke-fp-1",
                "lines": "exec(user_input)",
                "metadata": {"confidence": "HIGH"},
                "is_ignored": False,
            },
        },
    ],
    "errors": [],
    "paths": {"scanned": ["app.py"], "skipped": []},
}


@pytest.mark.asyncio
async def test_full_pipeline_mocked(tmp_path):
    """End-to-end: API -> orchestrator -> mocked LLM -> response."""
    app = create_app(api_key="test")

    orch = Orchestrator(
        repos_cache_dir=str(tmp_path / "repos"),
        cache_dir=str(tmp_path / "cache"),
        registry_path=str(tmp_path / "reg.json"),
        llm_provider="fpt_cloud",
        llm_api_key="fake",
        llm_model="test",
        llm_base_url="http://fake",
        cache_enabled=False,
    )
    set_orchestrator(orch)

    llm_response = '[{"finding_index": 1, "reasoning": "exec with user input is dangerous", "verdict": "true_positive", "confidence": 0.91, "remediation_code": null, "remediation_explanation": null}]'

    with patch.object(orch._repo, "clone", return_value=str(tmp_path)), \
         patch.object(orch._repo, "get_head_sha", return_value="abc123def456"), \
         patch.object(orch._repo, "validate_url"), \
         patch.object(orch._graph, "is_available", return_value=False), \
         patch.object(orch._llm, "complete", new_callable=AsyncMock, return_value=llm_response):

        # Create a fake file for tree-sitter to parse
        fake_file = tmp_path / "app.py"
        fake_file.write_text("def handler():\n    exec(user_input)\n")

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/analyze",
                json={"repo_url": "https://github.com/u/r", "semgrep_json": SEMGREP_JSON},
                headers={"X-API-Key": "test"},
            )

    assert resp.status_code == 200
    data = resp.json()
    assert "annotated_json" in data
    assert "markdown_summary" in data
    assert "True Positives" in data["markdown_summary"] or "Uncertain" in data["markdown_summary"]

    # Check x_fp_analysis was injected
    results = data["annotated_json"]["results"]
    assert len(results) == 1
    assert "x_fp_analysis" in results[0]["extra"]
