"""Smoke test — full pipeline with mocked LLM and gkg."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport
from src.api.app import create_app
from src.api.routes import set_orchestrator
from src.core.orchestrator import Orchestrator
from src.llm.schemas import VerdictOutput, VerdictOutputBatch


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
    app = create_app()

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

    mock_structured = AsyncMock()
    mock_structured.ainvoke.return_value = VerdictOutputBatch(verdicts=[
        VerdictOutput(
            finding_index=1,
            reasoning="exec with user input is dangerous",
            dataflow_analysis="User input flows directly to exec() call without sanitization.",
            verdict="true_positive",
            confidence=0.91,
        ),
    ])
    mock_llm = MagicMock()
    mock_llm.with_structured_output.return_value = mock_structured

    with patch.object(orch._repo, "clone", return_value=str(tmp_path)), \
         patch.object(orch._repo, "get_head_sha", return_value="abc123def456"), \
         patch.object(orch._repo, "validate_url"), \
         patch.object(orch._graph, "is_available", return_value=False):
        orch._llm = mock_llm

        # Create a fake file for tree-sitter to parse
        fake_file = tmp_path / "app.py"
        fake_file.write_text("def handler():\n    exec(user_input)\n")

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/analyze",
                json={"repo_url": "https://github.com/u/r", "semgrep_json": SEMGREP_JSON},
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


async def test_taint_flow_enrichment_e2e(tmp_path):
    """End-to-end: Semgrep finding → enrichment → taint flow → prompt includes flow."""
    vuln = tmp_path / "app.py"
    vuln.write_text(
        "def search(request):\n"
        "    query = request.args.get('q')\n"
        "    sql = f\"SELECT * FROM users WHERE name = '{query}'\"\n"
        "    cursor.execute(sql)\n"
    )

    from src.core.enricher import Enricher
    from src.models.semgrep import SemgrepFinding
    from src.llm.prompt_builder import build_grouped_prompt

    finding = SemgrepFinding.model_validate({
        "check_id": "python.lang.security.audit.sqli",
        "path": "app.py",
        "start": {"line": 4, "col": 4},
        "end": {"line": 4, "col": 25},
        "extra": {
            "message": "SQL injection",
            "severity": "WARNING",
            "fingerprint": "e2e123",
            "metadata": {"cwe": ["CWE-89: SQL Injection"]},
            "lines": "cursor.execute(sql)",
            "is_ignored": False,
        },
    })

    enricher = Enricher(repo_path=str(tmp_path))
    ctx = await enricher.enrich(finding)

    assert ctx.taint_flow is not None
    assert len(ctx.taint_flow.path) >= 2

    prompt = build_grouped_prompt(
        file_path="app.py",
        findings=[{"index": 0, "rule": "sqli", "line": 4, "message": "SQL injection"}],
        contexts={0: ctx},
    )
    assert "TRACED DATA FLOW" in prompt
