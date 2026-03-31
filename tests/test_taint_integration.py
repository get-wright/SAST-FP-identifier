"""Integration tests: enricher -> new taint engine -> prompt builder pipeline."""

import os
from src.core.enricher import Enricher
from src.models.semgrep import SemgrepFinding
from src.llm.prompt_builder import _render_taint_flow

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _make_finding(
    path: str, line: int, check_id: str, cwe: list[str]
) -> SemgrepFinding:
    return SemgrepFinding.model_validate(
        {
            "check_id": check_id,
            "path": path,
            "start": {"line": line, "col": 1},
            "end": {"line": line, "col": 50},
            "extra": {
                "message": "test finding",
                "severity": "WARNING",
                "fingerprint": "test123",
                "lines": "test",
                "metadata": {"cwe": cwe},
                "is_ignored": False,
            },
        }
    )


async def test_enricher_produces_taint_flow_with_guards():
    enricher = Enricher(repo_path=os.path.dirname(FIXTURES))
    finding = _make_finding(
        path="fixtures/taint_guards.py",
        line=8,
        check_id="python.ssrf",
        cwe=["CWE-918"],
    )
    ctx = await enricher.enrich(finding)
    assert ctx.taint_flow is not None
    assert len(ctx.taint_flow.guards) >= 1
    assert ctx.taint_flow.guards[0].name == "re.match"


async def test_enricher_taint_flow_rendered_with_guards():
    enricher = Enricher(repo_path=os.path.dirname(FIXTURES))
    finding = _make_finding(
        path="fixtures/taint_guards.py",
        line=8,
        check_id="python.ssrf",
        cwe=["CWE-918"],
    )
    ctx = await enricher.enrich(finding)
    rendered = _render_taint_flow(ctx.taint_flow)
    assert "GUARDS IN PATH" in rendered


async def test_enricher_basic_sqli():
    enricher = Enricher(repo_path=os.path.dirname(FIXTURES))
    finding = _make_finding(
        path="fixtures/taint_sample.py",
        line=8,
        check_id="python.sqli",
        cwe=["CWE-89"],
    )
    ctx = await enricher.enrich(finding)
    assert ctx.taint_flow is not None
    assert len(ctx.taint_flow.path) >= 2
    assert ctx.taint_flow.source.variable == "user_input"


async def test_enricher_multiline_call():
    enricher = Enricher(repo_path=os.path.dirname(FIXTURES))
    finding = _make_finding(
        path="fixtures/taint_sample.py",
        line=39,
        check_id="python.ssrf",
        cwe=["CWE-918"],
    )
    ctx = await enricher.enrich(finding)
    assert ctx.taint_flow is not None
    assert len(ctx.taint_flow.path) >= 2


async def test_enricher_js_innerhtml():
    enricher = Enricher(repo_path=os.path.dirname(FIXTURES))
    finding = _make_finding(
        path="fixtures/taint_sample.js",
        line=24,
        check_id="javascript.xss",
        cwe=["CWE-79"],
    )
    ctx = await enricher.enrich(finding)
    assert ctx.taint_flow is not None
    assert ctx.taint_flow.source.kind == "parameter"
