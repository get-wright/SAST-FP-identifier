"""Tests for enricher helpers."""

from unittest.mock import AsyncMock, MagicMock, patch

from src.core.enricher import Enricher, _parse_callers
from src.graph.joern_client import CallGraphResult, TaintResult
from src.models.semgrep import SemgrepFinding


def test_parse_callers_supports_nested_gkg_references_payload():
    refs = [
        {
            "definitions": [
                {
                    "name": "index",
                    "references": [
                        {
                            "file_path": "app/routes.py",
                            "range": {"start": {"line": 12}},
                            "enclosing_definition_name": "dispatch",
                            "context": "dispatch()",
                        }
                    ],
                }
            ]
        }
    ]

    callers = _parse_callers(refs)

    assert len(callers) == 1
    assert callers[0].file == "app/routes.py"
    assert callers[0].line == 12
    assert callers[0].function == "dispatch"
    assert callers[0].context == "dispatch()"


async def test_joern_enrichment_populates_callers_and_callees():
    """Joern call graph results should populate ctx.callers and ctx.callees."""
    mock_joern = AsyncMock()
    mock_joern.taint_check.return_value = TaintResult()
    mock_joern.get_call_graph.return_value = CallGraphResult(
        enclosing_method="handle_request",
        callers=[{"name": "dispatch", "file": "routes.py", "line": 15}],
        callees=["db_query", "validate"],
    )

    finding = SemgrepFinding(
        check_id="rules.sqli",
        path="app.py",
        start={"line": 42, "col": 1},
        end={"line": 42, "col": 30},
        extra={"message": "SQL injection", "severity": "ERROR"},
    )

    with patch("src.core.enricher.TreeSitterReader") as mock_ts_cls:
        mock_ts = MagicMock()
        mock_ts.read_context.return_value = "code snippet"
        mock_ts.find_enclosing_function.return_value = ""
        mock_ts.get_function_body.return_value = ""
        mock_ts.find_callees.return_value = []
        mock_ts.find_imports.return_value = []
        mock_ts_cls.return_value = mock_ts

        enricher = Enricher(
            repo_path="/repos/test",
            joern_client=mock_joern,
            joern_available=True,
        )
        ctx = await enricher.enrich(finding)

    assert ctx.source == "joern"
    assert ctx.enclosing_function == "handle_request"
    assert len(ctx.callers) == 1
    assert ctx.callers[0].function == "dispatch"
    assert ctx.callers[0].file == "routes.py"
    assert ctx.callers[0].line == 15
    assert ctx.callees == ["db_query", "validate"]


async def test_joern_enrichment_preserves_existing_callees():
    """Joern should not overwrite callees already populated by tree-sitter."""
    mock_joern = AsyncMock()
    mock_joern.taint_check.return_value = TaintResult()
    mock_joern.get_call_graph.return_value = CallGraphResult(
        enclosing_method="handler",
        callers=[],
        callees=["joern_callee"],
    )

    finding = SemgrepFinding(
        check_id="rules.xss",
        path="app.py",
        start={"line": 10, "col": 1},
        end={"line": 10, "col": 20},
        extra={"message": "XSS", "severity": "WARNING"},
    )

    with patch("src.core.enricher.TreeSitterReader") as mock_ts_cls:
        mock_ts = MagicMock()
        mock_ts.read_context.return_value = "snippet"
        mock_ts.find_enclosing_function.return_value = "handler"
        mock_ts.get_function_body.return_value = "def handler(): ..."
        mock_ts.find_callees.return_value = ["ts_callee"]
        mock_ts.find_imports.return_value = []
        mock_ts_cls.return_value = mock_ts

        enricher = Enricher(
            repo_path="/repos/test",
            joern_client=mock_joern,
            joern_available=True,
        )
        ctx = await enricher.enrich(finding)

    # Tree-sitter callees should be preserved since they were populated first
    assert ctx.callees == ["ts_callee"]


async def test_enrich_skips_joern_for_yaml(tmp_path):
    f = tmp_path / ".github" / "workflows"
    f.mkdir(parents=True)
    yml = f / "ci.yml"
    yml.write_text("name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n")

    mock_joern = AsyncMock()
    mock_joern.taint_check = AsyncMock()
    mock_joern.get_call_graph = AsyncMock()

    enricher = Enricher(
        repo_path=str(tmp_path),
        joern_client=mock_joern,
        joern_available=True,
        joern_path_translator=lambda p: p,
    )

    finding = SemgrepFinding(
        check_id="yaml.shell-injection",
        path=".github/workflows/ci.yml",
        start={"line": 4, "col": 1},
        end={"line": 4, "col": 10},
        extra={"message": "test", "severity": "ERROR", "fingerprint": "yaml123"},
    )
    ctx = await enricher.enrich(finding)

    mock_joern.taint_check.assert_not_called()
    assert ctx.taint_reachable is None
