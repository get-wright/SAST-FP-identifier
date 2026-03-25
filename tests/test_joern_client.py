"""Tests for JoernClient."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.graph.joern_client import (
    SANITIZER_PATTERNS,
    CallGraphResult,
    JoernClient,
    TaintResult,
)


def test_sanitizer_patterns_cover_common_cases():
    assert "xss" in SANITIZER_PATTERNS
    assert "sqli" in SANITIZER_PATTERNS
    assert "cmdi" in SANITIZER_PATTERNS
    assert len(SANITIZER_PATTERNS["xss"]) > 0
    assert len(SANITIZER_PATTERNS["sqli"]) > 0
    assert len(SANITIZER_PATTERNS["cmdi"]) > 0


def test_taint_result_dataclass():
    r = TaintResult(
        reachable=True,
        sanitized=False,
        path=["a.py:1:foo", "b.py:2:bar"],
        sanitizer_names=[],
    )
    assert r.reachable is True
    assert r.sanitized is False
    assert r.path == ["a.py:1:foo", "b.py:2:bar"]
    assert r.sanitizer_names == []


def test_taint_result_defaults():
    r = TaintResult()
    assert r.reachable is False
    assert r.sanitized is False
    assert r.path == []
    assert r.sanitizer_names == []


async def test_is_available_returns_false_on_connection_error():
    client = JoernClient(base_url="http://localhost:19999")
    result = await client.is_available()
    assert result is False


async def test_import_code_sends_query():
    client = JoernClient(base_url="http://localhost:8080")

    # _query_raw returns import result, _query returns workspace with project name
    with patch.object(client, "_query_raw", new_callable=AsyncMock, return_value={"success": False, "stdout": ""}), \
         patch.object(client, "_query", new_callable=AsyncMock, return_value="project: my_project"):
        result = await client.import_code("/repos/my_project")

    assert result is True


async def test_taint_check_parses_no_flows():
    client = JoernClient(base_url="http://localhost:8080")

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"stdout": "List()"}

    with patch("httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_cls.return_value = mock_http

        result = await client.taint_check("app.py", 42, "python")

    assert result.reachable is False
    assert result.path == []


def test_parse_taint_result_empty():
    client = JoernClient()
    r = client._parse_taint_result("List()")
    assert r.reachable is False
    assert r.path == []


def test_parse_taint_result_single_flow():
    client = JoernClient()
    raw = 'List("a.py:10:request.get(\\"x\\")" -> "b.py:20:cursor.execute(q)")'
    r = client._parse_taint_result(raw)
    assert r.reachable is True
    assert r.sanitized is False
    assert len(r.path) == 2


def test_parse_taint_result_detects_sanitizer():
    client = JoernClient()
    raw = 'List("a.py:5:user_input" -> "b.py:10:html.escape(v)" -> "c.py:15:render(v)")'
    r = client._parse_taint_result(raw)
    assert r.reachable is True
    assert r.sanitized is True
    assert any("html.escape" in s for s in r.sanitizer_names)


# --- CallGraphResult tests ---


def test_call_graph_result_defaults():
    cg = CallGraphResult()
    assert cg.enclosing_method == ""
    assert cg.callers == []
    assert cg.callees == []


def test_parse_call_graph_result_empty():
    client = JoernClient()
    assert client._parse_call_graph_result("") == CallGraphResult()
    assert client._parse_call_graph_result('val res1: String = ""') == CallGraphResult()


def test_parse_call_graph_result_with_data():
    client = JoernClient()
    raw = (
        'val methods: List[Method] = List(method)\n'
        'val m: Method = method\n'
        'val callerList: List[String] = List(dispatch|||routes.py|||15)\n'
        'val calleeList: List[String] = List(execute)\n'
        'val res42: String = "handle_request\\ndispatch|||routes.py|||15\\nCALLEES\\nexecute\\nvalidate"'
    )
    cg = client._parse_call_graph_result(raw)
    assert cg.enclosing_method == "handle_request"
    assert len(cg.callers) == 1
    assert cg.callers[0] == {"name": "dispatch", "file": "routes.py", "line": 15}
    assert cg.callees == ["execute", "validate"]


def test_parse_call_graph_result_no_callers():
    client = JoernClient()
    raw = 'val res1: String = "main\\nCALLEES\\nfoo\\nbar"'
    cg = client._parse_call_graph_result(raw)
    assert cg.enclosing_method == "main"
    assert cg.callers == []
    assert cg.callees == ["foo", "bar"]


def test_parse_call_graph_result_no_callees():
    client = JoernClient()
    raw = 'val res1: String = "leaf_func\\ncaller_a|||a.py|||5\\nCALLEES"'
    cg = client._parse_call_graph_result(raw)
    assert cg.enclosing_method == "leaf_func"
    assert len(cg.callers) == 1
    assert cg.callees == []


async def test_get_call_graph_sends_query():
    client = JoernClient()
    raw = 'val res1: String = "process\\nhandler|||app.py|||20\\nCALLEES\\ndb_query"'
    with patch.object(client, "_query", new_callable=AsyncMock, return_value=raw):
        cg = await client.get_call_graph("src/app.py", 42)

    assert cg.enclosing_method == "process"
    assert cg.callers == [{"name": "handler", "file": "app.py", "line": 20}]
    assert cg.callees == ["db_query"]


async def test_get_call_graph_returns_empty_on_error():
    client = JoernClient()
    with patch.object(client, "_query", new_callable=AsyncMock, side_effect=RuntimeError("connection refused")):
        cg = await client.get_call_graph("src/app.py", 10)

    assert cg.enclosing_method == ""
    assert cg.callers == []
    assert cg.callees == []
