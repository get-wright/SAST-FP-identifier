import os
from src.taint.flow_tracker import trace_taint_flow

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_direct_sqli_flow():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="vulnerable_sqli",
        sink_line=8,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
    )
    assert flow is not None
    assert len(flow.path) >= 2
    assert flow.source.kind in ("parameter", "source")
    assert flow.sink.kind == "sink"
    assert flow.source.variable == "user_input"
    assert not flow.sanitizers


def test_sanitized_xss_flow():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="sanitized_xss",
        sink_line=12,
        check_id="python.xss",
        cwe_list=["CWE-79"],
    )
    assert flow is not None
    assert len(flow.sanitizers) >= 1
    assert flow.sanitizers[0].name == "escape"


def test_conditional_sanitizer():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="conditional_sanitizer",
        sink_line=18,
        check_id="python.xss",
        cwe_list=["CWE-79"],
    )
    assert flow is not None
    assert len(flow.sanitizers) >= 1
    assert flow.sanitizers[0].conditional is True


def test_hardcoded_no_flow():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="hardcoded_no_source",
        sink_line=22,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
    )
    if flow is not None:
        assert any(
            "no external source" in f.lower() or "hardcoded" in f.lower()
            for f in flow.confidence_factors
        )


def test_multi_step_flow():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="multi_step_flow",
        sink_line=28,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
    )
    assert flow is not None
    assert len(flow.path) >= 3


def test_unresolved_call():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="calls_unknown",
        sink_line=32,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
    )
    assert flow is not None
    assert len(flow.unresolved_calls) >= 1


def test_js_vulnerable_xss():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.js"),
        function_name="vulnerableXss",
        sink_line=4,
        check_id="javascript.xss",
        cwe_list=["CWE-79"],
    )
    assert flow is not None
    assert flow.source.variable == "userInput"
    assert not flow.sanitizers


def test_js_sanitized_xss():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.js"),
        function_name="sanitizedXss",
        sink_line=11,
        check_id="javascript.xss",
        cwe_list=["CWE-79"],
    )
    assert flow is not None
    assert len(flow.sanitizers) >= 1


def test_unsupported_language_returns_none(tmp_path):
    f = tmp_path / "test.rb"
    f.write_text("def foo; end")
    flow = trace_taint_flow(
        file_path=str(f),
        function_name="foo",
        sink_line=1,
        check_id="ruby.test",
        cwe_list=[],
    )
    assert flow is None


def test_multiline_call_python():
    """Semgrep reports a line inside a multi-line call, not the call start."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="multiline_call",
        sink_line=39,  # the f-string line, NOT the requests.get( line
        check_id="python.ssrf",
        cwe_list=["CWE-918"],
    )
    assert flow is not None, "Flow should not be None for multi-line call"
    assert len(flow.path) >= 2
    assert flow.source.kind in ("parameter", "source")
    assert flow.sink.kind == "sink"


def test_multiline_call_js():
    """JS multi-line fetch() call with sink line on argument line."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.js"),
        function_name="multilineCall",
        sink_line=17,  # the argument line with userInput, NOT the fetch( line (line 16)
        check_id="javascript.ssrf",
        cwe_list=["CWE-918"],
    )
    assert flow is not None, "Flow should not be None for multi-line JS call"
    assert len(flow.path) >= 2
    assert flow.source.variable == "userInput"


def test_js_innerhtml_sink_from_param():
    """Assignment to innerHTML should be detected as a sink."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.js"),
        function_name="innerHtmlSink",
        sink_line=24,
        check_id="javascript.xss",
        cwe_list=["CWE-79"],
    )
    assert flow is not None, "innerHTML assignment should be detected as sink"
    assert len(flow.path) >= 2
    assert flow.source.kind == "parameter"
    assert flow.sink.kind == "sink"


def test_js_innerhtml_with_sanitizer():
    """innerHTML assignment with escapeHtml should detect the sanitizer."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.js"),
        function_name="innerHtmlSanitized",
        sink_line=29,
        check_id="javascript.xss",
        cwe_list=["CWE-79"],
    )
    assert flow is not None
    assert len(flow.sanitizers) >= 1
    assert flow.sanitizers[0].name == "escapeHtml"


def test_js_href_sink():
    """Assignment to .href should be detected as a sink."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.js"),
        function_name="hrefSink",
        sink_line=34,
        check_id="javascript.redirect",
        cwe_list=["CWE-601"],
    )
    assert flow is not None
    assert len(flow.path) >= 2
    assert flow.source.kind == "parameter"


def test_js_hardcoded_innerhtml_no_taint_source():
    """innerHTML with hardcoded SVG — svg is a string literal in the function,
    not a parameter or dangerous source. Should report 'no external source'."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.js"),
        function_name="hardcodedInnerHtml",
        sink_line=39,
        check_id="javascript.xss",
        cwe_list=["CWE-79"],
    )
    assert flow is not None, "Should still produce a flow (with sink-only path)"
    assert any(
        "hardcoded" in f.lower() or "no external" in f.lower()
        for f in flow.confidence_factors
    )


def test_python_response_data_sink():
    """Assignment to response.data should be detected as a sink in Python."""
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="response_data_sink",
        sink_line=48,
        check_id="python.xss",
        cwe_list=["CWE-79"],
    )
    assert flow is not None, "response.data assignment should be detected"
    assert len(flow.path) >= 2
    assert flow.source.kind in ("parameter", "source")
