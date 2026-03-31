"""Tests for src/taint/engine — reaching-definitions-based taint tracing."""

import os
from src.taint.engine import trace_taint_flow
from src.taint.rules import load_rules

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "taint", "rules")


def _make_parser():
    """Create a Parser-protocol-compatible adapter around TreeSitterReader."""
    from src.code_reader.tree_sitter_reader import TreeSitterReader

    reader = TreeSitterReader()

    class Adapter:
        def parse_file(self, path):
            return reader.parse_file(path)

        def get_grammar(self, extension):
            return reader.get_config(extension)

    return Adapter()


PARSER = _make_parser()
RULES = load_rules(RULES_DIR)


# --- Straight-line tracing ---


def test_straight_line_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="straight_line",
        sink_line=8,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.path) >= 2
    assert flow.source.kind in ("parameter", "source")
    assert flow.sink.kind == "sink"


def test_straight_line_js():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.js"),
        function_name="straightLine",
        sink_line=4,
        check_id="javascript.xss",
        cwe_list=["CWE-79"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.variable == "userInput"


# --- Kill semantics ---


def test_kill_semantics_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="kill_semantics",
        sink_line=14,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert any(
        "hardcoded" in f.lower() or "no external" in f.lower()
        for f in flow.confidence_factors
    )


def test_kill_semantics_js():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.js"),
        function_name="killSemantics",
        sink_line=10,
        check_id="javascript.xss",
        cwe_list=["CWE-79"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert any(
        "hardcoded" in f.lower() or "no external" in f.lower()
        for f in flow.confidence_factors
    )


# --- Branch merging ---


def test_branch_merge_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="branch_merge",
        sink_line=22,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


def test_branch_no_else_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="branch_no_else",
        sink_line=29,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


# --- Unknown call propagation ---


def test_unknown_call_propagation_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="unknown_call_propagation",
        sink_line=42,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")
    assert len(flow.unresolved_calls) >= 1


# --- Guard detection ---


def test_guard_detected():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_guards.py"),
        function_name="guarded_sink",
        sink_line=8,
        check_id="python.ssrf",
        cwe_list=["CWE-918"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.guards) >= 1
    assert flow.guards[0].name == "re.match"
    assert flow.guards[0].variable == "url"


def test_no_guard_when_unguarded():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_guards.py"),
        function_name="unguarded_sink",
        sink_line=20,
        check_id="python.ssrf",
        cwe_list=["CWE-918"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.guards == []


# --- String propagation ---


def test_fstring_propagation():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_string_ops.py"),
        function_name="fstring_propagation",
        sink_line=7,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


def test_concat_propagation():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_string_ops.py"),
        function_name="concat_propagation",
        sink_line=13,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


def test_template_literal_js():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_string_ops.js"),
        function_name="templateLiteralPropagation",
        sink_line=4,
        check_id="javascript.xss",
        cwe_list=["CWE-79"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.variable == "userInput"


# --- Access path tracking ---


def test_field_taint_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_access_paths.py"),
        function_name="field_taint",
        sink_line=8,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


def test_field_safe_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_access_paths.py"),
        function_name="field_safe",
        sink_line=15,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert any(
        "hardcoded" in f.lower() or "no external" in f.lower()
        for f in flow.confidence_factors
    )


# --- Format string propagation ---


def test_format_propagation():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_string_ops.py"),
        function_name="format_propagation",
        sink_line=19,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


# --- Guard with early return ---


def test_guard_with_return():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_guards.py"),
        function_name="guard_with_return",
        sink_line=15,
        check_id="python.ssrf",
        cwe_list=["CWE-918"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.guards) >= 1


# --- Loop taint ---


def test_loop_taint_python():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_reaching_defs.py"),
        function_name="loop_taint",
        sink_line=36,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind in ("parameter", "source")


# --- Parity tests: engine covers flow_tracker scenarios ---


def test_existing_fixture_direct_sqli():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="vulnerable_sqli",
        sink_line=8,
        check_id="python.sqli",
        cwe_list=["CWE-89"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.path) >= 2
    assert flow.source.variable == "user_input"


def test_existing_fixture_sanitized():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="sanitized_xss",
        sink_line=12,
        check_id="python.xss",
        cwe_list=["CWE-79"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.sanitizers) >= 1
    assert flow.sanitizers[0].name == "escape"


def test_existing_fixture_multiline():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.py"),
        function_name="multiline_call",
        sink_line=39,
        check_id="python.ssrf",
        cwe_list=["CWE-918"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert len(flow.path) >= 2


def test_existing_fixture_js_innerhtml():
    flow = trace_taint_flow(
        file_path=os.path.join(FIXTURES, "taint_sample.js"),
        function_name="innerHtmlSink",
        sink_line=24,
        check_id="javascript.xss",
        cwe_list=["CWE-79"],
        rules=RULES,
        parser=PARSER,
    )
    assert flow is not None
    assert flow.source.kind == "parameter"
