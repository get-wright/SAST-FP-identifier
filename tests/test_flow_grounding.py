from src.core.flow_grounding import ground_flow_steps, _extract_line
from src.models.analysis import (
    CrossFileHop,
    FlowStep,
    SanitizerInfo,
    TaintFlow,
)


def _step(variable: str, line: int, expression: str, kind: str) -> FlowStep:
    return FlowStep(variable=variable, line=line, expression=expression, kind=kind)


def _sanitizer(name: str, line: int) -> SanitizerInfo:
    return SanitizerInfo(name=name, line=line, cwe_categories=[], conditional=False, verified=True)


def test_maps_tree_sitter_flow_to_frontend_schema():
    flow = TaintFlow(path=[
        _step("user_input", 5, "request.args.get('q')", "parameter"),
        _step("query", 8, "query = 'SELECT * FROM t WHERE x=' + user_input", "assignment"),
        _step("query", 10, "cursor.execute(query)", "sink"),
    ])
    result = ground_flow_steps(flow, "app.py")

    assert len(result) == 3
    assert result[0] == {
        "label": "source", "location": "app.py:5",
        "code": "request.args.get('q')", "explanation": "", "grounded": True,
    }
    assert result[1]["label"] == "propagation"
    assert result[1]["location"] == "app.py:8"
    assert result[1]["grounded"] is True
    assert result[2]["label"] == "sink"
    assert result[2]["location"] == "app.py:10"


def test_returns_empty_when_no_flow():
    assert ground_flow_steps(None, "app.py") == []


def test_returns_empty_when_flow_has_no_path():
    flow = TaintFlow(path=[])
    assert ground_flow_steps(flow, "app.py") == []


def test_injects_sanitizers_at_correct_position():
    flow = TaintFlow(
        path=[
            _step("user_input", 5, "request.args.get('q')", "parameter"),
            _step("query", 15, "cursor.execute(query)", "sink"),
        ],
        sanitizers=[_sanitizer("escape", 10)],
    )
    result = ground_flow_steps(flow, "app.py")

    assert len(result) == 3
    assert result[0]["label"] == "source"
    assert result[1] == {
        "label": "sanitizer", "location": "app.py:10",
        "code": "escape", "explanation": "", "grounded": True,
    }
    assert result[2]["label"] == "sink"


def test_flattens_cross_file_hop_with_sub_flow():
    inner_flow = TaintFlow(path=[
        _step("arg", 3, "def helper(arg):", "parameter"),
        _step("result", 7, "return sanitize(arg)", "return"),
    ])
    flow = TaintFlow(
        path=[
            _step("data", 10, "data = request.form['x']", "source"),
            _step("data", 20, "sink(data)", "sink"),
        ],
        cross_file_hops=[CrossFileHop(callee="helper", file="utils.py", line=3, action="propagates", sub_flow=inner_flow)],
    )
    result = ground_flow_steps(flow, "app.py")

    # source + 2 inner steps + sink = 4
    assert len(result) == 4
    assert result[0]["label"] == "source"
    assert result[0]["location"] == "app.py:10"
    # inner steps use the hop's file path
    assert result[1]["location"] == "utils.py:3"
    assert result[1]["grounded"] is True
    assert result[2]["location"] == "utils.py:7"
    assert result[2]["grounded"] is True
    assert result[3]["label"] == "sink"
    assert result[3]["location"] == "app.py:20"


def test_cross_file_hop_without_sub_flow_becomes_gap():
    flow = TaintFlow(
        path=[
            _step("data", 10, "data = request.form['x']", "source"),
            _step("data", 20, "sink(data)", "sink"),
        ],
        cross_file_hops=[CrossFileHop(callee="mystery", file="lib.py", line=42, action="unknown")],
    )
    result = ground_flow_steps(flow, "app.py")

    assert len(result) == 3
    gap = result[1]
    assert gap == {
        "label": "propagation", "location": "lib.py:42",
        "code": "mystery()", "explanation": "", "grounded": False,
    }


def test_joern_fallback_parses_taint_path():
    joern_path = [
        "app.py:5:user_input = request.args['q']",
        "app.py:8:query = build(user_input)",
        "app.py:12:cursor.execute(query)",
    ]
    result = ground_flow_steps(None, "app.py", joern_taint_path=joern_path)

    assert len(result) == 3
    assert result[0] == {
        "label": "source", "location": "app.py:5",
        "code": "user_input = request.args['q']", "explanation": "", "grounded": True,
    }
    assert result[1]["label"] == "propagation"
    assert result[2]["label"] == "sink"
    assert result[2]["location"] == "app.py:12"


def test_joern_fallback_single_step():
    result = ground_flow_steps(None, "app.py", joern_taint_path=["app.py:5:eval(x)"])

    assert len(result) == 1
    # single step is both source and sink — label as source
    assert result[0]["label"] == "source"
    assert result[0]["grounded"] is True


def test_tree_sitter_takes_priority_over_joern():
    flow = TaintFlow(path=[
        _step("x", 5, "x = input()", "source"),
        _step("x", 10, "eval(x)", "sink"),
    ])
    joern_path = ["app.py:1:something_else"]

    result = ground_flow_steps(flow, "app.py", joern_taint_path=joern_path)

    assert len(result) == 2
    assert result[0]["code"] == "x = input()"
    assert result[1]["code"] == "eval(x)"


def test_joern_skips_malformed_entries():
    joern_path = [
        "app.py:5:x = input()",
        "some_label_without_colons",
        "not_a_line:abc:code",
        "app.py:10:eval(x)",
    ]
    result = ground_flow_steps(None, "app.py", joern_taint_path=joern_path)
    assert len(result) == 2
    assert result[0]["label"] == "source"
    assert result[0]["location"] == "app.py:5"
    assert result[1]["label"] == "sink"
    assert result[1]["location"] == "app.py:10"


def test_joern_all_malformed_returns_empty():
    result = ground_flow_steps(None, "app.py", joern_taint_path=["bad", "also_bad"])
    assert result == []


def test_extract_line():
    assert _extract_line("app.py:42") == 42
    assert _extract_line("src/utils.py:100") == 100
