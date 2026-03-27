from src.llm.prompt_builder import build_grouped_prompt, _render_taint_flow
from src.models.analysis import (
    FindingContext, FlowStep, TaintFlow, SanitizerInfo, CrossFileHop,
)


def test_grounded_steps_rendered_in_prompt():
    grounded = [
        {"label": "source", "location": "app.py:10", "code": "x = input()", "explanation": "", "grounded": True},
        {"label": "sink", "location": "app.py:20", "code": "eval(x)", "explanation": "", "grounded": True},
    ]
    ctx = FindingContext(
        code_snippet="eval(x)", enclosing_function="run", function_body="def run(): ...",
        taint_flow=TaintFlow(path=[
            FlowStep(variable="x", line=10, expression="x = input()", kind="source"),
            FlowStep(variable="x", line=20, expression="eval(x)", kind="sink"),
        ]),
    )
    findings = [{"index": 0, "rule": "exec-detect", "line": 20, "message": "exec usage"}]
    prompt = build_grouped_prompt(
        file_path="app.py", findings=findings, contexts={0: ctx},
        grounded_steps_by_finding={0: grounded},
    )
    assert "GROUNDED FLOW STEPS (Finding 1)" in prompt
    assert "[SOURCE] app.py:10" in prompt
    assert "[SINK] app.py:20" in prompt


def test_gap_steps_marked_in_prompt():
    grounded = [
        {"label": "source", "location": "app.py:10", "code": "x = input()", "explanation": "", "grounded": True},
        {"label": "propagation", "location": "lib.py:5", "code": "process()", "explanation": "", "grounded": False},
        {"label": "sink", "location": "app.py:20", "code": "eval(x)", "explanation": "", "grounded": True},
    ]
    ctx = FindingContext(code_snippet="eval(x)", enclosing_function="run", function_body="def run(): ...")
    findings = [{"index": 0, "rule": "exec-detect", "line": 20, "message": "exec usage"}]
    prompt = build_grouped_prompt(
        file_path="app.py", findings=findings, contexts={0: ctx},
        grounded_steps_by_finding={0: grounded},
    )
    assert "[PROPAGATION:GAP]" in prompt


def test_sub_flow_rendered_in_taint_flow():
    inner = TaintFlow(
        path=[
            FlowStep(variable="y", line=10, expression="y = param", kind="parameter"),
            FlowStep(variable="y", line=15, expression="return escape(y)", kind="return"),
        ],
    )
    flow = TaintFlow(
        path=[
            FlowStep(variable="x", line=5, expression="x = input()", kind="source"),
            FlowStep(variable="x", line=20, expression="eval(x)", kind="sink"),
        ],
        cross_file_hops=[
            CrossFileHop(callee="helper", file="utils.py", line=10, action="sanitizes", sub_flow=inner),
        ],
    )
    rendered = _render_taint_flow(flow)
    assert "[HOP] utils.py:10 helper() -> sanitizes" in rendered
    assert "[PARAMETER] utils.py:10" in rendered
    assert "[RETURN] utils.py:15" in rendered
