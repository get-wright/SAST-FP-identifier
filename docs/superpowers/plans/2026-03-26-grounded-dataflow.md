# Grounded Dataflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **IMPORTANT — Documentation-First:** Before writing ANY code in each task, use the context7 MCP server (`resolve-library-id` then `query-docs`) to look up current docs for every library you touch. This applies to: Pydantic v2, tree-sitter (py-tree-sitter), Preact, httpx, FastAPI. Also read `src/graph/mcp_client.py` for gkg MCP method signatures. Do not rely on memory — APIs change.

**Goal:** Ground the Dataflow tab in real code data from tree-sitter/Joern/gkg instead of LLM-generated flow steps, eliminating hallucinated line numbers and variable names.

**Architecture:** New `flow_grounding.py` module converts `TaintFlow` objects into the `flow_steps` schema. LLM prompt changes from "generate steps" to "annotate these traced steps." Orchestrator merges grounded steps with LLM annotations. Frontend adds visual distinction for grounded vs inferred steps.

**Tech Stack:** Python 3.11+, Pydantic v2, tree-sitter, Preact, CSS Modules

---

## File Map

| File | Responsibility | Action |
|---|---|---|
| `src/core/flow_grounding.py` | Convert TaintFlow/Joern data → frontend flow_steps schema | **Create** |
| `tests/test_flow_grounding.py` | Unit tests for grounding logic | **Create** |
| `src/llm/schemas.py` | Add `StepAnnotation`, `GapStep`; update `VerdictOutput`, `DataflowResult` | Modify |
| `src/llm/prompt_builder.py` | Render grounded steps in prompt, render sub_flow for hops | Modify |
| `tests/test_prompt_builder.py` | Test grounded steps appear in prompt | **Create** |
| `src/core/orchestrator.py` | Wire flow grounding, pass to prompt, merge after LLM | Modify |
| `src/reports/annotated_json.py` | Serialize `taint_flow` in graph_context | Modify |
| `src/taint/cross_file.py` | Use `get_definition` before `search_definitions` | Modify |
| `frontend/src/components/DataflowView.jsx` | Grounded vs gap step styling | Modify |
| `frontend/src/components/DataflowView.module.css` | Dashed connector, chip styles | Modify |

---

### Task 1: Flow Grounding Module — Core Mapping

**Files:**
- Create: `src/core/flow_grounding.py`
- Create: `tests/test_flow_grounding.py`

- [ ] **Step 1: Write failing test — basic tree-sitter FlowStep mapping**

```python
# tests/test_flow_grounding.py
from src.core.flow_grounding import ground_flow_steps
from src.models.analysis import FlowStep, TaintFlow


def test_maps_tree_sitter_flow_to_frontend_schema():
    flow = TaintFlow(
        path=[
            FlowStep(variable="user_input", line=10, expression="user_input = request.args.get('q')", kind="parameter"),
            FlowStep(variable="query", line=15, expression="query = 'SELECT * FROM ' + user_input", kind="assignment"),
            FlowStep(variable="query", line=22, expression="cursor.execute(query)", kind="sink"),
        ],
    )
    steps = ground_flow_steps(flow, "app.py")
    assert len(steps) == 3
    assert steps[0] == {
        "label": "source",
        "location": "app.py:10",
        "code": "user_input = request.args.get('q')",
        "explanation": "",
        "grounded": True,
    }
    assert steps[1]["label"] == "propagation"
    assert steps[1]["location"] == "app.py:15"
    assert steps[1]["grounded"] is True
    assert steps[2]["label"] == "sink"
    assert steps[2]["location"] == "app.py:22"


def test_returns_empty_when_no_flow():
    assert ground_flow_steps(None, "app.py") == []


def test_returns_empty_when_flow_has_no_path():
    flow = TaintFlow(path=[])
    assert ground_flow_steps(flow, "app.py") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_flow_grounding.py -v`
Expected: FAIL with `ModuleNotFoundError` or `ImportError`

- [ ] **Step 3: Write minimal implementation**

```python
# src/core/flow_grounding.py
"""Convert enrichment TaintFlow data into grounded frontend flow_steps."""

from __future__ import annotations

from typing import Optional

from src.models.analysis import TaintFlow

_KIND_TO_LABEL = {
    "parameter": "source",
    "source": "source",
    "assignment": "propagation",
    "call_result": "propagation",
    "return": "propagation",
    "sink": "sink",
}


def ground_flow_steps(
    taint_flow: Optional[TaintFlow],
    file_path: str,
    joern_taint_path: Optional[list[str]] = None,
) -> list[dict]:
    """Convert TaintFlow or Joern taint_path into grounded flow_steps.

    Priority: tree-sitter TaintFlow > Joern taint_path > empty.
    """
    if taint_flow and taint_flow.path:
        return _from_taint_flow(taint_flow, file_path)
    if joern_taint_path:
        return _from_joern_path(joern_taint_path)
    return []


def _from_taint_flow(flow: TaintFlow, file_path: str) -> list[dict]:
    """Convert tree-sitter TaintFlow into frontend flow_steps schema."""
    steps = []
    for step in flow.path:
        steps.append({
            "label": _KIND_TO_LABEL.get(step.kind, "propagation"),
            "location": f"{file_path}:{step.line}",
            "code": step.expression,
            "explanation": "",
            "grounded": True,
        })
    return steps


def _from_joern_path(taint_path: list[str]) -> list[dict]:
    """Convert Joern 'file:line:code' strings into frontend flow_steps."""
    steps = []
    total = len(taint_path)
    for i, entry in enumerate(taint_path):
        parts = entry.split(":", 2)
        file = parts[0] if len(parts) > 0 else ""
        line = parts[1] if len(parts) > 1 else "0"
        code = parts[2] if len(parts) > 2 else entry
        if i == 0:
            label = "source"
        elif i == total - 1:
            label = "sink"
        else:
            label = "propagation"
        steps.append({
            "label": label,
            "location": f"{file}:{line}",
            "code": code,
            "explanation": "",
            "grounded": True,
        })
    return steps
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_flow_grounding.py -v`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/core/flow_grounding.py tests/test_flow_grounding.py
git commit -m "feat: add flow grounding module — core TaintFlow mapping"
```

---

### Task 2: Flow Grounding — Sanitizer Injection

**Files:**
- Modify: `src/core/flow_grounding.py`
- Modify: `tests/test_flow_grounding.py`

- [ ] **Step 1: Write failing test — sanitizer injection at correct position**

```python
# tests/test_flow_grounding.py (append)
from src.models.analysis import SanitizerInfo


def test_injects_sanitizers_at_correct_position():
    flow = TaintFlow(
        path=[
            FlowStep(variable="x", line=5, expression="x = input()", kind="parameter"),
            FlowStep(variable="y", line=15, expression="y = process(x)", kind="assignment"),
            FlowStep(variable="y", line=25, expression="eval(y)", kind="sink"),
        ],
        sanitizers=[
            SanitizerInfo(name="html_escape", line=10, cwe_categories=["CWE-79"], conditional=False, verified=True),
        ],
    )
    steps = ground_flow_steps(flow, "app.py")
    assert len(steps) == 4
    assert steps[0]["label"] == "source"
    assert steps[0]["location"] == "app.py:5"
    assert steps[1]["label"] == "sanitizer"
    assert steps[1]["location"] == "app.py:10"
    assert steps[1]["code"] == "html_escape"
    assert steps[1]["grounded"] is True
    assert steps[2]["label"] == "propagation"
    assert steps[3]["label"] == "sink"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_flow_grounding.py::test_injects_sanitizers_at_correct_position -v`
Expected: FAIL — sanitizer not injected, len is 3

- [ ] **Step 3: Add sanitizer injection to `_from_taint_flow`**

In `src/core/flow_grounding.py`, update `_from_taint_flow`:

```python
def _from_taint_flow(flow: TaintFlow, file_path: str) -> list[dict]:
    """Convert tree-sitter TaintFlow into frontend flow_steps schema."""
    steps = []
    for step in flow.path:
        steps.append({
            "label": _KIND_TO_LABEL.get(step.kind, "propagation"),
            "location": f"{file_path}:{step.line}",
            "code": step.expression,
            "explanation": "",
            "grounded": True,
        })

    # Inject sanitizers at correct line positions
    for san in flow.sanitizers:
        san_step = {
            "label": "sanitizer",
            "location": f"{file_path}:{san.line}",
            "code": san.name,
            "explanation": "",
            "grounded": True,
        }
        # Insert before the first step with line > san.line
        insert_idx = len(steps)
        for i, s in enumerate(steps):
            step_line = _extract_line(s["location"])
            if step_line > san.line:
                insert_idx = i
                break
        steps.insert(insert_idx, san_step)

    return steps


def _extract_line(location: str) -> int:
    """Extract line number from 'file:line' string."""
    parts = location.rsplit(":", 1)
    try:
        return int(parts[-1])
    except (ValueError, IndexError):
        return 0
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_flow_grounding.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/core/flow_grounding.py tests/test_flow_grounding.py
git commit -m "feat: inject sanitizer steps at correct line positions"
```

---

### Task 3: Flow Grounding — Cross-File Hop Flattening

**Files:**
- Modify: `src/core/flow_grounding.py`
- Modify: `tests/test_flow_grounding.py`

- [ ] **Step 1: Write failing test — cross-file hop with sub_flow flattens**

```python
# tests/test_flow_grounding.py (append)
from src.models.analysis import CrossFileHop


def test_flattens_cross_file_hop_with_sub_flow():
    inner = TaintFlow(
        path=[
            FlowStep(variable="arg", line=10, expression="arg = param", kind="parameter"),
            FlowStep(variable="result", line=15, expression="result = sanitize(arg)", kind="assignment"),
            FlowStep(variable="result", line=20, expression="return result", kind="return"),
        ],
    )
    flow = TaintFlow(
        path=[
            FlowStep(variable="x", line=5, expression="x = input()", kind="source"),
            FlowStep(variable="x", line=30, expression="eval(x)", kind="sink"),
        ],
        cross_file_hops=[
            CrossFileHop(callee="helper", file="utils.py", line=10, action="propagates", sub_flow=inner),
        ],
    )
    steps = ground_flow_steps(flow, "app.py")
    # source + 3 sub_flow steps + sink = 5
    assert len(steps) == 5
    assert steps[0]["label"] == "source"
    assert steps[0]["location"] == "app.py:5"
    assert steps[1]["location"] == "utils.py:10"
    assert steps[1]["grounded"] is True
    assert steps[4]["label"] == "sink"
    assert steps[4]["location"] == "app.py:30"


def test_cross_file_hop_without_sub_flow_becomes_gap():
    flow = TaintFlow(
        path=[
            FlowStep(variable="x", line=5, expression="x = input()", kind="source"),
            FlowStep(variable="x", line=20, expression="eval(x)", kind="sink"),
        ],
        cross_file_hops=[
            CrossFileHop(callee="mystery", file="lib.py", line=1, action="unknown"),
        ],
    )
    steps = ground_flow_steps(flow, "app.py")
    assert len(steps) == 3
    gap = steps[1]
    assert gap["label"] == "propagation"
    assert gap["location"] == "lib.py:1"
    assert gap["code"] == "mystery()"
    assert gap["grounded"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_flow_grounding.py::test_flattens_cross_file_hop_with_sub_flow tests/test_flow_grounding.py::test_cross_file_hop_without_sub_flow_becomes_gap -v`
Expected: FAIL — cross-file hops not handled

- [ ] **Step 3: Add cross-file hop handling to `_from_taint_flow`**

In `src/core/flow_grounding.py`, update `_from_taint_flow` to process hops after building the initial step list, inserting between source and sink:

```python
def _from_taint_flow(flow: TaintFlow, file_path: str) -> list[dict]:
    """Convert tree-sitter TaintFlow into frontend flow_steps schema."""
    steps = []
    for step in flow.path:
        steps.append({
            "label": _KIND_TO_LABEL.get(step.kind, "propagation"),
            "location": f"{file_path}:{step.line}",
            "code": step.expression,
            "explanation": "",
            "grounded": True,
        })

    # Inject sanitizers at correct line positions
    for san in flow.sanitizers:
        san_step = {
            "label": "sanitizer",
            "location": f"{file_path}:{san.line}",
            "code": san.name,
            "explanation": "",
            "grounded": True,
        }
        insert_idx = len(steps)
        for i, s in enumerate(steps):
            if _extract_line(s["location"]) > san.line:
                insert_idx = i
                break
        steps.insert(insert_idx, san_step)

    # Flatten cross-file hops — insert between source and sink
    hop_steps = []
    for hop in flow.cross_file_hops:
        if hop.sub_flow and hop.sub_flow.path:
            for sub_step in hop.sub_flow.path:
                hop_steps.append({
                    "label": _KIND_TO_LABEL.get(sub_step.kind, "propagation"),
                    "location": f"{hop.file}:{sub_step.line}",
                    "code": sub_step.expression,
                    "explanation": "",
                    "grounded": True,
                })
        else:
            hop_steps.append({
                "label": "propagation",
                "location": f"{hop.file}:{hop.line}",
                "code": f"{hop.callee}()",
                "explanation": "",
                "grounded": False,
            })

    if hop_steps:
        # Insert cross-file steps before the sink (last step)
        sink_idx = len(steps) - 1 if steps and steps[-1]["label"] == "sink" else len(steps)
        for i, hs in enumerate(hop_steps):
            steps.insert(sink_idx + i, hs)

    return steps
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_flow_grounding.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/core/flow_grounding.py tests/test_flow_grounding.py
git commit -m "feat: flatten cross-file hops into grounded flow steps"
```

---

### Task 4: Flow Grounding — Joern Fallback

**Files:**
- Modify: `tests/test_flow_grounding.py`

- [ ] **Step 1: Write failing test — Joern taint_path parsing**

```python
# tests/test_flow_grounding.py (append)


def test_joern_fallback_parses_taint_path():
    joern_path = [
        "app.py:5:request.args.get('q')",
        "app.py:10:query = user_input",
        "app.py:15:cursor.execute(query)",
    ]
    steps = ground_flow_steps(None, "app.py", joern_taint_path=joern_path)
    assert len(steps) == 3
    assert steps[0]["label"] == "source"
    assert steps[0]["location"] == "app.py:5"
    assert steps[0]["code"] == "request.args.get('q')"
    assert steps[0]["grounded"] is True
    assert steps[1]["label"] == "propagation"
    assert steps[2]["label"] == "sink"
    assert steps[2]["location"] == "app.py:15"


def test_joern_fallback_single_step():
    steps = ground_flow_steps(None, "app.py", joern_taint_path=["app.py:10:eval(x)"])
    assert len(steps) == 1
    # Single step is both source and sink — label as source
    assert steps[0]["label"] == "source"


def test_tree_sitter_takes_priority_over_joern():
    flow = TaintFlow(
        path=[FlowStep(variable="x", line=5, expression="x = input()", kind="source")],
    )
    joern_path = ["app.py:99:something_else()"]
    steps = ground_flow_steps(flow, "app.py", joern_taint_path=joern_path)
    assert len(steps) == 1
    assert steps[0]["location"] == "app.py:5"  # tree-sitter, not Joern
```

- [ ] **Step 2: Run test to verify it passes** (Joern fallback was already implemented in Task 1)

Run: `pytest tests/test_flow_grounding.py -v`
Expected: All 9 tests PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_flow_grounding.py
git commit -m "test: add Joern fallback and priority tests for flow grounding"
```

---

### Task 5: LLM Schema Changes

**Files:**
- Modify: `src/llm/schemas.py`
- Modify: `tests/test_llm.py` (or create `tests/test_schemas.py`)

- [ ] **Step 1: Write failing test — new schema fields parse correctly**

Look up Pydantic v2 docs via context7 first (`resolve-library-id` for "pydantic" then `query-docs` for "BaseModel Field default_factory").

```python
# tests/test_schemas.py
from src.llm.schemas import (
    StepAnnotation, GapStep, VerdictOutput, VerdictOutputBatch,
    DataflowResult, DataflowBatch,
)


def test_step_annotation_parses():
    sa = StepAnnotation(step_index=1, explanation="User input enters here")
    assert sa.step_index == 1
    assert sa.explanation == "User input enters here"


def test_gap_step_parses():
    gs = GapStep(label="propagation", location="utils.py:10", code="transform(x)", explanation="Cross-file call", after_step=2)
    assert gs.after_step == 2
    assert gs.label == "propagation"


def test_verdict_output_with_annotations():
    v = VerdictOutput(
        finding_index=1,
        reasoning="Vulnerable.",
        dataflow_analysis="Data flows from source to sink.",
        step_annotations=[StepAnnotation(step_index=1, explanation="Source")],
        gap_steps=[GapStep(label="propagation", location="x.py:5", code="f()", explanation="gap", after_step=1)],
        flow_steps=[],
        verdict="true_positive",
        confidence=0.9,
    )
    assert len(v.step_annotations) == 1
    assert len(v.gap_steps) == 1
    assert v.flow_steps == []


def test_verdict_output_defaults_empty_annotations():
    v = VerdictOutput(
        finding_index=1, reasoning="x", dataflow_analysis="x",
        verdict="uncertain", confidence=0.5,
    )
    assert v.step_annotations == []
    assert v.gap_steps == []
    assert v.flow_steps == []


def test_dataflow_result_with_annotations():
    dr = DataflowResult(
        finding_index=1,
        dataflow_analysis="Flow traced.",
        step_annotations=[StepAnnotation(step_index=1, explanation="Source")],
        gap_steps=[],
        flow_steps=[],
        flow_complete=True,
    )
    assert len(dr.step_annotations) == 1


def test_verdict_output_batch_round_trip():
    batch = VerdictOutputBatch(verdicts=[
        VerdictOutput(
            finding_index=1, reasoning="x", dataflow_analysis="x",
            step_annotations=[StepAnnotation(step_index=1, explanation="y")],
            gap_steps=[], flow_steps=[],
            verdict="false_positive", confidence=0.85,
        ),
    ])
    d = batch.model_dump()
    restored = VerdictOutputBatch.model_validate(d)
    assert restored.verdicts[0].step_annotations[0].explanation == "y"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_schemas.py -v`
Expected: FAIL with `ImportError` — `StepAnnotation` not defined

- [ ] **Step 3: Add new schema classes to `src/llm/schemas.py`**

Add after `FlowStep` class, before `VerdictOutput`:

```python
class StepAnnotation(BaseModel):
    """LLM explanation for a grounded flow step."""
    step_index: int = Field(description="1-based index matching the grounded step position")
    explanation: str = Field(description="Brief explanation of what happens at this step")


class GapStep(BaseModel):
    """LLM-generated step to fill a gap in the grounded trace."""
    label: Literal["source", "propagation", "sanitizer", "sink"] = Field(
        description="Role of this gap step"
    )
    location: str = Field(description="file:line")
    code: str = Field(description="The code expression")
    explanation: str = Field(description="What happens at this step")
    after_step: int = Field(description="Insert after this grounded step index (0 = before first)")
```

Update `VerdictOutput` — add two new fields with defaults:

```python
class VerdictOutput(BaseModel):
    """Single-pass verdict with dataflow analysis."""
    finding_index: int
    reasoning: str = Field(description="3-5 sentence natural paragraph explaining why this is/isn't a vulnerability")
    dataflow_analysis: str = Field(description="Paragraph tracing data flow, or 'Not applicable' for config findings")
    step_annotations: list[StepAnnotation] = Field(default_factory=list, description="Explanations for grounded flow steps, keyed by 1-based index")
    gap_steps: list[GapStep] = Field(default_factory=list, description="LLM-generated steps to fill gaps in the grounded trace")
    flow_steps: list[FlowStep] = Field(default_factory=list, description="Fallback: full flow steps when no grounded steps provided. Empty otherwise.")
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(description="0.0 to 1.0")
    remediation_code: Optional[str] = None
    remediation_explanation: Optional[str] = None
```

Update `DataflowResult` similarly — add `step_annotations` and `gap_steps` with defaults:

```python
class DataflowResult(BaseModel):
    """Stage 1: dataflow analysis only (no verdict)."""
    finding_index: int
    dataflow_analysis: str = Field(description="Paragraph tracing data movement from source to sink")
    step_annotations: list[StepAnnotation] = Field(default_factory=list, description="Explanations for grounded flow steps")
    gap_steps: list[GapStep] = Field(default_factory=list, description="Gap-filling steps")
    flow_steps: list[FlowStep] = Field(default_factory=list, description="Fallback flow steps when no grounded steps provided")
    flow_complete: bool = Field(description="True if full source-to-sink path is traceable")
    gaps: list[str] = Field(default_factory=list, description="What context is missing")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_schemas.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Run existing tests to ensure no regression**

Run: `pytest tests/test_llm.py tests/test_orchestrator.py -v`
Expected: All PASS — new fields have defaults, so existing code is unaffected

- [ ] **Step 6: Commit**

```bash
git add src/llm/schemas.py tests/test_schemas.py
git commit -m "feat: add StepAnnotation and GapStep schemas for grounded dataflow"
```

---

### Task 6: Prompt Builder — Render Grounded Steps + Sub-Flow

**Files:**
- Modify: `src/llm/prompt_builder.py`
- Create: `tests/test_prompt_builder.py`

- [ ] **Step 1: Write failing test — grounded steps rendered in prompt**

```python
# tests/test_prompt_builder.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prompt_builder.py -v`
Expected: FAIL — `grounded_steps_by_finding` param doesn't exist yet

- [ ] **Step 3: Update `build_grouped_prompt` in `src/llm/prompt_builder.py`**

Add `grounded_steps_by_finding` parameter to `build_grouped_prompt` signature (line 235):

```python
def build_grouped_prompt(
    file_path: str,
    findings: list[dict],
    contexts: dict[int, FindingContext],
    repo_map: str = "",
    max_tokens: int = 6000,
    profile=None,
    memories: dict[int, list[TriageMemory]] | None = None,
    dataflow_summaries: dict[int, dict] | None = None,
    grounded_steps_by_finding: dict[int, list[dict]] | None = None,
) -> str:
```

After the `finding_context_parts` loop (after line 428), before imports section, add grounded steps rendering:

```python
    # Render grounded flow steps for each finding
    if grounded_steps_by_finding:
        grounded_parts = []
        for finding in findings:
            idx = finding["index"]
            steps = grounded_steps_by_finding.get(idx, [])
            if not steps:
                continue
            fnum = idx + 1
            lines = [f"GROUNDED FLOW STEPS (Finding {fnum}):"]
            for i, step in enumerate(steps, 1):
                label = step["label"].upper()
                if not step.get("grounded", True):
                    label += ":GAP"
                lines.append(f"  {i}. [{label}] {step['location']} — `{step['code']}`")
            grounded_parts.append("\n".join(lines))
        if grounded_parts:
            parts.append("\n\n".join(grounded_parts) + "\n")
```

Also add the same parameter to `build_dataflow_prompt` (line 174):

```python
def build_dataflow_prompt(
    file_path: str,
    findings: list[dict],
    contexts: dict[int, FindingContext],
    max_tokens: int = 3000,
    grounded_steps_by_finding: dict[int, list[dict]] | None = None,
) -> str:
```

And add the same grounded steps rendering at the end of `build_dataflow_prompt`, before the truncation check.

- [ ] **Step 4: Update `_render_taint_flow` to render sub_flow**

Replace lines 104-105 in `_render_taint_flow`:

```python
    for hop in flow.cross_file_hops:
        lines.append(f"  -> [HOP] {hop.file}:{hop.line} {hop.callee}() -> {hop.action}")
        if hop.sub_flow and hop.sub_flow.path:
            for step in hop.sub_flow.path[:5]:
                tag = step.kind.upper()
                lines.append(f"    [{tag}] {hop.file}:{step.line}: {step.expression[:60]}")
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_prompt_builder.py -v`
Expected: All 3 tests PASS

- [ ] **Step 6: Run existing tests to check for regressions**

Run: `pytest tests/ -v`
Expected: All PASS — new parameter has default `None`

- [ ] **Step 7: Commit**

```bash
git add src/llm/prompt_builder.py tests/test_prompt_builder.py
git commit -m "feat: render grounded steps and sub_flow in LLM prompts"
```

---

### Task 7: System Prompt Update

**Files:**
- Modify: `src/llm/prompt_builder.py`

- [ ] **Step 1: Update `SYSTEM_PROMPT_SINGLE_PASS`**

Replace the `flow_steps` instruction (line 20 in the current file) with:

```python
SYSTEM_PROMPT_SINGLE_PASS = """You are a security expert performing false-positive triage on SAST findings.

For each finding, consider internally:
- Is the data user-controlled or from an untrusted source?
- Is there sanitization/escaping between source and sink?
- Does untrusted data actually reach the vulnerable sink?
- Can it be meaningfully exploited in this context?

Then produce:
- "reasoning": A natural paragraph of 3-5 sentences explaining WHY this finding is or is not a real vulnerability. Write as a security reviewer explaining to a colleague. Cite specific code patterns. Do not use section headers or labels like "SOURCE:" — just explain clearly.
- "dataflow_analysis": A separate paragraph describing HOW data flows through the code. Trace from where data enters (parameter, request, external source) through transformations to the flagged operation. If a TRACED DATA FLOW section is in the evidence, narrate that trace in plain language. If no trace is available, describe what you can infer from the function body. If the finding is not about data flow (e.g., config issue), write "Not applicable — this finding is about configuration, not data flow."
- "step_annotations": If GROUNDED FLOW STEPS are provided, annotate each meaningful step with a brief explanation (by 1-based index). Skip trivial assignments. If no grounded steps are provided, leave as [].
- "gap_steps": If GROUNDED FLOW STEPS are provided and you identify gaps in the traced flow (e.g., cross-file data movement not captured, missing intermediate transformations), add gap steps. Each has: label (source/propagation/sanitizer/sink), location (file:line), code (the expression), explanation, and after_step (insert after this grounded step index; 0 = before first). If no grounded steps are provided, leave as [].
- "flow_steps": ONLY populate this if no GROUNDED FLOW STEPS are provided (e.g., config findings, unsupported languages). Each step has: label (source/propagation/sanitizer/sink), location (file:line), code (the expression), and explanation. For config findings, return []. If grounded steps ARE provided, return [].

CRITICAL: Optimize for NOT missing true vulnerabilities. Use "uncertain" when the available evidence is insufficient.

VERDICT CONSISTENCY: Your verdict MUST match your reasoning.
- If analysis shows data is sanitized or never reaches the sink → false_positive
- If unsanitized user input reaches a dangerous sink → true_positive
- If evidence is insufficient → uncertain

CONFIDENCE: 0.0 (guessing) to 1.0 (certain).
- 0.9+: Clear-cut with strong evidence
- 0.7-0.9: Likely correct, some ambiguity
- Below 0.7: Limited evidence, consider "uncertain"
"""
```

- [ ] **Step 2: Update `SYSTEM_PROMPT_DATAFLOW`**

Replace lines 35-43:

```python
SYSTEM_PROMPT_DATAFLOW = """You are a security engineer analyzing code dataflow. For each finding, trace how data moves through the code.

Describe how data enters the code (function parameter, HTTP request, file read, etc.), what transformations it undergoes (string operations, function calls, assignments), and where it arrives at the flagged operation. Narrate the path step by step in plain language. If a TRACED DATA FLOW section is provided, use it as your guide and narrate it. If the finding is not about data flow, write "Not applicable — this finding is about configuration, not data flow."

If GROUNDED FLOW STEPS are provided, annotate each meaningful step via "step_annotations" (by 1-based index). Add "gap_steps" for any gaps you identify. Only populate "flow_steps" if no grounded steps are provided.

Set flow_complete to true if you can trace the full path from source to sink. Set to false if there are gaps (cross-file calls, dynamic dispatch, missing caller context). List the gaps.

Do NOT judge whether the finding is exploitable. Only trace the data movement."""
```

- [ ] **Step 3: Run all tests**

Run: `pytest tests/ -v`
Expected: All PASS — prompt text changes don't affect test logic

- [ ] **Step 4: Commit**

```bash
git add src/llm/prompt_builder.py
git commit -m "feat: update system prompts for grounded step annotation"
```

---

### Task 8: Orchestrator — Wire Flow Grounding + Merge

**Files:**
- Modify: `src/core/orchestrator.py`

- [ ] **Step 1: Add grounding to `_analyze_batch` — single-pass path**

Look up the current `_analyze_batch` method (line 648). Add flow grounding before the prompt build.

Add import at top of file:

```python
from src.core.flow_grounding import ground_flow_steps
```

In `_analyze_batch`, after `findings_text, finding_memories = self._prepare_batch(...)` (line 659), add:

```python
        # Ground flow steps from enrichment data
        grounded_steps_by_finding: dict[int, list[dict]] = {}
        for i, f in enumerate(findings):
            ctx = contexts.get(i)
            if ctx:
                joern_path = ctx.taint_path if ctx.taint_path else None
                steps = ground_flow_steps(ctx.taint_flow, f.path, joern_path)
                if steps:
                    grounded_steps_by_finding[i] = steps
```

Pass `grounded_steps_by_finding` to `build_grouped_prompt` (line 677):

```python
        prompt = build_grouped_prompt(
            file_path=findings[0].path,
            findings=findings_text,
            contexts=contexts,
            memories=finding_memories,
            repo_map=repo_map,
            profile=profile,
            grounded_steps_by_finding=grounded_steps_by_finding,
        )
```

- [ ] **Step 2: Add merge logic after LLM response**

In `_map_verdicts` (line 778), after building each `FindingVerdict`, merge grounded steps with LLM annotations. Add a `grounded_steps_by_finding` parameter:

```python
    def _map_verdicts(
        self,
        parsed: list[dict[str, Any]],
        findings: list[SemgrepFinding],
        finding_memories: dict[int, list],
        index_offset: int,
        grounded_steps_by_finding: dict[int, list[dict]] | None = None,
    ) -> list[FindingVerdict]:
```

After building each verdict (line 801-812), merge:

```python
                # Merge grounded steps with LLM annotations
                grounded = (grounded_steps_by_finding or {}).get(i, [])
                if grounded:
                    merged = _merge_grounded_and_llm(grounded, matched)
                else:
                    # No grounded data — use LLM flow_steps, tag as ungrounded
                    raw_steps = matched.get("flow_steps", [])
                    merged = [{**s, "grounded": False} for s in raw_steps] if raw_steps else []
                # Override flow_steps with merged result
```

Then set `flow_steps=merged` in the `FindingVerdict` constructor instead of `flow_steps=matched.get("flow_steps", [])`.

- [ ] **Step 3: Add `_merge_grounded_and_llm` function**

Add at module level in `orchestrator.py`:

```python
def _merge_grounded_and_llm(grounded_steps: list[dict], llm_response: dict) -> list[dict]:
    """Merge grounded flow steps with LLM step annotations and gap steps."""
    steps = [dict(s) for s in grounded_steps]  # shallow copy

    # Apply LLM annotations
    for ann in llm_response.get("step_annotations", []):
        idx = ann.get("step_index", 0) - 1  # 1-based to 0-based
        if 0 <= idx < len(steps):
            steps[idx]["explanation"] = ann.get("explanation", "")

    # Insert gap steps (reverse order to preserve indices)
    gap_steps = llm_response.get("gap_steps", [])
    for gap in sorted(gap_steps, key=lambda g: g.get("after_step", 0), reverse=True):
        insert_pos = min(gap.get("after_step", 0), len(steps))
        steps.insert(insert_pos, {
            "label": gap.get("label", "propagation"),
            "location": gap.get("location", ""),
            "code": gap.get("code", ""),
            "explanation": gap.get("explanation", ""),
            "grounded": False,
        })

    return steps
```

- [ ] **Step 4: Wire `grounded_steps_by_finding` through to `_map_verdicts`**

Update all call sites of `_map_verdicts` to pass `grounded_steps_by_finding`:

In `_analyze_batch` single-pass path (line 686):
```python
        return self._map_verdicts(parsed, findings, finding_memories, index_offset, grounded_steps_by_finding)
```

In `_analyze_batch_two_stage` (line 776):
```python
        return self._map_verdicts(parsed, findings, finding_memories, index_offset, grounded_steps_by_finding)
```

Also wire grounded steps into the two-stage path — add the same grounding block at the start of `_analyze_batch_two_stage`, and pass `grounded_steps_by_finding` to `build_dataflow_prompt` and `build_grouped_prompt`.

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_orchestrator.py -v`
Expected: All PASS — grounded_steps_by_finding defaults to empty dict, merge produces same flow_steps for existing tests

Run: `pytest tests/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/core/orchestrator.py
git commit -m "feat: wire flow grounding and merge into orchestrator pipeline"
```

---

### Task 9: Annotated JSON — Serialize taint_flow

**Files:**
- Modify: `src/reports/annotated_json.py`
- Modify: `tests/test_reports.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_reports.py (append)
from src.models.analysis import TaintFlow, FlowStep as AnalysisFlowStep, SanitizerInfo, CrossFileHop


def test_annotated_json_includes_taint_flow_in_graph_context():
    verdicts = [FindingVerdict(
        finding_index=0, fingerprint="fp1", verdict="true_positive", confidence=0.9, reasoning="Vuln.",
    )]
    flow = TaintFlow(
        path=[
            AnalysisFlowStep(variable="x", line=5, expression="x = input()", kind="source"),
            AnalysisFlowStep(variable="x", line=10, expression="eval(x)", kind="sink"),
        ],
        sanitizers=[],
        cross_file_hops=[CrossFileHop(callee="helper", file="utils.py", line=1, action="propagates")],
    )
    contexts = {
        0: FindingContext(
            code_snippet="eval(x)", enclosing_function="run", function_body="def run(): ...",
            taint_flow=flow,
        ),
    }
    result = build_annotated_json(
        SAMPLE_SEMGREP, {"app.py": verdicts}, "abc123", "fpt_cloud",
        contexts_by_file={"app.py": contexts},
    )
    gc = result["results"][0]["extra"]["x_fp_analysis"]["graph_context"]
    assert "taint_flow" in gc
    assert len(gc["taint_flow"]["path"]) == 2
    assert gc["taint_flow"]["path"][0]["variable"] == "x"
    assert len(gc["taint_flow"]["cross_file_hops"]) == 1
    assert gc["taint_flow"]["cross_file_hops"][0]["callee"] == "helper"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reports.py::test_annotated_json_includes_taint_flow_in_graph_context -v`
Expected: FAIL — `taint_flow` not in `gc`

- [ ] **Step 3: Add taint_flow serialization to `_find_graph_context`**

In `src/reports/annotated_json.py`, after line 122 (`gc["taint_sanitizers"] = ctx.taint_sanitizers`), add:

```python
    if ctx.taint_flow:
        gc["taint_flow"] = ctx.taint_flow.to_dict()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reports.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/reports/annotated_json.py tests/test_reports.py
git commit -m "fix: serialize taint_flow in annotated JSON graph_context"
```

---

### Task 10: Cross-File Resolution — Use get_definition

**Files:**
- Modify: `src/taint/cross_file.py`
- Modify: `tests/test_cross_file.py`

- [ ] **Step 1: Write failing test — get_definition used before search_definitions**

```python
# tests/test_cross_file.py (append)


async def test_resolve_uses_get_definition_first(mock_gkg, tmp_path):
    """get_definition should be tried before search_definitions."""
    helper_file = tmp_path / "helper.py"
    helper_file.write_text("def process(x):\n    return x + 1\n")

    # get_definition returns a result — search_definitions should NOT be called
    mock_gkg.get_definition.return_value = {
        "name": "process", "file": str(helper_file), "line": 1, "end_line": 2,
    }
    mock_gkg.search_definitions.return_value = []

    result = await resolve_cross_file(
        callee_name="process", gkg_client=mock_gkg, repo_path=str(tmp_path),
        caller_file=str(tmp_path / "main.py"), caller_line=10,
    )
    mock_gkg.get_definition.assert_called_once()
    mock_gkg.search_definitions.assert_not_called()
    assert result.action != "unknown" or result.file == str(helper_file)


async def test_resolve_falls_back_to_search_when_get_definition_fails(mock_gkg, tmp_path):
    """If get_definition returns nothing, fall back to search_definitions."""
    helper_file = tmp_path / "helper.py"
    helper_file.write_text("def process(x):\n    return x + 1\n")

    mock_gkg.get_definition.return_value = None
    mock_gkg.search_definitions.return_value = [
        {"name": "process", "file": str(helper_file), "line": 1}
    ]

    result = await resolve_cross_file(
        callee_name="process", gkg_client=mock_gkg, repo_path=str(tmp_path),
        caller_file=str(tmp_path / "main.py"), caller_line=10,
    )
    mock_gkg.get_definition.assert_called_once()
    mock_gkg.search_definitions.assert_called_once()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cross_file.py::test_resolve_uses_get_definition_first -v`
Expected: FAIL — `caller_file` param doesn't exist

- [ ] **Step 3: Update `resolve_cross_file` to use `get_definition` first**

Add `caller_file` and `caller_line` parameters with defaults:

```python
async def resolve_cross_file(
    callee_name: str,
    gkg_client,
    repo_path: str,
    depth: int = 0,
    max_depth: int = 3,
    visited: Optional[set[str]] = None,
    resolution_counter=None,
    caller_file: str = "",
    caller_line: int = 0,
) -> CrossFileResult:
```

In the try block (after guards), before `search_definitions`, try `get_definition`:

```python
    try:
        resolution_counter.value += 1

        # Try precise jump-to-definition first (if caller context available)
        defn = None
        if caller_file and caller_line:
            try:
                defn = await asyncio.wait_for(
                    gkg_client.get_definition(caller_file, caller_line, callee_name),
                    timeout=_TIMEOUT_PER_RESOLUTION,
                )
            except Exception:
                pass  # Fall through to search_definitions

        # Fall back to search
        if not defn or not isinstance(defn, dict) or not defn.get("file", defn.get("file_path", "")):
            results = await asyncio.wait_for(
                gkg_client.search_definitions(callee_name, project_path=repo_path),
                timeout=_TIMEOUT_PER_RESOLUTION,
            )
            if not results:
                return CrossFileResult(action="unknown")
            defn = results[0] if isinstance(results[0], dict) else {}

        file_path = defn.get("file", defn.get("file_path", ""))
        line = defn.get("line", 0)
        # ... rest unchanged
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cross_file.py -v`
Expected: All PASS (existing tests unaffected — new params have defaults)

- [ ] **Step 5: Commit**

```bash
git add src/taint/cross_file.py tests/test_cross_file.py
git commit -m "feat: use gkg get_definition before search_definitions in cross-file resolution"
```

---

### Task 11: Enricher — Pass Caller Context to Cross-File Resolution

**Files:**
- Modify: `src/core/enricher.py`

- [ ] **Step 1: Read enricher.py cross-file call site**

Read the enricher's cross-file resolution call to understand the current interface. Look up the exact lines where `resolve_cross_file` is called.

- [ ] **Step 2: Pass `caller_file` and `caller_line` to `resolve_cross_file`**

In the enricher's cross-file resolution loop (where it iterates `taint_flow.unresolved_calls`), pass the finding's file path and line:

```python
result = await resolve_cross_file(
    callee_name=callee,
    gkg_client=self._gkg,
    repo_path=self._repo_path,
    caller_file=file_path,
    caller_line=finding_line,
)
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_enricher.py tests/test_cross_file.py -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add src/core/enricher.py
git commit -m "feat: pass caller context to cross-file resolution for precise get_definition"
```

---

### Task 12: Frontend — Grounded vs Gap Step Styling

**Files:**
- Modify: `frontend/src/components/DataflowView.jsx`
- Modify: `frontend/src/components/DataflowView.module.css`

Look up Preact docs via context7 first (`resolve-library-id` for "preact" then `query-docs` for component patterns).

- [ ] **Step 1: Add CSS for grounded chip and dashed connector**

Append to `frontend/src/components/DataflowView.module.css`:

```css
/* Grounded step indicator */
.groundedChip {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  font-size: 9px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--success);
  opacity: 0.7;
  margin-left: 6px;
}

.groundedChip::before {
  content: "\2713";
  font-size: 10px;
}

/* Gap/inferred step indicator */
.inferredChip {
  display: inline-flex;
  align-items: center;
  font-size: 9px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-tertiary);
  margin-left: 6px;
}

.connectorDashed {
  width: 2px;
  flex: 1;
  border-left: 2px dashed var(--border);
  min-height: 8px;
  background: none;
}
```

- [ ] **Step 2: Update `LLMFlowSteps` component in DataflowView.jsx**

Replace the `LLMFlowSteps` function (lines 155-191) with:

```jsx
function LLMFlowSteps({ steps, dataflowAnalysis }) {
  return (
    <div>
      <div class={styles.timeline}>
        {steps.map((step, i) => {
          const isLast = i === steps.length - 1;
          const color = ROLE_COLORS[step.label] || "var(--text-tertiary)";
          const isGrounded = step.grounded !== false;
          return (
            <div key={i} class={styles.step}>
              <div class={styles.stepLeft}>
                <div class={styles.dot} style={{ background: color }} />
                {!isLast && (
                  <div class={isGrounded ? styles.connector : styles.connectorDashed} />
                )}
              </div>
              <div class={styles.stepBody}>
                <div class={styles.stepHeader}>
                  <span class={styles.stepLabel} style={{ color }}>{step.label.toUpperCase()}</span>
                  {isGrounded && <span class={styles.groundedChip}>AST</span>}
                  {!isGrounded && <span class={styles.inferredChip}>inferred</span>}
                  {step.location && (
                    <span class={styles.stepLocation}>{step.location}</span>
                  )}
                </div>
                {step.code && (
                  <code class={styles.stepCode}>{step.code}</code>
                )}
                {step.explanation && (
                  <span class={styles.stepExplanation}>{step.explanation}</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
      {dataflowAnalysis && (
        <p class={styles.analysis}>{dataflowAnalysis}</p>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Verify build**

Run: `cd frontend && npm run build`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/DataflowView.jsx frontend/src/components/DataflowView.module.css
git commit -m "feat: add grounded vs inferred step styling in DataflowView"
```

---

### Task 13: Integration Test — Full Pipeline

**Files:**
- Modify: `tests/test_orchestrator.py`

- [ ] **Step 1: Write integration test — grounded steps flow through pipeline**

```python
# tests/test_orchestrator.py (append)


async def test_grounded_steps_merged_into_verdicts(orchestrator, tmp_path):
    """Verify grounded flow steps from TaintFlow reach FindingVerdict.flow_steps."""
    from src.models.analysis import FindingContext, TaintFlow, FlowStep as AnalysisFlowStep

    ctx = FindingContext(
        code_snippet="cursor.execute(query)",
        enclosing_function="index",
        function_body="def index(): ...",
        taint_flow=TaintFlow(path=[
            AnalysisFlowStep(variable="q", line=5, expression="q = request.args.get('q')", kind="parameter"),
            AnalysisFlowStep(variable="query", line=10, expression="query = 'SELECT ' + q", kind="assignment"),
            AnalysisFlowStep(variable="query", line=15, expression="cursor.execute(query)", kind="sink"),
        ]),
    )

    # Mock LLM to return step_annotations
    from src.core.orchestrator import _merge_grounded_and_llm
    from src.core.flow_grounding import ground_flow_steps

    grounded = ground_flow_steps(ctx.taint_flow, "app.py")
    assert len(grounded) == 3
    assert grounded[0]["grounded"] is True
    assert grounded[0]["label"] == "source"

    llm_response = {
        "step_annotations": [
            {"step_index": 1, "explanation": "User input enters via query parameter"},
            {"step_index": 3, "explanation": "Unsanitized input reaches SQL execution"},
        ],
        "gap_steps": [],
    }

    merged = _merge_grounded_and_llm(grounded, llm_response)
    assert len(merged) == 3
    assert merged[0]["explanation"] == "User input enters via query parameter"
    assert merged[0]["grounded"] is True
    assert merged[1]["explanation"] == ""  # step 2 not annotated
    assert merged[2]["explanation"] == "Unsanitized input reaches SQL execution"


async def test_merge_with_gap_steps():
    from src.core.orchestrator import _merge_grounded_and_llm

    grounded = [
        {"label": "source", "location": "a.py:5", "code": "x = input()", "explanation": "", "grounded": True},
        {"label": "sink", "location": "a.py:20", "code": "eval(x)", "explanation": "", "grounded": True},
    ]
    llm_response = {
        "step_annotations": [],
        "gap_steps": [
            {"label": "propagation", "location": "b.py:10", "code": "process(x)", "explanation": "Cross-file transform", "after_step": 1},
        ],
    }
    merged = _merge_grounded_and_llm(grounded, llm_response)
    assert len(merged) == 3
    assert merged[0]["grounded"] is True
    assert merged[1]["grounded"] is False
    assert merged[1]["location"] == "b.py:10"
    assert merged[2]["grounded"] is True


async def test_merge_fallback_no_grounded():
    from src.core.orchestrator import _merge_grounded_and_llm

    llm_response = {
        "step_annotations": [],
        "gap_steps": [],
        "flow_steps": [
            {"label": "source", "location": "a.py:1", "code": "x", "explanation": "src"},
        ],
    }
    # No grounded steps — merge returns empty, caller handles fallback
    merged = _merge_grounded_and_llm([], llm_response)
    assert merged == []  # Empty grounded → caller uses flow_steps directly
```

- [ ] **Step 2: Run test to verify it passes**

Run: `pytest tests/test_orchestrator.py::test_grounded_steps_merged_into_verdicts tests/test_orchestrator.py::test_merge_with_gap_steps tests/test_orchestrator.py::test_merge_fallback_no_grounded -v`
Expected: All PASS

- [ ] **Step 3: Run full test suite**

Run: `pytest tests/ -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add tests/test_orchestrator.py
git commit -m "test: add integration tests for grounded dataflow merge pipeline"
```

---

### Task 14: Final Verification

- [ ] **Step 1: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 2: Run frontend build**

Run: `cd frontend && npm run build`
Expected: Build succeeds with no errors

- [ ] **Step 3: Verify no regressions in existing flow**

Review that:
- Findings without TaintFlow (config findings) still get LLM-generated `flow_steps` tagged `grounded: false`
- Findings with TaintFlow get grounded steps with LLM annotations
- Two-stage strategy still works (grounded steps passed to both stages)
- Annotated JSON includes `taint_flow` in `graph_context`
- Frontend renders both grounded (solid line + AST chip) and gap (dashed line + inferred chip) steps

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: final verification — grounded dataflow feature complete"
```
