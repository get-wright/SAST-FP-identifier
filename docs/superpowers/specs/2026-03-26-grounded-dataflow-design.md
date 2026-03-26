# Grounded Dataflow Design

## Goal

Make the Dataflow tab render stable, accurate content by grounding flow steps in real code data (tree-sitter AST traces, Joern CPG, gkg cross-file resolution) instead of relying on LLM-generated steps that can hallucinate line numbers, variable names, and expressions.

## Problem

The current `flow_steps` in `FindingVerdict` are entirely LLM-generated. The LLM reads real code context in the prompt and narrates what it sees, but:

1. **Content accuracy**: LLM can cite wrong lines, fabricate variables, misattribute expressions
2. **Rendering stability**: inconsistent structure (missing fields, wrong labels) breaks the frontend
3. **Data loss**: the tree-sitter `TaintFlow` object (richest grounded data) is only used as prompt context — never serialized to the frontend
4. **Cross-file hops are dead code**: computed by `cross_file.py` and attached to `TaintFlow.cross_file_hops`, but lost in `annotated_json.py` serialization — users never see them
5. **Sub-flow ignored in prompts**: `prompt_builder.py` renders hop metadata but ignores `hop.sub_flow` — LLM never sees internal cross-file traces

## Approach

**Grounded steps as primary, LLM annotates.**

- Serialize tree-sitter/Joern `TaintFlow` into the `flow_steps` schema the frontend already renders
- Change the LLM prompt from "generate flow_steps" to "annotate these traced steps with explanations"
- LLM can add gap steps for cross-file hops it identifies, tagged `grounded: false`
- Fix the serialization and cross-file gaps as part of this work

## Design

### 1. Flow Grounding Module

**New file**: `src/core/flow_grounding.py`

**Function**: `ground_flow_steps(taint_flow: TaintFlow, file_path: str, joern_taint_path: list[str] | None) -> list[dict]`

**Input priority**:
1. Tree-sitter `TaintFlow` (has structured `FlowStep` objects with variable, line, expression, kind)
2. Joern `taint_path` (has `"file:line:code"` strings)
3. Neither → return empty list

**Tree-sitter FlowStep mapping**:

| `FlowStep.kind` | Output `label` |
|---|---|
| `parameter`, `source` | `source` |
| `assignment`, `call_result` | `propagation` |
| `return` | `propagation` |
| `sink` | `sink` |

Each step produces:
```python
{
    "label": mapped_label,
    "location": f"{file_path}:{step.line}",
    "code": step.expression,
    "explanation": "",  # LLM fills this
    "grounded": True,
}
```

**Sanitizer injection**: `TaintFlow.sanitizers` → inserted at correct position by line number:
```python
{
    "label": "sanitizer",
    "location": f"{file_path}:{san.line}",
    "code": san.name,
    "explanation": "",
    "grounded": True,
}
```

**Cross-file hop flattening**:
- Hops with `sub_flow` → flatten sub_flow steps into the list using `hop.file` as the file path, all `grounded: True`
- Hops with `action: "unknown"` (no sub_flow) → gap marker:
  ```python
  {
      "label": "propagation",
      "location": f"{hop.file}:{hop.line}",
      "code": f"{hop.callee}()",
      "explanation": "",
      "grounded": False,
  }
  ```

**Joern fallback**: parse `"file:line:code"` strings, assign labels by position (first=source, last=sink, rest=propagation), all `grounded: True`.

**Output**: list sorted in trace order (source → propagation → sink).

### 2. LLM Prompt Changes

#### System prompt

In `SYSTEM_PROMPT_SINGLE_PASS`, replace the `flow_steps` instruction with:

```
- "step_annotations": For each GROUNDED FLOW STEP provided (by 1-based index), write a brief explanation of what happens at that step. Only annotate steps that are meaningful — skip trivial assignments.
- "gap_steps": If you identify gaps in the traced flow (e.g., cross-file data movement, missing intermediate transformations), add gap steps. Each has: label, location (file:line), code (the expression), explanation, and after_step (insert after this grounded step index; 0 = before first).
- "flow_steps": ONLY populate this if no GROUNDED FLOW STEPS are provided (e.g., config findings, unsupported languages). Otherwise leave as [].
```

Same change in `SYSTEM_PROMPT_DATAFLOW` for two-stage strategy.

#### User prompt

In `build_grouped_prompt` and `build_dataflow_prompt`, after rendering taint flow evidence, add a numbered list of grounded steps:

```
GROUNDED FLOW STEPS (Finding 1):
  1. [SOURCE] file.py:10 — `user_input = request.args.get("q")`
  2. [PROPAGATION] file.py:15 — `query = "SELECT * FROM " + user_input`
  3. [PROPAGATION:GAP] helper.py:20 — `process()` (cross-file, unresolved)
  4. [SINK] file.py:22 — `cursor.execute(query)`
```

Gap markers (grounded=false) are labeled `[LABEL:GAP]` so the LLM knows to fill them.

#### Sub-flow rendering

In `_render_taint_flow`, render `hop.sub_flow` when present:

```python
for hop in flow.cross_file_hops:
    lines.append(f"  -> [HOP] {hop.file}:{hop.line} {hop.callee}() -> {hop.action}")
    if hop.sub_flow and hop.sub_flow.path:
        for step in hop.sub_flow.path[:5]:  # Cap to avoid prompt bloat
            tag = step.kind.upper()
            lines.append(f"    [{tag}] {hop.file}:{step.line}: {step.expression[:60]}")
```

### 3. LLM Response Schema Changes

**`src/llm/schemas.py`**:

```python
class StepAnnotation(BaseModel):
    step_index: int   # 1-based, matches grounded step position
    explanation: str

class GapStep(BaseModel):
    label: Literal["source", "propagation", "sanitizer", "sink"]
    location: str      # file:line
    code: str
    explanation: str
    after_step: int    # Insert after this grounded step index (0 = before first)

class VerdictOutput(BaseModel):
    finding_index: int
    reasoning: str
    dataflow_analysis: str
    step_annotations: list[StepAnnotation]   # NEW
    gap_steps: list[GapStep]                 # NEW
    flow_steps: list[FlowStep]              # KEPT for fallback (no grounded steps)
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float
    remediation_code: Optional[str]
    remediation_explanation: Optional[str]
```

Same pattern for `DataflowResult` (two-stage Stage 1) and `VerdictOnlyOutput` doesn't need changes (no flow data).

### 4. Merge Logic in Orchestrator

**Location**: `src/core/orchestrator.py`, in the per-file-group processing after LLM response parsing.

```python
def _merge_grounded_and_llm(grounded_steps, verdict) -> list[dict]:
    if not grounded_steps:
        # No grounded data — use LLM flow_steps as-is, all ungrounded
        return [
            {**step, "grounded": False}
            for step in verdict.flow_steps
        ]

    # Apply annotations
    for ann in verdict.step_annotations:
        idx = ann.step_index - 1  # 1-based to 0-based
        if 0 <= idx < len(grounded_steps):
            grounded_steps[idx]["explanation"] = ann.explanation

    # Insert gap steps
    merged = list(grounded_steps)
    for gap in sorted(verdict.gap_steps, key=lambda g: g.after_step, reverse=True):
        insert_pos = min(gap.after_step, len(merged))
        merged.insert(insert_pos, {
            "label": gap.label,
            "location": gap.location,
            "code": gap.code,
            "explanation": gap.explanation,
            "grounded": False,
        })

    return merged
```

The merged list is written to `FindingVerdict.flow_steps`.

### 5. Annotated JSON Serialization Fix

**`src/reports/annotated_json.py`**: In `_find_graph_context()`, serialize the full `TaintFlow`:

```python
if ctx.taint_flow:
    gc["taint_flow"] = ctx.taint_flow.to_dict()
```

This makes cross_file_hops, sub_flows, sanitizers, and confidence_factors available to the frontend. The primary rendering path is through `flow_steps` (now grounded), but the raw taint data is there for future use.

### 6. Frontend Changes

**`DataflowView.jsx` — `LLMFlowSteps` component**:

Minimal changes to the existing timeline renderer:

- **Grounded steps** (`step.grounded === true` or `step.grounded === undefined` for backward compat):
  - Solid connector line (current behavior)
  - Small "AST" or checkmark chip next to the label

- **Gap/inferred steps** (`step.grounded === false`):
  - Dashed connector line (CSS: `border-left: 2px dashed`)
  - "inferred" chip next to the label, muted color

- **Priority logic** in `DataflowView` stays the same — `hasLLMSteps` check first, which now contains mostly grounded data.

No new components needed. The `TaintFlow` and `CallerFlow` components remain as fallbacks.

### 7. gkg Improvements (Folded In)

**`src/taint/cross_file.py`**:

- Use `get_definition` (currently defined in MCP client but never called) for precise jump-to-definition before falling back to `search_definitions`
- Use `read_definitions` for batch reading when resolving 2+ callees simultaneously (currently does sequential tree-sitter parses)

These reduce `action: "unknown"` gaps, meaning fewer ungrounded gap steps in the final output.

### 8. Backward Compatibility

- `FindingVerdict.flow_steps` keeps the same type (`list[dict]`) — just gains a `grounded` field
- Frontend treats missing `grounded` field as `true` (safe default for old data)
- LLM `flow_steps` field kept in schema for fallback (config findings, unsupported languages)
- Cache invalidation: cached results won't have grounded steps — the cache key already includes enrichment hash, so re-analysis will naturally produce new results

## Files Changed

| File | Change |
|---|---|
| `src/core/flow_grounding.py` | **NEW** — TaintFlow → flow_steps conversion |
| `src/llm/prompt_builder.py` | Render grounded steps in prompt, render sub_flow for hops |
| `src/llm/schemas.py` | Add `StepAnnotation`, `GapStep`; update `VerdictOutput` |
| `src/core/orchestrator.py` | Call flow grounding, pass to prompt, merge after LLM |
| `src/reports/annotated_json.py` | Serialize `taint_flow` in graph_context |
| `src/taint/cross_file.py` | Use `get_definition` + `read_definitions` |
| `frontend/src/components/DataflowView.jsx` | Grounded vs gap step styling |
| `frontend/src/components/DataflowView.module.css` | Dashed connector, chip styles |

## Testing

- **Unit**: `test_flow_grounding.py` — mapping logic, sanitizer injection, cross-file flattening, Joern fallback
- **Unit**: `test_prompt_builder.py` — grounded steps appear in prompt, sub_flow rendered
- **Unit**: `test_schemas.py` — new schema fields parse correctly
- **Integration**: `test_orchestrator.py` — grounded steps flow through full pipeline, merge works
- **Integration**: `test_annotated_json.py` — taint_flow appears in graph_context output

## Implementation Constraint: Documentation-First

Every implementation step MUST look up current documentation for the libraries and APIs being used before writing code. This includes:

- **tree-sitter Python bindings**: Check `py-tree-sitter` docs for correct AST traversal APIs, node field names, and query syntax
- **Pydantic v2**: Check docs for `BaseModel` field defaults, `Literal` types, serialization behavior, and `model_validator` patterns
- **FastAPI / SSE**: Check docs for response streaming, event formatting
- **Preact**: Check docs for hooks, component patterns, CSS module usage
- **gkg MCP protocol**: Check the MCP client implementation (`src/graph/mcp_client.py`) for exact method signatures and response formats of `get_definition` and `read_definitions`

Use the context7 MCP server (`resolve-library-id` → `query-docs`) to fetch up-to-date documentation for each library before implementing against it. Do not rely on memory — APIs change.

## What Doesn't Change

- `dataflow_analysis` text narrative — still LLM-generated
- `TaintFlow` / `CallerFlow` frontend components — still fallback when no flow_steps
- Confidence scoring formula
- Two-stage strategy (Stage 1 gets same grounded steps treatment)
- Enricher logic (produces the same TaintFlow, just consumed differently downstream)
