# Verdict Output Redesign — LangChain Pipeline + Natural Language Output

**Date:** 2026-03-25
**Status:** Draft

## Goal

1. Replace the mechanical `SOURCE: ... | SANITIZATION: ... | SINK: ... | EXPLOITABILITY: ...` verdict format with natural prose reasoning and a separate dataflow analysis section.
2. Migrate the LLM pipeline from raw OpenAI/Anthropic SDK calls to LangChain LCEL chains with structured Pydantic output, eliminating the brittle `json_extractor.py` regex fallback chain.
3. Add A/B testable two-stage prompting where the LLM first verifies dataflow, then reasons about exploitability.

## Problems

1. **Bad output format**: `reasoning` field is a pipe-delimited string with 4 rigid sections. Reads like a checklist, not a human explanation.
2. **Brittle JSON parsing**: LLM returns freeform text, we parse with regex fallbacks (`json_extractor.py`). Fragile and lossy.
3. **No pipeline structure**: Single `llm.complete(system, prompt) → str` call with manual wiring. Hard to compose multi-stage flows.

## Output Format

### Before

```json
{
  "reasoning": "SOURCE: The `url` parameter... | SANITIZATION: No sanitization... | SINK: The `url` is encoded... | EXPLOITABILITY: An attacker could...",
  "verdict": "false_positive",
  "confidence": 0.89
}
```

### After

```json
{
  "reasoning": "This finding flags MD5 usage in `_hash_url`, but the function generates an 8-character hex hash purely for cookie-based deduplication of viewed posts. MD5 is not used for any security purpose — no password hashing, no integrity verification, no authentication. Even if an attacker crafted a collision, the only effect would be incorrectly marking a post as seen or unseen, which has no security impact.",
  "dataflow_analysis": "The `url` parameter enters `_hash_url()` directly as a function argument. It flows through `url.encode()` which converts it to bytes, then into `hashlib.md5()` which produces a digest. The result is truncated via `.hexdigest()[:8]` and returned. The caller `_set_seen_cookie` passes URLs from `FeedEntry.link` objects loaded from RSS feeds. No user-controlled request data reaches this function.",
  "verdict": "false_positive",
  "confidence": 0.89
}
```

- `reasoning`: 3-5 sentence natural paragraph explaining **why** the verdict is what it is.
- `dataflow_analysis`: Separate paragraph describing **how data flows** through the code. For non-dataflow findings: `"Not applicable — this finding is about configuration, not data flow."`

## Architecture

### LangChain Migration

Replace the hand-rolled LLM client with LangChain's LCEL (LangChain Expression Language). Key components:

**Dependencies** (minimal — no full `langchain` meta-package):
```
langchain-core>=0.3
langchain-openai>=0.3
langchain-anthropic>=0.3
```

**Provider initialization** — replace `src/llm/provider.py` factory:

```python
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic

# OpenAI-compatible (OpenAI, FPT Cloud, OpenRouter)
llm = ChatOpenAI(
    api_key=api_key,
    model=model,
    base_url=base_url,  # e.g., "https://openrouter.ai/api/v1"
    temperature=0.3,
    max_tokens=4000,
)

# Anthropic
llm = ChatAnthropic(
    api_key=api_key,
    model=model,
    temperature=0.3,
    max_tokens=4000,
)
```

Both return `BaseChatModel` — same interface, same `.with_structured_output()`, same LCEL composition.

**Structured output** — replace `json_extractor.py`:

```python
from pydantic import BaseModel, Field

class SinglePassVerdict(BaseModel):
    """LLM verdict for a single finding."""
    finding_index: int
    reasoning: str = Field(description="3-5 sentence paragraph explaining why this is or is not a vulnerability")
    dataflow_analysis: str = Field(description="Paragraph describing how data flows through the code")
    verdict: str = Field(description="true_positive, false_positive, or uncertain")
    confidence: float = Field(description="0.0 to 1.0")
    remediation_code: str | None = Field(default=None)
    remediation_explanation: str | None = Field(default=None)

class VerdictBatch(BaseModel):
    """Batch of verdicts for a file group."""
    verdicts: list[SinglePassVerdict]

structured_llm = llm.with_structured_output(VerdictBatch)
result = await structured_llm.ainvoke(messages)  # returns VerdictBatch, not str
```

This eliminates `json_extractor.py` entirely — no regex fallbacks, no `strip_wrappers`, no manual JSON parsing. The LLM uses tool calling / JSON mode to guarantee schema compliance.

**LCEL chain composition** — replace manual orchestrator wiring:

```python
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough

# Strategy A: single-pass chain
single_pass_chain = prompt_template | structured_llm

# Strategy B: two-stage chain
stage1_chain = dataflow_prompt | llm.with_structured_output(DataflowBatch)
stage2_chain = verdict_prompt | llm.with_structured_output(VerdictBatch)

two_stage_chain = (
    stage1_chain
    | RunnablePassthrough.assign(dataflow_results=lambda x: x)
    | build_stage2_input  # merge Stage 1 output into Stage 2 prompt
    | stage2_chain
)
```

**Retry and fallback** — replace manual retry loop:

```python
chain_with_retry = chain.with_retry(stop_after_attempt=3, wait_exponential_jitter=True)
chain_with_fallback = two_stage_chain.with_fallback([single_pass_chain])
```

**LangSmith tracing** — native, no more `wrap_openai` hacks. LangChain automatically traces every chain step when `LANGSMITH_TRACING=true`.

**Async batch processing** — replace manual semaphore:

```python
results = await chain.abatch(
    inputs,
    config={"max_concurrency": self._max_concurrent},
)
```

### Pydantic Output Schemas

**Strategy A (single-pass):**

```python
class SinglePassVerdict(BaseModel):
    finding_index: int
    reasoning: str = Field(description="3-5 sentence natural paragraph explaining why this is/isn't a vulnerability")
    dataflow_analysis: str = Field(description="Paragraph tracing data flow, or 'Not applicable' for config findings")
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(ge=0.0, le=1.0)
    remediation_code: str | None = None
    remediation_explanation: str | None = None

class SinglePassBatch(BaseModel):
    verdicts: list[SinglePassVerdict]
```

**Strategy B Stage 1 (dataflow):**

```python
class DataflowResult(BaseModel):
    finding_index: int
    dataflow_analysis: str = Field(description="Paragraph tracing data movement from source to sink")
    flow_complete: bool = Field(description="True if full source-to-sink path is traceable")
    gaps: list[str] = Field(default_factory=list, description="What context is missing")

class DataflowBatch(BaseModel):
    results: list[DataflowResult]
```

**Strategy B Stage 2 (verdict):**

```python
class VerdictResult(BaseModel):
    finding_index: int
    reasoning: str = Field(description="3-5 sentence natural paragraph")
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(ge=0.0, le=1.0)
    remediation_code: str | None = None
    remediation_explanation: str | None = None

class VerdictBatch(BaseModel):
    verdicts: list[VerdictResult]
```

### Two Prompt Strategies (A/B testable)

#### Strategy A: Single-Pass

One LLM call per batch. All evidence in one prompt, all outputs in one structured response.

```
[code context + taint trace + SBOM + CWE rubrics + finding metadata]
  → ChatPromptTemplate
  → llm.with_structured_output(SinglePassBatch)
  → SinglePassBatch (guaranteed schema)
```

#### Strategy B: Two-Stage (Dataflow-First)

Two sequential LLM calls per batch.

**Stage 1 — Dataflow Analysis:**
```
[code context + taint trace + callers/callees + imports]
  → ChatPromptTemplate
  → llm.with_structured_output(DataflowBatch)
  → DataflowBatch
```

**Stage 2 — Verdict Reasoning:**
```
[finding metadata + CWE rubrics + SBOM + dataflow_analysis from Stage 1]
  → ChatPromptTemplate
  → llm.with_structured_output(VerdictBatch)
  → VerdictBatch
```

**Merge:** Orchestrator combines `DataflowBatch.results[i].dataflow_analysis` with `VerdictBatch.verdicts[i]` into the final `FindingVerdict`.

**Stage 1 failure handling:** If Stage 1 call fails or returns empty, the `with_fallback` mechanism automatically falls back to the single-pass chain for that batch.

### Configuration

`LLM_PROMPT_STRATEGY` env var / config field (in `Settings` class, `src/config.py`):
- `"single_pass"` (default) — Strategy A
- `"two_stage"` — Strategy B

### Orchestrator Wiring

Replace `_analyze_batch` internals. The method currently does:
1. Build prompt string → `llm.complete(system, prompt)` → parse JSON with `extract_json_array`

New flow:
1. Build `ChatPromptTemplate` messages → `chain.ainvoke(input)` → receive typed Pydantic model
2. Map Pydantic results to `FindingVerdict` list

The strategy switch happens in chain construction (which chain to use), not in conditional branching. Both strategies produce `list[FindingVerdict]` — downstream code is unchanged.

```python
# In orchestrator __init__:
if config.LLM_PROMPT_STRATEGY == "two_stage":
    self._chain = self._build_two_stage_chain(llm)
else:
    self._chain = self._build_single_pass_chain(llm)

# In _analyze_batch:
result = await self._chain.ainvoke({"findings": findings_text, "contexts": contexts, ...})
verdicts = self._map_to_verdicts(result, findings, index_offset)
```

**Token budgets:** Each stage gets `max_tokens` (not halved) — structured output is more token-efficient than freeform text + regex parsing. The Pydantic schema constrains output length naturally.

### Cache Backward Compatibility

Old cached entries (without `dataflow_analysis`) deserialize to `dataflow_analysis=None` via Pydantic's `model_validate()`. No migration needed.

## Prompt Design

### Strategy A System Prompt

```
You are a security expert performing false-positive triage on SAST findings.

For each finding, consider internally:
- Is the data user-controlled or from an untrusted source?
- Is there sanitization/escaping between source and sink?
- Does untrusted data actually reach the vulnerable sink?
- Can it be meaningfully exploited in this context?

Then produce:
- "reasoning": A natural paragraph of 3-5 sentences explaining WHY this finding is or is not a real vulnerability. Write as a security reviewer explaining to a colleague. Cite specific code patterns. Do not use section headers or labels like "SOURCE:" — just explain clearly.
- "dataflow_analysis": A separate paragraph describing HOW data flows through the code. Trace from where data enters (parameter, request, external source) through transformations to the flagged operation. If a TRACED DATA FLOW section is in the evidence, narrate that trace in plain language. If no trace is available, describe what you can infer from the function body. If the finding is not about data flow (e.g., config issue), write "Not applicable — this finding is about configuration, not data flow."

VERDICT CONSISTENCY: Your verdict MUST match your reasoning.
- If analysis shows data is sanitized or never reaches the sink → false_positive
- If unsanitized user input reaches a dangerous sink → true_positive
- If evidence is insufficient → uncertain

CONFIDENCE: 0.0 (guessing) to 1.0 (certain).
- 0.9+: Clear-cut with strong evidence
- 0.7-0.9: Likely correct, some ambiguity
- Below 0.7: Limited evidence, consider "uncertain"
```

### Strategy B Stage 1 Prompt

```
You are a security engineer analyzing code dataflow. For each finding, trace how data moves through the code.

Describe how data enters the code (function parameter, HTTP request, file read, etc.), what transformations it undergoes (string operations, function calls, assignments), and where it arrives at the flagged operation. Narrate the path step by step in plain language. If a TRACED DATA FLOW section is provided, use it as your guide and narrate it. If the finding is not about data flow, write "Not applicable — this finding is about configuration, not data flow."

Set flow_complete to true if you can trace the full path from source to sink. Set to false if there are gaps (cross-file calls, dynamic dispatch, missing caller context). List the gaps.

Do NOT judge whether the finding is exploitable. Only trace the data movement.
```

### Strategy B Stage 2 Prompt

```
You are a security expert performing false-positive triage. You have been given SAST findings with pre-analyzed dataflow summaries. Use the dataflow analysis to inform your verdict.

Produce a natural paragraph of 3-5 sentences explaining WHY this finding is or is not a real vulnerability. Reference the dataflow analysis where relevant. Write as a security reviewer explaining to a colleague.

VERDICT CONSISTENCY: Your verdict MUST match your reasoning.
- If the dataflow shows data is sanitized or never reaches the sink → false_positive
- If the dataflow shows unsanitized user input reaches a dangerous sink → true_positive
- If the dataflow has gaps and you cannot determine exploitability → uncertain

CONFIDENCE: 0.0 (guessing) to 1.0 (certain).
- 0.9+: Clear-cut with strong evidence
- 0.7-0.9: Likely correct, some ambiguity
- Below 0.7: Limited evidence, consider "uncertain"
```

Stage 2 per-finding context includes the dataflow summary from Stage 1:
```
--- Finding 1 ---
DATAFLOW SUMMARY: [dataflow_analysis from Stage 1]
FLOW COMPLETE: yes/no
GAPS: [list or "none"]
[finding metadata, CWE rubrics, SBOM context]
```

## Data Model Changes

### `FindingVerdict` (src/models/analysis.py)

Add one field:
```python
dataflow_analysis: Optional[str] = None
```

### `x_fp_analysis` output (src/reports/annotated_json.py)

Add to the analysis dict:
```python
"dataflow_analysis": matched.dataflow_analysis,
```

### Markdown summary (src/reports/markdown_summary.py)

Add a collapsible "Dataflow Details" section after each verdict table:

```markdown
## True Positives (5) — Action Required
| File | Line | Confidence | Reasoning | Remediation |
|------|------|------------|-----------|-------------|
| app.py | 42 | 91% | This finding is a real SQL injection... | Use parameterized queries... |

<details>
<summary>Dataflow Details</summary>

**app.py:42** — The `query` parameter enters via `request.args.get("q")` at line 38...

</details>
```

Findings with `dataflow_analysis == None` or starting with "Not applicable" are omitted from the details section.

### Cache serialization

`FindingVerdict` is Pydantic `BaseModel` — `.model_dump()` handles the new field automatically. Old cache entries deserialize with `dataflow_analysis=None`.

## What Gets Deleted

| File | Reason |
|------|--------|
| `src/llm/json_extractor.py` | Replaced by `with_structured_output()` — no more regex fallbacks |
| `src/llm/provider.py` | Replaced by `langchain-openai` / `langchain-anthropic` chat models |

The `create_provider()` factory is replaced by a new `create_chain()` factory that returns an LCEL chain instead of a raw LLM client.

## Files Changed

| File | Change |
|------|--------|
| `requirements.txt` | Add `langchain-core>=0.3`, `langchain-openai>=0.3`, `langchain-anthropic>=0.3`. Remove direct `openai`, `anthropic` deps (pulled in transitively). |
| `src/llm/provider.py` | Rewrite: LangChain chat model factory + LCEL chain construction |
| `src/llm/json_extractor.py` | Delete (replaced by structured output) |
| `src/llm/schemas.py` | New: Pydantic output schemas (SinglePassVerdict, DataflowResult, VerdictResult, batch wrappers) |
| `src/llm/prompt_builder.py` | Rewrite system prompts. Add `build_dataflow_prompt()`. Modify `build_grouped_prompt()` to accept `dataflow_summaries`. |
| `src/models/analysis.py` | Add `dataflow_analysis: Optional[str] = None` to `FindingVerdict` |
| `src/config.py` | Add `LLM_PROMPT_STRATEGY: str = "single_pass"` |
| `src/core/orchestrator.py` | Replace `_analyze_batch` internals with chain invocation. Remove `extract_json_array` import. Strategy switch via chain construction. |
| `src/reports/annotated_json.py` | Include `dataflow_analysis` in `x_fp_analysis` dict |
| `src/reports/markdown_summary.py` | Render dataflow in collapsible details section |
| `tests/test_llm.py` | Rewrite: test chain invocation, structured output, both strategies |
| `tests/test_orchestrator.py` | Update: mock LangChain chain instead of `llm.complete()` |
| `tests/test_reports.py` | Test dataflow in annotated JSON and markdown |

## Testing

- Unit test: Pydantic schemas validate correctly (field constraints, Literal types)
- Unit test: both chain strategies produce correct typed output when mocked
- Unit test: `dataflow_analysis` field present in annotated JSON
- Unit test: markdown report renders dataflow details section
- Unit test: Stage 1 failure triggers fallback to single-pass
- Integration test: run both strategies on smallweb findings, compare output quality
- A/B comparison: same findings, both strategies, human evaluation

## Explicit Non-Goals

- No changes to the taint tracing engine (separate spec)
- No UI changes (API/report output only)
- No SARIF output format (future work)
- No LangGraph agents or complex agent loops — just LCEL chains
- No automated A/B evaluation metrics (manual comparison for now)
