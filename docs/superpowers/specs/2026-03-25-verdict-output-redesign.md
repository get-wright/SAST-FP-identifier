# Verdict Output Redesign — Natural Language Reasoning + Separate Dataflow Analysis

**Date:** 2026-03-25
**Status:** Draft

## Goal

Replace the mechanical `SOURCE: ... | SANITIZATION: ... | SINK: ... | EXPLOITABILITY: ...` verdict format with natural prose reasoning and a separate dataflow analysis section. Add A/B testable two-stage prompting where the LLM first verifies dataflow, then reasons about exploitability.

## Problem

Current `reasoning` field is a pipe-delimited string with 4 rigid sections. It reads like a checklist, not a human explanation. Dataflow evidence and verdict rationale are mixed into one field. Users see "4 colored parts" that look bad and are hard to act on.

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

- `reasoning`: 3-5 sentence natural paragraph explaining **why** the verdict is what it is. Written as a security reviewer would explain to a colleague.
- `dataflow_analysis`: Separate paragraph describing **how data flows** through the code. Traces from entry point through transformations to the flagged operation. For non-dataflow findings (Dockerfile config, missing headers): `"Not applicable — this finding is about configuration, not data flow."`

## Architecture

### Two Prompt Strategies (A/B testable)

#### Strategy A: Single-Pass

One LLM call per file group. The prompt includes all evidence (code, taint trace, SBOM, CWE rubrics). LLM produces `reasoning`, `dataflow_analysis`, `verdict`, and `confidence` together.

```
[code context + taint trace + SBOM + CWE rubrics + finding metadata]
  → LLM
  → { reasoning, dataflow_analysis, verdict, confidence, remediation }
```

Cheaper (~1x tokens), faster (~1x latency). Good baseline.

#### Strategy B: Two-Stage (Dataflow-First)

Two sequential LLM calls per file group.

**Stage 1 — Dataflow Analysis:**
LLM receives only code context and taint trace evidence. It produces a dataflow summary and flags whether the traced flow is complete or has gaps.

```
[code context + taint trace + callers/callees + imports]
  → LLM
  → { dataflow_analysis, flow_complete: bool, gaps: ["caller context missing", ...] }
```

Stage 1 system prompt focuses on tracing data movement, not judging exploitability. It asks: "Where does data enter? What happens to it? Where does it end up? Is the trace complete?"

**Stage 2 — Verdict Reasoning:**
LLM receives the original finding metadata, CWE rubrics, SBOM profile, and the dataflow summary from Stage 1. It reasons about exploitability over a verified dataflow.

```
[finding metadata + CWE rubrics + SBOM + dataflow_analysis from Stage 1]
  → LLM
  → { reasoning, verdict, confidence, remediation_code, remediation_explanation }
```

Stage 2 system prompt focuses on security judgment: "Given this dataflow, is this exploitable? Why or why not?"

More expensive (~2x tokens), slower (~2x latency), but higher quality because Stage 2 reasons over a verified dataflow summary rather than raw code.

### Configuration

`LLM_PROMPT_STRATEGY` env var / config field (in `Settings` class, `src/config.py`):
- `"single_pass"` (default) — Strategy A
- `"two_stage"` — Strategy B

### Orchestrator Wiring

The strategy switch happens in `_analyze_file_group` (not `_analyze_batch`). For two-stage:

```python
if self._config.LLM_PROMPT_STRATEGY == "two_stage":
    verdicts = await self._analyze_file_group_two_stage(findings, contexts, ...)
else:
    verdicts = await self._analyze_file_group_single_pass(findings, contexts, ...)
```

`_analyze_file_group_two_stage` does:
1. Build Stage 1 prompt via `build_dataflow_prompt(file_path, findings, contexts, max_tokens)`
2. Call `llm.complete(STAGE1_SYSTEM_PROMPT, stage1_prompt, ...)`
3. Parse Stage 1 JSON → `dict[int, DataflowSummary]` (finding_index → {dataflow_analysis, flow_complete, gaps})
4. Build Stage 2 prompt via `build_grouped_prompt(file_path, findings, contexts, ..., dataflow_summaries=stage1_results)`
5. Call `llm.complete(STAGE2_SYSTEM_PROMPT, stage2_prompt, ...)`
6. Parse Stage 2 JSON → list of verdict dicts
7. **Merge**: For each verdict, set `verdict.dataflow_analysis = stage1_results[finding_index].dataflow_analysis`
8. Return merged `FindingVerdict` list

**Stage 1 failure handling**: If Stage 1 LLM call fails (network error, parse error, or returns empty results), fall back to single-pass for that batch. Log a warning. This matches the existing retry/fallback pattern in `_analyze_batch`.

**Token budgets**: Each stage gets `max_tokens // 2` for output. Timeout per stage is `LLM_TIMEOUT` (unchanged) — the total wall time for two-stage is up to `2 × LLM_TIMEOUT` per batch. No config changes needed; the 2x cost is inherent to the strategy choice.

### Function Signatures

**New: `build_dataflow_prompt()`** (Stage 1 prompt builder):
```python
def build_dataflow_prompt(
    file_path: str,
    findings: list[dict],
    contexts: dict[int, FindingContext],
    max_tokens: int = 3000,
) -> str:
```
Builds a prompt with code context, taint trace, callers/callees, imports per finding. Does NOT include SBOM profile, CWE rubrics, or triage memories — those are only relevant to Stage 2.

**Modified: `build_grouped_prompt()`** (now serves both strategies):
```python
def build_grouped_prompt(
    file_path: str,
    findings: list[dict],
    contexts: dict[int, FindingContext],
    repo_map: str = "",
    max_tokens: int = 6000,
    profile=None,
    memories: dict[int, list] | None = None,
    dataflow_summaries: dict[int, dict] | None = None,  # NEW — Stage 1 results for two-stage
) -> str:
```
When `dataflow_summaries` is provided (Strategy B Stage 2), per-finding context includes the dataflow summary instead of raw code/taint trace. When `None` (Strategy A or standalone), behavior is unchanged.

### System Prompt Constants

Replace the single `SYSTEM_PROMPT` module-level constant with three:
```python
SYSTEM_PROMPT_SINGLE_PASS = """..."""     # Strategy A
SYSTEM_PROMPT_DATAFLOW = """..."""         # Strategy B Stage 1
SYSTEM_PROMPT_VERDICT = """..."""          # Strategy B Stage 2
```

The orchestrator imports all three and selects based on strategy. The old `SYSTEM_PROMPT` name is removed — any code importing it will fail at import time (compile-time error, not silent regression).

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

VERDICT VALUES:
- "true_positive": Exploitable in this context.
- "false_positive": Not exploitable due to sanitization, safe patterns, or framework protection.
- "uncertain": Cannot determine from available context. Do NOT guess.

CONFIDENCE: 0.0 (guessing) to 1.0 (certain).
- 0.9+: Clear-cut with strong evidence
- 0.7-0.9: Likely correct, some ambiguity
- Below 0.7: Limited evidence, consider "uncertain"
```

JSON output schema for Strategy A:
```json
[{
  "finding_index": 1,
  "reasoning": "natural paragraph",
  "dataflow_analysis": "natural paragraph or 'Not applicable...'",
  "verdict": "true_positive|false_positive|uncertain",
  "confidence": 0.0,
  "remediation_code": "code or null",
  "remediation_explanation": "text or null"
}]
```

### Strategy B Stage 1 Prompt

```
You are a security engineer analyzing code dataflow. For each finding, trace how data moves through the code.

For each finding, produce:
- "dataflow_analysis": Describe how data enters the code (function parameter, HTTP request, file read, etc.), what transformations it undergoes (string operations, function calls, assignments), and where it arrives at the flagged operation. Narrate the path step by step in plain language. If a TRACED DATA FLOW section is provided, use it as your guide and narrate it. If the finding is not about data flow, write "Not applicable — this finding is about configuration, not data flow."
- "flow_complete": true if you can trace the full path from source to sink, false if there are gaps (e.g., cross-file calls you can't see, dynamic dispatch, missing caller context).
- "gaps": List of strings describing what's missing. Empty list if flow is complete.

Do NOT judge whether the finding is exploitable. Only trace the data movement.
```

Stage 1 JSON schema:
```json
[{
  "finding_index": 1,
  "dataflow_analysis": "natural paragraph",
  "flow_complete": true,
  "gaps": []
}]
```

### Strategy B Stage 2 Prompt

```
You are a security expert performing false-positive triage. You have been given SAST findings with pre-analyzed dataflow summaries. Use the dataflow analysis to inform your verdict.

For each finding, produce:
- "reasoning": A natural paragraph of 3-5 sentences explaining WHY this finding is or is not a real vulnerability. Reference the dataflow analysis where relevant. Write as a security reviewer explaining to a colleague.

VERDICT CONSISTENCY: Your verdict MUST match your reasoning.
- If the dataflow shows data is sanitized or never reaches the sink → FALSE POSITIVE
- If the dataflow shows unsanitized user input reaches a dangerous sink → TRUE POSITIVE
- If the dataflow has gaps and you cannot determine exploitability → UNCERTAIN

VERDICT VALUES:
- "true_positive": Exploitable in this context.
- "false_positive": Not exploitable due to sanitization, safe patterns, or framework protection.
- "uncertain": Cannot determine from available context. Do NOT guess.

CONFIDENCE: 0.0 (guessing) to 1.0 (certain).
- 0.9+: Clear-cut with strong evidence
- 0.7-0.9: Likely correct, some ambiguity
- Below 0.7: Limited evidence, consider "uncertain"
```

Stage 2 receives the per-finding dataflow summaries inline:
```
--- Finding 1 ---
DATAFLOW: [dataflow_analysis from Stage 1]
FLOW COMPLETE: yes/no
GAPS: [list]
[rest of finding metadata, CWE rubrics, SBOM context]
```

Stage 2 JSON schema:
```json
[{
  "finding_index": 1,
  "reasoning": "natural paragraph",
  "verdict": "true_positive|false_positive|uncertain",
  "confidence": 0.0,
  "remediation_code": "code or null",
  "remediation_explanation": "text or null"
}]
```

Note: Stage 2 does NOT produce `dataflow_analysis` — that comes from Stage 1 and is merged by the orchestrator.

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

Add a "Dataflow Details" section after each verdict table (True Positives, False Positives, Uncertain). For each finding that has a non-null, non-"Not applicable" `dataflow_analysis`, render it as a sub-entry:

```markdown
## True Positives (5) — Action Required
| File | Line | Confidence | Reasoning | Remediation |
|------|------|------------|-----------|-------------|
| app.py | 42 | 91% | This finding is a real SQL injection... | Use parameterized queries... |

<details>
<summary>Dataflow Details</summary>

**app.py:42** — The `query` parameter enters via `request.args.get("q")` at line 38. It passes through `raw.strip()` at line 39, is concatenated into a SQL string at line 41, and reaches `cursor.execute()` at line 42 without sanitization.

</details>
```

Use `<details>` collapsible block to keep the report scannable. Findings with `dataflow_analysis == None` or starting with "Not applicable" are omitted from the details section.

### Cache serialization

`FindingVerdict` is a Pydantic `BaseModel` — `.model_dump()` already handles the new field. No manual serialization needed.

## Files Changed

| File | Change |
|------|--------|
| `src/models/analysis.py` | Add `dataflow_analysis: Optional[str] = None` to `FindingVerdict` |
| `src/config.py` | Add `LLM_PROMPT_STRATEGY: str = "single_pass"` |
| `src/llm/prompt_builder.py` | Rewrite system prompt (remove pipe format). Add `build_dataflow_prompt()` for Stage 1. Modify `build_grouped_prompt()` to accept `dataflow_summaries` for Stage 2. |
| `src/core/orchestrator.py` | Strategy switch in `_analyze_file_group`: single-pass vs two-stage. Wire Stage 1 → Stage 2 for two-stage. |
| `src/reports/annotated_json.py` | Include `dataflow_analysis` in `x_fp_analysis` dict |
| `src/reports/markdown_summary.py` | Render dataflow in report |
| `tests/test_llm.py` | Update prompt assertion tests for new format |
| `tests/test_orchestrator.py` | Test both strategies |
| `tests/test_reports.py` | Test dataflow in annotated JSON and markdown |

## Testing

- Unit test: both prompt strategies produce valid output schema
- Unit test: `dataflow_analysis` field present in annotated JSON
- Unit test: markdown report includes dataflow section
- Integration test: run both strategies on smallweb findings, compare output quality
- A/B comparison: same findings, both strategies, human evaluation of verdict quality and dataflow accuracy

## Explicit Non-Goals

- No changes to the taint tracing engine itself (that's a separate spec)
- No UI changes (this is API/report output only)
- No SARIF output format (future work)
- No automated A/B evaluation metrics (manual comparison for now)
