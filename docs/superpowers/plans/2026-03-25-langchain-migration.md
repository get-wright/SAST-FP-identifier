# LangChain Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace raw OpenAI/Anthropic SDK calls with LangChain chat models and `with_structured_output()`, eliminating the brittle json_extractor.py regex fallback chain. Same output behavior — no prompt or format changes yet.

**Architecture:** Swap `LLMProvider` Protocol + `create_provider()` for `BaseChatModel` + `create_chat_model()`. Replace `llm.complete() → str → extract_json_array()` with `llm.with_structured_output(Pydantic) → ainvoke() → typed model`. Existing prompts, verdicts, reports unchanged.

**Tech Stack:** langchain-core, langchain-openai, langchain-anthropic, Pydantic v2

**Spec:** `docs/superpowers/specs/2026-03-25-verdict-output-redesign.md` (LangChain Migration section)

---

### Task 1: Dependencies

**Files:**
- Modify: `requirements.txt`

- [ ] **Step 1: Update requirements.txt**

Replace the `# LLM` section:
```
# LLM
langchain-core>=0.3
langchain-openai>=0.3
langchain-anthropic>=0.3
```

Remove `openai>=2.28.0`, `anthropic>=0.85.0`, and `json-repair>=0.39.0` (json_extractor.py is deleted in Task 4).

- [ ] **Step 2: Install**

Run: `pip install -r requirements.txt`
Verify: `python -c "from langchain_openai import ChatOpenAI; print('ok')"`

- [ ] **Step 3: Commit**

```bash
git add requirements.txt
git commit -m "chore: replace openai/anthropic SDKs with langchain packages"
```

---

### Task 2: Pydantic Output Schema

**Files:**
- Create: `src/llm/schemas.py`
- Test: `tests/test_llm.py` (append)

This schema mirrors the current `extract_json_array` output shape — same fields the existing prompt asks for. No new fields yet.

- [ ] **Step 1: Write failing test**

Append to `tests/test_llm.py`:
```python
def test_verdict_output_schema():
    from src.llm.schemas import VerdictOutput, VerdictOutputBatch
    v = VerdictOutput(
        finding_index=1,
        reasoning="SOURCE: x | SANITIZATION: none | SINK: y | EXPLOITABILITY: z",
        verdict="false_positive",
        confidence=0.9,
    )
    assert v.verdict == "false_positive"
    batch = VerdictOutputBatch(verdicts=[v])
    assert len(batch.verdicts) == 1


def test_verdict_output_schema_validates_verdict():
    from src.llm.schemas import VerdictOutput
    import pytest
    with pytest.raises(Exception):
        VerdictOutput(finding_index=1, reasoning="x", verdict="bad", confidence=0.5)


def test_verdict_output_schema_clamps_confidence():
    from src.llm.schemas import VerdictOutput
    import pytest
    with pytest.raises(Exception):
        VerdictOutput(finding_index=1, reasoning="x", verdict="uncertain", confidence=1.5)
```

- [ ] **Step 2: Create `src/llm/schemas.py`**

```python
"""Pydantic output schemas for LLM structured output."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class VerdictOutput(BaseModel):
    """Single finding verdict — matches current LLM output format."""
    finding_index: int
    reasoning: str = Field(description="Security analysis reasoning")
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(ge=0.0, le=1.0)
    remediation_code: Optional[str] = None
    remediation_explanation: Optional[str] = None


class VerdictOutputBatch(BaseModel):
    """Batch of verdicts for a file group."""
    verdicts: list[VerdictOutput]
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_llm.py::test_verdict_output_schema -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/llm/schemas.py tests/test_llm.py
git commit -m "feat: add Pydantic output schema for LLM verdicts"
```

---

### Task 3: LangChain Provider Factory

**Files:**
- Modify: `src/llm/provider.py`
- Modify: `tests/test_llm.py`

- [ ] **Step 1: Write failing tests**

Replace the existing `test_create_provider_*` tests (lines 164-200) with:

```python
def test_create_chat_model_openai():
    from src.llm.provider import create_chat_model
    from langchain_core.language_models import BaseChatModel
    model = create_chat_model("openai", "sk-test", "gpt-4o", base_url="https://api.openai.com/v1")
    assert isinstance(model, BaseChatModel)


def test_create_chat_model_fpt_cloud():
    from src.llm.provider import create_chat_model
    from langchain_core.language_models import BaseChatModel
    model = create_chat_model("fpt_cloud", "test-key", "GLM-4.5", base_url="https://mkp-api.fptcloud.com")
    assert isinstance(model, BaseChatModel)


def test_create_chat_model_openrouter():
    from src.llm.provider import create_chat_model
    from langchain_core.language_models import BaseChatModel
    model = create_chat_model("openrouter", "sk-or-test", "google/gemini-2.5-flash")
    assert isinstance(model, BaseChatModel)


def test_create_chat_model_anthropic():
    from src.llm.provider import create_chat_model
    from langchain_core.language_models import BaseChatModel
    model = create_chat_model("anthropic", "sk-ant-test", "claude-sonnet-4-6-20250514")
    assert isinstance(model, BaseChatModel)


def test_create_chat_model_unknown_raises():
    from src.llm.provider import create_chat_model
    import pytest
    with pytest.raises(ValueError, match="Unknown LLM provider"):
        create_chat_model("unknown", "key", "model")


def test_create_chat_model_reasoning_model():
    from src.llm.provider import create_chat_model
    model = create_chat_model("openai", "sk-test", "o3", is_reasoning_model=True)
    # Should not raise — reasoning flag accepted
    assert model is not None
```

Also update the import at the top of `tests/test_llm.py`: replace `from src.llm.provider import create_provider` with `from src.llm.provider import create_chat_model`.

- [ ] **Step 2: Rewrite `src/llm/provider.py`**

```python
"""LangChain chat model factory."""

from __future__ import annotations

import logging
from typing import Optional

from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def create_chat_model(
    provider_name: str,
    api_key: str,
    model: str,
    base_url: Optional[str] = None,
    is_reasoning_model: bool = False,
    temperature: float = 0.3,
    max_tokens: int = 4000,
) -> BaseChatModel:
    """Factory for LangChain chat models.

    Supports: fpt_cloud, openai, openrouter, anthropic.
    Returns BaseChatModel with .ainvoke() and .with_structured_output().
    """
    if provider_name in ("fpt_cloud", "openai"):
        from langchain_openai import ChatOpenAI
        kwargs: dict = {
            "api_key": api_key, "model": model,
            "temperature": temperature, "max_tokens": max_tokens,
        }
        if base_url:
            kwargs["base_url"] = base_url
        if is_reasoning_model:
            kwargs["max_tokens"] = min(max_tokens * 4, 32000)
            kwargs["model_kwargs"] = {"reasoning_effort": "low"}
        return ChatOpenAI(**kwargs)

    elif provider_name == "openrouter":
        from langchain_openai import ChatOpenAI
        kwargs = {
            "api_key": api_key, "model": model,
            "base_url": base_url or OPENROUTER_BASE_URL,
            "temperature": temperature, "max_tokens": max_tokens,
        }
        if is_reasoning_model:
            kwargs["max_tokens"] = min(max_tokens * 4, 32000)
            kwargs["model_kwargs"] = {"reasoning_effort": "low"}
        return ChatOpenAI(**kwargs)

    elif provider_name == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            api_key=api_key, model=model,
            temperature=temperature, max_tokens=max_tokens,
        )

    else:
        raise ValueError(f"Unknown LLM provider: {provider_name}")
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_llm.py -k "create_chat_model" -v`
Expected: All 6 PASS

- [ ] **Step 4: Commit**

```bash
git add src/llm/provider.py tests/test_llm.py
git commit -m "feat: rewrite provider.py as LangChain chat model factory"
```

---

### Task 4: Orchestrator — Replace llm.complete() with structured output

**Files:**
- Modify: `src/core/orchestrator.py`
- Modify: `src/api/routes.py`
- Modify: `tests/test_llm.py` (remove json_extractor tests)
- Modify: `tests/test_orchestrator.py`
- Delete: `src/llm/json_extractor.py`

This is the core integration. The orchestrator's `_analyze_batch` currently does:
```
prompt_str → llm.complete(system, prompt) → raw_str → extract_json_array(raw_str) → list[dict]
```
After:
```
messages → llm.with_structured_output(VerdictOutputBatch).ainvoke(messages) → VerdictOutputBatch
```

- [ ] **Step 1: Update orchestrator imports**

In `src/core/orchestrator.py`, replace lines 19-21:
```python
from src.llm.json_extractor import extract_json_array
from src.llm.prompt_builder import SYSTEM_PROMPT, build_grouped_prompt
from src.llm.provider import LLMProvider, create_provider
```
with:
```python
from src.llm.prompt_builder import SYSTEM_PROMPT, build_grouped_prompt
from src.llm.provider import create_chat_model
from src.llm.schemas import VerdictOutputBatch
from langchain_core.language_models import BaseChatModel
```

- [ ] **Step 2: Update Orchestrator.__init__**

Replace line 227:
```python
self._llm = create_provider(llm_provider, llm_api_key, llm_model, llm_base_url, is_reasoning_model=is_reasoning_model)
```
with:
```python
self._llm: BaseChatModel = create_chat_model(
    llm_provider, llm_api_key, llm_model, llm_base_url,
    is_reasoning_model=is_reasoning_model,
    temperature=llm_temperature,
    max_tokens=llm_max_tokens,
)
```

Also remove `self._temperature` and `self._max_tokens` assignments (lines 233-234) — these are now baked into the chat model at construction time. The `_analyze_batch` method no longer needs to pass them per-call.

Update the type annotation on `analyze()` method's `llm_override` parameter (line 263):
```python
llm_override: Optional[BaseChatModel] = None,
```

Same for `_process_file_group` and `_analyze_file_group` — change `Optional[LLMProvider]` to `Optional[BaseChatModel]`.

- [ ] **Step 3: Rewrite `_analyze_batch` LLM call**

Replace the current `llm.complete()` + `extract_json_array()` block (lines 641-655) with:

```python
        structured = llm.with_structured_output(VerdictOutputBatch)
        messages = [("system", SYSTEM_PROMPT), ("human", prompt)]

        async with self._semaphore:
            batch_result = None
            for attempt in range(1 + self._retry_count):
                try:
                    batch_result = await structured.ainvoke(messages)
                    break
                except Exception as e:
                    if attempt < self._retry_count:
                        await asyncio.sleep(1 * (2 ** attempt))
                    else:
                        logger.error("LLM failed after %d retries: %s", self._retry_count, e)

        if batch_result is None:
            parsed = []
        else:
            parsed = [v.model_dump() for v in batch_result.verdicts]
```

The rest of `_analyze_batch` (verdict mapping, index offset, fingerprint assignment) stays unchanged — it already works with `list[dict]`.

- [ ] **Step 4: Update API routes**

In `src/api/routes.py`:
- Replace `from src.llm.provider import create_provider` with `from src.llm.provider import create_chat_model`
- In `_build_llm_override()`, replace `create_provider(...)` with `create_chat_model(...)`

- [ ] **Step 5: Remove json_extractor tests from test_llm.py**

Delete the 8 `test_extract_*` functions (lines 13-67) and remove the `from src.llm.json_extractor import extract_json_array` import.

Also update `from src.llm.prompt_builder import SYSTEM_PROMPT, build_grouped_prompt` — keep as-is since SYSTEM_PROMPT still exists in this PR.

- [ ] **Step 6: Update orchestrator tests**

In `tests/test_orchestrator.py`, find where `_llm.complete` is mocked and update to mock `with_structured_output().ainvoke()` returning a `VerdictOutputBatch`. The simplest approach:

```python
from src.llm.schemas import VerdictOutput, VerdictOutputBatch
from unittest.mock import AsyncMock, MagicMock

# Mock the LLM to return structured output
mock_llm = MagicMock()
mock_structured = AsyncMock()
mock_structured.ainvoke.return_value = VerdictOutputBatch(verdicts=[
    VerdictOutput(finding_index=1, reasoning="Safe.", verdict="false_positive", confidence=0.9),
])
mock_llm.with_structured_output.return_value = mock_structured
```

- [ ] **Step 7: Update integration test mocks**

`tests/test_integration.py` mocks `orch._llm.complete`. Update to mock `orch._llm.with_structured_output().ainvoke()` returning a `VerdictOutputBatch`, same pattern as Step 6.

- [ ] **Step 8: Delete `src/llm/json_extractor.py`**

- [ ] **Step 9: Run full test suite**

Run: `pytest -v`
Expected: All PASS. Fix any remaining import/mock issues.

- [ ] **Step 9: Commit**

```bash
git add src/core/orchestrator.py src/api/routes.py tests/test_llm.py tests/test_orchestrator.py
git rm src/llm/json_extractor.py
git commit -m "feat: replace llm.complete + json_extractor with LangChain structured output"
```

---

### Task 5: Final Regression Pass

- [ ] **Step 1: Run full test suite**

Run: `pytest -q`
Expected: All PASS, 0 failures. If any fail, fix and recommit.

- [ ] **Step 2: Verify docker build**

Run: `docker compose build --quiet`
Expected: Build succeeds with new langchain deps.
