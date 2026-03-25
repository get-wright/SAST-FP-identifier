"""Tests for LLM client components."""

import pytest
from src.llm.json_extractor import extract_json_array
from src.llm.prompt_builder import SYSTEM_PROMPT, build_grouped_prompt
from src.core.triage_memory import TriageMemory
from src.llm.provider import create_provider
from src.models.analysis import FindingContext


# --- JSON Extractor tests ---

def test_extract_clean_json():
    raw = '[{"finding_index": 1, "is_false_positive": true, "confidence": 0.9, "reasoning": "safe"}]'
    result = extract_json_array(raw)
    assert len(result) == 1
    assert result[0]["is_false_positive"] is True


def test_extract_json_from_markdown_fence():
    raw = '```json\n[{"finding_index": 1, "is_false_positive": false, "confidence": 0.8, "reasoning": "vuln"}]\n```'
    result = extract_json_array(raw)
    assert len(result) == 1


def test_extract_json_with_think_tags():
    raw = '<think>Let me analyze...</think>\n[{"finding_index": 1, "is_false_positive": true, "confidence": 0.7, "reasoning": "ok"}]'
    result = extract_json_array(raw)
    assert len(result) == 1


def test_extract_json_with_surrounding_text():
    raw = 'Here is my analysis:\n[{"finding_index": 1, "is_false_positive": true, "confidence": 0.85, "reasoning": "sanitized"}]\nHope this helps!'
    result = extract_json_array(raw)
    assert len(result) == 1


def test_extract_json_returns_empty_on_garbage():
    result = extract_json_array("This is not JSON at all")
    assert result == []


def test_extract_json_repairs_truncated_array():
    """Truncated JSON from reasoning model output budget exhaustion."""
    raw = '[{"finding_index": 1, "verdict": "true_positive", "confidence": 0.9, "reasoning": "vuln"}, {"finding_index": 2, "verdict": "false_positive", "confidence": 0.8, "reasoning": "sa'
    result = extract_json_array(raw)
    # Should recover at least the first complete item
    assert len(result) >= 1
    assert result[0]["finding_index"] == 1


def test_extract_json_repairs_truncated_in_markdown():
    """Truncated JSON inside markdown fences."""
    raw = '```json\n[{"finding_index": 1, "verdict": "true_positive", "confidence": 0.9, "reasoning": "real vuln"}, {"finding_in'
    result = extract_json_array(raw)
    assert len(result) >= 1
    assert result[0]["verdict"] == "true_positive"


def test_extract_json_repairs_truncated_after_comma():
    """Truncation right after a comma between objects."""
    raw = '[{"finding_index": 1, "verdict": "true_positive", "confidence": 0.9, "reasoning": "vuln"},'
    result = extract_json_array(raw)
    assert len(result) >= 1
    assert result[0]["finding_index"] == 1


# --- Prompt Builder tests ---

def test_build_grouped_prompt_basic():
    contexts = {
        0: FindingContext(
            code_snippet="10 | exec(x)",
            enclosing_function="run",
            function_body="def run():\n    exec(x)",
            callers=[],
            callees=["exec"],
            imports=["os"],
            related_definitions=[],
            source="tree_sitter",
        ),
    }
    findings_text = [
        {"index": 0, "rule": "exec-detected", "line": 10, "message": "exec usage"},
    ]
    prompt = build_grouped_prompt(
        file_path="src/app.py",
        findings=findings_text,
        contexts=contexts,
        repo_map="src/\n  app.py",
    )
    assert "exec-detected" in prompt
    assert "src/app.py" in prompt
    assert "EVIDENCE PER FINDING" in prompt
    assert "verdict" in prompt
    assert '"true_positive"' in prompt or '"false_positive"' in prompt
    assert "10 | exec(x)" in prompt


def test_build_grouped_prompt_includes_matching_memories():
    contexts = {
        0: FindingContext(
            code_snippet="10 | exec(x)",
            enclosing_function="run",
            function_body="def run():\n    exec(x)",
            callers=[],
            callees=["exec"],
            imports=["os"],
            related_definitions=[],
            source="tree_sitter",
        ),
    }
    findings_text = [
        {"index": 0, "rule": "exec-detected", "line": 10, "message": "exec usage"},
    ]
    memories = {
        0: [
            TriageMemory(
                id="repo-memory-1",
                scope="repo",
                repo_url="https://github.com/u/r",
                framework=None,
                rule="exec-detected",
                guidance="Internal scripts in this repo often use constant exec inputs and need exact sink inspection.",
            ),
        ],
    }
    prompt = build_grouped_prompt(
        file_path="src/app.py",
        findings=findings_text,
        contexts=contexts,
        repo_map="src/\n  app.py",
        memories=memories,
    )
    assert "REVIEWER MEMORIES" in prompt
    assert "repo-memory-1" in prompt
    assert "constant exec inputs" in prompt


def test_build_grouped_prompt_allows_uncertain_without_biasing_true_positive():
    assert "Do NOT guess" in SYSTEM_PROMPT
    assert "lean toward true positive" not in SYSTEM_PROMPT


def test_build_grouped_prompt_respects_max_tokens():
    """Large context should be truncated."""
    big_body = "x = 1\n" * 2000
    contexts = {
        0: FindingContext(
            code_snippet="1 | x",
            enclosing_function="f",
            function_body=big_body,
            source="tree_sitter",
        ),
    }
    findings_text = [{"index": 0, "rule": "r", "line": 1, "message": "m"}]
    prompt = build_grouped_prompt("f.py", findings_text, contexts, "", max_tokens=2000)
    # Prompt should be truncated — 2000 tokens * 4 chars = 8000 chars max
    assert len(prompt) < len(big_body)


# --- Provider factory test ---

def test_create_provider_fpt_cloud():
    p = create_provider("fpt_cloud", api_key="test", base_url="http://x", model="m")
    assert p is not None


def test_create_provider_openai():
    p = create_provider("openai", api_key="test", model="gpt-4")
    assert p is not None


def test_create_provider_anthropic():
    p = create_provider("anthropic", api_key="test", model="claude-3")
    assert p is not None


def test_create_provider_unknown_raises():
    with pytest.raises(ValueError):
        create_provider("unknown", api_key="test", model="m")


def test_create_provider_openrouter():
    p = create_provider("openrouter", api_key="test", model="gpt-oss-120b")
    assert p is not None


def test_create_provider_accepts_reasoning_flag():
    """create_provider should accept is_reasoning_model without error."""
    p = create_provider("openai", api_key="test", model="o3", is_reasoning_model=True)
    assert p is not None


def test_create_provider_anthropic_reasoning_flag_warns(caplog):
    """Anthropic provider should accept is_reasoning_model but log a warning."""
    import logging
    with caplog.at_level(logging.WARNING):
        p = create_provider("anthropic", api_key="test", model="claude-3", is_reasoning_model=True)
    assert p is not None
    assert "no effect" in caplog.text.lower() or "is_reasoning_model" in caplog.text


# --- Reasoning model integration tests ---

async def test_reasoning_provider_uses_max_completion_tokens(monkeypatch):
    """Verify reasoning model provider sends max_completion_tokens instead of max_tokens."""
    captured_kwargs = {}

    class FakeResponse:
        class Choice:
            finish_reason = "stop"
            class message:
                content = '[{"finding_index": 1, "verdict": "true_positive", "confidence": 0.9, "reasoning": "test"}]'
        choices = [Choice()]
        class usage:
            prompt_tokens = 100
            completion_tokens = 200

    async def fake_create(**kwargs):
        captured_kwargs.update(kwargs)
        return FakeResponse()

    provider = create_provider("openai", api_key="test", model="o3", is_reasoning_model=True)
    monkeypatch.setattr(provider._client.chat.completions, "create", fake_create)

    await provider.complete("system prompt", "user prompt", temperature=0.3, max_tokens=4000)

    assert "max_completion_tokens" in captured_kwargs
    assert "max_tokens" not in captured_kwargs
    assert "temperature" not in captured_kwargs
    assert captured_kwargs["max_completion_tokens"] == 16000


async def test_non_reasoning_provider_uses_max_tokens(monkeypatch):
    """Verify non-reasoning provider sends max_tokens and temperature as before."""
    captured_kwargs = {}

    class FakeResponse:
        class Choice:
            finish_reason = "stop"
            class message:
                content = "[]"
        choices = [Choice()]
        usage = None

    async def fake_create(**kwargs):
        captured_kwargs.update(kwargs)
        return FakeResponse()

    provider = create_provider("openai", api_key="test", model="gpt-4.1")
    monkeypatch.setattr(provider._client.chat.completions, "create", fake_create)

    await provider.complete("system", "prompt", temperature=0.3, max_tokens=4000)

    assert "max_tokens" in captured_kwargs
    assert "max_completion_tokens" not in captured_kwargs
    assert captured_kwargs["temperature"] == 0.3


async def test_finish_reason_length_logs_warning(monkeypatch, caplog):
    """Verify truncation warning is logged when finish_reason is 'length'."""
    import logging

    class FakeResponse:
        class Choice:
            finish_reason = "length"
            class message:
                content = '[{"finding_index": 1}]'
        choices = [Choice()]
        class usage:
            prompt_tokens = 500
            completion_tokens = 4000

    async def fake_create(**kwargs):
        return FakeResponse()

    provider = create_provider("openai", api_key="test", model="gpt-4.1")
    monkeypatch.setattr(provider._client.chat.completions, "create", fake_create)

    with caplog.at_level(logging.WARNING):
        await provider.complete("system", "prompt")

    assert "truncated" in caplog.text.lower()
    assert "finish_reason=length" in caplog.text
