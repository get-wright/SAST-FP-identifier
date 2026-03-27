"""Tests for LLM client components."""

import pytest
from src.llm.prompt_builder import SYSTEM_PROMPT, build_grouped_prompt
from src.core.triage_memory import TriageMemory
from src.llm.provider import create_chat_model
from src.models.analysis import FindingContext


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
    assert "Analyze each finding" in prompt
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
    assert "uncertain" in SYSTEM_PROMPT
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


def test_create_chat_model_reasoning():
    from src.llm.provider import create_chat_model
    model = create_chat_model("openai", "sk-test", "o3", is_reasoning_model=True)
    assert model is not None


def test_prompt_includes_taint_flow():
    from src.llm.prompt_builder import build_grouped_prompt
    from src.models.analysis import FindingContext, FlowStep, TaintFlow

    flow = TaintFlow(
        path=[
            FlowStep(variable="user_input", line=5, expression="user_input = request.args.get('q')", kind="source"),
            FlowStep(variable="query", line=8, expression="query = f'SELECT ... {user_input}'", kind="assignment"),
            FlowStep(variable="query", line=9, expression="cursor.execute(query)", kind="sink"),
        ],
        sanitizers=[],
        unresolved_calls=[],
        cross_file_hops=[],
        confidence_factors=["Direct source to sink with no sanitizer"],
        inferred=None,
    )

    ctx = FindingContext(
        code_snippet="9 | cursor.execute(query)",
        enclosing_function="handle",
        function_body="def handle(user_input):\n    query = ...\n    cursor.execute(query)",
        taint_flow=flow,
    )

    prompt = build_grouped_prompt(
        file_path="app.py",
        findings=[{"index": 0, "rule": "sqli", "line": 9, "message": "SQL injection"}],
        contexts={0: ctx},
    )

    assert "TRACED DATA FLOW" in prompt
    assert "user_input" in prompt
    assert "SOURCE" in prompt
    assert "SINK" in prompt


def test_prompt_taint_flow_with_sanitizer():
    from src.llm.prompt_builder import build_grouped_prompt
    from src.models.analysis import FindingContext, FlowStep, SanitizerInfo, TaintFlow

    flow = TaintFlow(
        path=[
            FlowStep(variable="user_input", line=5, expression="param", kind="parameter"),
            FlowStep(variable="safe", line=6, expression="safe = escape(user_input)", kind="call_result"),
            FlowStep(variable="safe", line=7, expression="output(safe)", kind="sink"),
        ],
        sanitizers=[SanitizerInfo(name="escape", line=6, cwe_categories=["CWE-79"], conditional=False, verified=False)],
        unresolved_calls=[],
        cross_file_hops=[],
        confidence_factors=[],
        inferred=None,
    )

    ctx = FindingContext(
        code_snippet="7 | output(safe)",
        enclosing_function="render",
        function_body="...",
        taint_flow=flow,
    )

    prompt = build_grouped_prompt(
        file_path="app.py",
        findings=[{"index": 0, "rule": "xss", "line": 7, "message": "XSS"}],
        contexts={0: ctx},
    )

    assert "SANITIZER" in prompt.upper()
    assert "escape" in prompt


def test_verdict_output_schema():
    from src.llm.schemas import VerdictOutput, VerdictOutputBatch
    v = VerdictOutput(
        finding_index=1,
        reasoning="SOURCE: x | SANITIZATION: none | SINK: y | EXPLOITABILITY: z",
        dataflow_analysis="Data enters at x, flows unsanitized to sink y.",
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


def test_verdict_output_has_dataflow_analysis():
    from src.llm.schemas import VerdictOutput
    v = VerdictOutput(
        finding_index=1, reasoning="Safe.",
        dataflow_analysis="Data enters via param, flows to md5().",
        verdict="false_positive", confidence=0.9,
    )
    assert v.dataflow_analysis == "Data enters via param, flows to md5()."


def test_dataflow_result_schema():
    from src.llm.schemas import DataflowResult, DataflowBatch
    r = DataflowResult(finding_index=1, dataflow_analysis="Data enters at line 5.", flow_complete=True, gaps=[])
    batch = DataflowBatch(results=[r])
    assert batch.results[0].flow_complete is True


def test_verdict_only_schema():
    from src.llm.schemas import VerdictOnlyOutput, VerdictOnlyBatch
    v = VerdictOnlyOutput(finding_index=1, reasoning="SQL injection is real.", verdict="true_positive", confidence=0.95)
    batch = VerdictOnlyBatch(verdicts=[v])
    assert batch.verdicts[0].verdict == "true_positive"


# --- Structured Output: reasoning model content block handling ---


def test_extract_text_content_plain_string():
    from src.llm.structured_output import _extract_text_content

    class FakeResponse:
        content = '{"verdicts": []}'

    assert _extract_text_content(FakeResponse()) == '{"verdicts": []}'


def test_extract_text_content_reasoning_blocks():
    from src.llm.structured_output import _extract_text_content

    class FakeResponse:
        content = [
            {"type": "thinking", "thinking": "Let me analyze this..."},
            {"type": "text", "text": '{"verdicts": [{"finding_index": 1}]}'},
        ]

    result = _extract_text_content(FakeResponse())
    assert '{"verdicts"' in result
    assert "thinking" not in result.lower() or "Let me analyze" not in result


def test_extract_text_content_list_of_strings():
    from src.llm.structured_output import _extract_text_content

    class FakeResponse:
        content = ["first part", "second part"]

    result = _extract_text_content(FakeResponse())
    assert "first part" in result
    assert "second part" in result


def test_extract_text_content_object_with_text_attr():
    from src.llm.structured_output import _extract_text_content

    class ContentBlock:
        def __init__(self, text):
            self.text = text

    class FakeResponse:
        content = [ContentBlock('{"verdicts": []}')]

    result = _extract_text_content(FakeResponse())
    assert '{"verdicts"' in result
