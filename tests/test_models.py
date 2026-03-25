"""Tests for data models."""

import pytest
from src.models.semgrep import SemgrepFinding, SemgrepOutput, parse_semgrep_json
from src.models.analysis import (
    FindingVerdict,
    FileGroupResult,
    AnalysisResult,
    CallerInfo,
    FindingContext,
)


SAMPLE_FINDING = {
    "check_id": "python.lang.security.audit.exec-detected",
    "path": "src/app.py",
    "start": {"line": 10, "col": 1},
    "end": {"line": 10, "col": 30},
    "extra": {
        "message": "Detected exec usage",
        "severity": "WARNING",
        "fingerprint": "abc123",
        "lines": "exec(user_input)",
        "metadata": {"confidence": "HIGH", "cwe": ["CWE-78"]},
        "is_ignored": False,
    },
}

SAMPLE_SEMGREP_JSON = {
    "version": "1.1.0",
    "results": [SAMPLE_FINDING],
    "errors": [],
    "paths": {"scanned": ["src/app.py"], "skipped": []},
}


def test_parse_semgrep_finding():
    f = SemgrepFinding.model_validate(SAMPLE_FINDING)
    assert f.check_id == "python.lang.security.audit.exec-detected"
    assert f.path == "src/app.py"
    assert f.start_line == 10
    assert f.fingerprint == "abc123"
    assert f.severity == "WARNING"
    assert f.is_ignored is False


def test_parse_semgrep_output():
    output = SemgrepOutput.model_validate(SAMPLE_SEMGREP_JSON)
    assert len(output.results) == 1
    assert output.results[0].check_id == "python.lang.security.audit.exec-detected"


def test_parse_semgrep_json_filters_ignored():
    data = SAMPLE_SEMGREP_JSON.copy()
    ignored = SAMPLE_FINDING.copy()
    ignored["extra"] = {**ignored["extra"], "is_ignored": True}
    data["results"] = [SAMPLE_FINDING, ignored]
    findings = parse_semgrep_json(data, filter_ignored=True)
    assert len(findings) == 1


def test_parse_semgrep_json_groups_by_file():
    f2 = {**SAMPLE_FINDING, "path": "src/other.py"}
    data = {**SAMPLE_SEMGREP_JSON, "results": [SAMPLE_FINDING, SAMPLE_FINDING, f2]}
    findings = parse_semgrep_json(data)
    groups = {}
    for f in findings:
        groups.setdefault(f.path, []).append(f)
    assert len(groups) == 2
    assert len(groups["src/app.py"]) == 2
    assert len(groups["src/other.py"]) == 1


def test_finding_verdict_model():
    v = FindingVerdict(
        finding_index=0,
        fingerprint="abc123",
        verdict="false_positive",
        confidence=0.85,
        reasoning="Input is sanitized",
    )
    assert v.classification(threshold=0.8) == "false_positive"


def test_finding_verdict_uncertain_below_threshold():
    v = FindingVerdict(
        finding_index=0,
        fingerprint="abc123",
        verdict="true_positive",
        confidence=0.6,
        reasoning="Unclear",
    )
    assert v.classification(threshold=0.8) == "uncertain"


def test_file_group_result_has_contexts():
    ctx = FindingContext(
        code_snippet="x = 1",
        enclosing_function="foo",
        function_body="def foo(): x = 1",
        source="tree_sitter",
    )
    fg = FileGroupResult(file_path="app.py", contexts={0: ctx})
    assert fg.contexts[0].enclosing_function == "foo"


def test_file_group_result_contexts_defaults_empty():
    fg = FileGroupResult(file_path="app.py")
    assert fg.contexts == {}


def test_finding_context_dataclass():
    ctx = FindingContext(
        code_snippet="10 | exec(user_input)",
        enclosing_function="handle_request",
        function_body="def handle_request():\n    exec(user_input)",
        callers=[],
        callees=["exec"],
        imports=["os"],
        related_definitions=[],
        source="tree_sitter",
    )
    assert ctx.enclosing_function == "handle_request"
    assert ctx.source == "tree_sitter"
