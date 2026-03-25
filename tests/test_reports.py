"""Tests for report builders."""

import pytest
from src.reports.annotated_json import build_annotated_json
from src.reports.markdown_summary import build_markdown_summary
from src.models.analysis import FindingVerdict, AnalysisResult, FileGroupResult, FindingContext, CallerInfo


SAMPLE_SEMGREP = {
    "version": "1.1.0",
    "results": [
        {
            "check_id": "sql-injection",
            "path": "app.py",
            "start": {"line": 10, "col": 1},
            "end": {"line": 10, "col": 30},
            "extra": {
                "message": "SQL injection",
                "severity": "HIGH",
                "fingerprint": "fp1",
                "lines": "query = f'SELECT...'",
                "metadata": {},
            },
        },
        {
            "check_id": "exec-detected",
            "path": "app.py",
            "start": {"line": 20, "col": 1},
            "end": {"line": 20, "col": 15},
            "extra": {
                "message": "exec usage",
                "severity": "MEDIUM",
                "fingerprint": "fp2",
                "lines": "exec(x)",
                "metadata": {},
            },
        },
    ],
    "errors": [],
    "paths": {"scanned": ["app.py"], "skipped": []},
}


def _make_verdicts():
    return [
        FindingVerdict(
            finding_index=0,
            fingerprint="fp1",
            verdict="true_positive",
            confidence=0.92,
            reasoning="Vulnerable",
            decision_source="llm",
            applied_memory_ids=["repo-memory-1"],
        ),
        FindingVerdict(
            finding_index=1,
            fingerprint="fp2",
            verdict="false_positive",
            confidence=0.85,
            reasoning="Sanitized",
            decision_source="human_override",
            override_id="override-1",
        ),
    ]


def test_annotated_json_preserves_original():
    verdicts = _make_verdicts()
    result = build_annotated_json(SAMPLE_SEMGREP, {"app.py": verdicts}, "abc123", "fpt_cloud")
    assert result["version"] == "1.1.0"
    assert len(result["results"]) == 2
    assert result["results"][0]["check_id"] == "sql-injection"


def test_annotated_json_adds_x_fp_analysis():
    verdicts = _make_verdicts()
    result = build_annotated_json(SAMPLE_SEMGREP, {"app.py": verdicts}, "abc123", "fpt_cloud")
    fp = result["results"][0]["extra"]["x_fp_analysis"]
    assert fp["verdict"] == "true_positive"
    assert fp["classification"] == "true_positive"
    assert fp["confidence"] == 0.92
    assert fp["commit_sha"] == "abc123"
    assert fp["decision_source"] == "llm"
    assert fp["applied_memory_ids"] == ["repo-memory-1"]


def test_annotated_json_includes_override_provenance():
    verdicts = _make_verdicts()
    result = build_annotated_json(SAMPLE_SEMGREP, {"app.py": verdicts}, "abc123", "fpt_cloud")
    fp = result["results"][1]["extra"]["x_fp_analysis"]
    assert fp["decision_source"] == "human_override"
    assert fp["override_id"] == "override-1"


def test_annotated_json_unmatched_finding_gets_uncertain():
    result = build_annotated_json(SAMPLE_SEMGREP, {}, "abc", "fpt")
    fp = result["results"][0]["extra"]["x_fp_analysis"]
    assert fp["verdict"] == "uncertain"
    assert fp["confidence"] == 0.0
    assert fp["status"] == "no_verdict"


def test_annotated_json_includes_graph_context():
    verdicts = _make_verdicts()
    contexts = {
        0: FindingContext(
            code_snippet="q = f'SELECT...'",
            enclosing_function="index",
            function_body="def index(): ...",
            callers=[CallerInfo(file="routes.py", line=50, function="dispatch", context="dispatch()")],
            callees=["execute", "format"],
            imports=["sqlite3"],
            source="gkg",
        ),
    }
    result = build_annotated_json(
        SAMPLE_SEMGREP,
        {"app.py": verdicts},
        "abc123",
        "fpt_cloud",
        contexts_by_file={"app.py": contexts},
    )
    gc = result["results"][0]["extra"]["x_fp_analysis"]["graph_context"]
    assert gc["enclosing_function"] == "index"
    assert gc["callers"][0]["file"] == "routes.py"
    assert gc["callers"][0]["function"] == "dispatch"
    assert gc["callers"][0]["context"] == "dispatch()"
    assert gc["callees"] == ["execute", "format"]
    assert gc["imports"] == ["sqlite3"]


def test_annotated_json_graph_context_absent_when_no_contexts():
    verdicts = _make_verdicts()
    result = build_annotated_json(SAMPLE_SEMGREP, {"app.py": verdicts}, "abc123", "fpt_cloud")
    assert "graph_context" not in result["results"][0]["extra"]["x_fp_analysis"]


def test_markdown_summary():
    analysis = AnalysisResult(
        repo_url="https://github.com/user/repo",
        commit_sha="abc123",
        file_groups=[
            FileGroupResult(file_path="app.py", verdicts=_make_verdicts()),
        ],
    )
    md = build_markdown_summary(analysis, threshold=0.8)
    assert "# Semgrep False-Positive Analysis Report" in md
    assert "True Positives" in md
    assert "False Positives" in md
    assert "sql-injection" in md or "app.py" in md
