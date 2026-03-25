"""Tests for dynamic CWE rubric selection."""

from src.llm.cwe_rubrics import (
    get_rubric,
    get_rubric_by_class,
    get_rubrics_for_findings,
    format_rubrics_for_prompt,
    _parse_cwe_id,
)


def test_get_rubric_known_cwe():
    r = get_rubric(89)
    assert r.name == "SQL Injection"
    assert len(r.high_risk) > 0
    assert len(r.safe_patterns) > 0


def test_get_rubric_unknown_returns_generic():
    r = get_rubric(99999)
    assert r.cwe_id == 0
    assert r.name == "Generic"


def test_get_rubric_by_class():
    r = get_rubric_by_class("SQL Injection")
    assert r is not None
    assert r.cwe_id == 89


def test_get_rubric_by_class_case_insensitive():
    r = get_rubric_by_class("cross-site-scripting")
    assert r is not None
    assert r.cwe_id == 79


def test_get_rubric_by_class_unknown():
    r = get_rubric_by_class("Unknown Category")
    assert r is None


def test_parse_cwe_id():
    assert _parse_cwe_id("CWE-89: Improper Neutralization") == 89
    assert _parse_cwe_id("CWE-79") == 79
    assert _parse_cwe_id("not a cwe") is None


def test_get_rubrics_for_findings_by_cwe():
    findings = [
        {"index": 0, "rule": "sql-injection", "cwe": ["CWE-89: SQL Injection"], "message": ""},
        {"index": 1, "rule": "xss", "cwe": ["CWE-79: XSS"], "message": ""},
    ]
    rubrics = get_rubrics_for_findings(findings)
    names = {r.name for r in rubrics}
    assert "SQL Injection" in names
    assert "Cross-Site Scripting (XSS)" in names


def test_get_rubrics_for_findings_by_class():
    findings = [
        {"index": 0, "rule": "redos", "vulnerability_class": "Denial-of-Service (DoS)", "message": ""},
    ]
    rubrics = get_rubrics_for_findings(findings)
    assert rubrics[0].cwe_id == 1333


def test_get_rubrics_for_findings_deduplicates():
    findings = [
        {"index": 0, "rule": "sqli-1", "cwe": ["CWE-89"], "message": ""},
        {"index": 1, "rule": "sqli-2", "cwe": ["CWE-89"], "message": ""},
    ]
    rubrics = get_rubrics_for_findings(findings)
    assert len(rubrics) == 1


def test_get_rubrics_for_findings_generic_fallback():
    findings = [{"index": 0, "rule": "unknown-rule", "message": ""}]
    rubrics = get_rubrics_for_findings(findings)
    assert len(rubrics) == 1
    assert rubrics[0].name == "Generic"


def test_format_rubrics_for_prompt():
    rubrics = get_rubrics_for_findings([{"index": 0, "cwe": ["CWE-89"], "message": ""}])
    text = format_rubrics_for_prompt(rubrics)
    assert "SQL Injection" in text
    assert "High risk" in text
    assert "Safe patterns" in text


def test_format_rubrics_empty():
    assert format_rubrics_for_prompt([]) == ""
