"""Tests for tree-sitter code reader."""

import pytest
from pathlib import Path
from src.code_reader.tree_sitter_reader import TreeSitterReader

FIXTURE = str(Path(__file__).parent / "fixtures" / "sample.py")
JS_FIXTURE = str(Path(__file__).parent / "fixtures" / "sample.js")
TS_FIXTURE = str(Path(__file__).parent / "fixtures" / "sample.ts")
RB_FIXTURE = str(Path(__file__).parent / "fixtures" / "sample.rb")
RS_FIXTURE = str(Path(__file__).parent / "fixtures" / "sample.rs")


@pytest.fixture
def reader():
    return TreeSitterReader()


# --- Python tests ---

def test_find_enclosing_function(reader):
    # Line 13 is inside process_input
    name = reader.find_enclosing_function(FIXTURE, 13)
    assert name == "process_input"


def test_find_enclosing_method(reader):
    # Line 22 is inside AuthService._validate
    name = reader.find_enclosing_function(FIXTURE, 22)
    assert name == "_validate"


def test_get_function_body(reader):
    body = reader.get_function_body(FIXTURE, "process_input")
    assert "SELECT * FROM users" in body
    assert "def process_input" in body


def test_get_function_body_not_found(reader):
    body = reader.get_function_body(FIXTURE, "nonexistent")
    assert body == ""


def test_find_callees(reader):
    callees = reader.find_callees(FIXTURE, "process_input")
    # process_input doesn't call other functions except f-string, no explicit calls
    assert isinstance(callees, list)


def test_find_callees_with_calls(reader):
    callees = reader.find_callees(FIXTURE, "login")
    assert "_validate" in callees


def test_find_imports(reader):
    imports = reader.find_imports(FIXTURE)
    assert "os" in imports


def test_read_context_lines(reader):
    snippet = reader.read_context(FIXTURE, line=13, context=3)
    assert "process_input" in snippet


def test_unsupported_language_returns_empty(reader):
    name = reader.find_enclosing_function("/fake/file.xyz", 1)
    assert name == ""


# --- JavaScript tests ---

def test_find_enclosing_javascript_function(reader):
    name = reader.find_enclosing_function(JS_FIXTURE, 6)
    assert name == "applyDark"


def test_find_callees_in_javascript_function(reader):
    callees = reader.find_callees(JS_FIXTURE, "applyDark")
    assert "updateIframeStyles" in callees
    assert "forEach" in callees


# --- TypeScript tests ---

def test_ts_find_enclosing_function(reader):
    # Line 5 is inside processRequest
    name = reader.find_enclosing_function(TS_FIXTURE, 5)
    assert name == "processRequest"


def test_ts_find_enclosing_arrow_function(reader):
    # Line 10 is inside validateInput (arrow function)
    name = reader.find_enclosing_function(TS_FIXTURE, 10)
    assert name == "validateInput"


def test_ts_find_enclosing_method(reader):
    # Line 15 is inside getUser method
    name = reader.find_enclosing_function(TS_FIXTURE, 15)
    assert name == "getUser"


def test_ts_find_callees(reader):
    callees = reader.find_callees(TS_FIXTURE, "getUser")
    assert "get" in callees


def test_ts_find_imports(reader):
    imports = reader.find_imports(TS_FIXTURE)
    assert "express" in imports
    assert "axios" in imports


def test_ts_get_function_body_arrow(reader):
    body = reader.get_function_body(TS_FIXTURE, "validateInput")
    assert "input.length" in body


# --- Ruby tests ---

def test_rb_find_enclosing_function(reader):
    # Line 5 is inside process_data
    name = reader.find_enclosing_function(RB_FIXTURE, 5)
    assert name == "process_data"


def test_rb_find_enclosing_method(reader):
    # Line 11 is inside authenticate
    name = reader.find_enclosing_function(RB_FIXTURE, 11)
    assert name == "authenticate"


def test_rb_find_callees(reader):
    callees = reader.find_callees(RB_FIXTURE, "authenticate")
    assert "validate" in callees
    assert "query_db" in callees


def test_rb_find_imports(reader):
    imports = reader.find_imports(RB_FIXTURE)
    assert "json" in imports
    assert "helpers" in imports


# --- Rust tests ---

def test_rs_find_enclosing_function(reader):
    # Line 5 is inside process_input
    name = reader.find_enclosing_function(RS_FIXTURE, 5)
    assert name == "process_input"


def test_rs_find_callees(reader):
    callees = reader.find_callees(RS_FIXTURE, "validate_and_store")
    assert "parse_data" in callees
    assert "store_result" in callees


def test_rs_find_imports(reader):
    imports = reader.find_imports(RS_FIXTURE)
    assert "std::io" in imports
    assert "std::collections::HashMap" in imports


# --- Edge cases ---

def test_svelte_ts_extension(reader, tmp_path):
    """Files like component.svelte.ts should be parsed as TypeScript."""
    ts_file = tmp_path / "component.svelte.ts"
    ts_file.write_text('function setup(): void { return; }\n')
    name = reader.find_enclosing_function(str(ts_file), 1)
    assert name == "setup"


# --- Taint field tests ---

def test_python_language_config_has_taint_fields():
    from src.code_reader.tree_sitter_reader import _LANG_REGISTRY
    _, config = _LANG_REGISTRY[".py"]
    assert config.assignment_types
    assert "assignment" in config.assignment_types
    assert config.parameter_types
    assert config.return_types
    assert config.conditional_types


def test_js_language_config_has_taint_fields():
    from src.code_reader.tree_sitter_reader import _LANG_REGISTRY
    _, config = _LANG_REGISTRY[".js"]
    assert "assignment_expression" in config.assignment_types or "variable_declarator" in config.assignment_types


def test_go_language_config_has_taint_fields():
    from src.code_reader.tree_sitter_reader import _LANG_REGISTRY
    _, config = _LANG_REGISTRY[".go"]
    assert "short_var_declaration" in config.assignment_types


def test_java_language_config_has_taint_fields():
    from src.code_reader.tree_sitter_reader import _LANG_REGISTRY
    _, config = _LANG_REGISTRY[".java"]
    assert "variable_declarator" in config.assignment_types


def test_unsupported_language_has_empty_taint_fields():
    from src.code_reader.tree_sitter_reader import _LANG_REGISTRY
    _, config = _LANG_REGISTRY[".php"]
    assert not config.assignment_types
    assert not config.parameter_types


def test_tree_sitter_reader_public_accessors():
    from src.code_reader.tree_sitter_reader import TreeSitterReader
    reader = TreeSitterReader()
    config = reader.get_config(".py")
    assert config is not None
    assert config.assignment_types
