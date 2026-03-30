"""Tests for src/taint/walker — AST body walking with branch/loop handling."""

import os

import tree_sitter_python as ts_python
from tree_sitter import Language, Parser as TSParser

from src.taint.walker import walk_body, WalkState, Definition
from src.taint.models import AccessPath
from src.taint.rules import load_rules

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "taint", "rules")


def _parse_python(code: str):
    """Parse Python code, return function_definition node."""
    parser = TSParser(Language(ts_python.language()))
    tree = parser.parse(code.encode())
    for child in tree.root_node.children:
        if child.type == "function_definition":
            return child
    raise ValueError("No function found in code")


def _make_grammar():
    """Return a LanguageConfig for Python."""
    from src.code_reader.tree_sitter_reader import TreeSitterReader

    reader = TreeSitterReader()
    return reader.get_config(".py")


def _param_def(name: str) -> Definition:
    """Create a parameter definition for testing."""
    return Definition(
        variable=AccessPath(name, ()),
        line=0,
        expression=f"parameter: {name}",
        node=None,
        deps=frozenset(),
        branch_context="",
    )


def test_walk_straight_line():
    code = "def f(x):\n    y = x\n    z = y\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    # z should have exactly one reaching def
    z_defs = state.active.reaching("z")
    assert len(z_defs) == 1


def test_walk_branch_merge():
    code = (
        "def f(x, flag):\n"
        "    if flag:\n"
        "        y = x\n"
        "    else:\n"
        "        y = 'safe'\n"
        "    z = y\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    state.active.define("flag", _param_def("flag"))
    walk_body(func, grammar, state)

    # y should have 2 reaching defs (one from each branch)
    y_defs = state.active.reaching("y")
    assert len(y_defs) == 2


def test_walk_kill_semantics():
    code = "def f(x):\n    y = x\n    y = 'safe'\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    # y should have exactly 1 def (the safe one killed the tainted one)
    y_defs = state.active.reaching("y")
    assert len(y_defs) == 1
    defn = next(iter(y_defs))
    assert "safe" in defn.expression


def test_walk_records_sanitizer():
    code = "def f(x):\n    y = escape(x)\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    assert len(state.sanitizers) >= 1
    assert state.sanitizers[0].name == "escape"


def test_walk_records_guard():
    code = "def f(x):\n    if re.match(r'^ok', x):\n        y = x\n"
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    assert len(state.guards) >= 1
    assert state.guards[0].name == "re.match"


def test_walk_loop():
    code = (
        "def f(x):\n    y = ''\n    for i in range(10):\n        y = y + x\n    z = y\n"
    )
    func = _parse_python(code)
    grammar = _make_grammar()
    rules = load_rules(RULES_DIR)
    state = WalkState(rules=rules, ext=".py", grammar=grammar)
    state.active.define("x", _param_def("x"))
    walk_body(func, grammar, state)

    # y should have defs from both the pre-loop init and the loop body
    y_defs = state.active.reaching("y")
    assert len(y_defs) >= 2
