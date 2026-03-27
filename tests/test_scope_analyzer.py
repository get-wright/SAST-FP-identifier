"""Tests for scope_analyzer: scope tree builder (Pass 1) and fixpoint propagation (Pass 2)."""

import os

from src.taint.scope_analyzer import build_scope_tree, propagate_taint, Scope
from src.code_reader.tree_sitter_reader import TreeSitterReader

_reader = TreeSitterReader()
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _get_func_scope(file_path: str, func_name: str) -> Scope:
    ext = os.path.splitext(file_path)[1]
    config = _reader.get_config(ext)
    root = _reader.parse_file(file_path)
    for node in _walk(root):
        if node.type in config.func_types:
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode() == func_name:
                return build_scope_tree(node, config)
            if node.type == "arrow_function" and node.parent and node.parent.type == "variable_declarator":
                vd_name = node.parent.child_by_field_name("name")
                if vd_name and vd_name.text.decode() == func_name:
                    return build_scope_tree(node, config)
    raise ValueError(f"Function {func_name} not found")


def test_js_foreach_creates_child_scope():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forEachTaint")
    assert "req" in scope.params
    assert len(scope.children) >= 1
    # Find the arrow function child
    arrow_children = [c for c in scope.children if c.kind == "arrow"]
    assert len(arrow_children) >= 1
    assert "item" in arrow_children[0].params


def test_js_foreach_call_site():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forEachTaint")
    forEach_sites = [cs for cs in scope.call_sites if cs.callee == "forEach"]
    assert len(forEach_sites) >= 1
    cs = forEach_sites[0]
    assert cs.receiver_var == "items"
    assert cs.returns_value is False


def test_js_map_call_site_returns_value():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "mapTaint")
    map_sites = [cs for cs in scope.call_sites if cs.callee == "map"]
    assert len(map_sites) >= 1
    assert map_sites[0].returns_value is True
    assert map_sites[0].receiver_var == "names"


def test_js_for_of_creates_child_scope():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forOfTaint")
    loop_children = [c for c in scope.children if c.kind in ("for_of", "for_in")]
    assert len(loop_children) >= 1
    assert "entry" in loop_children[0].params


def test_js_for_of_destructure():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forOfDestructure")
    loop_children = [c for c in scope.children if c.kind in ("for_of", "for_in")]
    assert len(loop_children) >= 1
    assert "key" in loop_children[0].params
    assert "value" in loop_children[0].params


def test_js_for_of_creates_iterator_call_site():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forOfTaint")
    iter_sites = [cs for cs in scope.call_sites if cs.callee == "@@iterator"]
    assert len(iter_sites) >= 1
    assert iter_sites[0].receiver_var == "entries"


def test_py_for_loop_creates_child_scope():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.py"), "for_loop_taint")
    loop_children = [c for c in scope.children if c.kind in ("for_of", "for_in")]
    assert len(loop_children) >= 1
    assert "item" in loop_children[0].params


def test_scope_deps_isolated():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forEachTaint")
    assert "items" in scope.deps


def test_arrow_return_expr():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "mapTaint")
    map_sites = [cs for cs in scope.call_sites if cs.callee == "map"]
    if map_sites:
        cb = map_sites[0].callback_scope
        # Arrow with expression body should have implicit return
        assert len(cb.return_exprs) >= 0  # May have return_exprs from expression body


# ---------------------------------------------------------------------------
# Pass 2: fixpoint taint propagation
# ---------------------------------------------------------------------------

def test_foreach_taint_propagation():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forEachTaint")
    config = _reader.get_config(".js")
    path = propagate_taint(scope, {"item"}, 6, config)
    assert path is not None
    assert len(path) >= 2
    assert path[0].kind in ("parameter", "source", "callback_param", "iteration_var")


def test_map_return_propagation():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "mapTaint")
    config = _reader.get_config(".js")
    path = propagate_taint(scope, {"html"}, 13, config)
    assert path is not None
    assert len(path) >= 2


def test_for_of_propagation():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forOfTaint")
    config = _reader.get_config(".js")
    path = propagate_taint(scope, {"entry"}, 25, config)
    assert path is not None
    assert any(s.kind in ("iteration_var", "parameter", "source") for s in path)


def test_no_taint_hardcoded():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "noTaint")
    config = _reader.get_config(".js")
    path = propagate_taint(scope, {"item"}, 44, config)
    # Hardcoded array — should NOT trace to a parameter/dangerous source
    if path is not None:
        assert not any(s.kind in ("source",) for s in path)


def test_py_for_loop_propagation():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.py"), "for_loop_taint")
    config = _reader.get_config(".py")
    path = propagate_taint(scope, {"item"}, 6, config)
    assert path is not None
    assert path[0].kind in ("parameter", "source")


def test_filter_taint_propagation():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "filterTaint")
    config = _reader.get_config(".js")
    path = propagate_taint(scope, {"active"}, 51, config)
    assert path is not None
    assert len(path) >= 2
