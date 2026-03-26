"""Scope tree builder for taint analysis (Pass 1).

Walks a function's AST to build a tree of Scope objects, each representing
a function/lambda/loop body with its own variable dependency graph.
Pass 2 (fixpoint propagation) will consume this tree.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from tree_sitter import Node

from src.code_reader.tree_sitter_reader import LanguageConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DepEntry:
    """One assignment to a variable: the RHS identifiers it depends on."""

    rhs_ids: set[str]
    line: int
    expr: str
    node: Node


@dataclass
class ReturnExpr:
    """A return expression inside a scope."""

    identifiers: set[str]
    line: int
    expr: str


@dataclass
class CallSite:
    """A callback-passing call like items.forEach(cb) or names.map(cb)."""

    callee: str            # method name, e.g. "forEach", "map", "@@iterator"
    receiver_var: str      # variable the method is called on
    returns_value: bool    # True for map/filter/reduce, False for forEach
    callback_scope: Optional[Scope] = None  # the child scope for the callback


@dataclass
class Scope:
    """One scope in the scope tree (function, arrow, loop body)."""

    kind: str                                       # "function", "arrow", "for_of", "for_in", "lambda"
    params: set[str] = field(default_factory=set)
    deps: dict[str, list[DepEntry]] = field(default_factory=dict)
    children: list[Scope] = field(default_factory=list)
    call_sites: list[CallSite] = field(default_factory=list)
    return_exprs: list[ReturnExpr] = field(default_factory=list)
    parent: Optional[Scope] = field(default=None, repr=False)
    node: Optional[Node] = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_scope_tree(func_node: Node, config: LanguageConfig) -> Scope:
    """Build a scope tree from a function AST node."""
    kind = _node_to_scope_kind(func_node)
    scope = Scope(kind=kind, node=func_node)
    scope.params = _extract_params(func_node, config)

    # Collect IDs of nodes that will become child scopes — don't recurse into them
    child_scope_ids: set[int] = set()
    _collect_child_scope_ids(func_node, config, child_scope_ids)

    # Build deps for this scope (excluding child scope bodies)
    _build_scope_deps(func_node, config, scope, child_scope_ids)

    # Build return exprs for this scope
    _build_return_exprs(func_node, config, scope, child_scope_ids)

    # Detect callback call sites and for-loop children
    _build_children(func_node, config, scope, child_scope_ids)

    return scope


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _node_to_scope_kind(node: Node) -> str:
    if node.type == "arrow_function":
        return "arrow"
    if node.type in ("lambda", "lambda_expression"):
        return "lambda"
    if node.type in ("for_in_statement", "for_statement"):
        op = node.child_by_field_name("operator")
        if op and op.text.decode() == "of":
            return "for_of"
        return "for_in"
    return "function"


def _extract_params(func_node: Node, config: LanguageConfig) -> set[str]:
    """Extract parameter names from a function/arrow/loop node."""
    params: set[str] = set()

    # For loops: params come from the `left` field
    if func_node.type in config.iteration_types:
        left = func_node.child_by_field_name("left")
        if left:
            _extract_identifiers_from_pattern(left, params)
        return params

    # Arrow function: single param via `parameter` field, multi via `parameters`
    if func_node.type == "arrow_function":
        single = func_node.child_by_field_name("parameter")
        if single:
            _extract_identifiers_from_pattern(single, params)
            return params
        multi = func_node.child_by_field_name("parameters")
        if multi:
            _extract_identifiers_from_params_node(multi, params)
            return params
        return params

    # Lambda (Python)
    if func_node.type in ("lambda", "lambda_expression"):
        for child in func_node.children:
            if child.type == "lambda_parameters":
                for n in _walk(child):
                    if n.type == "identifier":
                        params.add(n.text.decode())
        return params

    # Regular function: look for parameter_types children
    for child in func_node.children:
        if child.type in config.parameter_types:
            _extract_identifiers_from_params_node(child, params)

    return params


def _extract_identifiers_from_params_node(params_node: Node, out: set[str]) -> None:
    """Extract all identifier names from a formal_parameters / parameters node."""
    for n in _walk(params_node):
        if n.type == "identifier":
            out.add(n.text.decode())


def _extract_identifiers_from_pattern(node: Node, out: set[str]) -> None:
    """Extract identifiers from a pattern (identifier, object_pattern, array_pattern)."""
    if node.type == "identifier":
        out.add(node.text.decode())
    elif node.type == "object_pattern":
        for child in node.children:
            if child.type == "shorthand_property_identifier_pattern":
                out.add(child.text.decode())
            elif child.type == "pair_pattern":
                value = child.child_by_field_name("value")
                if value:
                    _extract_identifiers_from_pattern(value, out)
    elif node.type == "array_pattern":
        for child in node.children:
            if child.type == "identifier":
                out.add(child.text.decode())
            elif child.type in ("object_pattern", "array_pattern"):
                _extract_identifiers_from_pattern(child, out)
    elif node.type in ("pattern_list", "tuple_pattern"):
        # Python: for a, b in ...
        for child in node.children:
            _extract_identifiers_from_pattern(child, out)
    else:
        # Fallback: try to find identifiers
        for n in _walk(node):
            if n.type == "identifier":
                out.add(n.text.decode())


def _is_inside_child(node: Node, child_scope_ids: set[int]) -> bool:
    """Check if a node is inside any child scope body."""
    current = node.parent
    while current is not None:
        if id(current) in child_scope_ids:
            return True
        current = current.parent
    return False


def _collect_child_scope_ids(func_node: Node, config: LanguageConfig, out: set[int]) -> None:
    """Collect node IDs of all direct child scopes (arrows, loops) within func_node."""
    for node in _walk(func_node):
        if node is func_node:
            continue
        # Arrow functions / lambdas nested in this scope
        if node.type in ("arrow_function", "lambda", "lambda_expression"):
            out.add(id(node))
        # For-loops create child scopes
        if node.type in config.iteration_types:
            out.add(id(node))
        # Nested named functions
        if node.type in config.func_types and node is not func_node:
            if node.type not in ("arrow_function",):
                name = node.child_by_field_name("name")
                if name:
                    out.add(id(node))


def _build_scope_deps(
    func_node: Node,
    config: LanguageConfig,
    scope: Scope,
    child_scope_ids: set[int],
) -> None:
    """Walk func_node, build variable deps. Skip nodes inside child scopes."""
    for node in _walk(func_node):
        if node is func_node:
            continue
        if node.type not in config.assignment_types:
            continue
        if _is_inside_child(node, child_scope_ids):
            continue

        lhs_name, rhs_node = _extract_assignment(node)
        if not lhs_name or rhs_node is None:
            continue

        rhs_ids: set[str] = set()
        for n in _walk(rhs_node):
            if n.type == "identifier":
                rhs_ids.add(n.text.decode())

        entry = DepEntry(
            rhs_ids=rhs_ids,
            line=node.start_point[0] + 1,
            expr=node.text.decode(),
            node=node,
        )
        scope.deps.setdefault(lhs_name, []).append(entry)


def _extract_assignment(node: Node) -> tuple[str, Optional[Node]]:
    """Extract (lhs_name, rhs_node) from an assignment node."""
    if node.type == "variable_declarator":
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node and name_node.type == "identifier":
            return name_node.text.decode(), value_node
        return "", None

    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left and left.type == "identifier" and right:
        return left.text.decode(), right
    return "", None


def _build_return_exprs(
    func_node: Node,
    config: LanguageConfig,
    scope: Scope,
    child_scope_ids: set[int],
) -> None:
    """Collect return expressions in this scope (not from child scopes)."""
    # For arrow functions with expression body (no statement_block), the body IS an implicit return
    if func_node.type == "arrow_function":
        body = func_node.child_by_field_name("body")
        if body and body.type != "statement_block":
            ids: set[str] = set()
            for n in _walk(body):
                if n.type == "identifier":
                    ids.add(n.text.decode())
            scope.return_exprs.append(ReturnExpr(
                identifiers=ids,
                line=body.start_point[0] + 1,
                expr=body.text.decode(),
            ))
            return

    # Explicit return statements
    for node in _walk(func_node):
        if node is func_node:
            continue
        if node.type not in config.return_types:
            continue
        if _is_inside_child(node, child_scope_ids):
            continue

        ids = set()
        for n in _walk(node):
            if n.type == "identifier":
                ids.add(n.text.decode())
        scope.return_exprs.append(ReturnExpr(
            identifiers=ids,
            line=node.start_point[0] + 1,
            expr=node.text.decode(),
        ))


def _build_children(
    func_node: Node,
    config: LanguageConfig,
    scope: Scope,
    child_scope_ids: set[int],
) -> None:
    """Build child scopes (loops and callback arrows) and link call sites."""
    for node in _walk(func_node):
        if node is func_node:
            continue

        # For-loop creates a child scope
        if node.type in config.iteration_types and id(node) in child_scope_ids:
            # Don't process loops that are inside another child scope
            if _is_inside_child_excluding_self(node, child_scope_ids):
                continue
            child = build_scope_tree(node, config)
            child.parent = scope
            scope.children.append(child)

            # Create an @@iterator call site for the iterable
            right = node.child_by_field_name("right")
            if right:
                receiver = _extract_receiver_var(right)
                site = CallSite(
                    callee="@@iterator",
                    receiver_var=receiver,
                    returns_value=False,
                    callback_scope=child,
                )
                scope.call_sites.append(site)
            continue

        # Callback call: receiver.method(arrow/lambda)
        if node.type in config.call_types:
            if _is_inside_child(node, child_scope_ids):
                continue
            site = _detect_callback_call_site(node, config, scope)
            if site:
                scope.call_sites.append(site)


def _is_inside_child_excluding_self(node: Node, child_scope_ids: set[int]) -> bool:
    """Check if node's parent chain hits a child scope ID (excluding itself)."""
    current = node.parent
    while current is not None:
        if id(current) in child_scope_ids:
            return True
        current = current.parent
    return False


def _detect_callback_call_site(
    call_node: Node,
    config: LanguageConfig,
    parent_scope: Scope,
) -> Optional[CallSite]:
    """Detect receiver.method(callback) pattern and build a CallSite + child scope."""
    func_ref = call_node.child_by_field_name("function")
    if not func_ref or func_ref.type != "member_expression":
        return None

    prop = func_ref.child_by_field_name("property")
    obj = func_ref.child_by_field_name("object")
    if not prop or not obj:
        return None

    method_name = prop.text.decode()
    if method_name not in config.callback_methods:
        return None

    # Find the callback argument (first arrow_function or lambda in arguments)
    args_node = call_node.child_by_field_name("arguments")
    if not args_node:
        return None

    cb_node = None
    for child in args_node.children:
        if child.type in ("arrow_function", "lambda", "lambda_expression", "function"):
            cb_node = child
            break

    if cb_node is None:
        return None

    # Build child scope for the callback
    child = build_scope_tree(cb_node, config)
    child.parent = parent_scope
    parent_scope.children.append(child)

    receiver_var = _extract_receiver_var(obj)
    returns_value = method_name in config.callback_returns_value

    return CallSite(
        callee=method_name,
        receiver_var=receiver_var,
        returns_value=returns_value,
        callback_scope=child,
    )


def _extract_receiver_var(node: Node) -> str:
    """Extract the base variable name from an expression node."""
    if node.type == "identifier":
        return node.text.decode()
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        if obj:
            return _extract_receiver_var(obj)
    return node.text.decode()


def _walk(node: Node):
    """Depth-first walk of AST nodes."""
    yield node
    for child in node.children:
        yield from _walk(child)
