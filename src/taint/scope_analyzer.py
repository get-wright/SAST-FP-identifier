"""Scope tree builder (Pass 1) and fixpoint taint propagation (Pass 2).

Pass 1: Walks a function's AST to build a tree of Scope objects, each
representing a function/lambda/loop body with its own variable dependency graph.

Pass 2: Forward-propagates taint across scope boundaries until fixpoint,
then backward-traces from sink to source to build a FlowStep path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from tree_sitter import Node

from src.code_reader.tree_sitter_reader import LanguageConfig
from src.models.analysis import FlowStep
from src.taint.sanitizer_checker import check_known_sanitizer

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
    params: dict[str, int] = field(default_factory=dict)  # name → line number
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
# Pass 2: Fixpoint taint propagation
# ---------------------------------------------------------------------------

# Tainted variables per scope, keyed by scope identity.
TaintState = dict[int, set[str]]

_MAX_ITERATIONS = 20


def propagate_taint(
    root: Scope,
    sink_vars: set[str],
    sink_line: int,
    config: LanguageConfig,
) -> Optional[list[FlowStep]]:
    """Forward-propagate taint then backward-trace from sink to source.

    Returns a list of FlowStep from source to sink, or None if no taint
    path reaches the sink variables.
    """
    state = _init_taint(root, config)

    # Fixpoint: iterate until taint set stops growing
    for _ in range(_MAX_ITERATIONS):
        changed = _propagate_round(root, state, config)
        if not changed:
            break

    # Find the scope containing the sink line
    sink_scope = _find_scope_for_line(root, sink_line)
    if sink_scope is None:
        sink_scope = root

    # Check that at least one sink var is tainted
    tainted = state.get(id(sink_scope), set())
    reachable = sink_vars & tainted
    if not reachable:
        return None

    # Backward trace from sink to source
    sink_var = next(iter(reachable))
    path = _trace_path(sink_var, sink_scope, state, root, config, set())
    if path is None:
        return None

    # Append sink step
    path.append(FlowStep(
        variable=sink_var,
        line=sink_line,
        expression=_node_line_text(sink_scope.node, sink_line),
        kind="sink",
    ))
    return path


def _init_taint(root: Scope, config: LanguageConfig) -> TaintState:
    """Seed taint: root params, dangerous sources, and external references."""
    state: TaintState = {}
    tainted = set(root.params)

    # Deps whose RHS expression contains a dangerous source
    for var, entries in root.deps.items():
        for entry in entries:
            if _expr_has_dangerous_source(entry.expr, config):
                tainted.add(var)

    # External references: call site receivers that aren't locally defined
    # (imports, globals, module-level variables) — conservatively treat as tainted
    # since we can't verify their content within this function's scope
    local_vars = set(root.params) | set(root.deps.keys())
    for cs in root.call_sites:
        if cs.receiver_var and cs.receiver_var not in local_vars:
            tainted.add(cs.receiver_var)
    # Also check child scopes for external receivers
    for child in root.children:
        for cs in child.call_sites:
            if cs.receiver_var and cs.receiver_var not in local_vars:
                tainted.add(cs.receiver_var)

    state[id(root)] = tainted
    return state


def _expr_has_dangerous_source(expr: str, config: LanguageConfig) -> bool:
    for ds in config.dangerous_sources:
        if ds in expr:
            return True
    return False


def _propagate_round(scope: Scope, state: TaintState, config: LanguageConfig) -> bool:
    """One forward-propagation pass over the scope tree. Returns True if anything changed."""
    changed = False
    tainted = state.setdefault(id(scope), set())
    old_size = len(tainted)

    # Forward-propagate deps within this scope
    # Iterate multiple times within the scope for transitive deps
    for _ in range(5):
        inner_changed = False
        for var, entries in scope.deps.items():
            if var in tainted:
                continue
            for entry in entries:
                if entry.rhs_ids & tainted:
                    # Check for sanitizer in the RHS expression
                    if _dep_is_sanitized(entry):
                        continue
                    tainted.add(var)
                    inner_changed = True
                    break
        if not inner_changed:
            break

    # Process call sites: seed callback params from tainted receivers
    for cs in scope.call_sites:
        cb = cs.callback_scope
        if cb is None:
            continue
        cb_tainted = state.setdefault(id(cb), set())

        if cs.receiver_var in tainted:
            # Seed callback params (element of the collection is tainted)
            for param in cb.params:
                if param not in cb_tainted:
                    cb_tainted.add(param)

        # If callback returns_value and return exprs contain tainted vars,
        # taint the call result variable in the parent scope
        if cs.returns_value:
            for ret in cb.return_exprs:
                if ret.identifiers & cb_tainted:
                    result_var = _find_call_result_var(scope, cs)
                    if result_var and result_var not in tainted:
                        tainted.add(result_var)

    # Closure capture: propagate tainted variables from this scope into child scopes
    # that reference them (not just via call_sites, but any nested scope that captures a var)
    for child in scope.children:
        child_tainted = state.setdefault(id(child), set())
        for var, entries in child.deps.items():
            for entry in entries:
                captured = entry.rhs_ids & tainted
                for cap_var in captured:
                    if cap_var not in child_tainted:
                        child_tainted.add(cap_var)
                        changed = True

    # Recurse into children
    for child in scope.children:
        if _propagate_round(child, state, config):
            changed = True

    # Re-check callback returns after children propagated
    for cs in scope.call_sites:
        cb = cs.callback_scope
        if cb is None or not cs.returns_value:
            continue
        cb_tainted = state.get(id(cb), set())
        for ret in cb.return_exprs:
            if ret.identifiers & cb_tainted:
                result_var = _find_call_result_var(scope, cs)
                if result_var and result_var not in tainted:
                    tainted.add(result_var)

    if len(tainted) > old_size:
        changed = True

    return changed


def _dep_is_sanitized(entry: DepEntry) -> bool:
    """Check if a dep entry's RHS contains a known sanitizer call."""
    if entry.node is None:
        return False
    for n in _walk(entry.node):
        if n.type in ("call_expression", "call"):
            func_ref = n.child_by_field_name("function")
            if func_ref:
                callee = func_ref.text.decode()
                # Try the full name and just the last part
                if check_known_sanitizer(callee) is not None:
                    return True
                if "." in callee:
                    suffix = callee.rsplit(".", 1)[-1]
                    if check_known_sanitizer(suffix) is not None:
                        return True
    return False


def _find_call_result_var(scope: Scope, cs: CallSite) -> Optional[str]:
    """Find which variable receives the result of receiver.method(callback).

    Looks in scope.deps for a var whose RHS contains both the receiver
    and the method name.
    """
    for var, entries in scope.deps.items():
        for entry in entries:
            expr = entry.expr
            if cs.receiver_var in entry.rhs_ids and cs.callee in expr:
                return var
    return None


def _find_scope_for_line(scope: Scope, line: int) -> Optional[Scope]:
    """Find the innermost scope containing a given line number."""
    if scope.node is None:
        return None

    start = scope.node.start_point[0] + 1
    end = scope.node.end_point[0] + 1
    if line < start or line > end:
        return None

    # Check children first (innermost wins)
    for child in scope.children:
        result = _find_scope_for_line(child, line)
        if result is not None:
            return result

    # Also check call site callback scopes
    for cs in scope.call_sites:
        if cs.callback_scope:
            result = _find_scope_for_line(cs.callback_scope, line)
            if result is not None:
                return result

    return scope


def _trace_path(
    var: str,
    scope: Scope,
    state: TaintState,
    root: Scope,
    config: LanguageConfig,
    visited: frozenset[tuple[int, str]],
) -> Optional[list[FlowStep]]:
    """Backward trace from a tainted variable to its source.

    Returns path from source to the variable (exclusive of final sink step),
    or None if no source found.
    """
    key = (id(scope), var)
    if key in visited:
        return None
    visited = visited | {key}

    tainted = state.get(id(scope), set())
    if var not in tainted:
        return None

    # Base: root scope parameter
    if scope is root and var in root.params:
        param_line = root.params[var]  # actual line from AST
        return [FlowStep(variable=var, line=param_line, expression=f"parameter: {var}", kind="parameter")]

    # Base: dangerous source in deps
    for entry in scope.deps.get(var, []):
        if _expr_has_dangerous_source(entry.expr, config):
            return [FlowStep(variable=var, line=entry.line, expression=entry.expr, kind="source")]

    # Callback param: trace to parent scope's receiver variable
    if scope.parent is not None and var in scope.params:
        parent = scope.parent
        # Find which call site links to this scope
        for cs in parent.call_sites:
            if cs.callback_scope is scope:
                # This param came from iterating over receiver_var
                parent_path = _trace_path(cs.receiver_var, parent, state, root, config, visited)
                if parent_path is not None:
                    kind = "iteration_var" if cs.callee == "@@iterator" else "callback_param"
                    param_line = scope.params.get(var, scope.node.start_point[0] + 1)
                    step = FlowStep(variable=var, line=param_line, expression=f"{cs.callee}({var})", kind=kind)
                    return parent_path + [step]

    # Assignment dep: trace RHS variables
    for entry in scope.deps.get(var, []):
        for rhs_var in entry.rhs_ids:
            if rhs_var == var:
                continue
            sub = _trace_path(rhs_var, scope, state, root, config, visited)
            if sub is not None:
                return sub + [FlowStep(variable=var, line=entry.line, expression=entry.expr, kind="assignment")]

    # Callback return: if this var is the result of a callback call
    for cs in scope.call_sites:
        if not cs.returns_value or cs.callback_scope is None:
            continue
        result_var = _find_call_result_var(scope, cs)
        if result_var != var:
            continue
        cb = cs.callback_scope
        cb_tainted = state.get(id(cb), set())
        for ret in cb.return_exprs:
            for ret_var in ret.identifiers:
                if ret_var in cb_tainted:
                    sub = _trace_path(ret_var, cb, state, root, config, visited)
                    if sub is not None:
                        step = FlowStep(
                            variable=var, line=ret.line,
                            expression=ret.expr, kind="callback_return",
                        )
                        return sub + [step]

    # Closure capture: variable tainted from an ancestor scope
    if scope.parent is not None and var not in scope.params and var not in scope.deps:
        # var is captured from an outer scope — trace it there
        ancestor = scope.parent
        while ancestor is not None:
            if var in state.get(id(ancestor), set()):
                sub = _trace_path(var, ancestor, state, root, config, visited)
                if sub is not None:
                    return sub
            ancestor = ancestor.parent

    # External/import: variable is tainted but not traceable within this function
    # (module-level import, global, or unresolved reference)
    if var in tainted and var not in scope.params and var not in scope.deps:
        return [FlowStep(variable=var, line=0, expression=f"external: {var}", kind="external")]

    return None


def _node_line_text(node: Optional[Node], line: int) -> str:
    """Get the text of a specific line from a node's source."""
    if node is None:
        return ""
    try:
        source = node.text.decode()
        start_line = node.start_point[0] + 1
        for i, text in enumerate(source.split("\n"), start_line):
            if i == line:
                return text.strip()
    except (UnicodeDecodeError, AttributeError):
        pass
    return ""


# ---------------------------------------------------------------------------
# Internal helpers (Pass 1)
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


def _extract_params(func_node: Node, config: LanguageConfig) -> dict[str, int]:
    """Extract parameter names and their line numbers from a function/arrow/loop node."""
    params: dict[str, int] = {}

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
                        params[n.text.decode()] = n.start_point[0] + 1
        return params

    # Regular function: look for parameter_types children
    for child in func_node.children:
        if child.type in config.parameter_types:
            _extract_identifiers_from_params_node(child, params)

    return params


def _extract_identifiers_from_params_node(params_node: Node, out: dict[str, int]) -> None:
    """Extract all identifier names and line numbers from a formal_parameters / parameters node."""
    for n in _walk(params_node):
        if n.type == "identifier":
            out[n.text.decode()] = n.start_point[0] + 1


def _extract_identifiers_from_pattern(node: Node, out: dict[str, int]) -> None:
    """Extract identifiers from a pattern (identifier, object_pattern, array_pattern)."""
    if node.type == "identifier":
        out[node.text.decode()] = node.start_point[0] + 1
    elif node.type == "object_pattern":
        for child in node.children:
            if child.type == "shorthand_property_identifier_pattern":
                out[child.text.decode()] = child.start_point[0] + 1
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
