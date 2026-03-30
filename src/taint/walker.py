"""AST body walker for reaching-definitions analysis.

Walks a function body statement-by-statement, maintaining an ActiveDefs
state that tracks which definitions reach each point. Handles branches
(fork-merge), loops (two-pass approximation), and records sanitizers/guards.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field as dataclass_field

from src.taint.models import AccessPath, GuardInfo, SanitizerInfo

logger = logging.getLogger(__name__)


@dataclass(eq=False)
class Definition:
    """A single assignment/definition of a variable."""

    variable: AccessPath
    line: int
    expression: str
    node: object  # ASTNode or None (for parameters)
    deps: frozenset[str]  # variable names this definition reads from
    branch_context: str  # "" | "if_true" | "if_false" | "loop"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Definition):
            return NotImplemented
        return (self.variable, self.line, self.expression) == (
            other.variable,
            other.line,
            other.expression,
        )

    def __hash__(self) -> int:
        return hash((self.variable, self.line, self.expression))


@dataclass
class ActiveDefs:
    """Currently active definitions per variable — the state during analysis."""

    defs: dict[str, set[Definition]] = dataclass_field(default_factory=dict)

    def define(self, var: str, defn: Definition) -> None:
        """Kill prior defs, add new one."""
        self.defs[var] = {defn}

    def fork(self) -> ActiveDefs:
        """Snapshot for branch entry."""
        return ActiveDefs({k: set(v) for k, v in self.defs.items()})

    def merge(self, other: ActiveDefs) -> None:
        """Merge at branch join — union of definitions."""
        for var, other_defs in other.defs.items():
            self.defs.setdefault(var, set()).update(other_defs)

    def reaching(self, var: str) -> set[Definition]:
        """Which definitions of var are currently active?"""
        return self.defs.get(var, set())


@dataclass
class WalkState:
    """Mutable state accumulated during walk_body."""

    rules: object  # TaintRuleSet
    ext: str
    grammar: object  # LanguageGrammar
    active: ActiveDefs = dataclass_field(default_factory=ActiveDefs)
    sanitizers: list[SanitizerInfo] = dataclass_field(default_factory=list)
    guards: list[GuardInfo] = dataclass_field(default_factory=list)
    unresolved: list[str] = dataclass_field(default_factory=list)


def walk_body(func_node, grammar, state: WalkState) -> None:
    """Walk a function body, building reaching definitions in state.active."""
    body = _get_body(func_node)
    if body is None:
        return
    _walk_stmts(body.children, grammar, state)


def _walk_stmts(stmts: list, grammar, state: WalkState) -> None:
    """Walk a list of statements, updating state."""
    assignment_types = set(grammar.assignment_types)
    conditional_types = set(grammar.conditional_types)
    call_types = set(grammar.call_types)

    for stmt in stmts:
        if stmt.type in assignment_types:
            _handle_assignment(stmt, grammar, state)
        elif stmt.type in conditional_types:
            _handle_conditional(stmt, grammar, state)
        elif stmt.type in ("for_statement", "while_statement", "for_in_statement"):
            _handle_loop(stmt, grammar, state)
        elif stmt.type == "expression_statement":
            _handle_expression_statement(
                stmt, grammar, state, assignment_types, call_types
            )
        elif stmt.type in ("lexical_declaration", "variable_declaration"):
            # JS: const x = ...; / let x = ...;
            for child in stmt.children:
                if child.type in assignment_types:
                    _handle_assignment(child, grammar, state)
        elif stmt.type == "block":
            _walk_stmts(stmt.children, grammar, state)


def _handle_expression_statement(stmt, grammar, state, assignment_types, call_types):
    """Handle expression_statement: may contain assignments or mutating calls."""
    for child in stmt.children:
        if child.type in assignment_types:
            _handle_assignment(child, grammar, state)
        elif child.type in call_types:
            _handle_mutating_call(child, grammar, state)


def _handle_assignment(node, grammar, state: WalkState) -> None:
    """Process an assignment, record definition, check for sanitizers."""
    lhs_name, rhs_node = _extract_assignment(node, grammar)
    if not lhs_name or rhs_node is None:
        return

    rhs_ids = frozenset(_collect_identifiers(rhs_node))
    line = node.start_point[0] + 1
    expr_text = node.text.decode()

    defn = Definition(
        variable=AccessPath(lhs_name, ()),
        line=line,
        expression=expr_text,
        node=node,
        deps=rhs_ids,
        branch_context="",
    )
    state.active.define(lhs_name, defn)

    # Check RHS calls for sanitizers
    call_types = set(grammar.call_types)
    for call_node in _find_calls_in(rhs_node, call_types):
        _check_sanitizer(call_node, line, node, grammar, state)


def _check_sanitizer(call_node, line, context_node, grammar, state):
    """Check if a call is a known sanitizer and record it."""
    callee = _get_callee_name(call_node)
    if not callee:
        return
    callee_full = _get_full_callee(call_node) or callee

    # Try full dotted name first, then short name (suffix indexing)
    san = state.rules.check_sanitizer(state.ext, callee_full)
    if san is None and callee_full != callee:
        san = state.rules.check_sanitizer(state.ext, callee)

    if san is not None:
        san.line = line
        san.conditional = _is_conditional_ancestor(
            context_node, set(grammar.conditional_types)
        )
        state.sanitizers.append(san)
    else:
        if callee_full and callee_full not in state.unresolved:
            state.unresolved.append(callee_full)


def _handle_conditional(node, grammar, state: WalkState) -> None:
    """Handle if/elif/switch: fork-walk-merge."""
    # Check condition for guards
    condition = node.child_by_field_name("condition")
    if condition:
        _check_guards_in(condition, node, grammar, state)

    # Fork for true branch
    true_active = state.active.fork()
    true_state = WalkState(
        rules=state.rules,
        ext=state.ext,
        grammar=grammar,
        active=true_active,
        sanitizers=state.sanitizers,
        guards=state.guards,
        unresolved=state.unresolved,
    )

    # Walk true branch (consequence)
    consequence = node.child_by_field_name("consequence") or node.child_by_field_name(
        "body"
    )
    if consequence:
        _walk_stmts(consequence.children, grammar, true_state)

    # Walk false branch (alternative) on original state
    alternative = node.child_by_field_name("alternative")
    if alternative:
        if alternative.type in ("else_clause", "else"):
            body = alternative.child_by_field_name("body")
            if body:
                _walk_stmts(body.children, grammar, state)
            else:
                _walk_stmts(alternative.children, grammar, state)
        elif alternative.type in ("elif_clause", "if_statement"):
            _handle_conditional(alternative, grammar, state)
        else:
            _walk_stmts(alternative.children, grammar, state)

    # Merge at join point
    state.active.merge(true_active)


def _check_guards_in(condition, parent_node, grammar, state):
    """Check if condition contains guard function calls."""
    call_types = set(grammar.call_types)
    for call_node in _find_calls_in(condition, call_types):
        callee = _get_callee_name(call_node)
        if not callee:
            continue
        callee_full = _get_full_callee(call_node) or callee
        is_guard = state.rules.is_guard(state.ext, callee_full) or (
            callee_full != callee and state.rules.is_guard(state.ext, callee)
        )
        if is_guard:
            checked_var = _find_checked_variable(call_node)
            state.guards.append(
                GuardInfo(
                    name=callee_full,
                    line=parent_node.start_point[0] + 1,
                    variable=checked_var,
                )
            )


def _find_checked_variable(call_node) -> str:
    """Find which variable is being checked in a guard call's arguments."""
    args_node = call_node.child_by_field_name(
        "arguments"
    ) or call_node.child_by_field_name("argument_list")
    if not args_node:
        return ""
    for child in _walk_tree(args_node):
        if child.type == "identifier":
            return child.text.decode()
    return ""


def _handle_loop(node, grammar, state: WalkState) -> None:
    """Handle for/while: two-pass approximation with pre-loop snapshot merge."""
    snapshot = state.active.fork()

    body = node.child_by_field_name("body")
    if body:
        # First pass
        _walk_stmts(body.children, grammar, state)
        # Second pass (picks up loop-carried defs)
        _walk_stmts(body.children, grammar, state)

    # Merge with pre-loop snapshot (loop might not execute)
    state.active.merge(snapshot)


_MUTATING_METHODS = frozenset({"append", "extend", "insert", "update", "add"})


def _handle_mutating_call(call_node, grammar, state: WalkState) -> None:
    """Handle obj.method(arg) calls that taint the receiver.

    For calls like items.append(tainted), add a reaching definition for
    'items' that depends on the call arguments.
    """
    func_ref = call_node.child_by_field_name("function")
    if func_ref is None:
        return
    member_types = set(grammar.member_access_types)
    if func_ref.type not in member_types:
        return
    method_name = _get_member_property(func_ref)
    if method_name not in _MUTATING_METHODS:
        return
    obj_name = _get_member_object(func_ref)
    if not obj_name:
        return

    # Collect identifiers from arguments as dependencies
    args_node = call_node.child_by_field_name(
        "arguments"
    ) or call_node.child_by_field_name("argument_list")
    arg_ids: frozenset[str] = frozenset()
    if args_node:
        arg_ids = frozenset(_collect_identifiers(args_node))

    line = call_node.start_point[0] + 1
    expr_text = call_node.text.decode()

    # Merge (not kill) — the object retains its prior defs plus this new one
    defn = Definition(
        variable=AccessPath(obj_name, ()),
        line=line,
        expression=expr_text,
        node=call_node,
        deps=arg_ids,
        branch_context="",
    )
    state.active.defs.setdefault(obj_name, set()).add(defn)


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _get_body(func_node) -> object | None:
    """Get the body node of a function."""
    body = func_node.child_by_field_name("body")
    if body:
        return body
    for child in func_node.children:
        if child.type in ("block", "statement_block"):
            return child
    return None


def _extract_assignment(node, grammar) -> tuple[str, object | None]:
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
    # Member access on LHS: obj.field = value
    member_types = set(grammar.member_access_types)
    if left and left.type in member_types and right:
        prop = _get_member_property(left)
        obj = _get_member_object(left)
        if obj and prop:
            return f"{obj}.{prop}", right
    return "", None


def _get_member_property(member_node) -> str:
    """Extract property name from member-access node."""
    for field_name in ("property", "attribute", "field"):
        prop = member_node.child_by_field_name(field_name)
        if prop is not None:
            return prop.text.decode()
    return ""


def _get_member_object(member_node) -> str:
    """Extract object name from member-access node."""
    obj = member_node.child_by_field_name("object")
    if obj and obj.type == "identifier":
        return obj.text.decode()
    return ""


def _collect_identifiers(node) -> set[str]:
    """Collect all identifier names in a subtree."""
    ids: set[str] = set()
    for n in _walk_tree(node):
        if n.type == "identifier":
            ids.add(n.text.decode())
    return ids


def _find_calls_in(node, call_types: set[str]) -> list:
    """Find all call nodes in a subtree."""
    calls = []
    for n in _walk_tree(node):
        if n.type in call_types:
            calls.append(n)
    return calls


def _get_callee_name(call_node) -> str:
    """Get the simple callee name from a call node."""
    func_ref = call_node.child_by_field_name("function")
    if not func_ref:
        return ""
    if func_ref.type == "identifier":
        return func_ref.text.decode()
    if func_ref.type in ("attribute", "member_expression"):
        attr = func_ref.child_by_field_name(
            "attribute"
        ) or func_ref.child_by_field_name("property")
        if attr:
            return attr.text.decode()
    return ""


def _get_full_callee(call_node) -> str:
    """Get full dotted callee name (e.g. 're.match')."""
    func_ref = call_node.child_by_field_name("function")
    if not func_ref:
        return ""
    return func_ref.text.decode()


def _is_conditional_ancestor(node, conditional_types: set[str]) -> bool:
    """Check if node is inside a conditional block."""
    current = node.parent
    while current is not None:
        if current.type in conditional_types:
            return True
        if current.type in (
            "function_definition",
            "function_declaration",
            "method_definition",
            "method_declaration",
            "arrow_function",
        ):
            break
        current = current.parent
    return False


def _walk_tree(node):
    """Depth-first walk of AST nodes."""
    yield node
    for child in node.children:
        yield from _walk_tree(child)
