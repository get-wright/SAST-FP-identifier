"""Tree-sitter based taint flow tracker.

Walks the AST of a single function to build a variable dependency graph,
then traces backwards from sink to source to produce a TaintFlow.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from tree_sitter import Node

from src.code_reader.tree_sitter_reader import TreeSitterReader, LanguageConfig
from src.models.analysis import FlowStep, SanitizerInfo, TaintFlow
from src.taint.sanitizer_checker import check_known_sanitizer, is_conditional_ancestor
from src.taint.sink_source_inference import infer_sink_source

logger = logging.getLogger(__name__)

_reader = TreeSitterReader()


def trace_taint_flow(
    *,
    file_path: str,
    function_name: str,
    sink_line: int,
    check_id: str,
    cwe_list: list[str],
) -> Optional[TaintFlow]:
    """Trace taint from sink back to source within a single function.

    Returns None if the language doesn't support taint tracing or
    the function can't be found.
    """
    ext = Path(file_path).suffix.lower()
    config = _reader.get_config(ext)
    if config is None or not config.assignment_types:
        return None

    root = _reader.parse_file(file_path)
    if root is None:
        return None

    func_node = _find_function_node(root, function_name, config)
    if func_node is None:
        return None

    # Try scope-tree analysis first (handles callbacks, loops)
    if config.iteration_types or config.callback_methods:
        result = _trace_with_scope_tree(func_node, config, file_path, sink_line, check_id, cwe_list)
        if result is not None:
            return result

    # Fallback to flat analysis (original logic)
    return _trace_flat(func_node, config, file_path, sink_line, check_id, cwe_list)


def _trace_with_scope_tree(func_node, config, file_path, sink_line, check_id, cwe_list):
    from src.taint.scope_analyzer import build_scope_tree, propagate_taint

    scope_tree = build_scope_tree(func_node, config)
    sink_vars = _find_vars_at_line(func_node, sink_line, config)
    if not sink_vars:
        return None

    path = propagate_taint(scope_tree, set(sink_vars), sink_line, config)
    if path is None:
        return None

    # Collect sanitizers and unresolved calls from scope tree
    all_sans = _collect_sanitizers_from_scope(scope_tree, config)
    deduped = _dedup_sanitizers(all_sans)
    unresolved = _collect_unresolved_from_scope(scope_tree)

    confidence_factors = []
    if deduped:
        confidence_factors.append(f"Sanitizer {deduped[0].name} found in path")
    elif path[0].kind in ("parameter", "source"):
        confidence_factors.append("Direct source to sink with no sanitizer")

    inferred = infer_sink_source(check_id, cwe_list, _get_line_text(file_path, sink_line))

    return TaintFlow(
        path=path, sanitizers=deduped, unresolved_calls=unresolved,
        confidence_factors=confidence_factors, inferred=inferred,
    )


def _trace_flat(func_node, config, file_path, sink_line, check_id, cwe_list):
    """Original flat analysis — fallback when scope tree doesn't produce a result."""
    params = _extract_parameters(func_node, config)
    param_lines = _extract_parameter_lines(func_node, config)
    deps, sanitizers, unresolved = _build_deps(func_node, config, params)
    sink_vars = _find_vars_at_line(func_node, sink_line, config)

    if not sink_vars:
        return None

    # Trace backwards from each sink variable; take the first successful trace
    for sink_var in sink_vars:
        path, used_sanitizers = _trace_back(
            sink_var, deps, sanitizers, params, config, set(), param_lines,
        )
        if path is None:
            continue

        # Build sink step
        sink_step = FlowStep(
            variable=sink_var,
            line=sink_line,
            expression=_get_line_text(file_path, sink_line),
            kind="sink",
        )
        path.append(sink_step)

        # Filter sanitizers to only those applied to variables in the taint path
        path_vars = {step.variable for step in path}
        relevant_sanitizers = [
            s for s in used_sanitizers
            if _sanitizer_target_vars(sanitizers, s.name) & path_vars
        ]

        # Deduplicate sanitizers by name
        seen_names: set[str] = set()
        deduped: list[SanitizerInfo] = []
        for s in relevant_sanitizers:
            if s.name not in seen_names:
                seen_names.add(s.name)
                deduped.append(s)

        confidence_factors: list[str] = []
        source_step = path[0]
        if deduped:
            unconditional = [s for s in deduped if not s.conditional]
            if unconditional:
                confidence_factors.append(f"Sanitizer {unconditional[0].name} found in path")
            else:
                confidence_factors.append("Conditional sanitizer only — may not always execute")
        elif source_step.kind in ("parameter", "source"):
            confidence_factors.append("Direct source to sink with no sanitizer")

        inferred = infer_sink_source(check_id, cwe_list, _get_line_text(file_path, sink_line))

        return TaintFlow(
            path=path,
            sanitizers=deduped,
            unresolved_calls=unresolved,
            confidence_factors=confidence_factors,
            inferred=inferred,
        )

    # No taint path found — might be hardcoded
    confidence_factors = ["No external source — values appear hardcoded"]
    inferred = infer_sink_source(check_id, cwe_list, _get_line_text(file_path, sink_line))
    return TaintFlow(
        path=[FlowStep(
            variable=sink_vars[0],
            line=sink_line,
            expression=_get_line_text(file_path, sink_line),
            kind="sink",
        )],
        sanitizers=[],
        unresolved_calls=unresolved,
        confidence_factors=confidence_factors,
        inferred=inferred,
    )


def _collect_sanitizers_from_scope(scope, config=None) -> list[SanitizerInfo]:
    """Collect sanitizer info from dep entries across the scope tree."""
    result = []
    conditional_types = ()
    if config is not None:
        conditional_types = config.conditional_types
    for var, entries in scope.deps.items():
        for entry in entries:
            if entry.node is None:
                continue
            for n in _walk(entry.node):
                if n.type in ("call_expression", "call"):
                    func_ref = n.child_by_field_name("function")
                    if func_ref:
                        callee = func_ref.text.decode()
                        san = check_known_sanitizer(callee)
                        if san is None and "." in callee:
                            san = check_known_sanitizer(callee.rsplit(".", 1)[-1])
                        if san is not None:
                            san.line = entry.line
                            san.conditional = is_conditional_ancestor(
                                entry.node, conditional_types,
                            )
                            result.append(san)
    for child in scope.children:
        result.extend(_collect_sanitizers_from_scope(child, config))
    return result


def _collect_unresolved_from_scope(scope, params=None) -> list[str]:
    """Collect unresolved call names from dep entries across the scope tree."""
    if params is None:
        params = scope.params
    result: list[str] = []
    for var, entries in scope.deps.items():
        for entry in entries:
            if entry.node is None:
                continue
            for n in _walk(entry.node):
                if n.type in ("call_expression", "call"):
                    func_ref = n.child_by_field_name("function")
                    if not func_ref:
                        continue
                    full_name = func_ref.text.decode()
                    if "." in full_name:
                        obj = full_name.split(".")[0]
                        if obj not in params and full_name not in result:
                            result.append(full_name)
    for child in scope.children:
        result.extend(_collect_unresolved_from_scope(child, params))
    return result


def _dedup_sanitizers(sanitizers):
    seen = set()
    result = []
    for s in sanitizers:
        if s.name not in seen:
            seen.add(s.name)
            result.append(s)
    return result


def _find_function_node(root: Node, name: str, config: LanguageConfig) -> Optional[Node]:
    """Find a function node by name."""
    for node in _walk(root):
        if node.type not in config.func_types:
            continue
        name_node = node.child_by_field_name("name")
        if name_node and name_node.text.decode() == name:
            return node
        # JS arrow functions: name from parent variable_declarator
        if node.type == "arrow_function" and node.parent and node.parent.type == "variable_declarator":
            vd_name = node.parent.child_by_field_name("name")
            if vd_name and vd_name.text.decode() == name:
                return node
    return None


def _extract_parameters(func_node: Node, config: LanguageConfig) -> set[str]:
    """Extract parameter names from a function node."""
    params: set[str] = set()
    for child in func_node.children:
        if child.type in config.parameter_types:
            for node in _walk(child):
                if node.type == "identifier":
                    params.add(node.text.decode())
    return params


def _extract_parameter_lines(func_node: Node, config: LanguageConfig) -> dict[str, int]:
    """Extract parameter names with their line numbers from tree-sitter AST."""
    result: dict[str, int] = {}
    for child in func_node.children:
        if child.type in config.parameter_types:
            for node in _walk(child):
                if node.type == "identifier":
                    result[node.text.decode()] = node.start_point[0] + 1
    # Arrow function single param
    param_node = func_node.child_by_field_name("parameter")
    if param_node and param_node.type == "identifier":
        result[param_node.text.decode()] = param_node.start_point[0] + 1
    return result


# Dep entry: {"deps": set[str], "line": int, "expr": str, "node": Node, "sanitizer": SanitizerInfo|None}
_DepInfo = dict


def _build_deps(
    func_node: Node,
    config: LanguageConfig,
    params: set[str],
) -> tuple[dict[str, list[_DepInfo]], dict[str, list[SanitizerInfo]], list[str]]:
    """Walk function body, build variable dependency graph.

    Returns (deps, sanitizers_by_var, unresolved_calls).
    - deps: var_name -> list of {"deps": set[str], "line": int, "expr": str, "node": Node}
    - sanitizers_by_var: var_name -> [SanitizerInfo]
    - unresolved_calls: list of unresolved call names
    """
    deps: dict[str, list[_DepInfo]] = {}
    sanitizers_by_var: dict[str, list[SanitizerInfo]] = {}
    unresolved: list[str] = []

    for node in _walk(func_node):
        if node.type not in config.assignment_types:
            continue

        lhs_name, rhs_node = _extract_assignment(node, config)
        if not lhs_name or rhs_node is None:
            continue

        # Collect identifiers in RHS
        rhs_ids = _collect_identifiers(rhs_node)
        line = node.start_point[0] + 1
        expr_text = node.text.decode()

        deps.setdefault(lhs_name, []).append({
            "deps": rhs_ids,
            "line": line,
            "expr": expr_text,
            "node": node,
        })

        # Check for sanitizer calls in RHS
        for call_node in _find_calls(rhs_node, config):
            callee = _get_callee_name(call_node, config)
            if not callee:
                continue

            san_info = check_known_sanitizer(callee)
            if san_info is not None:
                san_info.line = line
                san_info.conditional = is_conditional_ancestor(node, config.conditional_types)
                sanitizers_by_var.setdefault(lhs_name, []).append(san_info)
            else:
                # Check if it's an unresolved external call
                # (not a method on a known variable, not a builtin)
                if callee not in params and "." in _get_full_callee(call_node, config):
                    full = _get_full_callee(call_node, config)
                    # Check if the object is a parameter — that makes it "known"
                    obj = full.split(".")[0]
                    if obj not in params:
                        if full not in unresolved:
                            unresolved.append(full)

    return deps, sanitizers_by_var, unresolved


def _extract_assignment(node: Node, config: LanguageConfig) -> tuple[str, Optional[Node]]:
    """Extract (lhs_name, rhs_node) from an assignment node."""
    if node.type == "variable_declarator":
        # JS: const x = expr → field "name" and "value"
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node and name_node.type == "identifier":
            return name_node.text.decode(), value_node
        return "", None

    # Python and others: left = right
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left and left.type == "identifier" and right:
        return left.text.decode(), right
    return "", None


def _collect_identifiers(node: Node) -> set[str]:
    """Collect all identifier names in a subtree."""
    ids: set[str] = set()
    for n in _walk(node):
        if n.type == "identifier":
            ids.add(n.text.decode())
    return ids


def _find_calls(node: Node, config: LanguageConfig) -> list[Node]:
    """Find all call expression nodes in a subtree."""
    calls = []
    call_types = set(config.call_types)
    for n in _walk(node):
        if n.type in call_types:
            calls.append(n)
    return calls


def _get_callee_name(call_node: Node, config: LanguageConfig) -> str:
    """Get the simple callee name from a call node (e.g., 'escape' from 'escape(x)')."""
    func_ref = call_node.child_by_field_name("function")
    if not func_ref:
        return ""
    if func_ref.type == "identifier":
        return func_ref.text.decode()
    if func_ref.type in ("attribute", "member_expression"):
        # Get just the method name
        attr = func_ref.child_by_field_name("attribute") or func_ref.child_by_field_name("property")
        if attr:
            return attr.text.decode()
    return ""


def _get_full_callee(call_node: Node, config: LanguageConfig) -> str:
    """Get the full dotted callee name (e.g., 'external_lib.process')."""
    func_ref = call_node.child_by_field_name("function")
    if not func_ref:
        return ""
    return func_ref.text.decode()


def _find_vars_at_line(func_node: Node, line: int, config: LanguageConfig) -> list[str]:
    """Find variable identifiers used at a specific line (in call arguments)."""
    row = line - 1
    variables: list[str] = []
    call_types = set(config.call_types)

    for node in _walk(func_node):
        if node.start_point[0] != row:
            continue
        if node.type in call_types:
            # Get arguments
            args_node = (
                node.child_by_field_name("arguments")
                or node.child_by_field_name("argument_list")
            )
            if args_node is None:
                # Python call uses argument_list as a child type
                for child in node.children:
                    if child.type == "argument_list":
                        args_node = child
                        break
            if args_node:
                for child in _walk(args_node):
                    if child.type == "identifier":
                        variables.append(child.text.decode())

    # Also check for return statements at that line
    for node in _walk(func_node):
        if node.start_point[0] != row:
            continue
        if node.type in config.return_types:
            for child in _walk(node):
                if child.type == "identifier":
                    variables.append(child.text.decode())

    # Deduplicate preserving order
    seen: set[str] = set()
    result: list[str] = []
    for v in variables:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result


def _trace_back(
    var: str,
    deps: dict[str, list[_DepInfo]],
    sanitizers_by_var: dict[str, list[SanitizerInfo]],
    params: set[str],
    config: LanguageConfig,
    visited: set[str],
    param_lines: dict[str, int] | None = None,
) -> tuple[Optional[list[FlowStep]], list[SanitizerInfo]]:
    """Recursively trace a variable back to its source.

    Returns (path_from_source, sanitizers_encountered) or (None, []) if no source found.
    Tries all assignment entries for a variable (handles reassignments).
    """
    if var in visited:
        return None, []
    visited = visited | {var}

    # Base case: parameter
    if var in params:
        line = (param_lines or {}).get(var, 0)
        step = FlowStep(variable=var, line=line, expression=f"parameter: {var}", kind="parameter")
        return [step], []

    # Base case: not in deps at all (external or builtin)
    if var not in deps:
        return None, []

    # Try each assignment to this variable (earliest first)
    for dep in deps[var]:
        dep_vars = dep["deps"]
        line = dep["line"]
        expr = dep["expr"]

        # Check if expression contains a dangerous source
        for ds in config.dangerous_sources:
            if ds in expr:
                step = FlowStep(variable=var, line=line, expression=expr, kind="source")
                san_list = sanitizers_by_var.get(var, [])
                return [step], list(san_list)

        # Recurse into dependencies
        for dep_var in dep_vars:
            if dep_var == var:
                continue
            sub_path, sub_sans = _trace_back(dep_var, deps, sanitizers_by_var, params, config, visited, param_lines)
            if sub_path is not None:
                step = FlowStep(variable=var, line=line, expression=expr, kind="assignment")
                san_list = sanitizers_by_var.get(var, [])
                return sub_path + [step], sub_sans + list(san_list)

    return None, []


def _get_line_text(file_path: str, line: int) -> str:
    """Read a single line from a file (1-indexed)."""
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for i, text in enumerate(f, 1):
                if i == line:
                    return text.rstrip()
    except OSError:
        pass
    return ""


def _param_names_from_dangerous(config: LanguageConfig) -> set[str]:
    """Extract base object names from dangerous_sources patterns."""
    names: set[str] = set()
    for ds in config.dangerous_sources:
        names.add(ds.split(".")[0])
    return names


def _sanitizer_target_vars(sanitizers_by_var: dict[str, list[SanitizerInfo]], san_name: str) -> set[str]:
    """Find which variables a sanitizer was applied to."""
    result: set[str] = set()
    for var, sans in sanitizers_by_var.items():
        for s in sans:
            if s.name == san_name:
                result.add(var)
    return result


def _walk(node: Node):
    """Depth-first walk of AST nodes."""
    yield node
    for child in node.children:
        yield from _walk(child)
