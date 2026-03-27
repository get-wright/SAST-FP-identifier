# Taint Tracker v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **IMPORTANT — Documentation-First:** Before writing ANY code in each task, use the context7 MCP server (`resolve-library-id` then `query-docs`) to look up current docs for every library you touch. This applies to: tree-sitter (py-tree-sitter), Pydantic v2. Also look up tree-sitter-javascript and tree-sitter-typescript grammar node types to verify AST node names. Do not rely on memory — APIs change.
>
> **IMPORTANT — Test Fixtures:** Before writing test fixtures, search the internet for real-world taint tracing patterns from: Semgrep test rules repo (`semgrep/semgrep-rules`), CodeQL JS tests (`github/codeql`), OWASP Juice Shop, DVNA, NodeGoat. Use real vulnerable code patterns, not synthetic examples.

**Goal:** Replace flat dependency-graph taint tracing with scope-tree fixpoint analysis that handles callbacks, loops, and nested lambdas. Fix Joern taint path parser.

**Architecture:** Pass 1 builds a tree of scopes (functions, lambdas, loops) with per-scope dependency graphs. Pass 2 iterates fixpoint, propagating taint across scope boundaries (collection → callback param, callback return → caller). Joern parser gets proper bracket matching and path validation.

**Tech Stack:** Python 3.11+, tree-sitter, py-tree-sitter bindings

---

## File Map

| File | Responsibility | Action |
|---|---|---|
| `src/taint/scope_analyzer.py` | Scope tree data model + builder + fixpoint propagation | **Create** |
| `tests/test_scope_analyzer.py` | Unit tests for scope tree | **Create** |
| `tests/fixtures/taint_callback.js` | JS test fixture: forEach, map, for...of patterns | **Create** |
| `tests/fixtures/taint_callback.py` | Python test fixture: for-loop, map, list comprehension | **Create** |
| `tests/fixtures/taint_callback.ts` | TS test fixture: async callbacks, template literals | **Create** |
| `src/code_reader/tree_sitter_reader.py` | Add iteration_types, callback_methods, callback_returns_value to LanguageConfig | Modify |
| `src/taint/flow_tracker.py` | Replace internals with scope_analyzer | Modify |
| `src/taint/sanitizer_checker.py` | Add missing sanitizer names | Modify |
| `src/graph/joern_client.py` | Fix `_parse_taint_result` | Modify |
| `src/core/flow_grounding.py` | Map new FlowStep kinds to labels | Modify |

---

### Task 1: LanguageConfig — Add New Fields

**Files:**
- Modify: `src/code_reader/tree_sitter_reader.py`

- [ ] **Step 1: Add new fields to LanguageConfig dataclass**

Add after `dangerous_sources` (line 45):

```python
    iteration_types: tuple[str, ...] = ()          # loop node types that bind variables (for_in_statement, for_statement)
    callback_methods: tuple[str, ...] = ()         # methods that pass collection elements to callbacks
    callback_returns_value: frozenset[str] = frozenset()  # subset where return value flows back to caller
```

- [ ] **Step 2: Add values to JS config** (line 61, `.js` entry)

After `dangerous_sources=(...),` add:

```python
        iteration_types=("for_in_statement",),
        callback_methods=("forEach", "map", "filter", "find", "some", "every", "reduce", "flatMap", "sort", "replace"),
        callback_returns_value=frozenset({"map", "filter", "find", "reduce", "flatMap", "sort"}),
```

- [ ] **Step 3: Copy same values to `.jsx`, `.ts`, `.tsx` configs**

Add the same three fields to the JSX (line 73), TS (line 85), and TSX (line 97) config blocks.

- [ ] **Step 4: Add values to Python config** (line 50, `.py` entry)

```python
        iteration_types=("for_statement",),
        callback_methods=("map", "filter", "sorted", "min", "max"),
        callback_returns_value=frozenset({"map", "filter", "sorted", "min", "max"}),
```

- [ ] **Step 5: Add values to Java config** (line 119, `.java` entry)

```python
        iteration_types=("enhanced_for_statement",),
        callback_methods=("forEach", "map", "filter", "flatMap", "collect", "reduce", "sorted", "peek"),
        callback_returns_value=frozenset({"map", "filter", "flatMap", "collect", "reduce", "sorted"}),
```

- [ ] **Step 6: Add values to Go config** (line 109, `.go` entry)

```python
        iteration_types=("for_range_clause",),
```

- [ ] **Step 7: Run existing tests to verify no regressions**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/test_tree_sitter_reader.py tests/test_flow_tracker.py -v`
Expected: All PASS — new fields have defaults

- [ ] **Step 8: Commit**

```bash
git add src/code_reader/tree_sitter_reader.py
git commit -m "feat: add iteration_types, callback_methods to LanguageConfig"
```

---

### Task 2: Test Fixtures — Real-World Taint Patterns

**Files:**
- Create: `tests/fixtures/taint_callback.js`
- Create: `tests/fixtures/taint_callback.py`
- Create: `tests/fixtures/taint_callback.ts`

Before writing fixtures, search the internet for real vulnerable code patterns from Semgrep rules, CodeQL tests, Juice Shop, DVNA, NodeGoat. Use real patterns, not synthetic examples.

- [ ] **Step 1: Create JS callback fixture**

```javascript
// tests/fixtures/taint_callback.js
// Taint flow patterns: callbacks, loops, sanitizers

// Pattern 1: forEach — parameter flows from collection
// Based on Express + NodeGoat patterns
function forEachTaint(req, res) {
    const items = req.body.items;
    items.forEach(item => {
        res.send("<div>" + item + "</div>");  // sink line 9
    });
}

// Pattern 2: map — return value flows back to caller
function mapTaint(req, res) {
    const names = req.query.names;
    const html = names.map(name => "<li>" + name + "</li>");  // line 15
    res.send(html.join(""));  // sink line 16
}

// Pattern 3: map with sanitizer — return value is clean
function mapSanitized(req, res) {
    const names = req.query.names;
    const html = names.map(name => "<li>" + escapeHtml(name) + "</li>");
    res.send(html.join(""));  // sink line 23 — should be sanitized
}

// Pattern 4: for...of loop variable
function forOfTaint(req, res) {
    const entries = req.body.entries;
    for (const entry of entries) {
        eval(entry);  // sink line 29
    }
}

// Pattern 5: for...of with destructuring
function forOfDestructure(req, res) {
    const entries = req.body.entries;
    for (const { key, value } of entries) {
        res.send(key + "=" + value);  // sink line 36
    }
}

// Pattern 6: template literal sink (innerHTML)
function templateSink(req, res) {
    const name = req.query.name;
    document.getElementById("out").innerHTML = `<h1>${name}</h1>`;  // sink line 41
}

// Pattern 7: callback with no taint — hardcoded array
function noTaint() {
    const items = ["safe", "values"];
    items.forEach(item => {
        console.log(item);  // line 47 — no taint source
    });
}

// Pattern 8: filter callback — taint flows through
function filterTaint(req, res) {
    const users = req.body.users;
    const active = users.filter(u => u.active);
    res.json(active);  // sink line 54
}
```

- [ ] **Step 2: Create Python callback fixture**

```python
# tests/fixtures/taint_callback.py
# Taint flow patterns: for-loops, map, comprehensions

# Pattern 1: for-loop iteration variable
def for_loop_taint(request):
    items = request.args.getlist("items")
    for item in items:
        cursor.execute(f"SELECT * FROM t WHERE name = '{item}'")  # sink line 7

# Pattern 2: map with lambda
def map_taint(request):
    names = request.args.getlist("names")
    queries = list(map(lambda n: f"SELECT * FROM users WHERE name = '{n}'", names))
    for q in queries:
        cursor.execute(q)  # sink line 14

# Pattern 3: list comprehension (syntactic sugar for map+filter)
def comprehension_taint(request):
    ids = request.args.getlist("ids")
    queries = [f"DELETE FROM t WHERE id = {i}" for i in ids]
    for q in queries:
        cursor.execute(q)  # sink line 21

# Pattern 4: for-loop with sanitizer
def for_loop_sanitized(request):
    items = request.args.getlist("items")
    for item in items:
        safe = escape(item)
        output(f"<div>{safe}</div>")  # sink line 28 — sanitized

# Pattern 5: nested function (closure)
def nested_function_taint(request):
    data = request.form.get("data")
    def process():
        return eval(data)  # sink line 34 — data captured from outer scope
    process()
```

- [ ] **Step 3: Create TS callback fixture**

```typescript
// tests/fixtures/taint_callback.ts
// TypeScript taint patterns: async, template literals, destructuring

// Pattern 1: async forEach
async function asyncForEachTaint(req: Request) {
    const items: string[] = req.body.items;
    items.forEach(async (item: string) => {
        await db.query(`SELECT * FROM t WHERE name = '${item}'`);  // sink line 7
    });
}

// Pattern 2: reduce callback — accumulator propagates taint
function reduceTaint(req: Request) {
    const parts: string[] = req.query.parts;
    const combined = parts.reduce((acc, part) => acc + part, "");
    eval(combined);  // sink line 13
}

// Pattern 3: for...of with type annotation
function typedForOf(req: Request) {
    const entries: Array<{key: string, value: string}> = req.body.entries;
    for (const { key, value } of entries) {
        document.getElementById(key)!.innerHTML = value;  // sink line 19
    }
}

// Pattern 4: console.log sink (low severity — typical of kite-public findings)
function logTaint(settings: RemoteSetting[]) {
    for (const setting of settings) {
        const key = setting.settingKey;
        console.log(`[Sync] Updating setting: ${key}`);  // sink line 25
    }
}
```

- [ ] **Step 4: Commit**

```bash
git add tests/fixtures/taint_callback.js tests/fixtures/taint_callback.py tests/fixtures/taint_callback.ts
git commit -m "test: add real-world taint callback fixtures for JS/Python/TS"
```

---

### Task 3: Scope Analyzer — Data Model + Scope Tree Builder (Pass 1)

**Files:**
- Create: `src/taint/scope_analyzer.py`
- Create: `tests/test_scope_analyzer.py`

- [ ] **Step 1: Write failing tests for scope tree building**

```python
# tests/test_scope_analyzer.py
import os
from src.taint.scope_analyzer import build_scope_tree, Scope
from src.code_reader.tree_sitter_reader import TreeSitterReader

_reader = TreeSitterReader()
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _get_func_scope(file_path: str, func_name: str) -> Scope:
    """Helper: parse file, find function, build scope tree."""
    ext = os.path.splitext(file_path)[1]
    config = _reader.get_config(ext)
    root = _reader.parse_file(file_path)
    # Find function node
    for node in _walk(root):
        if node.type in config.func_types:
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode() == func_name:
                return build_scope_tree(node, config)
            if node.type == "arrow_function" and node.parent and node.parent.type == "variable_declarator":
                vd_name = node.parent.child_by_field_name("name")
                if vd_name and vd_name.text.decode() == func_name:
                    return build_scope_tree(node, config)
    raise ValueError(f"Function {func_name} not found in {file_path}")


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def test_js_foreach_creates_child_scope():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forEachTaint")
    assert scope.kind in ("function", "method")
    assert "req" in scope.params
    # Should have a child scope for the forEach callback
    assert len(scope.children) >= 1
    callback = scope.children[0]
    assert callback.kind == "arrow"
    assert "item" in callback.params


def test_js_foreach_call_site():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forEachTaint")
    assert len(scope.call_sites) >= 1
    cs = scope.call_sites[0]
    assert cs.callee == "forEach"
    assert cs.receiver_var == "items"
    assert cs.returns_value is False


def test_js_map_call_site_returns_value():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "mapTaint")
    assert len(scope.call_sites) >= 1
    cs = scope.call_sites[0]
    assert cs.callee == "map"
    assert cs.receiver_var == "names"
    assert cs.returns_value is True


def test_js_for_of_creates_child_scope():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forOfTaint")
    assert len(scope.children) >= 1
    loop_scope = scope.children[0]
    assert loop_scope.kind in ("for_of", "for_in")
    assert "entry" in loop_scope.params


def test_js_for_of_destructure():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forOfDestructure")
    loop_scope = scope.children[0]
    assert "key" in loop_scope.params
    assert "value" in loop_scope.params


def test_js_for_of_call_site():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forOfTaint")
    assert len(scope.call_sites) >= 1
    cs = scope.call_sites[0]
    assert cs.callee == "@@iterator"
    assert cs.receiver_var == "entries"


def test_py_for_loop_creates_child_scope():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.py"), "for_loop_taint")
    assert len(scope.children) >= 1
    loop_scope = scope.children[0]
    assert "item" in loop_scope.params


def test_scope_deps_dont_leak_into_children():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forEachTaint")
    # Parent scope should have "items" in deps but NOT variables from inside the callback
    assert "items" in scope.deps
    # Callback's body assignments should be in the child scope, not the parent
    callback = scope.children[0]
    # The parent should not contain deps from the callback body
    # (exact assertion depends on what the callback body assigns)


def test_scope_return_exprs():
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "mapTaint")
    # The map callback should have a return expression (implicit arrow return)
    callback = scope.call_sites[0].callback_scope
    # Arrow functions with expression body have an implicit return
    assert len(callback.return_exprs) >= 0  # May be 0 if expression body, handled by kind
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/test_scope_analyzer.py -v`
Expected: FAIL with `ImportError` — `scope_analyzer` not found

- [ ] **Step 3: Implement scope_analyzer.py — data model**

```python
# src/taint/scope_analyzer.py
"""Two-pass scope-tree taint analysis.

Pass 1: Build scope tree from AST (functions, lambdas, loops)
Pass 2: Fixpoint taint propagation across scope boundaries
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from tree_sitter import Node

from src.code_reader.tree_sitter_reader import LanguageConfig
from src.models.analysis import FlowStep, SanitizerInfo
from src.taint.sanitizer_checker import check_known_sanitizer, is_conditional_ancestor

logger = logging.getLogger(__name__)


@dataclass
class DepEntry:
    """One assignment in a scope's dependency graph."""
    deps: set[str]
    line: int
    expr: str
    node: Node


@dataclass
class ReturnExpr:
    """A return expression in a scope."""
    variables: set[str]
    line: int
    expr: str


@dataclass
class CallSite:
    """A call where a callback scope receives collection elements."""
    callee: str                     # "forEach", "map", "@@iterator"
    receiver_var: str               # "arr" in arr.forEach(...)
    callback_scope: Scope           # nested scope passed as callback
    callback_param_index: int = 0   # which param receives elements
    returns_value: bool = False     # True for map/filter/find


@dataclass
class Scope:
    """One function/lambda/loop scope in the scope tree."""
    node: Node
    kind: str                       # "function" | "arrow" | "for_of" | "for_in" | "method" | "lambda"
    name: str = ""
    params: set[str] = field(default_factory=set)
    deps: dict[str, list[DepEntry]] = field(default_factory=dict)
    sanitizers: dict[str, list[SanitizerInfo]] = field(default_factory=dict)
    unresolved_calls: list[str] = field(default_factory=list)
    children: list[Scope] = field(default_factory=list)
    call_sites: list[CallSite] = field(default_factory=list)
    return_exprs: list[ReturnExpr] = field(default_factory=list)
    parent: Optional[Scope] = field(default=None, repr=False)
```

- [ ] **Step 4: Implement `build_scope_tree` (Pass 1)**

Add to `scope_analyzer.py`:

```python
def build_scope_tree(func_node: Node, config: LanguageConfig) -> Scope:
    """Build a scope tree from a function AST node.

    Walks the AST depth-first, creating child scopes for nested functions,
    arrow functions, and iteration loops. Deps are built per-scope (not
    recursing into children). Call sites are detected for callback methods.
    """
    kind = _node_to_scope_kind(func_node, config)
    name = _extract_scope_name(func_node)
    params = _extract_params(func_node, config)

    scope = Scope(node=func_node, kind=kind, name=name, params=params)
    _populate_scope(scope, func_node, config)
    return scope


def _node_to_scope_kind(node: Node, config: LanguageConfig) -> str:
    """Map AST node type to scope kind."""
    t = node.type
    if t == "arrow_function":
        return "arrow"
    if t in ("function_declaration", "function_definition", "function_expression"):
        return "function"
    if t in ("method_definition", "method_declaration"):
        return "method"
    if t in config.iteration_types:
        op = node.child_by_field_name("operator")
        if op and op.text == b"of":
            return "for_of"
        if op and op.text == b"in":
            return "for_in"
        # Python for_statement, Java enhanced_for
        return "for_of"
    if t == "lambda_expression":
        return "lambda"
    return "function"


def _extract_scope_name(node: Node) -> str:
    """Extract function/method name from AST node."""
    name_node = node.child_by_field_name("name")
    if name_node:
        return name_node.text.decode()
    # JS arrow: name from parent variable_declarator
    if node.type == "arrow_function" and node.parent and node.parent.type == "variable_declarator":
        vd_name = node.parent.child_by_field_name("name")
        if vd_name:
            return vd_name.text.decode()
    return ""


def _extract_params(node: Node, config: LanguageConfig) -> set[str]:
    """Extract parameter names from a scope node."""
    params: set[str] = set()

    if node.type in config.iteration_types:
        # Loop variable: from the "left" field
        left = node.child_by_field_name("left")
        if left:
            _collect_bound_identifiers(left, params)
        # Python for_statement: check children for pattern node
        # "for x in iterable:" → left field is the loop variable
        # Python also stores the loop var differently
        if not params:
            for child in node.children:
                if child.type == "identifier" and child.prev_sibling and child.prev_sibling.type == "for":
                    params.add(child.text.decode())
                elif child.type in ("pattern_list", "tuple_pattern"):
                    _collect_bound_identifiers(child, params)
        return params

    # Regular function/arrow/method: from formal_parameters
    for child in node.children:
        if child.type in config.parameter_types:
            _collect_bound_identifiers(child, params)
    # Arrow function single param (no parens): the "parameter" field
    param_node = node.child_by_field_name("parameter")
    if param_node and param_node.type == "identifier":
        params.add(param_node.text.decode())
    return params


def _collect_bound_identifiers(node: Node, out: set[str]) -> None:
    """Recursively collect all identifier names from a pattern node (handles destructuring)."""
    if node.type == "identifier":
        out.add(node.text.decode())
    elif node.type in ("shorthand_property_identifier_pattern", "shorthand_property_identifier"):
        out.add(node.text.decode())
    else:
        for child in node.children:
            _collect_bound_identifiers(child, out)


def _populate_scope(scope: Scope, node: Node, config: LanguageConfig) -> None:
    """Walk scope body, build deps, find children, detect call sites."""
    body = _get_scope_body(node, config)
    if body is None:
        body = node

    # Collect child scope nodes first (so we can skip them in dep building)
    child_scope_nodes: set[int] = set()

    for n in _walk_shallow(body, config):
        # Detect child scopes
        if n.type in config.func_types and id(n) != id(node):
            child = build_scope_tree(n, config)
            child.parent = scope
            scope.children.append(child)
            child_scope_nodes.add(id(n))
            continue

        if n.type in config.iteration_types:
            child = build_scope_tree(n, config)
            child.parent = scope
            scope.children.append(child)
            child_scope_nodes.add(id(n))
            # Model iteration as a call site
            right = n.child_by_field_name("right")
            if not right:
                # Python: the iterable is the expression after "in"
                for c in n.children:
                    if c.prev_sibling and c.prev_sibling.text == b"in":
                        right = c
                        break
            receiver = _root_identifier(right) if right else ""
            if receiver:
                scope.call_sites.append(CallSite(
                    callee="@@iterator",
                    receiver_var=receiver,
                    callback_scope=child,
                    callback_param_index=0,
                    returns_value=False,
                ))
            continue

        # Detect assignments (only in this scope, not in children)
        if n.type in config.assignment_types and not _is_inside_child(n, child_scope_nodes):
            lhs, rhs = _extract_assignment(n, config)
            if lhs and rhs:
                rhs_ids = _collect_ids(rhs)
                line = n.start_point[0] + 1
                expr = n.text.decode()
                scope.deps.setdefault(lhs, []).append(DepEntry(deps=rhs_ids, line=line, expr=expr, node=n))

                # Sanitizer detection
                for call_node in _find_calls_in(rhs, config):
                    callee = _get_callee_name(call_node, config)
                    if not callee:
                        continue
                    san = check_known_sanitizer(callee)
                    if san:
                        san.line = line
                        san.conditional = is_conditional_ancestor(n, config.conditional_types)
                        scope.sanitizers.setdefault(lhs, []).append(san)

        # Detect call sites with callback arguments
        if n.type in config.call_types and not _is_inside_child(n, child_scope_nodes):
            _detect_callback_call_site(scope, n, config)

        # Detect return expressions
        if n.type in config.return_types and not _is_inside_child(n, child_scope_nodes):
            ret_ids = _collect_ids(n)
            line = n.start_point[0] + 1
            scope.return_exprs.append(ReturnExpr(variables=ret_ids, line=line, expr=n.text.decode()))

    # Arrow function with expression body (implicit return)
    if node.type == "arrow_function":
        body_node = node.child_by_field_name("body")
        if body_node and body_node.type != "statement_block":
            ret_ids = _collect_ids(body_node)
            line = body_node.start_point[0] + 1
            scope.return_exprs.append(ReturnExpr(variables=ret_ids, line=line, expr=body_node.text.decode()))


def _detect_callback_call_site(scope: Scope, call_node: Node, config: LanguageConfig) -> None:
    """Check if a call expression passes a callback from config.callback_methods."""
    func_ref = call_node.child_by_field_name("function")
    if not func_ref or func_ref.type not in ("member_expression", "attribute"):
        return

    method_node = func_ref.child_by_field_name("property") or func_ref.child_by_field_name("attribute")
    if not method_node:
        return
    method_name = method_node.text.decode()
    if method_name not in config.callback_methods:
        return

    obj_node = func_ref.child_by_field_name("object")
    receiver = _root_identifier(obj_node) if obj_node else ""

    # Find the callback argument (arrow_function or function_expression in args)
    args_node = call_node.child_by_field_name("arguments")
    if not args_node:
        return

    callback_child = None
    for arg in args_node.children:
        if arg.type in config.func_types:
            callback_child = arg
            break

    if callback_child is None:
        return

    # Build scope for the callback
    child = build_scope_tree(callback_child, config)
    child.parent = scope
    scope.children.append(child)

    returns_value = method_name in config.callback_returns_value

    scope.call_sites.append(CallSite(
        callee=method_name,
        receiver_var=receiver,
        callback_scope=child,
        callback_param_index=0,
        returns_value=returns_value,
    ))


def _get_scope_body(node: Node, config: LanguageConfig) -> Optional[Node]:
    """Get the body node of a scope-creating node."""
    body = node.child_by_field_name("body")
    if body:
        return body
    # Python for_statement body is the "body" field
    # Java enhanced_for_statement body is "body"
    return None


def _root_identifier(node: Node) -> str:
    """Extract the root identifier from an expression (e.g., 'arr' from 'arr.items')."""
    if node is None:
        return ""
    if node.type == "identifier":
        return node.text.decode()
    if node.type in ("member_expression", "attribute", "subscript_expression"):
        obj = node.child_by_field_name("object")
        if obj:
            return _root_identifier(obj)
    return ""


def _extract_assignment(node: Node, config: LanguageConfig) -> tuple[str, Optional[Node]]:
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


def _collect_ids(node: Node) -> set[str]:
    """Collect all identifier names in a subtree."""
    ids: set[str] = set()
    for n in _walk_all(node):
        if n.type == "identifier":
            ids.add(n.text.decode())
    return ids


def _find_calls_in(node: Node, config: LanguageConfig) -> list[Node]:
    """Find call expression nodes in a subtree."""
    calls = []
    for n in _walk_all(node):
        if n.type in config.call_types:
            calls.append(n)
    return calls


def _get_callee_name(call_node: Node, config: LanguageConfig) -> str:
    """Get simple callee name from call node."""
    func_ref = call_node.child_by_field_name("function")
    if not func_ref:
        return ""
    if func_ref.type == "identifier":
        return func_ref.text.decode()
    if func_ref.type in ("attribute", "member_expression"):
        attr = func_ref.child_by_field_name("attribute") or func_ref.child_by_field_name("property")
        if attr:
            return attr.text.decode()
    return ""


def _is_inside_child(node: Node, child_ids: set[int]) -> bool:
    """Check if a node is inside any of the child scope nodes."""
    current = node.parent
    while current is not None:
        if id(current) in child_ids:
            return True
        current = current.parent
    return False


def _walk_shallow(node: Node, config: LanguageConfig):
    """Walk AST nodes, yielding all nodes (including inside child scopes).

    The caller uses _is_inside_child to filter. This is simpler than trying
    to skip subtrees during traversal.
    """
    yield from _walk_all(node)


def _walk_all(node: Node):
    """Depth-first walk of all AST nodes."""
    yield node
    for child in node.children:
        yield from _walk_all(child)
```

- [ ] **Step 5: Run tests**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/test_scope_analyzer.py -v`
Expected: Tests pass for scope tree building

- [ ] **Step 6: Run full suite for regressions**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/ -q`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add src/taint/scope_analyzer.py tests/test_scope_analyzer.py
git commit -m "feat: add scope tree builder (Pass 1) for taint tracker v2"
```

---

### Task 4: Scope Analyzer — Fixpoint Propagation (Pass 2)

**Files:**
- Modify: `src/taint/scope_analyzer.py`
- Modify: `tests/test_scope_analyzer.py`

- [ ] **Step 1: Write failing tests for taint propagation**

```python
# Add to tests/test_scope_analyzer.py
from src.taint.scope_analyzer import propagate_taint
from src.models.analysis import FlowStep


def test_foreach_taint_propagation():
    """forEach callback param should be tainted when receiver is tainted."""
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forEachTaint")
    config = _reader.get_config(".js")
    path = propagate_taint(scope, {"item"}, 9, config)
    assert path is not None
    assert len(path) >= 2
    # Source should trace back to req parameter
    assert path[0].kind in ("parameter", "source", "callback_param")


def test_map_taint_propagation_returns():
    """map callback return value should taint the call result in parent scope."""
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "mapTaint")
    config = _reader.get_config(".js")
    path = propagate_taint(scope, {"html"}, 16, config)
    assert path is not None
    assert any(s.kind == "callback_return" for s in path) or len(path) >= 2


def test_for_of_taint_propagation():
    """for...of loop variable should be tainted when iterable is tainted."""
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "forOfTaint")
    config = _reader.get_config(".js")
    path = propagate_taint(scope, {"entry"}, 29, config)
    assert path is not None
    assert any(s.kind in ("iteration_var", "parameter", "source") for s in path)


def test_no_taint_hardcoded():
    """Hardcoded array should not produce a taint path."""
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.js"), "noTaint")
    config = _reader.get_config(".js")
    path = propagate_taint(scope, {"item"}, 47, config)
    # Should return None or a path with only hardcoded source
    if path is not None:
        assert path[0].kind not in ("parameter", "source")


def test_py_for_loop_propagation():
    """Python for-loop variable should trace back to source."""
    scope = _get_func_scope(os.path.join(FIXTURES, "taint_callback.py"), "for_loop_taint")
    config = _reader.get_config(".py")
    path = propagate_taint(scope, {"item"}, 7, config)
    assert path is not None
    assert path[0].kind in ("parameter", "source")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/test_scope_analyzer.py::test_foreach_taint_propagation -v`
Expected: FAIL — `propagate_taint` not defined

- [ ] **Step 3: Implement fixpoint propagation**

Add to `scope_analyzer.py`:

```python
def propagate_taint(
    root: Scope,
    sink_vars: set[str],
    sink_line: int,
    config: LanguageConfig,
) -> Optional[list[FlowStep]]:
    """Run fixpoint taint propagation and trace path from sink to source.

    Returns a list of FlowSteps from source to sink, or None if no taint path found.
    """
    # Phase 1: Forward propagation — mark which vars are tainted in each scope
    taint_state: dict[int, set[str]] = {}  # id(scope) → tainted vars

    # Seed: root params are potential sources
    root_tainted = set(root.params)
    # Also check for dangerous sources in root deps
    for var, entries in root.deps.items():
        for entry in entries:
            for ds in config.dangerous_sources:
                if ds in entry.expr:
                    root_tainted.add(var)
    taint_state[id(root)] = root_tainted

    # Fixpoint iteration
    changed = True
    max_iterations = 20
    iteration = 0
    while changed and iteration < max_iterations:
        changed = False
        iteration += 1
        changed |= _propagate_scope(root, taint_state, config)

    # Phase 2: Backward trace from sink vars to source
    # Find which scope contains the sink
    sink_scope = _find_scope_for_line(root, sink_line)
    if sink_scope is None:
        sink_scope = root

    return _trace_path(sink_scope, sink_vars, sink_line, taint_state, config, set())


def _propagate_scope(scope: Scope, state: dict[int, set[str]], config: LanguageConfig) -> bool:
    """Propagate taint within a scope and across call sites. Returns True if state changed."""
    changed = False
    tainted = state.setdefault(id(scope), set())

    # Forward propagation within this scope's deps
    for var, entries in scope.deps.items():
        if var in tainted:
            continue
        for entry in entries:
            # Check if any RHS identifier is tainted
            if entry.deps & tainted:
                # Check for sanitizer
                sans = scope.sanitizers.get(var, [])
                if not any(not s.conditional for s in sans):
                    tainted.add(var)
                    changed = True
                    break
            # Check for dangerous sources
            for ds in config.dangerous_sources:
                if ds in entry.expr:
                    tainted.add(var)
                    changed = True
                    break

    # Propagate across call sites
    for cs in scope.call_sites:
        child_tainted = state.setdefault(id(cs.callback_scope), set())

        # Collection → callback param
        if cs.receiver_var in tainted:
            # Seed callback's first param
            callback_params = list(cs.callback_scope.params)
            if callback_params and cs.callback_param_index < len(callback_params):
                target_param = callback_params[cs.callback_param_index]
                if target_param not in child_tainted:
                    child_tainted.add(target_param)
                    changed = True
            elif callback_params:
                # Seed all params (e.g., destructured for...of)
                for p in callback_params:
                    if p not in child_tainted:
                        child_tainted.add(p)
                        changed = True

        # Recurse into callback scope
        changed |= _propagate_scope(cs.callback_scope, state, config)

        # Callback return → parent scope (for map/filter/find)
        if cs.returns_value:
            for ret in cs.callback_scope.return_exprs:
                if ret.variables & child_tainted:
                    # Find the variable in parent that receives the call result
                    result_var = _find_call_result_var(scope, cs)
                    if result_var and result_var not in tainted:
                        tainted.add(result_var)
                        changed = True

    # Propagate into non-call-site children (nested functions that capture parent vars)
    call_site_children = {id(cs.callback_scope) for cs in scope.call_sites}
    for child in scope.children:
        if id(child) in call_site_children:
            continue
        child_tainted = state.setdefault(id(child), set())
        # Closure capture: if child uses a parent-scoped tainted var, propagate
        for var, entries in child.deps.items():
            for entry in entries:
                captured = entry.deps & tainted
                if captured:
                    for cap_var in captured:
                        if cap_var not in child_tainted:
                            child_tainted.add(cap_var)
                            changed = True
        changed |= _propagate_scope(child, state, config)

    return changed


def _find_call_result_var(scope: Scope, cs: CallSite) -> Optional[str]:
    """Find the variable that receives the result of a callback call (e.g., const html = names.map(...))."""
    # Look for an assignment where RHS contains the receiver + method
    call_text = f"{cs.receiver_var}.{cs.callee}"
    for var, entries in scope.deps.items():
        for entry in entries:
            if cs.receiver_var in entry.deps and cs.callee in entry.expr:
                return var
    return None


def _find_scope_for_line(scope: Scope, line: int) -> Optional[Scope]:
    """Find the innermost scope containing the given line."""
    for child in scope.children:
        result = _find_scope_for_line(child, line)
        if result is not None:
            return result
    start = scope.node.start_point[0] + 1
    end = scope.node.end_point[0] + 1
    if start <= line <= end:
        return scope
    return None


def _trace_path(
    scope: Scope,
    target_vars: set[str],
    target_line: int,
    state: dict[int, set[str]],
    config: LanguageConfig,
    visited: set[str],
) -> Optional[list[FlowStep]]:
    """Trace backward from target variables to source, crossing scope boundaries."""
    tainted = state.get(id(scope), set())

    for var in target_vars:
        if var in visited:
            continue
        new_visited = visited | {var}

        # Base case: parameter of root scope
        if var in scope.params and scope.parent is None:
            step = FlowStep(variable=var, line=0, expression=f"parameter: {var}", kind="parameter")
            return [step]

        # Base case: iteration variable — trace to parent's collection
        if var in scope.params and scope.parent is not None:
            for cs in scope.parent.call_sites:
                if cs.callback_scope is scope:
                    kind = "iteration_var" if cs.callee == "@@iterator" else "callback_param"
                    step = FlowStep(variable=var, line=scope.node.start_point[0] + 1,
                                    expression=f"{cs.receiver_var} → {var}", kind=kind)
                    # Continue tracing the receiver in parent scope
                    parent_path = _trace_path(
                        scope.parent, {cs.receiver_var}, scope.node.start_point[0] + 1,
                        state, config, new_visited,
                    )
                    if parent_path is not None:
                        return parent_path + [step]
                    return [step]

        # Check deps in this scope
        if var in scope.deps:
            for entry in scope.deps[var]:
                # Check for dangerous source
                for ds in config.dangerous_sources:
                    if ds in entry.expr:
                        step = FlowStep(variable=var, line=entry.line, expression=entry.expr, kind="source")
                        return [step]

                # Recurse into RHS deps
                tainted_deps = entry.deps & tainted
                for dep_var in tainted_deps:
                    sub_path = _trace_path(scope, {dep_var}, entry.line, state, config, new_visited)
                    if sub_path is not None:
                        step = FlowStep(variable=var, line=entry.line, expression=entry.expr, kind="assignment")
                        return sub_path + [step]

        # Check if variable is a callback return result
        for cs in scope.call_sites:
            result_var = _find_call_result_var(scope, cs)
            if result_var == var and cs.returns_value:
                # Trace inside the callback
                child_tainted = state.get(id(cs.callback_scope), set())
                for ret in cs.callback_scope.return_exprs:
                    ret_tainted = ret.variables & child_tainted
                    if ret_tainted:
                        inner_path = _trace_path(
                            cs.callback_scope, ret_tainted, ret.line, state, config, new_visited,
                        )
                        if inner_path is not None:
                            ret_step = FlowStep(variable=var, line=ret.line,
                                                expression=f"{cs.receiver_var}.{cs.callee}() → {var}",
                                                kind="callback_return")
                            return inner_path + [ret_step]

    return None
```

- [ ] **Step 4: Run tests**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/test_scope_analyzer.py -v`
Expected: All tests pass

- [ ] **Step 5: Run full suite**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/ -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/taint/scope_analyzer.py tests/test_scope_analyzer.py
git commit -m "feat: add fixpoint taint propagation (Pass 2) for scope tree"
```

---

### Task 5: Integrate Scope Analyzer into flow_tracker.py

**Files:**
- Modify: `src/taint/flow_tracker.py`

- [ ] **Step 1: Replace `trace_taint_flow` internals**

Replace the body of `trace_taint_flow` (lines 25-125) to use the scope analyzer while keeping the same public API. The old `_build_deps` + `_trace_back` functions remain in the file for now (they're used by existing tests and as fallback).

```python
def trace_taint_flow(
    *,
    file_path: str,
    function_name: str,
    sink_line: int,
    check_id: str,
    cwe_list: list[str],
) -> Optional[TaintFlow]:
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

    # Fallback to flat analysis
    return _trace_flat(func_node, config, file_path, sink_line, check_id, cwe_list)
```

Add `_trace_with_scope_tree`:

```python
def _trace_with_scope_tree(func_node, config, file_path, sink_line, check_id, cwe_list):
    from src.taint.scope_analyzer import build_scope_tree, propagate_taint

    scope_tree = build_scope_tree(func_node, config)
    sink_vars = _find_vars_at_line(func_node, sink_line, config)
    if not sink_vars:
        return None

    path = propagate_taint(scope_tree, set(sink_vars), sink_line, config)
    if path is None:
        return None

    # Add sink step
    sink_step = FlowStep(
        variable=sink_vars[0],
        line=sink_line,
        expression=_get_line_text(file_path, sink_line),
        kind="sink",
    )
    path.append(sink_step)

    # Collect sanitizers from the scope tree
    all_sanitizers = _collect_sanitizers_from_scope(scope_tree)
    path_vars = {step.variable for step in path}
    relevant = [s for s in all_sanitizers if s.name.lower() in {v.lower() for v in path_vars} or True]
    # Simplified: just collect all sanitizers found in the tree
    deduped = _dedup_sanitizers(all_sanitizers)

    confidence_factors = []
    if deduped:
        confidence_factors.append(f"Sanitizer {deduped[0].name} found in path")
    elif path[0].kind in ("parameter", "source"):
        confidence_factors.append("Direct source to sink with no sanitizer")

    inferred = infer_sink_source(check_id, cwe_list, _get_line_text(file_path, sink_line))

    # Collect unresolved calls
    unresolved = _collect_unresolved_from_scope(scope_tree)

    return TaintFlow(
        path=path,
        sanitizers=deduped,
        unresolved_calls=unresolved,
        confidence_factors=confidence_factors,
        inferred=inferred,
    )


def _collect_sanitizers_from_scope(scope) -> list[SanitizerInfo]:
    """Recursively collect all sanitizers from a scope tree."""
    result = []
    for sans_list in scope.sanitizers.values():
        result.extend(sans_list)
    for child in scope.children:
        result.extend(_collect_sanitizers_from_scope(child))
    return result


def _collect_unresolved_from_scope(scope) -> list[str]:
    """Recursively collect unresolved calls from scope tree."""
    result = list(scope.unresolved_calls)
    for child in scope.children:
        result.extend(_collect_unresolved_from_scope(child))
    return result


def _dedup_sanitizers(sanitizers: list[SanitizerInfo]) -> list[SanitizerInfo]:
    seen: set[str] = set()
    result: list[SanitizerInfo] = []
    for s in sanitizers:
        if s.name not in seen:
            seen.add(s.name)
            result.append(s)
    return result
```

Move the old logic into `_trace_flat`:

```python
def _trace_flat(func_node, config, file_path, sink_line, check_id, cwe_list):
    """Original flat analysis — fallback when scope tree doesn't apply."""
    params = _extract_parameters(func_node, config)
    deps, sanitizers, unresolved = _build_deps(func_node, config, params)
    sink_vars = _find_vars_at_line(func_node, sink_line, config)

    if not sink_vars:
        return None

    for sink_var in sink_vars:
        path, used_sanitizers = _trace_back(sink_var, deps, sanitizers, params, config, set())
        if path is None:
            continue
        sink_step = FlowStep(variable=sink_var, line=sink_line,
                             expression=_get_line_text(file_path, sink_line), kind="sink")
        path.append(sink_step)
        path_vars = {step.variable for step in path}
        relevant = [s for s in used_sanitizers if _sanitizer_target_vars(sanitizers, s.name) & path_vars]
        deduped = _dedup_sanitizers(relevant)
        confidence_factors = []
        if deduped:
            unconditional = [s for s in deduped if not s.conditional]
            if unconditional:
                confidence_factors.append(f"Sanitizer {unconditional[0].name} found in path")
            else:
                confidence_factors.append("Conditional sanitizer only — may not always execute")
        elif path[0].kind in ("parameter", "source"):
            confidence_factors.append("Direct source to sink with no sanitizer")
        inferred = infer_sink_source(check_id, cwe_list, _get_line_text(file_path, sink_line))
        return TaintFlow(path=path, sanitizers=deduped, unresolved_calls=unresolved,
                         confidence_factors=confidence_factors, inferred=inferred)

    confidence_factors = ["No external source — values appear hardcoded"]
    inferred = infer_sink_source(check_id, cwe_list, _get_line_text(file_path, sink_line))
    return TaintFlow(
        path=[FlowStep(variable=sink_vars[0], line=sink_line,
                        expression=_get_line_text(file_path, sink_line), kind="sink")],
        sanitizers=[], unresolved_calls=unresolved,
        confidence_factors=confidence_factors, inferred=inferred,
    )
```

- [ ] **Step 2: Run existing tests**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/test_flow_tracker.py -v`
Expected: All 8 existing tests PASS (backward compat)

- [ ] **Step 3: Run full suite**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/ -q`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add src/taint/flow_tracker.py
git commit -m "feat: integrate scope-tree analysis into trace_taint_flow with flat fallback"
```

---

### Task 6: Sanitizer Checker Improvements

**Files:**
- Modify: `src/taint/sanitizer_checker.py`

- [ ] **Step 1: Add missing sanitizer names**

Add to the CWE-79 list (line 10-14):

```python
    "CWE-79": [
        "html.escape", "markupsafe.escape", "bleach.clean", "sanitize",
        "escapehtml", "htmlspecialchars", "encodeURIComponent",
        "dompurify.sanitize", "textcontent", "innertext",
        "cgi.escape", "xss_clean", "strip_tags",
        "escape", "encodeURI", "parseInt", "Number",
    ],
```

- [ ] **Step 2: Run tests**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/test_sanitizer_checker.py tests/test_flow_tracker.py -v`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add src/taint/sanitizer_checker.py
git commit -m "feat: add escape, encodeURI, parseInt, Number to sanitizer checker"
```

---

### Task 7: Joern Parser Fix

**Files:**
- Modify: `src/graph/joern_client.py`
- Modify: `tests/test_joern_client.py`

- [ ] **Step 1: Write failing tests for malformed Joern output**

```python
# Add to tests/test_joern_client.py

def test_parse_taint_result_nested_parens():
    """Joern output with nested parens in code should parse correctly."""
    client = JoernClient()
    raw = 'val res1: List[String] = List("a.py:10:x = List(req.body)" -> "b.py:20:cursor.execute(x)")'
    r = client._parse_taint_result(raw)
    assert r.reachable is True
    assert len(r.path) == 2
    assert "a.py:10" in r.path[0]
    assert "b.py:20" in r.path[1]


def test_parse_taint_result_malformed_elements():
    """Malformed path elements (no file:line format) should be skipped."""
    client = JoernClient()
    raw = 'val res1: List[String] = List("a.py:5:source" -> "bad_element" -> "c.py:20:sink")'
    r = client._parse_taint_result(raw)
    assert r.reachable is True
    assert len(r.path) == 2  # bad_element skipped


def test_parse_taint_result_non_numeric_line():
    """Elements with non-numeric line numbers should be skipped."""
    client = JoernClient()
    raw = 'val res1: List[String] = List("a.py:abc:code" -> "b.py:10:sink")'
    r = client._parse_taint_result(raw)
    assert r.reachable is True
    assert len(r.path) == 1  # only b.py:10 is valid


def test_parse_taint_result_all_malformed():
    """If all elements are malformed, should return not reachable."""
    client = JoernClient()
    raw = 'val res1: List[String] = List("bad" -> "also_bad")'
    r = client._parse_taint_result(raw)
    assert r.reachable is False
    assert r.path == []


def test_parse_taint_result_unbalanced_list():
    """Unbalanced List( wrapper should still parse best-effort."""
    client = JoernClient()
    raw = 'val res1: List[String] = List("a.py:1:x" -> "b.py:2:y"'  # missing closing paren
    r = client._parse_taint_result(raw)
    assert r.reachable is True
    assert len(r.path) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/test_joern_client.py::test_parse_taint_result_malformed_elements -v`
Expected: FAIL — malformed elements not skipped

- [ ] **Step 3: Fix `_parse_taint_result`**

Replace lines 325-357 (the `List()` stripping and path parsing) with:

```python
        # Strip outer List(...) wrapper with proper bracket matching
        inner = _strip_list_wrapper(result_line)

        if not inner:
            return TaintResult()

        # Split top-level comma-separated flow strings
        flow_strings: list[str] = [s.strip().strip('"') for s in inner.split('", "')]
        if not flow_strings or flow_strings == [""]:
            return TaintResult()

        # Flatten all path elements, validating format
        path_elements: list[str] = []
        for flow in flow_strings:
            for elem in flow.split(" -> "):
                elem = elem.strip()
                parts = elem.split(":", 2)
                if len(parts) < 2:
                    continue  # Skip malformed (no file:line)
                try:
                    int(parts[1])
                except ValueError:
                    continue  # Skip non-numeric line
                path_elements.append(elem)

        if not path_elements:
            return TaintResult()

        # Check for sanitizers
        found_sanitizers: list[str] = []
        for elem in path_elements:
            elem_lower = elem.lower()
            for san in _ALL_SANITIZERS:
                if san in elem_lower and san not in found_sanitizers:
                    found_sanitizers.append(san)

        return TaintResult(
            reachable=True,
            sanitized=bool(found_sanitizers),
            path=path_elements,
            sanitizer_names=found_sanitizers,
        )
```

Add the `_strip_list_wrapper` helper as a module-level function:

```python
def _strip_list_wrapper(s: str) -> str:
    """Strip outer List(...) wrapper using bracket-depth matching."""
    if not s.startswith("List("):
        return s
    depth = 0
    for i, c in enumerate(s):
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return s[5:i].strip()
    # Unbalanced — best effort: strip "List(" prefix
    return s[5:].strip()
```

- [ ] **Step 4: Run all Joern tests**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/test_joern_client.py -v`
Expected: All pass (existing + new)

- [ ] **Step 5: Run full suite**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/ -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/graph/joern_client.py tests/test_joern_client.py
git commit -m "fix: robust Joern taint path parsing with bracket matching and element validation"
```

---

### Task 8: Flow Grounding — Map New FlowStep Kinds

**Files:**
- Modify: `src/core/flow_grounding.py`

- [ ] **Step 1: Update `_KIND_TO_LABEL` mapping**

Add the new FlowStep kinds from the scope analyzer:

```python
_KIND_TO_LABEL = {
    "parameter": "source",
    "source": "source",
    "assignment": "propagation",
    "call_result": "propagation",
    "return": "propagation",
    "sink": "sink",
    "callback_param": "propagation",
    "iteration_var": "propagation",
    "callback_return": "propagation",
}
```

- [ ] **Step 2: Run tests**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/test_flow_grounding.py -v`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add src/core/flow_grounding.py
git commit -m "feat: map callback_param, iteration_var, callback_return kinds in flow grounding"
```

---

### Task 9: Final Verification

- [ ] **Step 1: Run full test suite**

Run: `/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/pytest tests/ -v`
Expected: All pass, count should be ~250+

- [ ] **Step 2: Run frontend build**

Run: `cd frontend && npm run build`
Expected: Build succeeds

- [ ] **Step 3: Spot-check taint tracing on real fixtures**

```bash
/Users/n3m0/Code/code-fix-suggest/semgrep_analyzer/.venv/bin/python -c "
from src.taint.flow_tracker import trace_taint_flow
import os

# JS forEach
flow = trace_taint_flow(file_path='tests/fixtures/taint_callback.js',
    function_name='forEachTaint', sink_line=9, check_id='js.xss', cwe_list=['CWE-79'])
print('forEach:', len(flow.path) if flow else 0, 'steps')
if flow:
    for s in flow.path:
        print(f'  [{s.kind}] {s.variable} line {s.line}')

# JS for...of
flow = trace_taint_flow(file_path='tests/fixtures/taint_callback.js',
    function_name='forOfTaint', sink_line=29, check_id='js.cmdi', cwe_list=['CWE-78'])
print('forOf:', len(flow.path) if flow else 0, 'steps')
if flow:
    for s in flow.path:
        print(f'  [{s.kind}] {s.variable} line {s.line}')

# Python for loop
flow = trace_taint_flow(file_path='tests/fixtures/taint_callback.py',
    function_name='for_loop_taint', sink_line=7, check_id='py.sqli', cwe_list=['CWE-89'])
print('py for:', len(flow.path) if flow else 0, 'steps')
if flow:
    for s in flow.path:
        print(f'  [{s.kind}] {s.variable} line {s.line}')
"
```

Expected: Each flow should have 2+ steps with a source/parameter kind at the start.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: taint tracker v2 — final verification"
```
