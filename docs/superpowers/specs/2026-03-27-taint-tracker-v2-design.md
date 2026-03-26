# Taint Tracker v2: Scope-Tree Fixpoint Analysis + Joern Parser Fix

## Goal

Fix the two systemic issues discovered during grounded dataflow validation:
1. **Tree-sitter taint tracker** fails to trace sources for callback patterns (for...of, .forEach, .map), misses sanitizers in expression position, and only produces sink-only flows for 9/12 grounded findings
2. **Joern taint path parser** returns malformed entries (`List(`) due to brittle string parsing, producing 0 usable paths across 33 findings

## Problem

### Tree-sitter gaps (flow_tracker.py)

Current architecture: `_build_deps` walks assignments → `_trace_back` traces backward from sink. This misses:

- **Loop variable binding**: `for (const x of arr)` — `for_in_statement` not in `assignment_types`, so `x` never enters the dependency graph
- **Callback parameter binding**: `arr.forEach(x => sink(x))` — arrow function params inside call arguments are invisible to `_build_deps`
- **Nested scope taint propagation**: taint from parent scope doesn't flow into callback bodies; return values from callbacks don't flow back to caller
- **Sanitizers in expression position**: `escapeHtml(x)` inside template literals — the sanitizer call is found but the callee name extraction fails for method chains inside template substitutions

Validated against real repos: smallweb (5 findings with taint data, only 3 had source traced), kite-public (7 findings with taint data, 0 had source traced).

### Joern parser gaps (joern_client.py)

`_parse_taint_result` uses naive string slicing (`[5:-1]`) to strip `List(...)` wrapper and `split(", ")` to separate flow elements. This breaks when:
- Nested parens in code expressions (e.g., `List(req.body)` inside a flow element)
- Joern output format varies (different escaping, multiline)
- Empty or error output from CPGQL query

Result: 0/33 findings had usable Joern taint paths despite Joern reporting `taint_reachable=True` for 4 of them.

## Approach

**Two-pass scope-tree architecture** replacing the flat `_build_deps` + `_trace_back`:

- **Pass 1**: Walk AST, build a tree of scopes (functions, lambdas, loops) with per-scope dependency graphs
- **Pass 2**: Fixpoint iteration propagating taint across scope boundaries until stable

Plus a targeted fix for Joern's `_parse_taint_result`.

## Design

### 1. Scope Tree Data Model

**New file**: `src/taint/scope_analyzer.py`

```python
@dataclass
class DepEntry:
    deps: set[str]          # RHS identifiers
    line: int
    expr: str
    node: Node
    sanitizer: SanitizerInfo | None = None

@dataclass
class ReturnExpr:
    variables: set[str]     # identifiers in the return expression
    line: int
    expr: str

@dataclass
class CallSite:
    callee: str             # method name: "forEach", "map", "@@iterator"
    receiver_var: str       # collection variable: "arr" in arr.forEach(...)
    callback_scope: Scope   # nested scope passed as callback
    callback_param_index: int  # which callback param receives collection elements (usually 0)
    returns_value: bool     # True for map/filter/find/reduce, False for forEach

@dataclass
class Scope:
    node: Node
    kind: str               # "function" | "arrow" | "for_of" | "for_in" | "method" | "lambda"
    name: str               # function name or "" for anonymous
    params: set[str]
    deps: dict[str, list[DepEntry]]
    sanitizers: dict[str, list[SanitizerInfo]]
    unresolved_calls: list[str]
    children: list[Scope]
    call_sites: list[CallSite]
    return_exprs: list[ReturnExpr]
    parent: Scope | None = None
```

### 2. Pass 1 — Build Scope Tree

**Function**: `build_scope_tree(func_node: Node, config: LanguageConfig) -> Scope`

Walk the function AST depth-first. At each scope-creating node:

1. **Identify scope boundaries**: nodes in `config.func_types` + `config.iteration_types` create new child scopes
2. **Extract parameters**:
   - Functions/arrows: from `formal_parameters`
   - `for...of`/`for...in`: from the `left` field of `for_in_statement`
   - Destructuring: recursively extract all `identifier` nodes from patterns
3. **Build deps for this scope only**: walk `assignment_types` in the scope's body, stopping at child scope boundaries (don't recurse into nested functions/lambdas)
4. **Detect call sites**: when a call expression has a child scope as an argument, record the `CallSite` binding:
   - Check if the callee is a known callback method (from `config.callback_methods`)
   - Identify which argument position is the callback
   - Identify which parameter of the callback receives collection elements
5. **Collect return expressions**: `return` statements and implicit arrow returns (expression body)
6. **Detect sanitizers**: same as current — check calls in assignment RHS via `check_known_sanitizer`

**For `for...of`/`for...in` loops**: Model as a `CallSite` with `callee="@@iterator"`, `receiver_var` = the iterable expression's root identifier, `callback_scope` = the loop body scope, `callback_param_index=0`.

**For destructuring**: `for (const {key, value} of entries)` — extract `key` and `value` as parameters of the loop scope. Both are tainted if the iterable is tainted.

### 3. Pass 2 — Fixpoint Taint Propagation

**Function**: `propagate_taint(root: Scope, sink_vars: set[str], sink_line: int, config: LanguageConfig) -> TaintPath | None`

```
TaintState = dict[id(Scope), set[str]]  # tainted variables per scope

Algorithm:
1. Initialize:
   - Root scope params matching config.dangerous_sources → tainted
   - ALL root scope params → potential sources (for parameter-to-sink tracing)

2. Repeat until TaintState is stable:
   For each scope in tree (top-down breadth-first):
     For each CallSite in scope:
       a. If receiver_var is tainted in this scope:
          → Add callback_scope.params[callback_param_index] to callback_scope's tainted set
       b. Analyze callback_scope:
          → Run step 2 recursively for callback_scope
       c. If callback.returns_value:
          → Check if any of callback_scope.return_exprs reference tainted vars
          → If yes, mark the call-result variable in parent scope as tainted
     For each dep assignment in scope:
       → If any RHS identifier is tainted, mark LHS as tainted
       → If assignment goes through a sanitizer, mark as CLEAN (taint stops)

3. After fixpoint: backward-trace from sink_vars to build the TaintFlow path
```

**Convergence**: taint set only grows (monotone), finite variables per scope, cycle detection via scope identity. Worst case: O(scopes * variables) iterations.

**Sanitizer handling in callbacks**: If `.map(x => escapeHtml(x))` — the callback scope has a sanitizer on the return path. The return expression references a sanitized variable, so taint does NOT propagate back to the caller. This is the key advantage over flat analysis.

### 4. Path Collection

After fixpoint, build the `TaintFlow` by replaying the trace:

1. Start from sink variable at sink_line
2. Walk backward through deps to find which assignment tainted it
3. If the source is a callback parameter, include a cross-scope step: `[CALLBACK] arr.forEach(x => ...) at line N`
4. Continue tracing in the parent scope (where the collection variable was tainted)
5. Repeat until reaching a root parameter or dangerous source

Each step becomes a `FlowStep(variable, line, expression, kind)` where kind includes the new values:
- `"callback_param"` — callback parameter seeded from collection
- `"iteration_var"` — for...of loop variable
- `"callback_return"` — return value flowing back to caller

### 5. Integration with flow_tracker.py

**Replace** `trace_taint_flow()` internals:

```python
def trace_taint_flow(*, file_path, function_name, sink_line, check_id, cwe_list):
    # Same: find function node, get config
    config = _reader.get_config(ext)
    root = _reader.parse_file(file_path)
    func_node = _find_function_node(root, function_name, config)

    # NEW: build scope tree instead of flat deps
    scope_tree = build_scope_tree(func_node, config)

    # NEW: find sink variables (same logic as current _find_vars_at_line)
    sink_vars = _find_vars_at_line(func_node, sink_line, config)

    # NEW: fixpoint propagation
    path = propagate_taint(scope_tree, sink_vars, sink_line, config)

    # Same: build TaintFlow from path, attach sanitizers, inferred sink/source
    ...
```

Public API unchanged. `Enricher`, `flow_grounding.py`, `prompt_builder.py` all consume the same `TaintFlow` object.

### 6. LanguageConfig Updates

**New fields** added to `LanguageConfig` dataclass:

```python
iteration_types: tuple[str, ...] = ()      # AST node types for loops that bind variables
callback_methods: tuple[str, ...] = ()     # method names that pass collection elements to callbacks
callback_returns_value: frozenset[str] = frozenset()  # subset of callback_methods where return value matters
```

**JS/TS config additions**:
```python
iteration_types=("for_in_statement",),
callback_methods=("forEach", "map", "filter", "find", "some", "every", "reduce", "flatMap", "sort", "replace"),
callback_returns_value=frozenset({"map", "filter", "find", "reduce", "flatMap", "sort"}),
```

**Python config additions**:
```python
iteration_types=("for_statement",),
callback_methods=("map", "filter", "sorted", "min", "max"),
callback_returns_value=frozenset({"map", "filter", "sorted", "min", "max"}),
```

**Java config additions**:
```python
iteration_types=("enhanced_for_statement",),
callback_methods=("forEach", "map", "filter", "flatMap", "collect", "reduce", "sorted", "peek"),
callback_returns_value=frozenset({"map", "filter", "flatMap", "collect", "reduce", "sorted"}),
```

**Go config additions**:
```python
iteration_types=("for_range_clause",),
callback_methods=(),  # Go doesn't use callback iteration
callback_returns_value=frozenset(),
```

Other languages: add iteration_types where applicable, callback_methods=() by default.

### 7. Sanitizer Checker Improvements

In `sanitizer_checker.py`, add to the CWE-79 (XSS) list:
- `escape` (generic)
- `encodeURI`
- `parseInt` (type coercion — numeric output can't inject HTML)
- `Number` (same)

Verify the callee name extraction works for calls inside template literal substitutions. The current `_find_calls` + `_get_callee_name` should work since `template_substitution` children are yielded by `_walk`, but need a test to confirm.

### 8. Joern Parser Fix

In `joern_client.py:_parse_taint_result`:

**Replace** the naive `List()` stripping and splitting with:

```python
def _parse_taint_result(self, raw: str) -> TaintResult:
    # ... existing: strip ANSI, find result_line, check for errors ...

    # Strip List() wrapper with proper bracket matching
    inner = _strip_list_wrapper(result_line)
    if not inner:
        return TaintResult()

    # Split flow strings (handling nested quotes/parens)
    flow_strings = _split_flow_strings(inner)

    # Parse each flow into path elements, validating format
    path_elements = []
    for flow in flow_strings:
        for elem in flow.split(" -> "):
            elem = elem.strip()
            parts = elem.split(":", 2)
            # Validate: must have file:line:code with numeric line
            if len(parts) >= 2:
                try:
                    int(parts[1])
                    path_elements.append(elem)
                except ValueError:
                    continue  # skip malformed

    if not path_elements:
        return TaintResult()

    # ... existing: detect sanitizers, build result ...
```

**`_strip_list_wrapper`**: Use bracket-depth counting instead of `[5:-1]`:
```python
def _strip_list_wrapper(s: str) -> str:
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
    return s[5:].strip()  # unbalanced — best effort
```

### 9. Backward Compatibility

- `trace_taint_flow()` public API unchanged — same inputs, same `TaintFlow` output
- `LanguageConfig` new fields have defaults (`iteration_types=()`, `callback_methods=()`) — existing configs work without changes, just miss the new patterns
- `FlowStep.kind` gains new values (`callback_param`, `iteration_var`, `callback_return`) — `flow_grounding.py` maps all unknown kinds to `"propagation"`, so frontend rendering is safe
- Joern parser fix only affects internal parsing — `TaintResult` schema unchanged

## Files Changed

| File | Change |
|---|---|
| `src/taint/scope_analyzer.py` | **NEW** — Scope tree builder + fixpoint propagation |
| `src/taint/flow_tracker.py` | Replace internals with scope_analyzer calls |
| `src/taint/sanitizer_checker.py` | Add sanitizer names |
| `src/code_reader/tree_sitter_reader.py` | Add iteration_types, callback_methods to LanguageConfig + per-language configs |
| `src/graph/joern_client.py` | Fix `_parse_taint_result` parser |
| `src/core/flow_grounding.py` | Map new FlowStep kinds to labels |

## Testing

- **Unit**: `tests/test_scope_analyzer.py` — scope tree building for JS/TS/Python, callback binding, for...of, destructuring
- **Unit**: `tests/test_flow_tracker.py` — existing tests must pass + new tests for callback taint propagation, loop variable tracing, sanitizer in callback return
- **Unit**: `tests/test_joern_client.py` — malformed List() output, nested parens, empty output, valid paths
- **Integration**: Re-run against smallweb and kite-public findings, verify previously-sink-only flows now have sources

## Implementation Constraint: Documentation-First

Every implementation step MUST look up current documentation via context7:
- tree-sitter node types for each language (for_in_statement fields, arrow_function fields, template_substitution)
- Pydantic v2 for any model changes
- tree-sitter Python bindings for AST traversal APIs

## Success Criteria

Against the 12 grounded findings from validation:
- **Before**: 3/12 had complete source→sink traces
- **Target**: 10/12 should have complete traces (the 2 config findings will remain sink-only)
- Joern paths: at least the 4 `taint_reachable=True` findings should have parseable paths
