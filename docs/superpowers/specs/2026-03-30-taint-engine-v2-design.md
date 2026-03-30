# Taint Engine v2: Decoupled Module with Rules and Hardened Tracing

## Goal

Rebuild the taint tracing engine as a decoupled subpackage (`src/taint/`) with:
1. A JSON rule system for defining sources, sinks, sanitizers, and guards per language
2. Reaching-definitions-based tracing that replaces the current flat dependency graph
3. Clean module boundary — own models, protocol-based parser injection, no imports from `src/code_reader` or `src/models`

## Context

### Current state

The taint module at `src/taint/` has 4 files (~750 lines total). It traces data flow backwards from a sink through a variable dependency graph built by `_build_deps`. It's tightly coupled to `src/code_reader/tree_sitter_reader.py` (imports `TreeSitterReader`, `LanguageConfig`) and `src/models/analysis.py` (imports `FlowStep`, `SanitizerInfo`, `TaintFlow`, `InferredSinkSource`).

### Diagnosed gaps (from research)

Testing against 16 real findings in `/Users/n3m0/Code/smallweb` and comparing with Semgrep, CodeQL, and Joern architectures revealed:

| Gap | Impact | Example |
|-----|--------|---------|
| No kill semantics on reassignment | Wrong traces | `x = safe; x = tainted; sink(x)` — tracer reports both defs instead of only `tainted` |
| No branch-aware merging | Missing branch info | `if c: x = a; else: x = b; sink(x)` — no way to distinguish branch sources |
| Traces stop at unknown calls | False "no source" signals | `y = helper(tainted); sink(y)` — tracer reports "no external source" |
| No guard detection | Missed FP signals | `if not validate(x): return; sink(x)` — guard not reported |
| Hardcoded source/sink/sanitizer databases | Not extensible, not per-language | Adding a sink requires code changes in `LanguageConfig` and `sanitizer_checker.py` |
| No access path tracking | Imprecise field taint | `obj.safe = 1; obj.bad = tainted; sink(obj.safe)` — can't distinguish fields |
| No string operation propagation | Missed taint through formatting | `x = f"prefix {tainted}"` — result not recognized as tainted |
| Tight coupling to TreeSitterReader | Can't be extracted or tested independently | Module-level `_reader = TreeSitterReader()` singleton |

### Prior art informing the design

- **Semgrep**: Builds per-function CFG from AST, runs reaching definitions. Taint rules are declarative YAML with pattern-sources/sinks/sanitizers. Intraprocedural in OSS.
- **CodeQL**: SSA form, demand-driven global flow, barrier guards as first-class concept. Sources/sinks/barriers as logic predicates.
- **Joern**: CPG (AST+CFG+PDG merged), `reachableBy` over data-dependence edges. Custom flow semantics for modeling how data passes through functions.
- **weggli/ast-grep**: Name-based matching on tree-sitter ASTs. No data flow, but demonstrates that tree-sitter + structural matching is sufficient for source/sink identification.

---

## Design

### 1. Module Boundary

**`src/taint/` owns:**
- All taint data models (`FlowStep`, `SanitizerInfo`, `TaintFlow`, `InferredSinkSource`, `CrossFileHop`, `AccessPath`)
- Rule loading and matching
- The tracing engine (reaching definitions, taint propagation)
- Sanitizer and guard detection

**`src/taint/` does NOT import from:**
- `src/code_reader/` — instead accepts a `Parser` protocol
- `src/models/` — instead defines its own models
- `src/llm/` — no dependency
- `src/graph/` — `cross_file.py` accepts a gkg client as a parameter (duck-typed)

**Backward compatibility:**
- `src/models/analysis.py` re-exports taint models: `from src.taint.models import FlowStep, SanitizerInfo, TaintFlow, InferredSinkSource, CrossFileHop`
- Existing consumers continue to import from `src.models.analysis` unchanged

**Parser protocol (`src/taint/parser_protocol.py`):**

```python
class ASTNode(Protocol):
    @property
    def type(self) -> str: ...
    @property
    def start_point(self) -> tuple[int, int]: ...
    @property
    def end_point(self) -> tuple[int, int]: ...
    @property
    def text(self) -> bytes: ...
    @property
    def children(self) -> list["ASTNode"]: ...
    @property
    def parent(self) -> "ASTNode | None": ...
    def child_by_field_name(self, name: str) -> "ASTNode | None": ...

class LanguageGrammar(Protocol):
    func_types: tuple[str, ...]
    call_types: tuple[str, ...]
    assignment_types: tuple[str, ...]
    parameter_types: tuple[str, ...]
    return_types: tuple[str, ...]
    conditional_types: tuple[str, ...]
    member_access_types: tuple[str, ...]
    has_arrow_functions: bool

class Parser(Protocol):
    def parse_file(self, path: str) -> ASTNode: ...
    def get_grammar(self, extension: str) -> LanguageGrammar | None: ...
```

The existing `TreeSitterReader` + `LanguageConfig` already satisfy these protocols. The enricher wraps them in a trivial adapter.

### 2. JSON Rule System

**Rule file format** (one per language, at `src/taint/rules/<language>.json`):

```json
{
  "language": "javascript",
  "extensions": [".js", ".jsx", ".ts", ".tsx"],
  "sources": [
    "req.body", "req.query", "req.params",
    "document.location", "window.location",
    "process.env"
  ],
  "sinks": {
    "call": ["eval", "setTimeout", "document.write", "document.writeln"],
    "property": ["innerHTML", "outerHTML", "srcdoc", "href", "src", "action", "cssText", "location"]
  },
  "sanitizers": [
    { "name": "escapeHtml", "neutralizes": ["CWE-79"] },
    { "name": "encodeURI", "neutralizes": ["CWE-79"] },
    { "name": "parseInt", "neutralizes": ["CWE-89", "CWE-79"] },
    { "name": "DOMPurify.sanitize", "neutralizes": ["CWE-79"] }
  ],
  "guards": [
    "re.match", "re.fullmatch", "isinstance", "hasattr"
  ]
}
```

**Field definitions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `language` | string | yes | Human-readable language name |
| `extensions` | string[] | yes | File extensions this rule applies to |
| `sources` | string[] | yes | Dotted names of taint sources (e.g., `request.args.get`). The engine checks if a variable originates from one of these. |
| `sinks.call` | string[] | no | Function names where passing tainted args is dangerous. Matched against call expressions. |
| `sinks.property` | string[] | no | Property names where assignment is dangerous (`obj.<property> = tainted`). Matched against member-access assignment LHS. |
| `sanitizers` | object[] | no | Functions that neutralize taint. Each has `name` (string, required) and `neutralizes` (string[] of CWE IDs, optional — defaults to all CWEs). |
| `guards` | string[] | no | Function names that, when used in a conditional before the sink, restrict tainted values. |

**Loading API:**

```python
def load_rules(path: str) -> TaintRuleSet:
    """Load rules from a directory of JSON files or a single JSON file.
    
    If path is a directory, loads all *.json files and merges by extension.
    If path is a file, loads that single file.
    Returns a TaintRuleSet that can be queried by file extension.
    """
```

```python
@dataclass(frozen=True)
class TaintRuleSet:
    """Merged rules queryable by file extension."""
    
    def for_extension(self, ext: str) -> LanguageRules | None:
        """Get rules for a file extension (e.g., '.js')."""
    
    def is_source(self, ext: str, dotted_name: str) -> bool:
        """Check if a dotted name is a known source for this language."""
    
    def is_call_sink(self, ext: str, callee: str) -> bool:
        """Check if a callee is a known call sink."""
    
    def is_property_sink(self, ext: str, property_name: str) -> bool:
        """Check if a property name is a known assignment sink."""
    
    def check_sanitizer(self, ext: str, callee: str) -> SanitizerInfo | None:
        """Check if a callee is a known sanitizer. Returns info or None."""
    
    def is_guard(self, ext: str, callee: str) -> bool:
        """Check if a callee is a known guard function."""
```

**What this replaces:**
- `_SANITIZER_DB` and `_SANITIZER_LOOKUP` in `sanitizer_checker.py` → `rules.check_sanitizer()`
- `LanguageConfig.dangerous_sources` → `rules.is_source()`
- `LanguageConfig.dangerous_sinks` → `rules.is_property_sink()`
- New: `rules.is_call_sink()` for call-expression sinks
- New: `rules.is_guard()` for guard detection

### 3. Tracing Engine (`src/taint/engine.py`)

Replaces `flow_tracker.py` with a reaching-definitions-based approach.

#### 3.1 Core data structures

```python
@dataclass
class Definition:
    """A single assignment/definition of a variable."""
    variable: str          # or AccessPath for field tracking
    line: int
    expression: str        # source text
    node: ASTNode
    deps: set[str]         # variables this definition reads from
    branch_context: str    # "" (unconditional), "if_true", "if_false", "loop"

@dataclass  
class ActiveDefs:
    """Currently active definitions per variable — the state during analysis."""
    defs: dict[str, set[Definition]]
    
    def define(self, var: str, defn: Definition) -> None:
        """Kill prior defs, add new one."""
        self.defs[var] = {defn}
    
    def fork(self) -> "ActiveDefs":
        """Snapshot for branch entry."""
        return ActiveDefs({k: set(v) for k, v in self.defs.items()})
    
    def merge(self, other: "ActiveDefs") -> None:
        """Merge at branch join — union of definitions."""
        for var, other_defs in other.defs.items():
            self.defs.setdefault(var, set()).update(other_defs)
    
    def reaching(self, var: str) -> set[Definition]:
        """Which definitions of var are currently active?"""
        return self.defs.get(var, set())
```

#### 3.2 Analysis algorithm

```
function analyze(func_node, grammar, rules, ext):
    params = extract_parameters(func_node, grammar)
    active = ActiveDefs()
    
    # Initialize: parameters are definitions from "outside"
    for p in params:
        active.define(p, Definition(variable=p, kind="parameter", ...))
    
    # Walk the function body, building reaching definitions
    walk_body(func_node.body, grammar, rules, ext, active)
    
    # At the sink line, look up which definitions reach the sink variables
    sink_vars = find_vars_at_line(func_node, sink_line, grammar, rules, ext)
    
    # Trace backwards through the reaching definitions
    for var in sink_vars:
        path = trace_back(var, active, params, rules, ext)
        if path:
            return build_taint_flow(path, ...)
```

The `walk_body` function handles control flow:

```
function walk_body(stmts, grammar, rules, ext, active):
    for stmt in stmts:
        match stmt.type:
            case assignment:
                lhs, rhs = extract_assignment(stmt)
                deps = collect_reads(rhs)
                defn = Definition(variable=lhs, deps=deps, ...)
                
                # Check sanitizer on RHS calls
                for call in find_calls(rhs):
                    if rules.check_sanitizer(ext, callee_name(call)):
                        record_sanitizer(...)
                
                active.define(lhs, defn)
            
            case if_statement:
                condition = stmt.condition
                true_branch = stmt.true_body
                false_branch = stmt.false_body  # may be None
                
                # Check if condition is a guard
                for call in find_calls(condition):
                    if rules.is_guard(ext, callee_name(call)):
                        record_guard(call, ...)
                
                saved = active.fork()
                walk_body(true_branch, ..., active)    # mutates active
                true_state = active
                active = saved                          # restore
                if false_branch:
                    walk_body(false_branch, ..., active)
                active.merge(true_state)                # join
            
            case for/while_loop:
                # Walk body twice for fixpoint (handles loop-carried deps)
                snapshot = active.fork()
                walk_body(loop_body, ..., active)
                walk_body(loop_body, ..., active)  # second pass for convergence
                active.merge(snapshot)  # loop might not execute
            
            case call_expression:
                # Standalone call (not RHS of assignment)
                # Check for side-effect sources: e.g., list.append(tainted)
                ...
            
            case return_statement:
                # Record return as a potential sink point
                ...
```

#### 3.3 Taint propagation through unknown calls (item 3a)

When `_trace_back` encounters a definition like `y = f(x)` where `f` is not a known sanitizer:

- **Old behavior**: stop, report `f` as unresolved, trace ends
- **New behavior**: trace into `f`'s arguments. If any argument traces back to a tainted source, `y` is tainted. Record `f` in `unresolved_calls` and add confidence factor "Taint propagates through unresolved call f()".

This matches Semgrep/CodeQL/Joern's default behavior: unknown functions propagate taint from arguments to return.

#### 3.4 Guard detection (item 3b)

During `walk_body`, when processing `if_statement` nodes, check if the condition calls a known guard function (from `rules.guards`). If a tainted variable appears as an argument to the guard:

```python
# Example: if re.match(r"^[a-z]+$", user_input): ...
# The guard restricts user_input's domain
```

Record a `GuardInfo` (new dataclass in models.py):

```python
@dataclass
class GuardInfo:
    name: str       # e.g., "re.match"
    line: int
    variable: str   # which tainted variable is being checked
```

Guards are reported in `TaintFlow.guards` (new field) and rendered in prompts. The orchestrator's evidence scoring can use them: a guard between source and sink is a moderate FP signal.

#### 3.5 Access path tracking (item 3g)

Replace flat `str` variable names with `AccessPath`:

```python
@dataclass(frozen=True)
class AccessPath:
    base: str                    # e.g., "obj"
    selectors: tuple[str, ...]   # e.g., ("field",) for obj.field
    
    @property
    def name(self) -> str:
        """Dotted string representation."""
        if self.selectors:
            return f"{self.base}.{'.'.join(self.selectors)}"
        return self.base
    
    def with_field(self, field: str) -> "AccessPath":
        """Extend by one field, capped at depth 2."""
        if len(self.selectors) >= 2:
            return self  # don't extend beyond depth 2
        return AccessPath(self.base, self.selectors + (field,))
```

Tracking rules:
- `obj.field = tainted` → define `AccessPath("obj", ("field",))` as tainted
- `sink(obj.field)` → look up `AccessPath("obj", ("field",))`
- `obj.field = tainted; sink(obj.other)` → no match, no taint
- `list.append(tainted)` → define `AccessPath("list", ())` as tainted (whole-container approximation)
- Depth cap at 2 selectors to prevent explosion

#### 3.6 String operation propagation (item 3h)

In `collect_reads`, when the RHS is:
- **f-string / template literal**: collect all identifiers from interpolated expressions
- **String concatenation** (`+` with string operands): collect identifiers from both sides
- **Format call** (`.format()`, `%`): collect identifiers from arguments

If any collected identifier is tainted, the assigned variable is tainted. This is standard across all tools.

Implementation: in the AST walker, recognize these node types per language:
- Python: `formatted_string`, `binary_operator` with `+`, `call` on `.format()`
- JS/TS: `template_string`, `binary_expression` with `+`
- Go: `fmt.Sprintf` calls (handled by call propagation)
- Java: string `+` operator, `String.format` calls

### 4. File Structure

```
src/taint/
├── __init__.py              # Public API re-exports
├── models.py                # FlowStep, SanitizerInfo, TaintFlow, GuardInfo, AccessPath, etc.
├── rules.py                 # load_rules(), TaintRuleSet, LanguageRules
├── engine.py                # Reaching defs, taint propagation, trace_taint_flow()
├── parser_protocol.py       # ASTNode, LanguageGrammar, Parser protocols
├── sanitizer_checker.py     # Rewritten: delegates to TaintRuleSet, keeps is_conditional_ancestor
├── sink_source_inference.py # Minimal changes: uses rules for source/sink matching
├── cross_file.py            # Minimal changes: updated model imports
└── rules/
    ├── python.json
    ├── javascript.json
    ├── go.json
    ├── java.json
    └── php.json
```

**Line budget estimates:**

| File | Estimated lines | Notes |
|------|----------------|-------|
| `models.py` | ~180 | Moved from analysis.py + AccessPath + GuardInfo |
| `rules.py` | ~120 | Rule loading, merging, lookup |
| `engine.py` | ~400 | Reaching defs, walk_body, trace_back, find_vars_at_line |
| `parser_protocol.py` | ~40 | Protocol definitions |
| `sanitizer_checker.py` | ~40 | Thin wrapper around rules |
| `sink_source_inference.py` | ~80 | Mostly unchanged |
| `cross_file.py` | ~100 | Mostly unchanged |
| Rule JSONs | ~50 each | 5 languages |

Total: ~1200 lines (up from ~750, but replacing hardcoded data in `tree_sitter_reader.py` and `sanitizer_checker.py`).

### 5. Consumer Changes

#### `src/core/enricher.py`

```python
# Before:
from src.taint.flow_tracker import trace_taint_flow

# After:
from src.taint import trace_taint_flow, load_rules

class Enricher:
    def __init__(self, reader, ...):
        self._parser = _TreeSitterAdapter(reader)
        self._rules = load_rules("src/taint/rules/")
    
    async def enrich(self, finding, ...):
        ...
        flow = trace_taint_flow(
            file_path=..., function_name=..., sink_line=...,
            check_id=..., cwe_list=...,
            rules=self._rules, parser=self._parser,
        )
```

#### `src/models/analysis.py`

Taint dataclasses removed. Replaced with re-exports:

```python
# Backward compatibility
from src.taint.models import (
    FlowStep, SanitizerInfo, TaintFlow, 
    InferredSinkSource, CrossFileHop,
)
```

Non-taint models (`SemgrepFinding`, `FindingContext`, `AnalysisResult`, etc.) remain in `analysis.py`.

#### `src/code_reader/tree_sitter_reader.py`

Remove taint-specific fields from `LanguageConfig`:
- `dangerous_sources` → moved to JSON rules
- `dangerous_sinks` → moved to JSON rules

Keep AST-structural fields: `func_types`, `call_types`, `assignment_types`, `parameter_types`, `return_types`, `conditional_types`, `member_access_types`, `has_arrow_functions`. These describe grammar structure, not security semantics.

Remove `_JS_TAINT_FIELDS` shared dict (no longer needed — taint config is in JSON rules). The JS/TS/JSX/TSX entries shrink significantly.

#### `src/core/orchestrator.py` and `src/llm/prompt_builder.py`

Import path changes only (or no changes if using backward-compat re-exports from `src/models/analysis.py`). Prompt builder renders the new `guards` field if present.

### 6. Testing Strategy

- **Unit tests for `engine.py`**: Test each tracing capability against fixture files:
  - Straight-line taint: param → assignment → sink
  - Kill semantics: reassignment kills prior def
  - Branch merging: if/else with different assignments
  - Loop handling: taint through loop body
  - Unknown call propagation: taint through `helper(tainted)`
  - Guard detection: conditional check before sink
  - Access paths: `obj.field` tracking
  - String propagation: f-strings, concatenation, template literals
  - Multi-line call range matching (existing test, migrated)
  - Assignment-based sinks: innerHTML, href (existing test, migrated)

- **Unit tests for `rules.py`**: Load, merge, lookup, invalid JSON handling

- **Integration tests**: Enricher → engine → prompt builder pipeline with mocked parser

- **Regression**: All existing tests must continue to pass (via backward-compat re-exports)

### 7. Migration Path

The work can be done incrementally:

1. **Phase 1**: Create `models.py`, `parser_protocol.py`, `rules.py`, rule JSON files. Add backward-compat re-exports. No behavior change.
2. **Phase 2**: Build `engine.py` with reaching definitions. Keep `flow_tracker.py` alongside. Add feature flag or parallel execution for comparison.
3. **Phase 3**: Wire `engine.py` into enricher, replacing `flow_tracker.py`. Update `sanitizer_checker.py` to use rules.
4. **Phase 4**: Remove `flow_tracker.py`, remove taint fields from `LanguageConfig`, clean up.

Each phase is independently deployable and testable.
