"""tree-sitter based code reader for single-file AST analysis."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import tree_sitter_python as ts_python
import tree_sitter_javascript as ts_javascript
import tree_sitter_java as ts_java
import tree_sitter_go as ts_go
import tree_sitter_php as ts_php
import tree_sitter_ruby as ts_ruby
from tree_sitter_typescript import language_typescript, language_tsx
from tree_sitter import Language, Parser, Node

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Language registry — single source of truth for all language-specific behavior.
#
# Adding a new language = one LanguageConfig entry + optional lazy import.
# No scattered if/elif branches needed.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LanguageConfig:
    """Everything the reader needs to handle one language."""

    func_types: list[str]  # AST node types for functions/methods
    call_types: list[str] = field(default_factory=lambda: ["call_expression"])
    import_type: str = ""  # top-level import node type
    import_source_field: str = ""  # field name for import source string
    import_style: str = "none"  # "python", "js", "ruby", "rust", "go", "java", "none"
    has_arrow_functions: bool = False  # needs parent variable_declarator lookup
    lazy_module: str = ""  # module to import lazily (empty = already imported)
    lazy_func: str = "language"  # function name on the module
    # Taint-specific fields (empty = language does not support flow tracking)
    assignment_types: tuple[str, ...] = ()
    parameter_types: tuple[str, ...] = ()
    return_types: tuple[str, ...] = ()
    conditional_types: tuple[str, ...] = ()
    dangerous_sources: tuple[str, ...] = ()
    # Member-access assignment sink detection
    member_access_types: tuple[
        str, ...
    ] = ()  # AST node types for property access on LHS
    dangerous_sinks: tuple[str, ...] = ()  # Property names that are security sinks


# Core languages (always imported)
_LANG_REGISTRY: dict[str, tuple[object, LanguageConfig]] = {
    ".py": (
        ts_python,
        LanguageConfig(
            func_types=["function_definition"],
            call_types=["call"],
            import_style="python",
            assignment_types=("assignment", "augmented_assignment"),
            parameter_types=("parameters",),
            return_types=("return_statement",),
            conditional_types=(
                "if_statement",
                "try_statement",
                "elif_clause",
                "else_clause",
            ),
            dangerous_sources=(
                "request.args",
                "request.form",
                "request.json",
                "request.data",
                "os.environ",
                "sys.argv",
                "input()",
                "request.GET",
                "request.POST",
            ),
            member_access_types=("attribute",),
            dangerous_sinks=(
                "data",
                "content",
            ),
        ),
    ),
    ".js": (
        ts_javascript,
        LanguageConfig(
            func_types=["function_declaration", "arrow_function", "method_definition"],
            call_types=["call_expression"],
            import_style="js",
            has_arrow_functions=True,
            assignment_types=(
                "assignment_expression",
                "variable_declarator",
                "augmented_assignment_expression",
            ),
            parameter_types=("formal_parameters",),
            return_types=("return_statement",),
            conditional_types=(
                "if_statement",
                "try_statement",
                "switch_statement",
                "ternary_expression",
            ),
            dangerous_sources=(
                "req.body",
                "req.query",
                "req.params",
                "req.headers",
                "document.location",
                "window.location",
                "process.env",
            ),
            member_access_types=("member_expression",),
            dangerous_sinks=(
                "innerHTML",
                "outerHTML",
                "srcdoc",
                "src",
                "href",
                "action",
                "formAction",
                "onclick",
                "onerror",
                "onload",
                "onmouseover",
                "onfocus",
                "onblur",
                "onsubmit",
                "onchange",
                "onkeydown",
                "onkeyup",
                "onkeypress",
                "cssText",
                "data",
                "codebase",
                "location",
            ),
        ),
    ),
    ".jsx": (
        ts_javascript,
        LanguageConfig(
            func_types=["function_declaration", "arrow_function", "method_definition"],
            call_types=["call_expression"],
            import_style="js",
            has_arrow_functions=True,
            assignment_types=(
                "assignment_expression",
                "variable_declarator",
                "augmented_assignment_expression",
            ),
            parameter_types=("formal_parameters",),
            return_types=("return_statement",),
            conditional_types=(
                "if_statement",
                "try_statement",
                "switch_statement",
                "ternary_expression",
            ),
            dangerous_sources=(
                "req.body",
                "req.query",
                "req.params",
                "req.headers",
                "document.location",
                "window.location",
                "process.env",
            ),
            member_access_types=("member_expression",),
            dangerous_sinks=(
                "innerHTML",
                "outerHTML",
                "srcdoc",
                "src",
                "href",
                "action",
                "formAction",
                "onclick",
                "onerror",
                "onload",
                "onmouseover",
                "onfocus",
                "onblur",
                "onsubmit",
                "onchange",
                "onkeydown",
                "onkeyup",
                "onkeypress",
                "cssText",
                "data",
                "codebase",
                "location",
            ),
        ),
    ),
    ".ts": (
        language_typescript,
        LanguageConfig(
            func_types=["function_declaration", "arrow_function", "method_definition"],
            call_types=["call_expression"],
            import_style="js",
            has_arrow_functions=True,
            assignment_types=(
                "assignment_expression",
                "variable_declarator",
                "augmented_assignment_expression",
            ),
            parameter_types=("formal_parameters",),
            return_types=("return_statement",),
            conditional_types=(
                "if_statement",
                "try_statement",
                "switch_statement",
                "ternary_expression",
            ),
            dangerous_sources=(
                "req.body",
                "req.query",
                "req.params",
                "req.headers",
                "document.location",
                "window.location",
                "process.env",
            ),
            member_access_types=("member_expression",),
            dangerous_sinks=(
                "innerHTML",
                "outerHTML",
                "srcdoc",
                "src",
                "href",
                "action",
                "formAction",
                "onclick",
                "onerror",
                "onload",
                "onmouseover",
                "onfocus",
                "onblur",
                "onsubmit",
                "onchange",
                "onkeydown",
                "onkeyup",
                "onkeypress",
                "cssText",
                "data",
                "codebase",
                "location",
            ),
        ),
    ),
    ".tsx": (
        language_tsx,
        LanguageConfig(
            func_types=["function_declaration", "arrow_function", "method_definition"],
            call_types=["call_expression"],
            import_style="js",
            has_arrow_functions=True,
            assignment_types=(
                "assignment_expression",
                "variable_declarator",
                "augmented_assignment_expression",
            ),
            parameter_types=("formal_parameters",),
            return_types=("return_statement",),
            conditional_types=(
                "if_statement",
                "try_statement",
                "switch_statement",
                "ternary_expression",
            ),
            dangerous_sources=(
                "req.body",
                "req.query",
                "req.params",
                "req.headers",
                "document.location",
                "window.location",
                "process.env",
            ),
            member_access_types=("member_expression",),
            dangerous_sinks=(
                "innerHTML",
                "outerHTML",
                "srcdoc",
                "src",
                "href",
                "action",
                "formAction",
                "onclick",
                "onerror",
                "onload",
                "onmouseover",
                "onfocus",
                "onblur",
                "onsubmit",
                "onchange",
                "onkeydown",
                "onkeyup",
                "onkeypress",
                "cssText",
                "data",
                "codebase",
                "location",
            ),
        ),
    ),
    ".go": (
        ts_go,
        LanguageConfig(
            func_types=["function_declaration", "method_declaration"],
            call_types=["call_expression"],
            import_style="go",
            assignment_types=("short_var_declaration", "assignment_statement"),
            parameter_types=("parameter_list",),
            return_types=("return_statement",),
            conditional_types=("if_statement", "switch_statement"),
            dangerous_sources=(
                "r.URL.Query",
                "r.FormValue",
                "r.Body",
                "os.Getenv",
                "os.Args",
            ),
            member_access_types=("selector_expression",),
            dangerous_sinks=(),
        ),
    ),
    ".java": (
        ts_java,
        LanguageConfig(
            func_types=["method_declaration", "constructor_declaration"],
            call_types=["call_expression"],
            import_style="java",
            assignment_types=(
                "assignment_expression",
                "variable_declarator",
                "local_variable_declaration",
            ),
            parameter_types=("formal_parameters",),
            return_types=("return_statement",),
            conditional_types=("if_statement", "try_statement", "switch_expression"),
            dangerous_sources=(
                "request.getParameter",
                "request.getAttribute",
                "request.getHeader",
                "System.getenv",
                "System.getProperty",
            ),
            member_access_types=("field_access",),
            dangerous_sinks=(),
        ),
    ),
    ".php": (
        ts_php,
        LanguageConfig(
            func_types=["function_definition", "method_declaration"],
            call_types=["function_call_expression", "member_call_expression"],
            import_style="none",
        ),
    ),
    ".rb": (
        ts_ruby,
        LanguageConfig(
            func_types=["method", "singleton_method"],
            call_types=["call", "method_call"],
            import_style="ruby",
        ),
    ),
}

# Optional languages (lazy-imported on first use to avoid hard dependency)
_OPTIONAL_REGISTRY: dict[str, LanguageConfig] = {
    ".rs": LanguageConfig(
        func_types=["function_item"],
        call_types=["call_expression"],
        import_style="rust",
        lazy_module="tree_sitter_rust",
    ),
    ".c": LanguageConfig(
        func_types=["function_definition"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_c",
    ),
    ".h": LanguageConfig(
        func_types=["function_definition"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_c",
    ),
    ".cpp": LanguageConfig(
        func_types=["function_definition"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_cpp",
    ),
    ".cc": LanguageConfig(
        func_types=["function_definition"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_cpp",
    ),
    ".cxx": LanguageConfig(
        func_types=["function_definition"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_cpp",
    ),
    ".hpp": LanguageConfig(
        func_types=["function_definition"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_cpp",
    ),
    ".cs": LanguageConfig(
        func_types=["method_declaration", "constructor_declaration"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_c_sharp",
    ),
    ".kt": LanguageConfig(
        func_types=["function_declaration"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_kotlin",
    ),
    ".kts": LanguageConfig(
        func_types=["function_declaration"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_kotlin",
    ),
    ".scala": LanguageConfig(
        func_types=["function_definition"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_scala",
    ),
    ".sc": LanguageConfig(
        func_types=["function_definition"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_scala",
    ),
    ".swift": LanguageConfig(
        func_types=["function_declaration"],
        call_types=["call_expression"],
        lazy_module="tree_sitter_swift",
    ),
    ".sh": LanguageConfig(
        func_types=["function_definition"],
        call_types=["command"],
        lazy_module="tree_sitter_bash",
    ),
    ".bash": LanguageConfig(
        func_types=["function_definition"],
        call_types=["command"],
        lazy_module="tree_sitter_bash",
    ),
    ".hs": LanguageConfig(
        func_types=["function"],
        call_types=["function_application"],
        lazy_module="tree_sitter_haskell",
    ),
    ".ex": LanguageConfig(
        func_types=["call"], call_types=["call"], lazy_module="tree_sitter_elixir"
    ),
    ".exs": LanguageConfig(
        func_types=["call"], call_types=["call"], lazy_module="tree_sitter_elixir"
    ),
    ".lua": LanguageConfig(
        func_types=["function_declaration"],
        call_types=["function_call"],
        lazy_module="tree_sitter_lua",
    ),
    ".html": LanguageConfig(
        func_types=[], call_types=[], lazy_module="tree_sitter_html"
    ),
    ".htm": LanguageConfig(
        func_types=[], call_types=[], lazy_module="tree_sitter_html"
    ),
    ".css": LanguageConfig(func_types=[], call_types=[], lazy_module="tree_sitter_css"),
}


class TreeSitterReader:
    """AST-based code reader using tree-sitter."""

    def __init__(self):
        self._parsers: dict[str, Parser] = {}
        self._languages: dict[str, Language] = {}
        self._configs: dict[str, LanguageConfig] = {}
        self._tree_cache: dict[str, tuple] = {}  # file_path → (mtime, tree)

    def _get_config(self, ext: str) -> Optional[LanguageConfig]:
        """Return LanguageConfig for an extension, lazy-loading if needed."""
        if ext in self._configs:
            return self._configs[ext]

        if ext in _LANG_REGISTRY:
            _, config = _LANG_REGISTRY[ext]
            self._configs[ext] = config
            return config

        if ext in _OPTIONAL_REGISTRY:
            config = _OPTIONAL_REGISTRY[ext]
            self._configs[ext] = config
            return config

        return None

    def _get_parser(self, ext: str) -> Optional[Parser]:
        if ext in self._parsers:
            return self._parsers[ext]

        lang_fn = None

        if ext in _LANG_REGISTRY:
            lang_mod_or_fn, _ = _LANG_REGISTRY[ext]
            if callable(lang_mod_or_fn) and not isinstance(lang_mod_or_fn, type):
                lang_fn = lang_mod_or_fn
            else:
                lang_fn = getattr(lang_mod_or_fn, "language", None) or getattr(
                    lang_mod_or_fn, "language_php", None
                )
        elif ext in _OPTIONAL_REGISTRY:
            config = _OPTIONAL_REGISTRY[ext]
            try:
                import importlib

                mod = importlib.import_module(config.lazy_module)
                lang_fn = getattr(mod, config.lazy_func, None)
                if lang_fn:
                    # Promote to core registry for future lookups
                    _LANG_REGISTRY[ext] = (lang_fn, config)
            except ImportError:
                logger.debug(
                    "Optional language package %s not installed", config.lazy_module
                )
                return None

        if not lang_fn:
            return None

        language = Language(lang_fn())
        parser = Parser(language)
        self._parsers[ext] = parser
        self._languages[ext] = language
        return parser

    def _parse_file(self, file_path: str) -> Optional[Node]:
        """Parse file, returning root node. Cached by mtime."""
        path = Path(file_path)
        if not path.exists():
            return None

        ext = path.suffix.lower()
        # Handle compound extensions like .svelte.ts
        if ext in (".ts", ".tsx") or path.stem.endswith((".svelte", ".vue")):
            pass  # .svelte.ts → use .ts parser
        parser = self._get_parser(ext)
        if not parser:
            return None

        mtime = path.stat().st_mtime
        if file_path in self._tree_cache:
            cached_mtime, cached_tree = self._tree_cache[file_path]
            if cached_mtime == mtime:
                return cached_tree.root_node

        source = path.read_bytes()
        tree = parser.parse(source)
        self._tree_cache[file_path] = (mtime, tree)
        return tree.root_node

    def find_enclosing_function(self, file_path: str, line: int) -> str:
        """Find the function/method containing the given line (1-indexed)."""
        root = self._parse_file(file_path)
        if root is None:
            return ""

        ext = Path(file_path).suffix.lower()
        config = self._get_config(ext)
        func_types = config.func_types if config else ["function_definition"]

        row = line - 1
        node = root.descendant_for_point_range((row, 0), (row, 0))

        while node is not None:
            if node.type in func_types:
                name_node = node.child_by_field_name("name")
                if name_node:
                    return name_node.text.decode()
                # arrow_function: name comes from parent variable_declarator
                if node.type == "arrow_function" and node.parent:
                    if node.parent.type == "variable_declarator":
                        vd_name = node.parent.child_by_field_name("name")
                        if vd_name:
                            return vd_name.text.decode()
            node = node.parent

        return ""

    def get_function_body(self, file_path: str, function_name: str) -> str:
        """Get full text of a named function."""
        body, _ = self._find_function(file_path, function_name)
        return body

    def get_function_body_numbered(self, file_path: str, function_name: str) -> str:
        """Get function text with line numbers prefixed (e.g. '  42 | code')."""
        body, start_line = self._find_function(file_path, function_name)
        if not body:
            return ""
        lines = body.split("\n")
        return "\n".join(f"  {start_line + i} | {line}" for i, line in enumerate(lines))

    def _find_function(self, file_path: str, function_name: str) -> tuple[str, int]:
        """Find a named function, return (body_text, 1-based start line)."""
        root = self._parse_file(file_path)
        if root is None:
            return "", 0

        ext = Path(file_path).suffix.lower()
        config = self._get_config(ext)
        func_types = config.func_types if config else ["function_definition"]

        for node in self._walk(root):
            if node.type in func_types:
                start_line = node.start_point[0] + 1  # 0-based → 1-based
                name_node = node.child_by_field_name("name")
                if name_node and name_node.text.decode() == function_name:
                    return node.text.decode(), start_line
                # arrow_function: check parent variable_declarator
                if (
                    node.type == "arrow_function"
                    and node.parent
                    and node.parent.type == "variable_declarator"
                ):
                    vd_name = node.parent.child_by_field_name("name")
                    if vd_name and vd_name.text.decode() == function_name:
                        return node.text.decode(), start_line
        return "", 0

    def find_callees(self, file_path: str, function_name: str) -> list[str]:
        """Find all function calls inside a named function."""
        root = self._parse_file(file_path)
        if root is None:
            return []

        ext = Path(file_path).suffix.lower()
        config = self._get_config(ext)
        func_types = config.func_types if config else ["function_definition"]
        call_types = set(config.call_types) if config else {"call_expression"}

        # Find the function node
        func_node = None
        for node in self._walk(root):
            if node.type in func_types:
                name_node = node.child_by_field_name("name")
                if name_node and name_node.text.decode() == function_name:
                    func_node = node
                    break
                # arrow_function: check parent variable_declarator
                if (
                    node.type == "arrow_function"
                    and node.parent
                    and node.parent.type == "variable_declarator"
                ):
                    vd_name = node.parent.child_by_field_name("name")
                    if vd_name and vd_name.text.decode() == function_name:
                        func_node = node
                        break

        if not func_node:
            return []

        # Extract callee names from call expressions
        callees = []
        for node in self._walk(func_node):
            if node.type not in call_types:
                continue

            # "function" field — used by most languages (JS, TS, Python, Rust, C, Go, etc.)
            func_ref = node.child_by_field_name("function")
            if func_ref:
                name = _extract_callee_name(func_ref)
                if name:
                    callees.append(name)
                continue

            # "method" field — Ruby
            method_ref = node.child_by_field_name("method")
            if method_ref:
                callees.append(method_ref.text.decode())
                continue

            # "name" field — PHP member_call_expression
            name_ref = node.child_by_field_name("name")
            if name_ref and node.type == "member_call_expression":
                callees.append(name_ref.text.decode())

        return list(dict.fromkeys(callees))  # dedupe preserving order

    def find_imports(self, file_path: str) -> list[str]:
        """Find all imported names/modules in a file."""
        root = self._parse_file(file_path)
        if root is None:
            return []

        ext = Path(file_path).suffix.lower()
        config = self._get_config(ext)
        if not config or config.import_style == "none":
            return []

        style = config.import_style
        imports: list[str] = []

        for node in root.children:
            if style == "python":
                _extract_python_imports(node, imports)
            elif style == "js":
                _extract_js_imports(node, imports)
            elif style == "ruby":
                _extract_ruby_imports(node, imports)
            elif style == "rust":
                _extract_rust_imports(node, imports)
            elif style == "go":
                _extract_go_imports(node, imports, self._walk)
            elif style == "java":
                _extract_java_imports(node, imports)

        return list(dict.fromkeys(imports))

    def read_context(self, file_path: str, line: int, context: int = 10) -> str:
        """Read lines around a target line with line numbers."""
        path = Path(file_path)
        if not path.exists():
            return ""

        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        total = len(lines)
        start = max(0, line - 1 - context)
        end = min(total, line + context)

        result = []
        for i in range(start, end):
            num = i + 1
            marker = " << VULNERABLE" if num == line else ""
            result.append(f"{num:4d} | {lines[i]}{marker}")
        return "\n".join(result)

    def _walk(self, node: Node):
        """Depth-first walk of AST nodes."""
        yield node
        for child in node.children:
            yield from self._walk(child)

    def get_config(self, ext: str):
        """Public accessor for language config by extension."""
        return self._get_config(ext)

    def parse_file(self, file_path: str):
        """Public accessor for parsing a file into AST."""
        return self._parse_file(file_path)


# ---------------------------------------------------------------------------
# Callee name extraction — language-agnostic, driven by AST node type.
# ---------------------------------------------------------------------------


def _extract_callee_name(func_ref: Node) -> str:
    """Extract the callee name from a call's function reference node."""
    # obj.method() → attribute (Python) / member_expression (JS/TS) / field_expression (Rust)
    if func_ref.type == "attribute":
        attr = func_ref.child_by_field_name("attribute")
        return attr.text.decode() if attr else ""
    if func_ref.type == "member_expression":
        prop = func_ref.child_by_field_name("property")
        return prop.text.decode() if prop else ""
    if func_ref.type == "field_expression":
        fld = func_ref.child_by_field_name("field")
        return fld.text.decode() if fld else ""
    # Direct function call: foo()
    if func_ref.type in ("identifier", "name"):
        return func_ref.text.decode()
    return ""


# ---------------------------------------------------------------------------
# Import extraction — one function per import style.
# ---------------------------------------------------------------------------


def _extract_python_imports(node: Node, imports: list[str]) -> None:
    if node.type == "import_statement":
        for child in node.children:
            if child.type == "dotted_name":
                imports.append(child.text.decode())
    elif node.type == "import_from_statement":
        for child in node.children:
            if (
                child.type == "dotted_name"
                and child.prev_sibling
                and child.prev_sibling.type == "import"
            ):
                imports.append(child.text.decode())
            elif child.type == "aliased_import":
                name_node = child.child_by_field_name("name")
                if name_node:
                    imports.append(name_node.text.decode())


def _extract_js_imports(node: Node, imports: list[str]) -> None:
    if node.type == "import_statement":
        source = node.child_by_field_name("source")
        if source:
            imports.append(source.text.decode().strip("'\""))


def _extract_ruby_imports(node: Node, imports: list[str]) -> None:
    if node.type == "call":
        method = node.child_by_field_name("method")
        if method and method.text.decode() in ("require", "require_relative"):
            args = node.child_by_field_name("arguments")
            if args:
                for arg in args.children:
                    if arg.type == "string":
                        imports.append(arg.text.decode().strip("'\""))


def _extract_rust_imports(node: Node, imports: list[str]) -> None:
    if node.type == "use_declaration":
        for child in node.children:
            if child.type == "scoped_identifier":
                imports.append(child.text.decode())


def _extract_go_imports(node: Node, imports: list[str], walk) -> None:
    if node.type == "import_declaration":
        for child in walk(node):
            if child.type == "interpreted_string_literal_content":
                imports.append(child.text.decode())


def _extract_java_imports(node: Node, imports: list[str]) -> None:
    if node.type == "import_declaration":
        for child in node.children:
            if child.type == "scoped_identifier":
                imports.append(child.text.decode())
