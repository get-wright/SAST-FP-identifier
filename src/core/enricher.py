"""Enrich Semgrep findings with code context from gkg or tree-sitter."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from src.code_reader.tree_sitter_reader import TreeSitterReader
from src.graph.joern_client import CallGraphResult, JoernClient, TaintResult
from src.graph.mcp_client import GkgMCPClient
from src.models.analysis import CrossFileHop, FindingContext, CallerInfo
from src.models.semgrep import SemgrepFinding
from src.taint.flow_tracker import trace_taint_flow
from src.taint.cross_file import resolve_cross_file

logger = logging.getLogger(__name__)

# File extensions Joern's CPG frontends can parse
_JOERN_SUPPORTED_EXTS: frozenset[str] = frozenset({
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py",
    ".java",
    ".c", ".h", ".cpp", ".cc", ".hpp", ".hh", ".cxx",
    ".go",
    ".php",
    ".rb",
    ".kt", ".kts",
    ".cs",
    ".swift",
    ".scala",
})


class Enricher:
    def __init__(
        self,
        repo_path: str,
        gkg_client: Optional[GkgMCPClient] = None,
        gkg_available: bool = False,
        joern_client=None,
        joern_available: bool = False,
        joern_path_translator=None,
        context_lines: int = 10,
    ):
        self._repo_path = repo_path
        self._gkg = gkg_client
        self._gkg_available = gkg_available
        self._joern = joern_client
        self._joern_available = joern_available
        self._joern_translate = joern_path_translator
        self._ts = TreeSitterReader()
        self._context_lines = context_lines

    async def enrich(self, finding: SemgrepFinding) -> FindingContext:
        """Build FindingContext for a single finding."""
        file_path = f"{self._repo_path}/{finding.path}"
        line = finding.start_line
        snippet = self._ts.read_context(file_path, line, self._context_lines)

        # Base enrichment: gkg or tree-sitter
        if self._gkg_available and self._gkg:
            ctx = await self._enrich_with_gkg(file_path, finding, snippet)
        else:
            ctx = self._enrich_with_tree_sitter(file_path, finding, snippet)

        # Tree-sitter taint flow tracing (always runs for supported languages)
        try:
            taint_flow = trace_taint_flow(
                file_path=file_path,
                function_name=ctx.enclosing_function or "",
                sink_line=line,
                check_id=finding.check_id,
                cwe_list=finding.metadata.get("cwe", []),
            )
            ctx.taint_flow = taint_flow

            # Cross-file resolution for unresolved callees (when gkg available)
            if taint_flow and taint_flow.unresolved_calls and self._gkg_available and self._gkg:
                hops = []
                for callee in taint_flow.unresolved_calls[:3]:
                    try:
                        result = await resolve_cross_file(
                            callee_name=callee,
                            gkg_client=self._gkg,
                            repo_path=self._repo_path,
                        )
                        hops.append(CrossFileHop(
                            callee=callee,
                            file=result.file,
                            line=result.line,
                            action=result.action,
                            sub_flow=result.sub_flow,
                        ))
                    except Exception as e:
                        logger.warning("Cross-file resolution failed for %s: %s", callee, e)
                taint_flow.cross_file_hops = hops
        except Exception as e:
            logger.warning("Taint flow tracing failed for %s:%d: %s", finding.path, line, e)

        # Joern taint analysis (adds taint fields to existing context)
        ext = Path(file_path).suffix.lower()
        if self._joern_available and self._joern and ext in _JOERN_SUPPORTED_EXTS:
            await self._enrich_with_joern(ctx, file_path, finding)

        return ctx

    async def _enrich_with_gkg(
        self, file_path: str, finding: SemgrepFinding, snippet: str
    ) -> FindingContext:
        """Enrich using gkg MCP queries + tree-sitter for function bodies.

        gkg returns XML-formatted text responses. We extract callers from
        get_references XML and use tree-sitter for reliable function body extraction.
        """
        line = finding.start_line
        fn_name = self._ts.find_enclosing_function(file_path, line)

        # Function body from tree-sitter (reliable, always works)
        body = self._ts.get_function_body(file_path, fn_name) if fn_name else ""

        # Callers from gkg get_references (cross-file data)
        callers = []
        if fn_name:
            try:
                refs = await self._gkg.get_references(file_path, line, fn_name)
                callers = _parse_callers(refs)
            except Exception as e:
                logger.warning("gkg get_references failed for %s:%d: %s", finding.path, line, e)

        callees = self._ts.find_callees(file_path, fn_name) if fn_name else []
        imports = self._ts.find_imports(file_path)

        # Only claim gkg source if gkg actually provided cross-file data
        has_gkg_data = len(callers) > 0
        return FindingContext(
            code_snippet=snippet,
            enclosing_function=fn_name,
            function_body=body,
            callers=callers,
            callees=callees,
            imports=imports,
            related_definitions=[],
            source="gkg" if has_gkg_data else "tree_sitter",
        )

    def _enrich_with_tree_sitter(
        self, file_path: str, finding: SemgrepFinding, snippet: str
    ) -> FindingContext:
        """Enrich using tree-sitter only (no cross-file data)."""
        line = finding.start_line
        fn_name = self._ts.find_enclosing_function(file_path, line)
        body = self._ts.get_function_body(file_path, fn_name) if fn_name else ""
        callees = self._ts.find_callees(file_path, fn_name) if fn_name else []
        imports = self._ts.find_imports(file_path)

        return FindingContext(
            code_snippet=snippet,
            enclosing_function=fn_name,
            function_body=body,
            callers=[],
            callees=callees,
            imports=imports,
            related_definitions=[],
            source="tree_sitter",
        )


    async def _enrich_with_joern(
        self, ctx: FindingContext, file_path: str, finding: SemgrepFinding
    ) -> None:
        """Add Joern taint analysis to an existing FindingContext."""
        try:
            joern_file = self._joern_translate(file_path) if self._joern_translate else file_path
            lang = file_path.rsplit(".", 1)[-1] if "." in file_path else "unknown"

            result = await self._joern.taint_check(joern_file, finding.start_line, lang)

            ctx.taint_reachable = result.reachable
            ctx.taint_sanitized = result.sanitized
            ctx.taint_path = result.path
            ctx.taint_sanitizers = result.sanitizer_names

            # Call graph: callers/callees from Joern CPG
            cg = await self._joern.get_call_graph(joern_file, finding.start_line)
            if cg.enclosing_method:
                if not ctx.enclosing_function:
                    ctx.enclosing_function = cg.enclosing_method
                if cg.callers:
                    ctx.callers = [
                        CallerInfo(
                            file=c["file"], line=c["line"],
                            function=c["name"],
                            context=self._get_caller_body(c["file"], c["name"]),
                        )
                        for c in cg.callers[:5]  # cap to avoid prompt bloat
                    ]
                if cg.callees and not ctx.callees:
                    ctx.callees = cg.callees

            # Upgrade source to joern — the taint query ran successfully
            ctx.source = "joern"

        except Exception as e:
            logger.warning("Joern enrichment failed for %s:%d: %s", finding.path, finding.start_line, e)

    def _get_caller_body(self, caller_file: str, function_name: str) -> str:
        """Try to extract a caller's function body via tree-sitter for prompt context.

        Joern stores relative paths (e.g., scripts/foo.ts) in the CPG.
        We resolve them against self._repo_path. Returns empty string on failure.
        """
        if not function_name:
            return ""
        candidates = [
            # Direct path (already absolute)
            caller_file,
            # Relative path from Joern → prepend repo_path
            f"{self._repo_path}/{caller_file}",
            # Strip leading slash if present
            f"{self._repo_path}/{caller_file.lstrip('/')}",
        ]

        for p in candidates:
            if not Path(p).exists():
                continue
            try:
                body = self._ts.get_function_body_numbered(p, function_name)
                if not body:
                    continue
                lines = body.splitlines()
                if len(lines) > 30:
                    return "\n".join(lines[:30]) + "\n  // ... truncated"
                return body
            except Exception:
                continue
        return ""


def _parse_callers(refs: list) -> list[CallerInfo]:
    """Parse gkg get_references response into CallerInfo list.

    gkg returns either:
    - dicts with file/line/function keys (structured)
    - XML strings in <ToolResponse> format (text)
    """
    callers = []
    for r in refs:
        if isinstance(r, dict):
            definitions = r.get("definitions")
            if isinstance(definitions, list):
                for definition in definitions:
                    for reference in definition.get("references", []):
                        start = reference.get("range", {}).get("start", {})
                        callers.append(CallerInfo(
                            file=reference.get("file", reference.get("file_path", "")),
                            line=reference.get("line", start.get("line", 0)),
                            function=reference.get(
                                "function",
                                reference.get(
                                    "enclosing_definition_name",
                                    definition.get("name", ""),
                                ),
                            ),
                            context=reference.get("context", ""),
                        ))
                continue

            callers.append(CallerInfo(
                file=r.get("file", r.get("file_path", "")),
                line=r.get("line", 0),
                function=r.get("function", r.get("definition_name", "")),
                context=r.get("context", ""),
            ))
        elif isinstance(r, str):
            # Parse gkg XML ToolResponse format:
            # <definition><name>fn</name><location>file:L10-20</location>
            #   <references><reference><location>...</location><context>...</context></reference></references>
            # </definition>
            for def_match in re.finditer(
                r"<definition>(.*?)</definition>",
                r, re.DOTALL,
            ):
                def_block = def_match.group(1)
                name_m = re.search(r"<name>(.*?)</name>", def_block)
                fn_name = name_m.group(1) if name_m else ""

                # Extract the definition's own location for file path
                def_loc_m = re.search(r"<location>(.*?)</location>", def_block)
                def_file = ""
                def_line = 0
                if def_loc_m:
                    loc = def_loc_m.group(1)
                    # Format: /path/to/file.py:L330-344
                    loc_parts = loc.rsplit(":", 1)
                    if len(loc_parts) == 2:
                        def_file = loc_parts[0]
                        line_str = loc_parts[1].lstrip("L").split("-")[0]
                        try:
                            def_line = int(line_str)
                        except ValueError:
                            pass

                # Extract context from first reference
                ctx_m = re.search(r"<context>(.*?)</context>", def_block, re.DOTALL)
                context = ctx_m.group(1).strip() if ctx_m else ""

                if def_file:
                    callers.append(CallerInfo(
                        file=def_file,
                        line=def_line,
                        function=fn_name,
                        context=context,
                    ))
    return callers
