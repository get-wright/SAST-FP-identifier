"""REST API wrapper for Joern server (CPG query engine)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import re

import httpx

logger = logging.getLogger(__name__)


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
    return s[5:].strip()  # unbalanced — best effort

# Strip ANSI escape codes from Joern's colored terminal output
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

SANITIZER_PATTERNS: dict[str, list[str]] = {
    "xss": [
        "escapeHtml",
        "sanitize",
        "DOMPurify.sanitize",
        "textContent",
        "encodeURIComponent",
        "escape",
        "htmlspecialchars",
        "html.escape",
        "markupsafe.escape",
        "bleach.clean",
    ],
    "sqli": [
        "parameterize",
        "prepare",
        "placeholder",
        "sanitize_sql",
    ],
    "cmdi": [
        "shlex.quote",
        "escapeshellarg",
        "escapeshellcmd",
    ],
}

_ALL_SANITIZERS: frozenset[str] = frozenset(
    name.lower()
    for names in SANITIZER_PATTERNS.values()
    for name in names
)

# CPGQL call graph query template — placeholders: SINK_LINE, FILE_BASENAME
_CALL_GRAPH_QUERY_TEMPLATE = """\
val methods = cpg.method.filter(m => m.lineNumber.exists(_ <= SINK_LINE) && m.lineNumberEnd.exists(_ >= SINK_LINE)).where(_.file.name(".*FILE_BASENAME.*")).filterNot(m => m.name.startsWith(":") || m.name.startsWith("<") || m.name == "<global>").l
val m = if (methods.nonEmpty) methods.minBy(m => m.lineNumberEnd.getOrElse(99999) - m.lineNumber.getOrElse(0)) else null
if (m != null) {
  val callerList = m.caller.filterNot(c => c.isExternal || c.name.startsWith(":") || c.name.startsWith("<")).map(c => s"${c.name}|||${c.filename}|||${c.lineNumber.getOrElse(0)}").dedup.l
  val calleeList = m.callee.filterNot(c => c.isExternal || c.name.startsWith("<operator>")).name.dedup.l
  s"${m.name}\\n${callerList.mkString("\\n")}\\nCALLEES\\n${calleeList.mkString("\\n")}"
} else ""
"""

# CPGQL taint query template — placeholders: SINK_LINE, FILE_BASENAME
_TAINT_QUERY_TEMPLATE = """\
val sink = cpg.call.lineNumber(SINK_LINE).where(_.file.name(".*FILE_BASENAME.*"))
val sources = cpg.method.parameter.where(_.name("(?i).*(request|req|input|param|query|body|cookie|header|args|form|data).*"))
val flows = sink.reachableByFlows(sources).l
flows.map(flow => flow.elements.map(e => e.location.filename + ":" + e.location.lineNumber.getOrElse(0).toString + ":" + e.code.take(60)).mkString(" -> "))"""


@dataclass
class TaintResult:
    reachable: bool = False
    sanitized: bool = False
    path: list[str] = field(default_factory=list)
    sanitizer_names: list[str] = field(default_factory=list)


@dataclass
class CallGraphResult:
    enclosing_method: str = ""
    callers: list[dict] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)


class JoernClient:
    """HTTP client for Joern's REST API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        import_timeout: int = 120,
        query_timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.import_timeout = import_timeout
        self.query_timeout = query_timeout

    async def is_available(self) -> bool:
        """Return True if Joern server is reachable (status < 500)."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(self.base_url)
                return resp.status_code < 500
        except Exception:
            return False

    async def import_code(self, repo_path: str) -> bool:
        """Import a codebase into Joern's CPG.

        Joern's importCode returns success=false even on successful imports
        (the return value is the project object, not a boolean). We submit
        the import, wait for it to complete, then verify by querying the
        workspace.
        """
        query = f'importCode("{repo_path}")'
        try:
            await self._query_raw(query, timeout=self.import_timeout)
            # Verify import by checking workspace
            result = await self._query("workspace.toString", timeout=10)
            project_name = repo_path.rstrip("/").split("/")[-1]
            if project_name in result:
                logger.info("Joern importCode verified for %s", repo_path)
                return True
            logger.warning("Joern importCode completed but project %s not in workspace", project_name)
            return False
        except Exception as exc:
            logger.warning("Joern importCode failed for %s: %s", repo_path, exc)
            return False

    async def _query_raw(self, cpgql: str, timeout: Optional[int] = None) -> dict:
        """Submit a CPGQL query and return the raw result dict (ignoring success flag)."""
        if timeout is None:
            timeout = self.query_timeout
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{self.base_url}/query",
                json={"query": cpgql},
            )
            resp.raise_for_status()
            data = resp.json()

            uuid = data.get("uuid")
            if not uuid:
                return data

            import asyncio
            deadline = asyncio.get_event_loop().time() + timeout
            while asyncio.get_event_loop().time() < deadline:
                result_resp = await client.get(f"{self.base_url}/result/{uuid}")
                if result_resp.status_code == 200:
                    result_data = result_resp.json()
                    # "No result (yet?)" means not ready, keep polling
                    err_msg = result_data.get("err", "")
                    if "No result" in err_msg or "yet" in err_msg:
                        await asyncio.sleep(1)
                        continue
                    return result_data
                await asyncio.sleep(1)

            raise TimeoutError(f"Joern query {uuid} did not complete within {timeout}s")

    async def taint_check(
        self, sink_file: str, sink_line: int, language: str
    ) -> TaintResult:
        """Run CPGQL taint-flow query from user-controlled sources to the sink.

        Returns a TaintResult with reachability and sanitizer information.
        """
        basename = Path(sink_file).name
        cpgql = (
            _TAINT_QUERY_TEMPLATE
            .replace("SINK_LINE", str(sink_line))
            .replace("FILE_BASENAME", basename)
        )
        try:
            raw = await self._query(cpgql, timeout=self.query_timeout)
            return self._parse_taint_result(raw)
        except Exception as exc:
            logger.warning(
                "Joern taint_check failed for %s:%s: %s", sink_file, sink_line, exc
            )
            return TaintResult()

    async def get_call_graph(
        self, sink_file: str, sink_line: int
    ) -> CallGraphResult:
        """Query Joern for the enclosing method's callers and callees."""
        basename = Path(sink_file).name
        cpgql = (
            _CALL_GRAPH_QUERY_TEMPLATE
            .replace("SINK_LINE", str(sink_line))
            .replace("FILE_BASENAME", basename)
        )
        try:
            raw = await self._query(cpgql, timeout=self.query_timeout)
            return self._parse_call_graph_result(raw)
        except Exception as exc:
            logger.warning(
                "Joern get_call_graph failed for %s:%s: %s",
                sink_file, sink_line, exc,
            )
            return CallGraphResult()

    def _parse_call_graph_result(self, raw: str) -> CallGraphResult:
        """Parse Joern call graph output into a CallGraphResult.

        Joern returns the result in a `val resN: String = ...` line.
        The value may be a single-line "..." or multiline triple-quoted \"\"\"...\"\"\".
        The content format is:
          methodName
          callerA|||file.py|||10
          CALLEES
          calleeA
        """
        raw = _ANSI_RE.sub("", raw).strip()

        if not raw or "Error" in raw or "Exception" in raw:
            return CallGraphResult()

        # Strategy 1: Extract triple-quoted multiline result (val resN: String = """...""")
        result_value = ""
        tq_match = re.search(
            r'val res\d+:\s*String\s*=\s*"""(.*?)"""',
            raw, re.DOTALL,
        )
        if tq_match:
            result_value = tq_match.group(1).strip()

        # Strategy 2: Single-line result (val resN: String = "...")
        if not result_value:
            for line in reversed(raw.split("\n")):
                line = line.strip()
                if re.match(r"val res\d+:", line):
                    eq_pos = line.find("= ")
                    if eq_pos >= 0:
                        result_value = line[eq_pos + 2:].strip().strip('"')
                    break

        if not result_value:
            return CallGraphResult()

        # Split on real newlines (multiline) or escaped newlines (single-line)
        if "\n" in result_value:
            parts = [p.strip() for p in result_value.split("\n") if p.strip()]
        else:
            parts = [p.strip() for p in result_value.split("\\n") if p.strip()]

        if not parts:
            return CallGraphResult()

        enclosing = parts[0].strip()
        if not enclosing:
            return CallGraphResult()

        callers: list[dict] = []
        callees: list[str] = []
        in_callees = False

        for part in parts[1:]:
            part = part.strip()
            if not part:
                continue
            if part == "CALLEES":
                in_callees = True
                continue
            if in_callees:
                callees.append(part)
            else:
                segments = part.split("|||")
                if len(segments) == 3:
                    try:
                        caller_line = int(segments[2])
                    except ValueError:
                        caller_line = 0
                    callers.append({
                        "name": segments[0],
                        "file": segments[1],
                        "line": caller_line,
                    })

        return CallGraphResult(
            enclosing_method=enclosing,
            callers=callers,
            callees=callees,
        )

    def _parse_taint_result(self, raw: str) -> TaintResult:
        """Parse Joern's 'List(...)' output into a TaintResult.

        Joern REPL stdout includes ALL variable declarations, e.g.:
          val sink: Iterator[...] = empty iterator
          val sources: Iterator[...] = empty iterator
          val flows: List[...] = List()
          val res38: List[String] = List()

        The actual result is the LAST line starting with 'val res'.
        We extract that line and parse the List(...) value.
        """
        raw = _ANSI_RE.sub("", raw).strip()

        # Detect CPGQL compilation/runtime errors
        if "Error" in raw or "Exception" in raw or "Required:" in raw:
            logger.warning("Joern taint query returned error: %s", raw[:200])
            return TaintResult()

        # Extract the actual result line (last `val resN: ... = ...`)
        result_line = ""
        for line in reversed(raw.split("\n")):
            line = line.strip()
            if re.match(r"val res\d+:", line):
                # Extract the value after '= '
                eq_pos = line.find("= ")
                if eq_pos >= 0:
                    result_line = line[eq_pos + 2:].strip()
                break

        # Fall back to raw if no result line found (shouldn't happen)
        if not result_line:
            result_line = raw

        # No flows — List() or empty
        if not result_line or re.match(r"List\(\s*\)", result_line):
            return TaintResult()

        # Strip outer List(...) wrapper with proper bracket matching
        inner = _strip_list_wrapper(result_line)
        if not inner:
            return TaintResult()

        flow_strings: list[str] = [s.strip().strip('"') for s in inner.split('", "')]
        if not flow_strings or flow_strings == [""]:
            return TaintResult()

        # Flatten path elements, validating format
        path_elements: list[str] = []
        for flow in flow_strings:
            for elem in flow.split(" -> "):
                elem = elem.strip()
                parts = elem.split(":", 2)
                if len(parts) < 2:
                    continue
                try:
                    int(parts[1])
                except ValueError:
                    continue
                path_elements.append(elem)

        if not path_elements:
            return TaintResult()

        # Detect sanitizers
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

    async def _query(self, cpgql: str, timeout: Optional[int] = None) -> str:
        """POST a CPGQL query to Joern and return stdout.

        Joern's REST API is async:
        1. POST /query → {"uuid": "..."}
        2. GET /result/$uuid → {"success": true/false, "stdout": "...", "stderr": "..."}
        We poll /result until the query completes.
        """
        if timeout is None:
            timeout = self.query_timeout
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Submit query
            resp = await client.post(
                f"{self.base_url}/query",
                json={"query": cpgql},
            )
            resp.raise_for_status()
            data = resp.json()

            # If response has stdout directly (some Joern versions), return it
            if "stdout" in data:
                return data["stdout"]

            # Async pattern: poll for result
            uuid = data.get("uuid")
            if not uuid:
                raise RuntimeError(f"Joern /query returned no uuid: {data}")

            import asyncio
            deadline = asyncio.get_event_loop().time() + timeout
            while asyncio.get_event_loop().time() < deadline:
                result_resp = await client.get(f"{self.base_url}/result/{uuid}")
                if result_resp.status_code == 200:
                    result_data = result_resp.json()
                    # Joern returns 200 + success=false + "No result (yet?)" when not ready
                    err_msg = result_data.get("err", "")
                    if "No result" in err_msg or "yet" in err_msg:
                        await asyncio.sleep(1)
                        continue
                    if result_data.get("stderr"):
                        logger.warning("Joern query stderr: %s", result_data["stderr"])
                    if not result_data.get("success", True):
                        raise RuntimeError(f"Joern query failed: {result_data.get('stderr', err_msg)}")
                    return _ANSI_RE.sub("", result_data.get("stdout", ""))
                # 404 or other = not ready yet
                await asyncio.sleep(1)

            raise TimeoutError(f"Joern query {uuid} did not complete within {timeout}s")
