"""Build grouped LLM prompts for file-group analysis."""

from __future__ import annotations

from src.core.triage_memory import TriageMemory
from src.llm.cwe_rubrics import get_rubrics_for_findings, format_rubrics_for_prompt
from src.models.analysis import FindingContext

SYSTEM_PROMPT_SINGLE_PASS = """You are a security expert performing false-positive triage on SAST findings.

For each finding, consider internally:
- Is the data user-controlled or from an untrusted source?
- Is there sanitization/escaping between source and sink?
- Does untrusted data actually reach the vulnerable sink?
- Can it be meaningfully exploited in this context?

Then produce:
- "reasoning": A natural paragraph of 3-5 sentences explaining WHY this finding is or is not a real vulnerability. Write as a security reviewer explaining to a colleague. Cite specific code patterns. Do not use section headers or labels like "SOURCE:" — just explain clearly.
- "dataflow_analysis": A separate paragraph describing HOW data flows through the code. Trace from where data enters (parameter, request, external source) through transformations to the flagged operation. If a TRACED DATA FLOW section is in the evidence, narrate that trace in plain language. If no trace is available, describe what you can infer from the function body. If the finding is not about data flow (e.g., config issue), write "Not applicable — this finding is about configuration, not data flow."

CRITICAL: Optimize for NOT missing true vulnerabilities. Use "uncertain" when the available evidence is insufficient.

VERDICT CONSISTENCY: Your verdict MUST match your reasoning.
- If analysis shows data is sanitized or never reaches the sink → false_positive
- If unsanitized user input reaches a dangerous sink → true_positive
- If evidence is insufficient → uncertain

CONFIDENCE: 0.0 (guessing) to 1.0 (certain).
- 0.9+: Clear-cut with strong evidence
- 0.7-0.9: Likely correct, some ambiguity
- Below 0.7: Limited evidence, consider "uncertain"
"""

SYSTEM_PROMPT_DATAFLOW = """You are a security engineer analyzing code dataflow. For each finding, trace how data moves through the code.

Describe how data enters the code (function parameter, HTTP request, file read, etc.), what transformations it undergoes (string operations, function calls, assignments), and where it arrives at the flagged operation. Narrate the path step by step in plain language. If a TRACED DATA FLOW section is provided, use it as your guide and narrate it. If the finding is not about data flow, write "Not applicable — this finding is about configuration, not data flow."

Set flow_complete to true if you can trace the full path from source to sink. Set to false if there are gaps (cross-file calls, dynamic dispatch, missing caller context). List the gaps.

Do NOT judge whether the finding is exploitable. Only trace the data movement."""

SYSTEM_PROMPT_VERDICT = """You are a security expert performing false-positive triage. You have been given SAST findings with pre-analyzed dataflow summaries. Use the dataflow analysis to inform your verdict.

Produce a natural paragraph of 3-5 sentences explaining WHY this finding is or is not a real vulnerability. Reference the dataflow analysis where relevant. Write as a security reviewer explaining to a colleague.

VERDICT CONSISTENCY: Your verdict MUST match your reasoning.
- If the dataflow shows data is sanitized or never reaches the sink → false_positive
- If the dataflow shows unsanitized user input reaches a dangerous sink → true_positive
- If the dataflow has gaps and you cannot determine exploitability → uncertain

CONFIDENCE: 0.0 (guessing) to 1.0 (certain).
- 0.9+: Clear-cut with strong evidence
- 0.7-0.9: Likely correct, some ambiguity
- Below 0.7: Limited evidence, consider "uncertain"
"""

# Backwards compatibility alias
SYSTEM_PROMPT = SYSTEM_PROMPT_SINGLE_PASS

# Rough chars-per-token estimate
CHARS_PER_TOKEN = 4


def _render_taint_flow(flow) -> str:
    """Render a TaintFlow into structured prompt text."""
    if not flow or not flow.path:
        if flow and flow.inferred:
            return (
                f"INFERRED SINK TYPE: {flow.inferred.sink_type} "
                f"(via {flow.inferred.inferred_from})\n"
                f"Expected sources: {', '.join(flow.inferred.expected_sources)}\n"
            )
        return ""

    FLOW_CHAR_BUDGET = 6000
    lines = []
    path = flow.path

    if len(path) > 15:
        shown = path[:5] + path[-5:]
        omitted = len(path) - 10
    else:
        shown = path
        omitted = 0

    hop_count = len(flow.cross_file_hops)
    header = "TRACED DATA FLOW"
    if hop_count:
        header += f" (cross-file, {hop_count} hops)"
    header += f" ({len(path)} steps):"
    lines.append(header)

    for i, step in enumerate(shown):
        if omitted and i == 5:
            lines.append(f"  [... {omitted} intermediate steps ...]")
        tag = step.kind.upper()
        if tag == "PARAMETER":
            tag = "SOURCE"
        lines.append(f"  [{tag}] line {step.line}: {step.expression[:80]}")

    for hop in flow.cross_file_hops:
        lines.append(f"  -> [HOP] {hop.file}:{hop.line} {hop.callee}() -> {hop.action}")

    if flow.sanitizers:
        san_strs = []
        for s in flow.sanitizers:
            cond = " (CONDITIONAL)" if s.conditional else ""
            verified = " [verified]" if s.verified else ""
            san_strs.append(f"{s.name} at line {s.line} ({', '.join(s.cwe_categories)}){cond}{verified}")
        lines.append("SANITIZERS IN PATH: " + "; ".join(san_strs))
    else:
        lines.append("SANITIZERS IN PATH: NONE")

    if flow.unresolved_calls:
        lines.append(f"UNRESOLVED CALLS: {', '.join(flow.unresolved_calls)}")

    if flow.confidence_factors:
        lines.append(f"FLOW EVIDENCE: {'; '.join(flow.confidence_factors)}")

    result = "\n".join(lines)
    if len(result) > FLOW_CHAR_BUDGET:
        result = result[:FLOW_CHAR_BUDGET] + "\n  [... taint flow truncated due to length]"
    return result


def build_dataflow_prompt(
    file_path: str,
    findings: list[dict],
    contexts: dict[int, FindingContext],
    max_tokens: int = 3000,
) -> str:
    """Build Stage 1 prompt -- code context + taint trace only, no SBOM/CWE/memories."""
    max_chars = max_tokens * CHARS_PER_TOKEN
    parts = [f"FILE: {file_path}\n"]

    finding_parts = []
    for finding in findings:
        idx = finding["index"]
        ctx = contexts.get(idx)
        if not ctx:
            continue
        fnum = idx + 1
        lines = [f"--- Finding {fnum} ---"]
        lines.append(f"Rule: {finding['rule']} | Line {finding['line']} — {finding['message']}")
        if ctx.code_snippet:
            lines.append(f"CODE:\n{ctx.code_snippet}")
        if ctx.taint_flow:
            flow_text = _render_taint_flow(ctx.taint_flow)
            if flow_text:
                lines.append(flow_text)
        if ctx.enclosing_function and ctx.function_body:
            lines.append(f"ENCLOSING FUNCTION ({ctx.enclosing_function}):\n{ctx.function_body}")
        if ctx.callers:
            caller_strs = [f"{c.file}:{c.line} {c.function}()" for c in ctx.callers[:5]]
            lines.append(f"Called by: {', '.join(caller_strs)}")
        if ctx.callees:
            lines.append(f"Calls: {', '.join(ctx.callees[:10])}")
        finding_parts.append("\n".join(lines))

    if finding_parts:
        parts.append("\n\n".join(finding_parts))

    prompt = "\n".join(parts)
    if len(prompt) > max_chars:
        prompt = prompt[:max_chars] + "\n\n[Context truncated]"
    return prompt


def build_grouped_prompt(
    file_path: str,
    findings: list[dict],
    contexts: dict[int, FindingContext],
    repo_map: str = "",
    max_tokens: int = 6000,
    profile=None,
    memories: dict[int, list[TriageMemory]] | None = None,
    dataflow_summaries: dict[int, dict] | None = None,
) -> str:
    """Build a prompt for all findings in one file.

    Args:
        file_path: Path of the file being analyzed.
        findings: List of {index, rule, line, message} dicts.
        contexts: Map of finding_index → FindingContext.
        repo_map: Compact repo overview text.
        max_tokens: Token budget for the entire prompt.
    """
    max_chars = max_tokens * CHARS_PER_TOKEN
    parts = []

    # Project context from SBOM
    if profile and profile.all_deps:
        ctx_lines = []
        if profile.language:
            ctx_lines.append(f"Language: {profile.language.title()}")
        if profile.framework:
            ctx_lines.append(f"Framework: {profile.framework.title()}")
        dep_count = len(profile.all_deps)
        ctx_lines.append(f"Dependencies: {dep_count} packages")
        if dep_count <= 80:
            ctx_lines.append(f"Installed: {', '.join(profile.all_deps)}")
        else:
            shown = ', '.join(profile.all_deps[:80])
            ctx_lines.append(f"Installed (first 80 of {dep_count}): {shown}")
        if profile.security_deps:
            ctx_lines.append(f"Security deps: {', '.join(profile.security_deps)}")
        if not profile.has_csrf_protection:
            ctx_lines.append("CSRF protection: NONE DETECTED")
        else:
            ctx_lines.append("CSRF protection: Present")
        if profile.has_xss_protection:
            ctx_lines.append("XSS protection: Template auto-escaping active")
        if profile.has_sql_orm:
            ctx_lines.append("SQL ORM: Present (parameterized queries likely)")
        else:
            ctx_lines.append("SQL ORM: NONE DETECTED")

        # Framework-specific notes
        notes = _framework_notes(profile)
        if notes:
            ctx_lines.append(f"NOTE: {notes}")

        parts.append("PROJECT CONTEXT (SBOM):\n" + "\n".join(ctx_lines) + "\n")

    # Repo map (capped at 1500 tokens)
    if repo_map:
        map_budget = 1500 * CHARS_PER_TOKEN
        truncated_map = repo_map[:map_budget]
        parts.append(f"REPOSITORY MAP:\n{truncated_map}\n")

    # File-type context — helps LLM understand if this is build tooling vs app code
    file_type_hint = _file_type_hint(file_path)
    if file_type_hint:
        parts.append(f"FILE: {file_path}\nFILE CONTEXT: {file_type_hint}\n")
    else:
        parts.append(f"FILE: {file_path}\n")

    # Dynamic CWE guidance based on actual findings
    rubrics = get_rubrics_for_findings(findings)
    rubric_text = format_rubrics_for_prompt(rubrics)
    if rubric_text:
        parts.append(f"CWE-SPECIFIC TRIAGE GUIDANCE:\n{rubric_text}\n")

    if memories is None:
        memories = {}

    # Determine if any finding has Joern taint data — drives context strategy
    has_taint_data = any(
        ctx.source == "joern" and ctx.taint_reachable is not None
        for ctx in contexts.values()
    )

    # Build per-finding context structured around the verification checklist:
    # SOURCE → SANITIZATION → SINK → TAINT PATH
    # Two strategies: taint-path-first (Joern available) or function-body fallback
    finding_context_parts = []

    for finding in findings:
        idx = finding["index"]
        ctx = contexts.get(idx)
        if not ctx:
            continue

        fnum = idx + 1
        lines = [f"--- Finding {fnum} context ---"]

        # Dataflow summary from Stage 1 (two-stage strategy)
        if dataflow_summaries and idx in dataflow_summaries:
            ds = dataflow_summaries[idx]
            lines.append(f"DATAFLOW SUMMARY: {ds.get('dataflow_analysis', 'N/A')}")
            complete = "yes" if ds.get("flow_complete") else "no"
            lines.append(f"FLOW COMPLETE: {complete}")
            gaps = ds.get("gaps", [])
            if gaps:
                lines.append(f"GAPS: {', '.join(gaps)}")

        # Taint flow (primary evidence when available)
        if ctx.taint_flow:
            flow_text = _render_taint_flow(ctx.taint_flow)
            if flow_text:
                lines.append(flow_text)

        if ctx.source == "joern" and ctx.taint_reachable is not None:
            # Strategy 1: Taint-path-first — compact, structured context
            # SINK (the finding location — always include snippet)
            if ctx.code_snippet:
                lines.append(f"SINK (line {finding['line']}):\n{ctx.code_snippet}")

            # SOURCE determination from taint data
            if ctx.taint_reachable and ctx.taint_path:
                lines.append(f"SOURCE: {ctx.taint_path[0]}")
                # Taint path (sampled if long — keep first, last, and evenly spaced middle)
                path = ctx.taint_path
                if len(path) <= 10:
                    sampled = path
                else:
                    # Sample: first + 8 evenly spaced + last
                    step = (len(path) - 1) / 9
                    sampled = [path[int(i * step)] for i in range(10)]
                lines.append(f"TAINT PATH ({len(path)} steps): {' → '.join(sampled)}")
            elif ctx.taint_reachable:
                lines.append("SOURCE: Reachable by untrusted input (path not available)")
            else:
                lines.append("SOURCE: NOT reachable by untrusted input")

            # SANITIZATION
            if ctx.taint_sanitized:
                lines.append(f"SANITIZATION: SANITIZED via {', '.join(ctx.taint_sanitizers)}")
            elif ctx.taint_reachable:
                lines.append("SANITIZATION: NONE found between source and sink")

            # Enclosing function signature (not full body) for context
            if ctx.enclosing_function:
                lines.append(f"Function: {ctx.enclosing_function}()")

            # Callers as list only (no inlined bodies)
            if ctx.callers:
                shown = ctx.callers[:5]
                caller_strs = [f"{c.file}:{c.line} {c.function}()" for c in shown]
                if len(ctx.callers) > 5:
                    caller_strs.append(f"... +{len(ctx.callers) - 5} more")
                lines.append(f"Called by: {', '.join(caller_strs)}")

            # Security-relevant callees only (cap at 10)
            if ctx.callees:
                shown = ctx.callees[:10]
                suffix = f" +{len(ctx.callees) - 10} more" if len(ctx.callees) > 10 else ""
                lines.append(f"Calls: {', '.join(shown)}{suffix}")

        else:
            # Strategy 2: Function-body fallback (tree-sitter only or no taint data)
            # SINK snippet
            if ctx.code_snippet:
                lines.append(f"SINK (line {finding['line']}):\n{ctx.code_snippet}")

            # Function body as primary context
            if ctx.enclosing_function and ctx.function_body:
                lines.append(f"ENCLOSING FUNCTION ({ctx.enclosing_function}):\n{ctx.function_body}")

            # Callers as list only (no inlined bodies)
            if ctx.callers:
                shown = ctx.callers[:5]
                caller_strs = [f"{c.file}:{c.line} {c.function}()" for c in shown]
                if len(ctx.callers) > 5:
                    caller_strs.append(f"... +{len(ctx.callers) - 5} more")
                lines.append(f"Called by: {', '.join(caller_strs)}")

            if ctx.callees:
                shown = ctx.callees[:10]
                suffix = f" +{len(ctx.callees) - 10} more" if len(ctx.callees) > 10 else ""
                lines.append(f"Calls: {', '.join(shown)}{suffix}")

        finding_context_parts.append("\n".join(lines))

    if finding_context_parts:
        parts.append("EVIDENCE PER FINDING:\n" + "\n\n".join(finding_context_parts) + "\n")

    # File imports — helps LLM identify security-relevant libraries in scope
    all_imports = set()
    for ctx in contexts.values():
        all_imports.update(ctx.imports)
    if all_imports:
        parts.append("IMPORTS:\n" + ", ".join(sorted(all_imports)) + "\n")

    memory_parts = []
    for finding in findings:
        idx = finding["index"]
        matched_memories = memories.get(idx, [])
        if not matched_memories:
            continue
        lines = [f"  - [{m.scope}] {m.id}: {m.guidance}" for m in matched_memories]
        memory_parts.append(f"Finding {idx + 1} ({finding['rule']}):\n" + "\n".join(lines))
    if memory_parts:
        parts.append("REVIEWER MEMORIES:\n" + "\n".join(memory_parts) + "\n")

    # Findings list (include rule confidence if available)
    finding_lines = []
    for f in findings:
        line = f"{f['index'] + 1}. [Rule: {f['rule']}] Line {f['line']} — {f['message']}"
        if f.get("severity"):
            line += f" (severity: {f['severity']})"
        if f.get("rule_confidence"):
            line += f" (rule confidence: {f['rule_confidence']})"
        finding_lines.append(line)
    parts.append(
        f"FINDINGS TO TRIAGE ({len(findings)} findings):\n" + "\n".join(finding_lines)
    )

    parts.append(
        "Analyze each finding and provide your verdict with reasoning."
    )

    prompt = "\n".join(parts)

    # Truncate if over budget
    if len(prompt) > max_chars:
        prompt = prompt[:max_chars] + "\n\n[Context truncated due to length]"

    return prompt


def _file_type_hint(file_path: str) -> str:
    """Infer file type context from path to help LLM understand execution environment."""
    p = file_path.lower()
    if "/.github/workflows/" in p or "/.github/actions/" in p:
        return "GitHub Actions workflow (YAML). Runs in CI, not in app runtime. ${{ }} expressions are evaluated by GitHub."
    if "/scripts/" in p or p.endswith(".sh") or p.endswith(".bash"):
        return "Build/CLI script. Runs locally or in CI, not as part of the deployed application. No user-facing input."
    if "/tests/" in p or "/test/" in p or "/__tests__/" in p or p.endswith("_test.py") or p.endswith(".test.ts") or p.endswith(".spec.ts"):
        return "Test file. Not deployed to production."
    if "/migrations/" in p or "migration" in p.rsplit("/", 1)[-1]:
        return "Database migration. Runs once during deployment, not at request time."
    basename = p.rsplit("/", 1)[-1] if "/" in p else p
    if basename in ("dockerfile", "docker-compose.yml", "docker-compose.yaml"):
        return "Container configuration. Not application code."
    if basename.endswith((".yaml", ".yml", ".toml", ".ini", ".cfg")):
        return "Configuration file. Not executable application code."
    if basename.endswith(".json") and "/src/" not in p:
        return "Data/config JSON file. Not executable code."
    return ""


def _framework_notes(profile) -> str:
    """Generate framework-specific security notes."""
    fw = profile.framework
    if fw == "flask" and not profile.has_csrf_protection:
        return "Flask does NOT include built-in CSRF protection. POST forms require Flask-WTF or manual CSRF tokens."
    if fw == "express" and not profile.has_csrf_protection:
        return "Express does NOT include built-in CSRF protection. Requires csurf middleware."
    if fw == "django":
        return "Django includes CSRF middleware and template auto-escaping by default."
    if fw == "spring" and not profile.has_csrf_protection:
        return "Spring does NOT include CSRF protection without Spring Security."
    return ""
