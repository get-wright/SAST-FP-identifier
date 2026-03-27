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
- RULE APPLICABILITY: Check the rule ID against the PROJECT CONTEXT. If the rule targets a specific framework or library (identifiable from the rule ID, e.g., "django.", "rails.", "spring.") but PROJECT CONTEXT shows a different framework, the rule is a false positive — the check is irrelevant to this codebase. Even if the underlying security concern exists, a rule designed for one framework cannot correctly detect issues in another. Mark as false_positive and explain the mismatch.
- EXECUTION CONTEXT: Consider where this code actually runs. CI/CD configs, build scripts, and test files have different threat models than production application code. For workflow files, distinguish between expressions evaluated by the CI runner vs values injected into shell scripts.

Then produce:
- "reasoning": A natural paragraph of 3-5 sentences explaining WHY this finding is or is not a real vulnerability. Write as a security reviewer explaining to a colleague. Cite specific code patterns. Do not use section headers or labels like "SOURCE:" — just explain clearly.
- "dataflow_analysis": A separate paragraph describing HOW data flows through the code. Trace from where data enters (parameter, request, external source) through transformations to the flagged operation. If a TRACED DATA FLOW section is in the evidence, narrate that trace in plain language. If no trace is available, describe what you can infer from the function body. If the finding is not about data flow (e.g., config issue), write "Not applicable — this finding is about configuration, not data flow."
- "step_annotations": If GROUNDED FLOW STEPS are provided, annotate each meaningful step with a brief explanation (by 1-based index). Skip trivial assignments. If no grounded steps are provided, leave as [].
- "gap_steps": If GROUNDED FLOW STEPS are provided and you identify gaps in the traced flow (e.g., cross-file data movement not captured, missing intermediate transformations), add gap steps. Each has: label (source/propagation/sanitizer/sink), location (file:line), code (the expression), explanation, and after_step (insert after this grounded step index; 0 = before first). If no grounded steps are provided, leave as [].
- "flow_steps": ONLY populate this if no GROUNDED FLOW STEPS are provided (e.g., config findings, unsupported languages). Each step has: label (source/propagation/sanitizer/sink), location (file:line), code (the expression), and explanation. For config findings, return []. If grounded steps ARE provided, return [].

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

Also return "flow_steps": an array of structured steps tracing data from source to sink. Each step has label ("source", "propagation", "sanitizer", or "sink"), location (file:line), code (the expression), explanation (what happens at this step). Include at least source and sink for dataflow findings. For config/non-dataflow findings, return an empty array.

If GROUNDED FLOW STEPS are provided, annotate each meaningful step via "step_annotations" (by 1-based index). Add "gap_steps" for any gaps you identify. Only populate "flow_steps" if no grounded steps are provided.

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
        if hop.sub_flow and hop.sub_flow.path:
            for step in hop.sub_flow.path[:5]:
                tag = step.kind.upper()
                lines.append(f"    [{tag}] {hop.file}:{step.line}: {step.expression[:60]}")

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


def _slice_code_by_flow(file_path: str, taint_flow, context_radius: int = 5) -> str:
    """Extract ±N lines around each step in a taint flow trace.

    Returns numbered code slices instead of the full function body.
    Based on Snyk CodeReduce / LLM4FPM research: less targeted context = better LLM accuracy.
    """
    # Collect all relevant line numbers from the flow
    relevant_lines: set[int] = set()
    for step in taint_flow.path:
        if step.line > 0:
            for offset in range(-context_radius, context_radius + 1):
                relevant_lines.add(step.line + offset)
    for san in taint_flow.sanitizers:
        if san.line > 0:
            for offset in range(-context_radius, context_radius + 1):
                relevant_lines.add(san.line + offset)

    if not relevant_lines:
        return ""

    # Read the file and extract relevant line ranges
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
    except OSError:
        return ""

    total = len(all_lines)
    relevant_lines = {ln for ln in relevant_lines if 1 <= ln <= total}
    if not relevant_lines:
        return ""

    # Group consecutive lines into ranges, insert "..." between gaps
    sorted_lines = sorted(relevant_lines)
    slices: list[str] = []
    prev = -1
    for ln in sorted_lines:
        if prev > 0 and ln > prev + 1:
            slices.append("  ...")
        slices.append(f"{ln:4d} | {all_lines[ln - 1].rstrip()}")
        prev = ln

    return "\n".join(slices)


def build_dataflow_prompt(
    file_path: str,
    findings: list[dict],
    contexts: dict[int, FindingContext],
    max_tokens: int = 3000,
    grounded_steps_by_finding: dict[int, list[dict]] | None = None,
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
            # Dataflow-sliced context: ±5 lines around each flow step
            full_path = f"{ctx.enclosing_function or ''}"
            # Resolve file path for slicing
            slice_path = file_path
            if not file_path.startswith("/"):
                # Try common prefixes for repo-relative paths
                import os
                for candidate in [file_path, os.path.join(".", file_path)]:
                    if os.path.exists(candidate):
                        slice_path = candidate
                        break
            sliced = _slice_code_by_flow(slice_path, ctx.taint_flow)
            if sliced:
                label = f"CODE SLICES around dataflow steps"
                if ctx.enclosing_function:
                    label += f" in {ctx.enclosing_function}()"
                lines.append(f"{label}:\n{sliced}")
        elif ctx.enclosing_function and ctx.function_body:
            # Fallback: full function body when no taint flow
            lines.append(f"ENCLOSING FUNCTION ({ctx.enclosing_function}):\n{ctx.function_body}")
        if ctx.callers:
            caller_strs = [f"{c.file}:{c.line} {c.function}()" for c in ctx.callers[:5]]
            lines.append(f"Called by: {', '.join(caller_strs)}")
        if ctx.callees:
            lines.append(f"Calls: {', '.join(ctx.callees[:10])}")
        finding_parts.append("\n".join(lines))

    if finding_parts:
        parts.append("\n\n".join(finding_parts))

    # Render grounded flow steps for each finding
    if grounded_steps_by_finding:
        grounded_parts = []
        for finding in findings:
            idx = finding["index"]
            steps = grounded_steps_by_finding.get(idx, [])
            if not steps:
                continue
            fnum = idx + 1
            lines = [f"GROUNDED FLOW STEPS (Finding {fnum}):"]
            for i, step in enumerate(steps, 1):
                label = step["label"].upper()
                if not step.get("grounded", True):
                    label += ":GAP"
                lines.append(f"  {i}. [{label}] {step['location']} — `{step['code']}`")
            grounded_parts.append("\n".join(lines))
        if grounded_parts:
            parts.append("\n\n".join(grounded_parts) + "\n")

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
    grounded_steps_by_finding: dict[int, list[dict]] | None = None,
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

    # Project context from SBOM — pass raw dependency data, let LLM reason about protections
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
            # Strategy 2: Fallback (tree-sitter only or no Joern taint data)
            if ctx.code_snippet:
                lines.append(f"SINK (line {finding['line']}):\n{ctx.code_snippet}")

            # Use dataflow-sliced context when taint flow is available
            if ctx.taint_flow:
                import os
                slice_path = f"{file_path}" if os.path.isabs(file_path) else file_path
                sliced = _slice_code_by_flow(slice_path, ctx.taint_flow)
                if sliced:
                    label = f"CODE SLICES around dataflow steps"
                    if ctx.enclosing_function:
                        label += f" in {ctx.enclosing_function}()"
                    lines.append(f"{label}:\n{sliced}")
            elif ctx.enclosing_function and ctx.function_body:
                # Full function body only when no taint flow available
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

    # Render grounded flow steps for each finding
    if grounded_steps_by_finding:
        grounded_parts = []
        for finding in findings:
            idx = finding["index"]
            steps = grounded_steps_by_finding.get(idx, [])
            if not steps:
                continue
            fnum = idx + 1
            lines = [f"GROUNDED FLOW STEPS (Finding {fnum}):"]
            for i, step in enumerate(steps, 1):
                label = step["label"].upper()
                if not step.get("grounded", True):
                    label += ":GAP"
                lines.append(f"  {i}. [{label}] {step['location']} — `{step['code']}`")
            grounded_parts.append("\n".join(lines))
        if grounded_parts:
            parts.append("\n\n".join(grounded_parts) + "\n")

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


