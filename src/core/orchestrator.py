"""Main analysis pipeline orchestrator."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from typing import Any, Awaitable, Callable, Optional

from langsmith import traceable

from src.core.cache import ResultCache
from src.core.enricher import Enricher
from src.core.triage_memory import TriageMemoryStore
from src.graph.joern_manager import JoernManager
from src.graph.manager import GraphManager
from src.llm.prompt_builder import (
    SYSTEM_PROMPT_SINGLE_PASS,
    SYSTEM_PROMPT_DATAFLOW,
    SYSTEM_PROMPT_VERDICT,
    build_dataflow_prompt,
    build_grouped_prompt,
)
from src.llm.provider import create_chat_model
from src.llm.schemas import DataflowBatch, VerdictOnlyBatch, VerdictOutputBatch
from src.llm.structured_output import invoke_structured
from langchain_core.language_models import BaseChatModel
from src.models.analysis import AnalysisResult, CallerInfo, FileGroupResult, FindingContext, FindingVerdict, TaintFlow
from src.models.semgrep import SemgrepFinding, parse_semgrep_json
from src.repo.handler import RepoHandler
from src.sbom.generator import generate_sbom
from src.sbom.profile import RepoProfile, parse_sbom
logger = logging.getLogger(__name__)

# Weighted confidence scoring.
#
# final_confidence = 0.70 × llm_confidence + 0.30 × evidence_score
#
# LLM judgment is the dominant signal (70%). Evidence score is a composite
# of enrichment quality, rule weight, context, and SBOM adjustments.

_LLM_WEIGHT = 0.70
_EVIDENCE_WEIGHT = 0.30

_VENDORED_PATTERNS = ("vendor/", "node_modules/", ".min.js", "polyfill")

_SEVERITY_WEIGHTS = {
    "ERROR": 1.0,
    "WARNING": 0.95,
    "INFO": 0.85,
}

_RULE_CONFIDENCE_WEIGHTS = {
    "HIGH": 1.0,
    "MEDIUM": 0.90,
    "LOW": 0.75,
}

_CONFIG_EXTS = (".yaml", ".yml", ".toml", ".json", ".xml", ".dockerfile", ".html", ".jinja", ".jinja2", ".twig")


def _base_evidence(ctx, file_path: str) -> float:
    """Evidence weight based on enrichment source quality."""
    if not ctx:
        return 0.60

    # TaintFlow adjustments (tree-sitter taint tracing)
    if ctx.taint_flow is not None:
        flow = ctx.taint_flow
        base = 0.80  # elevated base when flow is present

        if flow.path and len(flow.path) >= 2 and not flow.sanitizers:
            base += 0.15  # strong TP signal: source->sink, no sanitizer

        if flow.sanitizers:
            unconditional = [s for s in flow.sanitizers if not s.conditional and s.verified]
            conditional_only = [s for s in flow.sanitizers if s.conditional]
            if unconditional:
                base -= 0.20  # strong FP signal
            elif conditional_only:
                base += 0.05  # weak signal

        if flow.path and len(flow.path) == 1:
            base -= 0.10  # only sink, no traced source

        if flow.cross_file_hops:
            if any(h.action == "sanitizes" for h in flow.cross_file_hops):
                base -= 0.15

        return max(0.0, min(base, 1.0))

    if ctx.source in ("joern",):
        return 1.0
    if ctx.source == "gkg":
        return 0.95
    # Tree-sitter: depends on what was extracted
    if ctx.function_body and ctx.callees:
        return 0.92
    if ctx.function_body:
        return 0.88
    if ctx.enclosing_function:
        return 0.80
    # Config/infra files are self-contained
    path_lower = file_path.lower()
    basename = path_lower.rsplit("/", 1)[-1] if "/" in path_lower else path_lower
    is_config = basename == "dockerfile" or any(basename.endswith(e) for e in _CONFIG_EXTS)
    return 0.92 if is_config else 0.70


def _calc_confidence(
    llm_confidence: float,
    ctx,
    file_path: str,
    severity: str = "WARNING",
    rule_confidence: str = "",
    rule_adjustment: float = 1.0,
) -> float:
    """Compute final confidence as weighted average of LLM and evidence signals.

    final = 0.70 × llm_confidence + 0.30 × evidence_score
    """
    base = _base_evidence(ctx, file_path)

    # Rule weight
    sev_weight = _SEVERITY_WEIGHTS.get(severity.upper(), 0.90)
    rc = rule_confidence.upper() if rule_confidence else ""
    rc_weight = _RULE_CONFIDENCE_WEIGHTS.get(rc, 0.95)
    rule_weight = (sev_weight + rc_weight) / 2

    # Context weight
    context_weight = 1.0
    path_lower = file_path.lower()
    for pattern in _VENDORED_PATTERNS:
        if pattern in path_lower:
            context_weight = 0.50
            break

    evidence = min(base * rule_weight * context_weight * rule_adjustment, 1.0)
    return round(_LLM_WEIGHT * llm_confidence + _EVIDENCE_WEIGHT * evidence, 3)


# SBOM-based rule adjustments
_RULE_CATEGORY_KEYWORDS = {
    "csrf": "csrf",
    "sqli": "sql",
    "xss": "xss",
}


def _rule_adjustment(finding, profile: RepoProfile) -> float:
    """Compute rule adjustment based on SBOM context."""
    if not profile or not profile.all_deps:
        return 1.0

    rule_lower = finding.check_id.lower() if finding else ""

    # CSRF finding + no CSRF protection → boost
    if "csrf" in rule_lower and not profile.has_csrf_protection:
        return 1.1

    # CSRF finding + CSRF dep present → suppress
    if "csrf" in rule_lower and profile.has_csrf_protection:
        return 0.85

    # SQL injection + no ORM → boost
    if "sql" in rule_lower and not profile.has_sql_orm:
        return 1.1

    # SQL injection + ORM present → suppress slightly
    if "sql" in rule_lower and profile.has_sql_orm:
        return 0.90

    return 1.0


class Orchestrator:
    def __init__(
        self,
        repos_cache_dir: str = "./repos_cache",
        cache_dir: str = "./cache",
        triage_data_dir: str = "./triage_data",
        cache_enabled: bool = True,
        cache_ttl_hours: int = 24,
        registry_path: str = "./index_registry.json",
        allowed_domains: Optional[list[str]] = None,
        shallow_clone: bool = True,
        gkg_path: str = "gkg",
        gkg_server_port: int = 27495,
        gkg_enable_reindexing: bool = True,
        gkg_index_timeout: int = 300,
        joern_url: str = "http://localhost:8080",
        joern_enabled: bool = False,
        joern_import_timeout: int = 120,
        joern_query_timeout: int = 30,
        sbom_enabled: bool = True,
        sbom_tool: str = "auto",
        sbom_timeout: int = 60,
        llm_provider: str = "fpt_cloud",
        llm_api_key: str = "",
        llm_model: str = "GLM-4.5",
        llm_base_url: Optional[str] = None,
        llm_max_concurrent: int = 5,
        llm_temperature: float = 0.3,
        llm_max_tokens: int = 4000,
        llm_retry_count: int = 2,
        llm_timeout: int = 60,
        is_reasoning_model: bool = False,
        fp_threshold: float = 0.8,
        max_findings: int = 200,
        context_lines: int = 20,
        prompt_strategy: str = "single_pass",
    ):
        self._repo = RepoHandler(
            cache_dir=repos_cache_dir,
            shallow=shallow_clone,
            allowed_domains=allowed_domains,
        )
        self._graph = GraphManager(
            gkg_path=gkg_path,
            server_port=gkg_server_port,
            enable_reindexing=gkg_enable_reindexing,
            index_timeout=gkg_index_timeout,
            registry_path=registry_path,
        )
        self._joern = JoernManager(
            joern_url=joern_url,
            import_timeout=joern_import_timeout,
            query_timeout=joern_query_timeout,
            registry_path=registry_path,
        ) if joern_enabled else None
        self._sbom_enabled = sbom_enabled
        self._sbom_tool = sbom_tool
        self._sbom_timeout = sbom_timeout
        self._llm: BaseChatModel = create_chat_model(
            llm_provider, llm_api_key, llm_model, llm_base_url,
            is_reasoning_model=is_reasoning_model,
            temperature=llm_temperature,
            max_tokens=llm_max_tokens,
        )
        self._llm_provider_name = llm_provider
        self._is_reasoning_model = is_reasoning_model
        self._cache = ResultCache(cache_dir, cache_ttl_hours, cache_enabled)
        self._triage_memory = TriageMemoryStore(triage_data_dir)
        self._semaphore = asyncio.Semaphore(llm_max_concurrent)
        self._retry_count = llm_retry_count
        self._prompt_strategy = prompt_strategy
        self._fp_threshold = fp_threshold
        self._max_findings = max_findings
        self._context_lines = context_lines
        self._on_step: Optional[Callable[[dict], Awaitable[None]]] = None

    async def _emit(self, step: str, status: str, detail: str = "", duration_ms: int | None = None) -> None:
        """Emit a trace event to the on_step callback and log it."""
        event: dict[str, Any] = {"trace": True, "step": step, "status": status}
        if detail:
            event["detail"] = detail
        if duration_ms is not None:
            event["duration_ms"] = duration_ms
        logger.info(
            "pipeline %s: %s%s%s", step, status,
            f" ({duration_ms}ms)" if duration_ms else "",
            f" — {detail}" if detail else "",
        )
        if self._on_step:
            await self._on_step(event)

    @traceable(name="analyze_pipeline", run_type="chain")
    async def analyze(
        self,
        repo_url: str,
        semgrep_json: dict[str, Any],
        commit_sha: Optional[str] = None,
        git_token: Optional[str] = None,
        llm_override: Optional[BaseChatModel] = None,
        on_step: Optional[Callable[[dict], Awaitable[None]]] = None,
    ) -> AnalysisResult:
        """Run the full analysis pipeline.

        Args:
            git_token: OAuth/PAT token for private repo cloning.
            llm_override: If provided, use this LLM provider instead of the default.
            on_step: Async callback for trace events emitted at each pipeline step.
        """
        self._on_step = on_step
        llm = llm_override or self._llm

        # Step 1: Repo clone
        import os
        t0 = time.monotonic()
        await self._emit("repo_clone", "in_progress", detail="cloning repository")
        repo_path = os.path.abspath(
            await asyncio.to_thread(self._repo.clone, repo_url, git_token)
        )
        head_sha = await asyncio.to_thread(self._repo.get_head_sha, repo_path) or "unknown"
        sha_mismatch = commit_sha is not None and commit_sha != head_sha
        await self._emit("repo_clone", "completed", detail="cloned", duration_ms=int((time.monotonic() - t0) * 1000))

        # Step 2: gkg check + index
        gkg_available = False
        if self._graph.is_available():
            await self._emit("gkg_check", "completed", detail="gkg found")
            repo_key = self._repo._get_repo_name(repo_url)
            t0 = time.monotonic()
            await self._emit("gkg_index", "in_progress", detail="indexing call graph")
            gkg_available = await self._graph.ensure_index_and_server(
                repo_path, repo_key, head_sha,
            )
            status = "completed" if gkg_available else "error"
            await self._emit("gkg_index", status, duration_ms=int((time.monotonic() - t0) * 1000))
        else:
            await self._emit("gkg_check", "skipped", detail="gkg not found")

        # Joern setup
        joern_available = False
        if self._joern:
            if await self._joern.client.is_available():
                await self._emit("joern_check", "completed", detail="Joern available")
                t0 = time.monotonic()
                await self._emit("joern_cpg", "in_progress", detail="building CPG")
                joern_available = await self._joern.ensure_cpg(repo_path, head_sha)
                status = "completed" if joern_available else "error"
                detail = "CPG ready" if joern_available else "CPG generation failed"
                await self._emit("joern_cpg", status, detail=detail, duration_ms=int((time.monotonic() - t0) * 1000))
            else:
                await self._emit("joern_check", "skipped", detail="Joern not available")
        else:
            await self._emit("joern_check", "skipped", detail="Joern disabled")

        # SBOM analysis
        profile = RepoProfile()
        if self._sbom_enabled:
            t0 = time.monotonic()
            await self._emit("sbom_generate", "in_progress", detail="generating SBOM")
            sbom_json = await generate_sbom(repo_path, self._sbom_tool, self._sbom_timeout)
            if sbom_json:
                profile = parse_sbom(sbom_json)
                detail = f"{profile.framework or profile.language or 'unknown'}, {len(profile.all_deps)} deps"
                if not profile.has_csrf_protection:
                    detail += ", no CSRF"
                await self._emit("sbom_generate", "completed", detail=detail, duration_ms=int((time.monotonic() - t0) * 1000))
            else:
                await self._emit("sbom_generate", "error", detail="SBOM generation failed", duration_ms=int((time.monotonic() - t0) * 1000))
        else:
            await self._emit("sbom_generate", "skipped", detail="SBOM disabled")

        # Step 3: Parse & group
        file_groups = self._group_findings(semgrep_json)

        # Step 4: Enrich + LLM (parallel per file-group)
        enricher = Enricher(
            repo_path=repo_path,
            gkg_client=self._graph.client if gkg_available else None,
            gkg_available=gkg_available,
            joern_client=self._joern.client if joern_available else None,
            joern_available=joern_available,
            joern_path_translator=self._joern.translate_path if joern_available else None,
            context_lines=self._context_lines,
        )

        # Get repo_map
        repo_map = ""
        if gkg_available:
            t0 = time.monotonic()
            try:
                repo_map = await self._graph.client.repo_map(repo_path)
                await self._emit("repo_map", "completed", detail="retrieved", duration_ms=int((time.monotonic() - t0) * 1000))
            except Exception:
                await self._emit("repo_map", "error", detail="failed")
        else:
            await self._emit("repo_map", "skipped", detail="gkg unavailable")

        tasks = [
            self._process_file_group(
                file_path, findings, enricher, repo_map, head_sha, repo_url, llm,
                profile=profile,
            )
            for file_path, findings in file_groups.items()
        ]
        group_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Step 5: Assemble
        result = AnalysisResult(
            repo_url=repo_url,
            commit_sha=head_sha,
            commit_sha_mismatch=sha_mismatch,
            gkg_available=gkg_available,
            joern_available=joern_available,
            sbom_profile={
                "language": profile.language,
                "framework": profile.framework,
                "security_deps": profile.security_deps,
                "all_deps": profile.all_deps,
                "has_csrf_protection": profile.has_csrf_protection,
                "has_xss_protection": profile.has_xss_protection,
                "has_sql_orm": profile.has_sql_orm,
                "dep_count": len(profile.all_deps),
            } if profile.all_deps else None,
        )

        if sha_mismatch:
            result.warnings.append(
                f"Requested commit {commit_sha} doesn't match HEAD {head_sha}. Analysis used HEAD."
            )
        if not gkg_available:
            result.warnings.append("Call graph unavailable -- analysis uses tree-sitter only.")

        for gr in group_results:
            if isinstance(gr, Exception):
                logger.error("File group failed: %s", gr)
                continue
            result.file_groups.append(gr)

        return result

    def _group_findings(self, semgrep_json: dict) -> dict[str, list[SemgrepFinding]]:
        findings = parse_semgrep_json(semgrep_json, filter_ignored=True, max_findings=self._max_findings)
        groups: dict[str, list[SemgrepFinding]] = {}
        for f in findings:
            groups.setdefault(f.path, []).append(f)
        return groups

    async def _process_file_group(
        self,
        file_path: str,
        findings: list[SemgrepFinding],
        enricher: Enricher,
        repo_map: str,
        commit_sha: str,
        repo_url: str,
        llm: Optional[BaseChatModel] = None,
        profile: Optional[RepoProfile] = None,
    ) -> FileGroupResult:
        """Enrich + analyze one file-group."""
        llm = llm or self._llm

        # Check cache
        triage_hash = self._triage_memory.policy_hash(
            repo_url,
            profile.framework if profile else None,
            findings,
        )
        base_fp_hash = self._fingerprints_hash(findings)
        fp_hash = f"{base_fp_hash}-{triage_hash}"
        cached, cached_contexts = self._cache.get_with_contexts(repo_url, commit_sha, file_path, fp_hash)
        if cached is None and triage_hash == "no-triage-data":
            cached, cached_contexts = self._cache.get_with_contexts(repo_url, commit_sha, file_path, base_fp_hash)
        if cached is not None:
            # Migrate old cache format: is_false_positive → verdict
            for v in cached:
                if "is_false_positive" in v and "verdict" not in v:
                    v["verdict"] = "false_positive" if v.pop("is_false_positive") else "true_positive"
            verdicts = [FindingVerdict.model_validate(v) for v in cached]
            contexts = {
                int(i): FindingContext(
                    code_snippet=ctx.get("code_snippet", ""),
                    enclosing_function=ctx.get("enclosing_function", ""),
                    function_body=ctx.get("function_body", ""),
                    callers=[
                        CallerInfo(
                            file=caller.get("file", ""),
                            line=caller.get("line", 0),
                            function=caller.get("function", ""),
                            context=caller.get("context", ""),
                        )
                        for caller in ctx.get("callers", [])
                    ],
                    callees=ctx.get("callees", []),
                    imports=ctx.get("imports", []),
                    related_definitions=ctx.get("related_definitions", []),
                    source=ctx.get("source", "unknown"),
                    taint_reachable=ctx.get("taint_reachable"),
                    taint_sanitized=ctx.get("taint_sanitized"),
                    taint_path=ctx.get("taint_path", []),
                    taint_sanitizers=ctx.get("taint_sanitizers", []),
                    taint_flow=TaintFlow.from_dict(ctx.get("taint_flow")),
                )
                for i, ctx in cached_contexts.items()
            }
            await self._emit("enrich", "skipped", detail=f"{file_path}: cache hit")
            return FileGroupResult(file_path=file_path, verdicts=verdicts, contexts=contexts)

        # Enrich
        t0 = time.monotonic()
        contexts: dict[int, FindingContext] = {}
        for i, finding in enumerate(findings):
            try:
                contexts[i] = await enricher.enrich(finding)
            except Exception as e:
                logger.warning("Enrichment failed for %s:%d: %s", file_path, finding.start_line, e)

        sources = set(ctx.source for ctx in contexts.values())
        caller_count = sum(len(ctx.callers) for ctx in contexts.values())
        callee_count = sum(len(ctx.callees) for ctx in contexts.values())
        source_label = "joern" if "joern" in sources else "gkg" if "gkg" in sources else "tree-sitter only"
        detail = f"{file_path}: {source_label}, {caller_count} callers, {callee_count} callees"
        await self._emit("enrich", "completed", detail=detail, duration_ms=int((time.monotonic() - t0) * 1000))

        # LLM analysis
        t0 = time.monotonic()
        verdicts = await self._analyze_file_group(findings, contexts, repo_map, repo_url, llm, profile)
        dur = int((time.monotonic() - t0) * 1000)
        await self._emit("llm_call", "completed",
                         detail=f"{file_path}: {len(verdicts)} verdicts",
                         duration_ms=dur)

        # Parse results summary
        ok_count = sum(1 for v in verdicts if v.status == "ok")
        err_count = sum(1 for v in verdicts if v.status != "ok")
        if err_count:
            await self._emit("parse_results", "completed", detail=f"{file_path}: {ok_count} parsed, {err_count} fallback")
        else:
            await self._emit("parse_results", "completed", detail=f"{file_path}: {ok_count} verdicts parsed")

        # Adjust confidence using weighted average formula
        for v in verdicts:
            ctx = contexts.get(v.finding_index)
            finding = findings[v.finding_index] if v.finding_index < len(findings) else None
            severity = finding.severity if finding else "WARNING"
            rule_conf = finding.metadata.get("confidence", "") if finding else ""
            ra = _rule_adjustment(finding, profile) if profile and finding else 1.0
            v.confidence = _calc_confidence(v.confidence, ctx, file_path, severity, rule_conf, ra)
            if finding:
                override = self._triage_memory.find_override(repo_url, finding.fingerprint)
                if override:
                    v.verdict = override.verdict
                    v.confidence = override.confidence
                    v.reasoning = override.reasoning or v.reasoning
                    v.remediation_code = None
                    v.remediation_explanation = None
                    v.decision_source = "human_override"
                    v.override_id = override.id

        # Cache
        self._cache.set_with_contexts(
            repo_url,
            commit_sha,
            file_path,
            fp_hash,
            [v.model_dump() for v in verdicts],
            {
                str(i): {
                    "code_snippet": ctx.code_snippet,
                    "enclosing_function": ctx.enclosing_function,
                    "function_body": ctx.function_body,
                    "callers": [
                        {
                            "file": caller.file,
                            "line": caller.line,
                            "function": caller.function,
                            "context": caller.context,
                        }
                        for caller in ctx.callers
                    ],
                    "callees": ctx.callees,
                    "imports": ctx.imports,
                    "related_definitions": ctx.related_definitions,
                    "source": ctx.source,
                    "taint_reachable": ctx.taint_reachable,
                    "taint_sanitized": ctx.taint_sanitized,
                    "taint_path": ctx.taint_path,
                    "taint_sanitizers": ctx.taint_sanitizers,
                    "taint_flow": ctx.taint_flow.to_dict() if ctx.taint_flow else None,
                }
                for i, ctx in contexts.items()
            },
        )

        return FileGroupResult(file_path=file_path, verdicts=verdicts, contexts=contexts)

    # Per-finding analysis: each finding gets its own LLM call with focused context.
    # Industry research (Snyk CodeReduce, Semgrep Assistant, LLM4FPM) shows
    # accuracy improves with less, more targeted context per finding.
    # Findings at the same line with the same rule are batched together.

    @traceable(name="llm_file_group_analysis", run_type="chain")
    async def _analyze_file_group(
        self,
        findings: list[SemgrepFinding],
        contexts: dict[int, FindingContext],
        repo_map: str,
        repo_url: str,
        llm: Optional[BaseChatModel] = None,
        profile: Optional[RepoProfile] = None,
    ) -> list[FindingVerdict]:
        """Analyze findings per-finding (or per-group for same-line/same-rule duplicates)."""
        llm = llm or self._llm

        # Group findings that share the same line AND same rule (true duplicates).
        # Everything else gets its own LLM call.
        batches: list[tuple[list[SemgrepFinding], dict[int, FindingContext], int]] = []
        i = 0
        while i < len(findings):
            # Collect findings at the same line with the same check_id
            group = [findings[i]]
            group_contexts = {0: contexts[i]} if i in contexts else {}
            j = i + 1
            while j < len(findings) and findings[j].start_line == findings[i].start_line and findings[j].check_id == findings[i].check_id:
                idx_in_group = j - i
                group.append(findings[j])
                if j in contexts:
                    group_contexts[idx_in_group] = contexts[j]
                j += 1
            batches.append((group, group_contexts, i))
            i = j

        verdicts: list[FindingVerdict] = []
        for batch_findings, batch_contexts, offset in batches:
            batch_verdicts = await self._analyze_batch(
                batch_findings, batch_contexts, repo_map, repo_url, llm, profile,
                index_offset=offset,
            )
            verdicts.extend(batch_verdicts)

        return verdicts

    def _prepare_batch(
        self,
        findings: list[SemgrepFinding],
        repo_url: str,
        profile: Optional[RepoProfile],
    ) -> tuple[list[dict[str, Any]], dict[int, list]]:
        """Build findings_text and finding_memories for a batch."""
        framework = profile.framework if profile else None
        findings_text: list[dict[str, Any]] = []
        finding_memories: dict[int, list] = {}
        for i, f in enumerate(findings):
            entry: dict[str, Any] = {
                "index": i, "rule": f.check_id, "line": f.start_line,
                "message": f.message, "severity": f.severity,
            }
            rule_conf = f.metadata.get("confidence")
            if rule_conf:
                entry["rule_confidence"] = rule_conf
            cwe = f.metadata.get("cwe", [])
            if cwe:
                entry["cwe"] = cwe
            vuln_class = f.metadata.get("vulnerability_class")
            if vuln_class:
                entry["vulnerability_class"] = vuln_class[0] if isinstance(vuln_class, list) else vuln_class
            findings_text.append(entry)
            matched_memories = self._triage_memory.find_memories(repo_url, framework, f.check_id)
            if matched_memories:
                finding_memories[i] = matched_memories
        return findings_text, finding_memories

    async def _analyze_batch(
        self,
        findings: list[SemgrepFinding],
        contexts: dict[int, FindingContext],
        repo_map: str,
        repo_url: str,
        llm: BaseChatModel,
        profile: Optional[RepoProfile],
        index_offset: int = 0,
    ) -> list[FindingVerdict]:
        """Send a single batch of findings to the LLM."""
        findings_text, finding_memories = self._prepare_batch(findings, repo_url, profile)

        if self._prompt_strategy == "two_stage":
            # Skip Stage 1 (dataflow) if no finding has meaningful enrichment context.
            # Saves an entire LLM call for config findings (Dockerfile, HTML templates, etc.)
            has_enrichment = any(
                ctx.enclosing_function or ctx.callers or ctx.callees or ctx.taint_flow
                for ctx in contexts.values()
            )
            if not has_enrichment:
                logger.info("Skipping Stage 1 — no enrichment context for %s", findings[0].path)
            else:
                return await self._analyze_batch_two_stage(
                    findings, findings_text, contexts, llm, profile, repo_map, repo_url,
                    finding_memories, index_offset,
                )

        # Single-pass path
        prompt = build_grouped_prompt(
            file_path=findings[0].path,
            findings=findings_text,
            contexts=contexts,
            memories=finding_memories,
            repo_map=repo_map,
            profile=profile,
        )
        parsed = await self._run_single_pass_batch(llm, prompt)
        return self._map_verdicts(parsed, findings, finding_memories, index_offset)

    async def _run_single_pass_batch(
        self,
        llm: BaseChatModel,
        prompt: str,
    ) -> list[dict[str, Any]]:
        """Execute single-pass LLM call and return parsed verdict dicts."""
        messages = [("system", SYSTEM_PROMPT_SINGLE_PASS), ("human", prompt)]

        async with self._semaphore:
            batch_result = None
            for attempt in range(1 + self._retry_count):
                try:
                    batch_result = await invoke_structured(llm, VerdictOutputBatch, messages)
                    break
                except Exception as e:
                    if attempt < self._retry_count:
                        await asyncio.sleep(1 * (2 ** attempt))
                    else:
                        logger.error("LLM failed after %d retries: %s", self._retry_count, e)

        if batch_result is None:
            return []
        return [v.model_dump() for v in batch_result.verdicts]

    async def _analyze_batch_two_stage(
        self,
        findings: list[SemgrepFinding],
        findings_text: list[dict[str, Any]],
        contexts: dict[int, FindingContext],
        llm: BaseChatModel,
        profile: Optional[RepoProfile],
        repo_map: str,
        repo_url: str,
        finding_memories: dict[int, list],
        index_offset: int,
    ) -> list[FindingVerdict]:
        """Two-stage analysis: Stage 1 (dataflow) -> Stage 2 (verdict)."""
        file_path = findings[0].path

        # Stage 1: dataflow analysis
        df_prompt = build_dataflow_prompt(file_path, findings_text, contexts)
        messages1 = [("system", SYSTEM_PROMPT_DATAFLOW), ("human", df_prompt)]

        try:
            async with self._semaphore:
                df_result = await invoke_structured(llm, DataflowBatch, messages1)
        except Exception as e:
            logger.warning("Stage 1 (dataflow) failed, falling back to single-pass: %s", e)
            prompt = build_grouped_prompt(
                file_path=file_path, findings=findings_text, contexts=contexts,
                memories=finding_memories, repo_map=repo_map, profile=profile,
            )
            parsed = await self._run_single_pass_batch(llm, prompt)
            return self._map_verdicts(parsed, findings, finding_memories, index_offset)

        # Stage 2: verdict with dataflow summaries
        summaries = {r.finding_index: r.model_dump() for r in df_result.results}
        stage2_prompt = build_grouped_prompt(
            file_path=file_path, findings=findings_text, contexts=contexts,
            memories=finding_memories, repo_map=repo_map, profile=profile,
            dataflow_summaries=summaries,
        )
        messages2 = [("system", SYSTEM_PROMPT_VERDICT), ("human", stage2_prompt)]

        async with self._semaphore:
            v_result = None
            for attempt in range(1 + self._retry_count):
                try:
                    v_result = await invoke_structured(llm, VerdictOnlyBatch, messages2)
                    break
                except Exception as e:
                    if attempt < self._retry_count:
                        await asyncio.sleep(1 * (2 ** attempt))
                    else:
                        logger.error("Stage 2 LLM failed after retries: %s", e)

        if v_result is None:
            parsed = []
        else:
            # Merge Stage 1 dataflow into Stage 2 verdicts
            parsed = []
            for v in v_result.verdicts:
                d = v.model_dump()
                df_match = summaries.get(v.finding_index, {})
                d["dataflow_analysis"] = df_match.get("dataflow_analysis", "")
                d["flow_steps"] = df_match.get("flow_steps", [])
                parsed.append(d)

        return self._map_verdicts(parsed, findings, finding_memories, index_offset)

    def _map_verdicts(
        self,
        parsed: list[dict[str, Any]],
        findings: list[SemgrepFinding],
        finding_memories: dict[int, list],
        index_offset: int,
    ) -> list[FindingVerdict]:
        """Map parsed LLM dicts back to FindingVerdict objects."""
        verdicts = []
        for i, finding in enumerate(findings):
            matched = next(
                (p for p in parsed if p.get("finding_index") in (i + 1, i)),
                None,
            )
            global_index = i + index_offset
            if matched:
                verdict = matched.get("verdict", "uncertain")
                if verdict not in ("true_positive", "false_positive", "uncertain"):
                    if "is_false_positive" in matched:
                        verdict = "false_positive" if matched["is_false_positive"] else "true_positive"
                    else:
                        verdict = "uncertain"
                raw_conf = matched.get("confidence", 0.0)
                verdicts.append(FindingVerdict(
                    finding_index=global_index,
                    fingerprint=finding.fingerprint,
                    verdict=verdict,
                    confidence=max(0.0, min(1.0, raw_conf)),
                    reasoning=matched.get("reasoning", ""),
                    dataflow_analysis=matched.get("dataflow_analysis", ""),
                    flow_steps=matched.get("flow_steps", []),
                    remediation_code=matched.get("remediation_code"),
                    remediation_explanation=matched.get("remediation_explanation"),
                    applied_memory_ids=[m.id for m in finding_memories.get(i, [])],
                ))
            else:
                verdicts.append(FindingVerdict(
                    finding_index=global_index,
                    fingerprint=finding.fingerprint,
                    verdict="uncertain",
                    confidence=0.0,
                    reasoning="LLM did not return verdict for this finding",
                    status="parse_error",
                    applied_memory_ids=[m.id for m in finding_memories.get(i, [])],
                ))

        return verdicts

    def _fingerprints_hash(self, findings: list[SemgrepFinding]) -> str:
        fps = sorted(f.fingerprint for f in findings)
        return hashlib.sha256("|".join(fps).encode()).hexdigest()[:16]
