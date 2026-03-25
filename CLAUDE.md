# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Semgrep False-Positive Analyzer — a FastAPI service that takes raw Semgrep JSON output, enriches findings with code context (via tree-sitter AST and optionally gkg call graphs), sends grouped findings to an LLM for false-positive triage, and returns annotated JSON + Markdown summary reports with verdicts and remediation suggestions.

## Commands

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run API server
python run.py                    # starts on :8000

# Run all tests
pytest

# Run a single test file / test function
pytest tests/test_orchestrator.py
pytest tests/test_llm.py::test_extract_json_array_from_markdown
```

Configuration: copy `.env.example` to `.env`, set `API_KEY` and `LLM_API_KEY`. All settings via env vars (see `src/config.py`).

## Architecture

### Pipeline (Orchestrator)

`src/core/orchestrator.py` runs the analysis pipeline:

1. **Clone/update repo** via `RepoHandler` (shallow git clone, cached in `repos_cache/`)
2. **gkg setup** — if gkg binary is on PATH, start server + ensure repo is indexed (tracked via `IndexRegistry`)
3. **Parse & group** — parse Semgrep JSON into `SemgrepFinding` models, group by file path
4. **Enrich** (parallel per file-group) — `Enricher` adds code context per finding:
   - Always: tree-sitter AST for enclosing function, callees, imports, code snippet
   - If gkg available: cross-file call graph (callers, definitions via MCP HTTP client)
5. **LLM analysis** — `PromptBuilder` creates grouped prompts per file; `LLMProvider` sends to LLM (OpenAI-compatible or Anthropic); `json_extractor` parses JSON array from response
6. **Assemble** — verdicts collected into `AnalysisResult`, tree-sitter-only verdicts capped at 0.7 confidence

### Key Modules

- **`src/api/`** — FastAPI app factory, API key middleware (`X-API-Key` header), two endpoints: `POST /analyze` (sync) and `POST /analyze/stream` (SSE)
- **`src/core/`** — `Orchestrator` (pipeline), `Enricher` (context gathering), `ResultCache` (file-based, keyed by repo+sha+file+fingerprints hash)
- **`src/llm/`** — `LLMProvider` protocol with `OpenAICompatibleProvider` (FPT Cloud, OpenAI) and `AnthropicProvider`; `prompt_builder` for grouped prompts; `json_extractor` with fallback chain (direct parse → strip wrappers → regex)
- **`src/graph/`** — `GraphManager` (gkg server lifecycle), `GkgMCPClient` (HTTP MCP calls), `IndexRegistry` (file-locked JSON for index state)
- **`src/code_reader/`** — `TreeSitterReader` (AST parsing with mtime cache, supports .py/.js/.jsx/.go/.java)
- **`src/models/`** — `SemgrepFinding`/`SemgrepOutput` (input), `FindingContext`/`FindingVerdict`/`AnalysisResult` (output)
- **`src/reports/`** — `annotated_json` (injects `x_fp_analysis` into Semgrep JSON), `markdown_summary` (three-tier report: true positive / false positive / uncertain)

### Data Flow

```
POST /analyze {repo_url, semgrep_json, commit_sha?}
  → Orchestrator.analyze()
    → RepoHandler.clone() → GraphManager.ensure_index()
    → parse_semgrep_json() → group by file
    → per file-group (parallel):
        Enricher.enrich() → LLM prompt → LLMProvider.complete() → extract_json_array()
    → AnalysisResult
  → build_annotated_json() + build_markdown_summary()
  → {annotated_json, markdown_summary, warnings}
```

### Testing

- pytest with `asyncio_mode = auto` (no `@pytest.mark.asyncio` needed)
- Tests mock external dependencies (git, LLM, gkg) — no real API calls
- `tests/fixtures/sample.py` used by tree-sitter reader tests

### Important Details

- Auth: all endpoints except `/health` require `X-API-Key` header
- LLM prompt uses 1-indexed `finding_index`, orchestrator maps back to 0-indexed
- gkg is optional — graceful degradation to tree-sitter-only analysis (with confidence cap at 0.7)
- Result cache uses SHA-256 hash of fingerprints as part of the key, TTL-based expiry
- Repo URL validation: HTTPS-only, domain allowlist
