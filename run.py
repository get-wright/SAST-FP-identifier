"""Entrypoint for the Semgrep False-Positive Analyzer API."""

import uvicorn
from src.config import Settings
from src.api.app import create_app


def main():
    settings = Settings()
    app = create_app(
        api_key=settings.API_KEY,
        repos_cache_dir=settings.REPOS_CACHE_DIR,
        cache_dir=settings.RESULT_CACHE_DIR,
        triage_data_dir=settings.TRIAGE_DATA_DIR,
        cache_enabled=settings.RESULT_CACHE_ENABLED,
        cache_ttl_hours=settings.RESULT_CACHE_TTL_HOURS,
        registry_path=settings.INDEX_REGISTRY_PATH,
        allowed_domains=settings.ALLOWED_REPO_DOMAINS,
        shallow_clone=settings.SHALLOW_CLONE,
        gkg_path=settings.GKG_PATH,
        gkg_server_port=settings.GKG_SERVER_PORT,
        gkg_enable_reindexing=settings.GKG_ENABLE_REINDEXING,
        gkg_index_timeout=settings.GKG_INDEX_TIMEOUT,
        joern_url=settings.JOERN_URL,
        joern_enabled=settings.JOERN_ENABLED,
        joern_import_timeout=settings.JOERN_IMPORT_TIMEOUT,
        joern_query_timeout=settings.JOERN_QUERY_TIMEOUT,
        sbom_enabled=settings.SBOM_ENABLED,
        sbom_tool=settings.SBOM_TOOL,
        sbom_timeout=settings.SBOM_TIMEOUT,
        llm_provider=settings.LLM_PROVIDER,
        llm_api_key=settings.LLM_API_KEY,
        llm_model=settings.LLM_MODEL,
        llm_base_url=settings.LLM_BASE_URL,
        llm_max_concurrent=settings.LLM_MAX_CONCURRENT,
        llm_temperature=settings.LLM_TEMPERATURE,
        llm_max_tokens=settings.LLM_MAX_TOKENS,
        llm_retry_count=settings.LLM_RETRY_COUNT,
        llm_timeout=settings.LLM_TIMEOUT,
        is_reasoning_model=settings.LLM_IS_REASONING_MODEL,
        fp_threshold=settings.FP_CONFIDENCE_THRESHOLD,
        max_findings=settings.MAX_FINDINGS_PER_REQUEST,
        context_lines=settings.MAX_CONTEXT_LINES,
        prompt_strategy=settings.LLM_PROMPT_STRATEGY,
    )
    uvicorn.run(app, host=settings.HOST, port=settings.PORT, log_level=settings.LOG_LEVEL.lower())


if __name__ == "__main__":
    main()
