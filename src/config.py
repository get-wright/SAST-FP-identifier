"""Application configuration via environment variables."""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    API_KEY: str = Field(default="changeme", description="API key for server authentication")
    ALLOWED_REPO_DOMAINS: list[str] = ["github.com", "gitlab.com"]
    MAX_REQUEST_BODY_MB: int = 10

    # Repository
    REPOS_CACHE_DIR: str = "./repos_cache"
    SHALLOW_CLONE: bool = True

    # gkg
    GKG_PATH: str = "gkg"
    GKG_SERVER_PORT: int = 27495
    GKG_ENABLE_REINDEXING: bool = True
    GKG_INDEX_TIMEOUT: int = 300
    GKG_QUERY_TIMEOUT: int = 30

    # Joern
    JOERN_URL: str = "http://localhost:8080"
    JOERN_ENABLED: bool = False  # Enable via env var in Docker; avoids timeout in dev
    JOERN_IMPORT_TIMEOUT: int = 120
    JOERN_QUERY_TIMEOUT: int = 30
    JOERN_REPO_MOUNT: str = "/repos"

    # SBOM
    SBOM_ENABLED: bool = True
    SBOM_TOOL: str = "auto"  # "auto", "cdxgen", "syft"
    SBOM_TIMEOUT: int = 60

    # LLM
    LLM_PROVIDER: str = "fpt_cloud"
    LLM_MODEL: str = "GLM-4.5"
    LLM_API_KEY: str = Field(default="", description="Default LLM API key (optional if provided per-request from frontend)")
    LLM_BASE_URL: str = "https://mkp-api.fptcloud.com"
    LLM_MAX_CONCURRENT: int = 5
    LLM_TEMPERATURE: float = 0.3
    LLM_MAX_TOKENS: int = 4000
    LLM_RETRY_COUNT: int = 2
    LLM_TIMEOUT: int = 60
    LLM_IS_REASONING_MODEL: bool = False
    LLM_PROMPT_STRATEGY: str = "single_pass"  # "single_pass" or "two_stage"

    # Analysis
    FP_CONFIDENCE_THRESHOLD: float = 0.8
    MAX_FINDINGS_PER_REQUEST: int = 200
    MAX_CONTEXT_LINES: int = 20

    # Cache
    RESULT_CACHE_ENABLED: bool = True
    RESULT_CACHE_DIR: str = "./cache"
    RESULT_CACHE_TTL_HOURS: int = 24
    TRIAGE_DATA_DIR: str = "./triage_data"

    # Index Registry
    INDEX_REGISTRY_PATH: str = "./index_registry.json"

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: Optional[str] = None

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    def validate_repo_url(self, url: str) -> bool:
        """Validate repo URL scheme and domain."""
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError(f"Only https:// URLs accepted, got {parsed.scheme}://")
        domain = parsed.hostname or ""
        if domain not in self.ALLOWED_REPO_DOMAINS:
            raise ValueError(
                f"Domain '{domain}' not in allowed list: {self.ALLOWED_REPO_DOMAINS}"
            )
        return True


def get_settings(**overrides) -> Settings:
    return Settings(**overrides)


# Lazy singleton — only created when imported in the running app, not at test time
try:
    settings = Settings()
except Exception:
    settings = None  # Tests create their own instances
