"""Git repository handler with caching and SHA tracking."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from git import Repo, GitCommandError

logger = logging.getLogger(__name__)


class RepoHandler:
    def __init__(
        self,
        cache_dir: str = "./repos_cache",
        shallow: bool = True,
        allowed_domains: Optional[list[str]] = None,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.shallow = shallow
        self.allowed_domains = allowed_domains or ["github.com", "gitlab.com"]

    def validate_url(self, url: str) -> None:
        """Raise ValueError if URL scheme or domain is not allowed."""
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError(f"Only https:// URLs accepted, got {parsed.scheme}://")
        domain = parsed.hostname or ""
        if domain not in self.allowed_domains:
            raise ValueError(f"Domain '{domain}' not in allowed: {self.allowed_domains}")

    def clone(self, repo_url: str, git_token: Optional[str] = None) -> str:
        """Clone or update a repo. Returns local path."""
        if repo_url == "." or not repo_url.startswith("https://"):
            return repo_url

        self.validate_url(repo_url)
        auth_url = self._inject_token(repo_url, git_token) if git_token else repo_url
        repo_name = self._get_repo_name(repo_url)
        local_path = self.cache_dir / repo_name

        if local_path.exists():
            return self._pull(local_path, auth_url)

        return self._clone_fresh(auth_url, local_path)

    def _clone_fresh(self, url: str, path: Path) -> str:
        logger.info("Cloning %s → %s", url, path)
        kwargs = {}
        if self.shallow:
            kwargs["depth"] = 1
        Repo.clone_from(url, str(path), **kwargs)
        return str(path)

    def _pull(self, path: Path, auth_url: Optional[str] = None) -> str:
        logger.info("Pulling latest for %s", path)
        try:
            repo = Repo(str(path))
            if auth_url:
                repo.remotes.origin.set_url(auth_url)
            repo.remotes.origin.pull()
        except Exception as e:
            logger.warning("Pull failed, using cached: %s", e)
        return str(path)

    def get_head_sha(self, repo_path: str) -> Optional[str]:
        """Get HEAD commit SHA for a repo path."""
        try:
            repo = Repo(repo_path)
            return repo.head.commit.hexsha
        except Exception:
            return None

    def needs_pull(self, repo_path: str, last_known_sha: str) -> bool:
        """Check if HEAD has advanced past the last known SHA."""
        current = self.get_head_sha(repo_path)
        return current != last_known_sha

    @staticmethod
    def _inject_token(url: str, token: str) -> str:
        """Inject OAuth/PAT token into HTTPS URL for private repo access.

        https://github.com/org/repo -> https://oauth2:TOKEN@github.com/org/repo
        """
        parsed = urlparse(url)
        authed = parsed._replace(netloc=f"oauth2:{token}@{parsed.hostname}")
        return authed.geturl()

    def _get_repo_name(self, repo_url: str) -> str:
        url = repo_url.rstrip("/")
        if url.endswith(".git"):
            url = url[:-4]
        parts = url.split("/")
        if len(parts) >= 2:
            return f"{parts[-2]}_{parts[-1]}"
        return parts[-1].replace("/", "_")
