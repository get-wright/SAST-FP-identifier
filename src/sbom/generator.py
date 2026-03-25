"""Generate CycloneDX SBOM via cdxgen (preferred) or syft (fallback)."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


async def generate_sbom(
    repo_path: str,
    tool: str = "auto",
    timeout: int = 60,
) -> Optional[dict[str, Any]]:
    """Generate CycloneDX SBOM for a repository.

    Args:
        repo_path: Absolute path to the cloned repo.
        tool: "auto" (try cdxgen then syft), "cdxgen", or "syft".
        timeout: Max seconds for SBOM generation.

    Returns:
        Parsed CycloneDX JSON dict, or None on failure.
    """
    if tool == "auto":
        result = await _try_cdxgen(repo_path, timeout)
        if result:
            return result
        return await _try_syft(repo_path, timeout)
    elif tool == "cdxgen":
        return await _try_cdxgen(repo_path, timeout)
    elif tool == "syft":
        return await _try_syft(repo_path, timeout)
    return None


async def _try_cdxgen(repo_path: str, timeout: int) -> Optional[dict]:
    """Run cdxgen to generate SBOM."""
    if not shutil.which("cdxgen"):
        logger.debug("cdxgen not found on PATH")
        return None

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    cmd = ["cdxgen", "-o", out_path, "--spec-version", "1.6", repo_path]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode == 0:
            data = json.loads(Path(out_path).read_text())
            n = len(data.get("components", []))
            logger.info("cdxgen generated SBOM with %d components", n)
            return data
        logger.warning("cdxgen failed (rc=%d): %s", proc.returncode, stderr.decode()[:200])
    except asyncio.TimeoutError:
        logger.warning("cdxgen timed out after %ds", timeout)
        proc.kill()
    except Exception as e:
        logger.warning("cdxgen error: %s", e)
    finally:
        Path(out_path).unlink(missing_ok=True)
    return None


async def _try_syft(repo_path: str, timeout: int) -> Optional[dict]:
    """Run syft as fallback SBOM generator."""
    if not shutil.which("syft"):
        logger.debug("syft not found on PATH")
        return None

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    cmd = ["syft", repo_path, "-o", f"cyclonedx-json={out_path}"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode == 0:
            data = json.loads(Path(out_path).read_text())
            n = len(data.get("components", []))
            logger.info("syft generated SBOM with %d components", n)
            return data
        logger.warning("syft failed (rc=%d): %s", proc.returncode, stderr.decode()[:200])
    except asyncio.TimeoutError:
        logger.warning("syft timed out after %ds", timeout)
        proc.kill()
    except Exception as e:
        logger.warning("syft error: %s", e)
    finally:
        Path(out_path).unlink(missing_ok=True)
    return None
