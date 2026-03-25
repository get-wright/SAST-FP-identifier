"""Extract JSON arrays from LLM responses with fallback chain."""

from __future__ import annotations

import json
import re
import logging

logger = logging.getLogger(__name__)


def extract_json_array(raw: str) -> list[dict]:
    """Extract a JSON array from an LLM response.

    Fallback chain:
    1. Direct json.loads
    2. Strip markdown fences + think tags, retry
    3. Regex extract first [...] array → json.loads → json_repair if needed
    4. json_repair on full cleaned text (handles truncation without closing ])
    5. Return empty list
    """
    text = raw.strip()

    # Attempt 1: direct parse
    parsed = _try_parse(text)
    if parsed is not None:
        return parsed

    # Attempt 2: strip wrappers
    cleaned = _strip_wrappers(text)
    parsed = _try_parse(cleaned)
    if parsed is not None:
        return parsed

    # Attempt 3: regex extract → parse → repair
    match = re.search(r"\[[\s\S]*\]", cleaned)
    if match:
        parsed = _try_parse(match.group())
        if parsed is not None:
            return parsed
        # Regex matched but json.loads failed — try repair on the substring
        repaired = _try_repair(match.group())
        if repaired is not None:
            return repaired

    # Attempt 4: repair on full cleaned text (no closing ] found by regex)
    repaired = _try_repair(cleaned)
    if repaired is not None:
        return repaired

    logger.warning("Failed to extract JSON from LLM response (%d chars): %.200s...", len(raw), raw)
    return []


def _try_parse(text: str) -> list[dict] | None:
    """Try json.loads, return list or None."""
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
        return [result]
    except (json.JSONDecodeError, ValueError):
        return None


def _try_repair(text: str) -> list[dict] | None:
    """Try json_repair.loads, return list of dicts or None."""
    try:
        from json_repair import loads as repair_loads
        result = repair_loads(text)
        if isinstance(result, list):
            # Filter to only dict items (discard strings/nulls from partial repair)
            dicts = [item for item in result if isinstance(item, dict)]
            if dicts:
                logger.info("json_repair recovered %d items from malformed response", len(dicts))
                return dicts
        elif isinstance(result, dict):
            return [result]
    except Exception as e:
        logger.debug("json_repair failed: %s", e)
    return None


def _strip_wrappers(text: str) -> str:
    """Strip <think> tags and markdown fences."""
    # Remove <think>...</think>
    if "<think>" in text:
        parts = text.split("</think>")
        if len(parts) > 1:
            text = parts[-1].strip()

    # Remove markdown fences
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif text.startswith("```"):
        text = text.split("```", 2)[1].strip()
        if text.startswith("\n"):
            text = text[1:]

    return text
