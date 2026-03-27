"""Structured output with fallback for providers that don't support tool calling.

Some providers (e.g., FPT Cloud GLM) don't support function calling / tool use,
which is what LangChain's with_structured_output() relies on. This module provides
a wrapper that tries structured output first, then falls back to plain text + JSON parsing.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TypeVar

from langchain_core.language_models import BaseChatModel
from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


def _extract_json_from_text(text: str) -> str:
    """Extract JSON from markdown code blocks or raw text."""
    # Try ```json ... ``` blocks first
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        return match.group(1).strip()

    # Try to find a JSON object/array directly
    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start = text.find(start_char)
        if start >= 0:
            # Find the matching closing bracket
            depth = 0
            for i in range(start, len(text)):
                if text[i] == start_char:
                    depth += 1
                elif text[i] == end_char:
                    depth -= 1
                    if depth == 0:
                        return text[start : i + 1]

    return text.strip()


def _extract_text_content(response) -> str:
    """Extract text from an LLM response, handling reasoning model content blocks.

    Reasoning models (o1/o3/gpt-5.4-mini) may return content as a list of
    content blocks [{"type": "thinking", ...}, {"type": "text", "text": "..."}]
    instead of a plain string.
    """
    content = response.content if hasattr(response, "content") else str(response)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Extract text blocks, skip thinking blocks
        text_parts = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    text_parts.append(block.get("text", ""))
                elif block.get("type") != "thinking":
                    text_parts.append(str(block))
            elif isinstance(block, str):
                text_parts.append(block)
            elif hasattr(block, "text"):
                text_parts.append(block.text)
        return "\n".join(text_parts) if text_parts else str(content)
    return str(content)


async def invoke_structured(
    llm: BaseChatModel,
    schema: type[T],
    messages: list,
) -> T:
    """Try with_structured_output first, fall back to plain invoke + JSON parsing.

    Returns a validated Pydantic model instance.
    Raises on both structured and fallback failure.
    """
    # Try structured output (tool calling)
    try:
        structured = llm.with_structured_output(schema)
        result = await structured.ainvoke(messages)
        return result
    except Exception as e:
        logger.debug("Structured output failed, trying plain text fallback: %s", e)

    # Fallback: plain invoke + JSON extraction
    response = await llm.ainvoke(messages)
    text = _extract_text_content(response)
    json_str = _extract_json_from_text(text)
    parsed = json.loads(json_str)

    # Try direct validation first
    try:
        return schema.model_validate(parsed)
    except Exception:
        pass

    # LLM may return an unwrapped single object or array instead of the batch wrapper.
    # Try to auto-wrap: find which field in the schema is a list and wrap the parsed data.
    for field_name, field_info in schema.model_fields.items():
        annotation = field_info.annotation
        # Check if this field is list[SomeModel]
        origin = getattr(annotation, "__origin__", None)
        if origin is list:
            if isinstance(parsed, list):
                return schema.model_validate({field_name: parsed})
            elif isinstance(parsed, dict):
                return schema.model_validate({field_name: [parsed]})

    # If nothing worked, raise with the original parsed data for debugging
    return schema.model_validate(parsed)
