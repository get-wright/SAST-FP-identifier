"""Multi-provider async LLM client."""

from __future__ import annotations

import logging
import os
from typing import Optional, Protocol

logger = logging.getLogger(__name__)


def _langsmith_enabled() -> bool:
    return os.environ.get("LANGSMITH_TRACING", "").lower() == "true"


class LLMProvider(Protocol):
    async def complete(self, system: str, prompt: str, temperature: float, max_tokens: int) -> str: ...


class OpenAICompatibleProvider:
    """Provider for OpenAI-compatible APIs (OpenAI, FPT Cloud, OpenRouter)."""

    def __init__(self, api_key: str, model: str, base_url: Optional[str] = None, is_reasoning_model: bool = False):
        from openai import AsyncOpenAI
        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        client = AsyncOpenAI(**kwargs)
        if _langsmith_enabled():
            from langsmith.wrappers import wrap_openai
            client = wrap_openai(client)
            logger.info("LangSmith tracing enabled for OpenAI-compatible provider")
        self._client = client
        self._model = model
        self._is_reasoning = is_reasoning_model

    async def complete(self, system: str, prompt: str, temperature: float = 0.3, max_tokens: int = 4000) -> str:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        kwargs = {"model": self._model, "messages": messages}

        if self._is_reasoning:
            kwargs["max_completion_tokens"] = min(max_tokens * 4, 32000)
            # Limit reasoning effort to reduce latency — structured prompts
            # already guide the model, deep reasoning is unnecessary.
            # OpenRouter silently drops unsupported params, so this is safe.
            kwargs["extra_body"] = {"reasoning_effort": "low"}
        else:
            kwargs["temperature"] = temperature
            kwargs["max_tokens"] = max_tokens

        response = await self._client.chat.completions.create(**kwargs)

        finish_reason = response.choices[0].finish_reason
        if finish_reason == "length":
            usage = response.usage
            prompt_tokens = usage.prompt_tokens if usage else "?"
            completion_tokens = usage.completion_tokens if usage else "?"
            logger.warning(
                "LLM response truncated (finish_reason=length) model=%s prompt_tokens=%s completion_tokens=%s",
                self._model, prompt_tokens, completion_tokens,
            )

        return response.choices[0].message.content or ""


class AnthropicProvider:
    """Provider for Anthropic API."""

    def __init__(self, api_key: str, model: str):
        from anthropic import AsyncAnthropic
        client = AsyncAnthropic(api_key=api_key)
        if _langsmith_enabled():
            from langsmith.wrappers import wrap_anthropic
            client = wrap_anthropic(client)
            logger.info("LangSmith tracing enabled for Anthropic provider")
        self._client = client
        self._model = model

    async def complete(self, system: str, prompt: str, temperature: float = 0.3, max_tokens: int = 4000) -> str:
        response = await self._client.messages.create(
            model=self._model,
            system=system,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.content[0].text


OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def create_provider(
    provider_name: str,
    api_key: str,
    model: str,
    base_url: Optional[str] = None,
    is_reasoning_model: bool = False,
) -> LLMProvider:
    """Factory for LLM providers."""
    if provider_name in ("fpt_cloud", "openai"):
        return OpenAICompatibleProvider(
            api_key=api_key, model=model, base_url=base_url,
            is_reasoning_model=is_reasoning_model,
        )
    elif provider_name == "anthropic":
        if is_reasoning_model:
            logger.warning("is_reasoning_model has no effect for Anthropic provider (use extended thinking API instead)")
        return AnthropicProvider(api_key=api_key, model=model)
    elif provider_name == "openrouter":
        return OpenAICompatibleProvider(
            api_key=api_key, model=model, base_url=base_url or OPENROUTER_BASE_URL,
            is_reasoning_model=is_reasoning_model,
        )
    else:
        raise ValueError(f"Unknown LLM provider: {provider_name}")
