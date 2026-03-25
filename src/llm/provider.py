"""LangChain chat model factory."""

from __future__ import annotations

import logging
from typing import Optional

from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def create_chat_model(
    provider_name: str,
    api_key: str,
    model: str,
    base_url: Optional[str] = None,
    is_reasoning_model: bool = False,
    temperature: float = 0.3,
    max_tokens: int = 4000,
) -> BaseChatModel:
    """Factory for LangChain chat models.

    Supports: fpt_cloud, openai, openrouter, anthropic.
    Returns BaseChatModel with .ainvoke() and .with_structured_output().
    """
    if provider_name in ("fpt_cloud", "openai"):
        from langchain_openai import ChatOpenAI
        kwargs: dict = {
            "api_key": api_key, "model": model,
            "temperature": temperature, "max_tokens": max_tokens,
        }
        if base_url:
            kwargs["base_url"] = base_url
        if is_reasoning_model:
            kwargs["max_tokens"] = min(max_tokens * 4, 32000)
            kwargs["model_kwargs"] = {"reasoning_effort": "low"}
        return ChatOpenAI(**kwargs)

    elif provider_name == "openrouter":
        from langchain_openai import ChatOpenAI
        kwargs = {
            "api_key": api_key, "model": model,
            "base_url": base_url or OPENROUTER_BASE_URL,
            "temperature": temperature, "max_tokens": max_tokens,
        }
        if is_reasoning_model:
            kwargs["max_tokens"] = min(max_tokens * 4, 32000)
            kwargs["model_kwargs"] = {"reasoning_effort": "low"}
        return ChatOpenAI(**kwargs)

    elif provider_name == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            api_key=api_key, model=model,
            temperature=temperature, max_tokens=max_tokens,
        )

    else:
        raise ValueError(f"Unknown LLM provider: {provider_name}")
