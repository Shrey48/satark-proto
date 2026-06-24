"""
SATARK Layer 1 — LLM Module

Public surface — import from here, not from individual provider files.

    from core.llm import get_llm_provider, LLMMessage, ConstrainedChoiceResponse, FreeTextResponse

Switching providers: change LLM_PROVIDER in .env.
  development → LLM_PROVIDER=deepseek
  production  → LLM_PROVIDER=anthropic
"""
from core.llm.factory import get_llm_provider, reset_llm_provider
from core.llm.base import (
    LLMProvider,
    LLMMessage,
    ConstrainedChoiceResponse,
    FreeTextResponse,
)

__all__ = [
    "get_llm_provider",
    "reset_llm_provider",
    "LLMProvider",
    "LLMMessage",
    "ConstrainedChoiceResponse",
    "FreeTextResponse",
]
