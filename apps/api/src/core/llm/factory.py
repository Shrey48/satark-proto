"""
SATARK Layer 1 — LLM Provider Factory

The ONLY place that knows which provider is active.
Everything else imports `get_llm_provider()` from here.

Usage anywhere in the codebase:
    from core.llm.factory import get_llm_provider
    llm = get_llm_provider()
    result = await llm.constrained_choice(system, messages, options, sentinels)

To switch providers: change LLM_PROVIDER in .env. Nothing else changes.
"""
from functools import lru_cache
from core.llm.base import LLMProvider
from core.config import get_settings
import structlog

logger = structlog.get_logger(__name__)


@lru_cache(maxsize=1)
def get_llm_provider() -> LLMProvider:
    """
    Returns the active LLM provider singleton based on LLM_PROVIDER env var.
    Cached — provider is initialised once and reused across all requests.

    LLM_PROVIDER=deepseek  → DeepSeekProvider  (development default)
    LLM_PROVIDER=anthropic → AnthropicProvider (production / final testing)
    """
    settings = get_settings()
    provider_name = settings.llm_provider

    if provider_name == "anthropic":
        from core.llm.anthropic_provider import AnthropicProvider
        provider = AnthropicProvider()
        logger.info(
            "llm_provider_initialised",
            provider="anthropic",
            model=provider.model_name,
            env=settings.app_env,
        )
        return provider

    if provider_name == "deepseek":
        from core.llm.deepseek_provider import DeepSeekProvider
        provider = DeepSeekProvider()
        logger.info(
            "llm_provider_initialised",
            provider="deepseek",
            model=provider.model_name,
            env=settings.app_env,
        )
        return provider

    # Should never reach here — Pydantic validator in config catches invalid values
    raise ValueError(f"Unknown LLM provider: '{provider_name}'")


def reset_llm_provider():
    """
    Clears the cached provider. Use in tests to swap providers between test cases.
    NOT for production use.
    """
    get_llm_provider.cache_clear()
    logger.debug("llm_provider_cache_cleared")
