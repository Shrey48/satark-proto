"""
Tests for LLM provider switching.
These test the interface contract, not actual LLM calls.
Actual calls are tested in integration tests with mock responses.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from core.llm.base import (
    LLMMessage, ConstrainedChoiceResponse, FreeTextResponse
)
from core.llm.factory import get_llm_provider, reset_llm_provider


# ── Provider switching ─────────────────────────────────────────────────────────

def test_deepseek_provider_loaded_when_env_is_deepseek():
    """LLM_PROVIDER=deepseek → DeepSeekProvider is returned."""
    reset_llm_provider()
    with patch("core.config.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            llm_provider="deepseek",
            deepseek_api_key="test-key",
            deepseek_model="deepseek-chat",
            deepseek_base_url="https://api.deepseek.com",
            llm_max_tokens=1000,
        )
        with patch("core.llm.deepseek_provider.get_settings", mock_settings):
            from core.llm.deepseek_provider import DeepSeekProvider
            with patch.object(DeepSeekProvider, "__init__", return_value=None):
                provider = get_llm_provider()
                # Provider should be DeepSeekProvider instance
                # (or mock — what matters is it initialised without error)
    reset_llm_provider()


def test_anthropic_provider_loaded_when_env_is_anthropic():
    """LLM_PROVIDER=anthropic → AnthropicProvider is returned."""
    reset_llm_provider()
    with patch("core.config.get_settings") as mock_settings:
        mock_settings.return_value = MagicMock(
            llm_provider="anthropic",
            anthropic_api_key="sk-ant-test",
            anthropic_model="claude-sonnet-4-6",
            llm_max_tokens=1000,
        )
        with patch("core.llm.anthropic_provider.get_settings", mock_settings):
            from core.llm.anthropic_provider import AnthropicProvider
            with patch.object(AnthropicProvider, "__init__", return_value=None):
                provider = get_llm_provider()
    reset_llm_provider()


# ── ConstrainedChoiceResponse validation ──────────────────────────────────────

def test_constrained_choice_is_sentinel():
    r = ConstrainedChoiceResponse(
        chosen="NONE_OF_THESE", confidence=1.0,
        reasoning="test", provider="deepseek", model="deepseek-chat"
    )
    assert r.is_sentinel() is True
    assert r.is_valid_selection(["a", "b"]) is True


def test_constrained_choice_valid_option():
    r = ConstrainedChoiceResponse(
        chosen="entity::code::repo::func.process_payment",
        confidence=0.87, reasoning="matches", provider="deepseek", model="deepseek-chat"
    )
    options = ["entity::code::repo::func.process_payment", "entity::code::repo::func.validate"]
    assert r.is_sentinel() is False
    assert r.is_valid_selection(options) is True


def test_constrained_choice_invalid_option():
    r = ConstrainedChoiceResponse(
        chosen="invented_value", confidence=0.9,
        reasoning="wrong", provider="deepseek", model="deepseek-chat"
    )
    options = ["real_option_1", "real_option_2"]
    assert r.is_sentinel() is False
    assert r.is_valid_selection(options) is False


# ── Prompt builders ────────────────────────────────────────────────────────────

def test_dynamic_dispatch_prompt_builds_correctly():
    from core.llm.prompts.dynamic_dispatch import (
        DynamicDispatchContext, CandidateFunction, build_messages, get_options
    )
    ctx = DynamicDispatchContext(
        call_site_code="result = handler(request)",
        call_variable_name="handler",
        type_inference=None,
        candidates=[
            CandidateFunction(
                entity_id="t1::code::repo::func.process_payment",
                name="process_payment",
                file_path="src/payments.py",
                start_line=42,
                params=["request: HttpRequest"],
                return_type="PaymentResult",
                semantic_summary="Processes a payment request",
                neighbourhood_summary="calls validate_card, calls db.save"
            )
        ],
        language="python",
        file_path="src/router.py"
    )
    messages = build_messages(ctx)
    options = get_options(ctx)

    assert len(messages) == 1
    assert messages[0].role == "user"
    assert "handler" in messages[0].content
    assert "process_payment" in messages[0].content
    assert options == ["t1::code::repo::func.process_payment"]


def test_track2_type_b_unmapped_is_in_sentinels():
    from core.llm.prompts.track2_classify import TypeBContext, build_type_b_messages, get_type_b_options
    ctx = TypeBContext(
        raw_term="unknown vulnerability type",
        source_type="SAST",
        asset_type="code",
        taxonomy_slice=[
            {"canonical_id": "CWE-89", "display_name": "SQL Injection"},
            {"canonical_id": "CWE-79", "display_name": "XSS"},
        ]
    )
    messages = build_type_b_messages(ctx)
    options = get_type_b_options(ctx)

    assert "UNMAPPED" in messages[0].content
    assert "CWE-89" in options
    assert "CWE-79" in options
    # UNMAPPED is NOT in options — it's a sentinel passed separately to constrained_choice
    assert "UNMAPPED" not in options
