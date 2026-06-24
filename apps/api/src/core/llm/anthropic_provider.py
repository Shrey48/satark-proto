"""
SATARK Layer 1 — Anthropic / Claude LLM Provider

Used in: production, final testing.
Set LLM_PROVIDER=anthropic in .env to activate.

Model: claude-sonnet-4-6 (default — fast, accurate, cost-effective at scale)

Constraint enforcement strategy:
  constrained_choice() uses Claude's JSON mode via a structured system prompt
  that instructs the model to respond ONLY with a JSON object containing
  {chosen, confidence, reasoning}. The chosen field is validated against
  the options list. If validation fails, one retry with explicit correction.
"""
import json
import structlog
from anthropic import AsyncAnthropic
from anthropic import APIStatusError, APITimeoutError, RateLimitError

from core.llm.base import (
    LLMProvider, LLMMessage, ConstrainedChoiceResponse, FreeTextResponse
)
from core.config import get_settings

logger = structlog.get_logger(__name__)


class AnthropicProvider(LLMProvider):

    def __init__(self):
        settings = get_settings()
        if not settings.anthropic_api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. "
                "Set it in .env or set LLM_PROVIDER=deepseek for development."
            )
        self._client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        self._model = settings.anthropic_model
        self._max_tokens = settings.llm_max_tokens

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self._model

    def _build_constrained_system_prompt(
        self, base_system: str, options: list[str], allow_sentinels: list[str]
    ) -> str:
        all_valid = options + allow_sentinels
        return f"""{base_system}

RESPONSE FORMAT — MANDATORY:
You MUST respond with ONLY a valid JSON object. No prose before or after. No markdown fences.
The JSON must have exactly these three fields:

{{
  "chosen": "<exactly one value from the list below>",
  "confidence": <float between 0.0 and 1.0>,
  "reasoning": "<one sentence explaining your choice>"
}}

VALID VALUES FOR "chosen" (pick exactly one):
{chr(10).join(f'  - "{v}"' for v in all_valid)}

If none of the options are appropriate and the sentinels include "NONE_OF_THESE",
return {{"chosen": "NONE_OF_THESE", "confidence": 1.0, "reasoning": "..."}}"""

    async def constrained_choice(
        self,
        system_prompt: str,
        messages: list[LLMMessage],
        options: list[str],
        allow_sentinels: list[str],
        temperature: float = 0.0,
    ) -> ConstrainedChoiceResponse:
        all_valid = set(options + allow_sentinels)
        system = self._build_constrained_system_prompt(system_prompt, options, allow_sentinels)
        api_messages = [{"role": m.role, "content": m.content} for m in messages]

        for attempt in range(2):
            try:
                response = await self._client.messages.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    system=system,
                    messages=api_messages,
                    temperature=temperature,
                )
                raw = response.content[0].text.strip()
                parsed = self._parse_json_response(raw)

                if parsed and parsed.get("chosen") in all_valid:
                    return ConstrainedChoiceResponse(
                        chosen=parsed["chosen"],
                        confidence=float(parsed.get("confidence", 0.5)),
                        reasoning=parsed.get("reasoning", ""),
                        provider=self.provider_name,
                        model=self.model_name,
                        raw_response=raw,
                    )

                if attempt == 0:
                    # Retry with explicit correction
                    correction = (
                        f"Your previous response was invalid. "
                        f"You chose '{parsed.get('chosen', 'nothing')}' which is not in the valid options list. "
                        f"You MUST pick from: {list(all_valid)}. Respond with ONLY the JSON object."
                    )
                    api_messages = api_messages + [
                        {"role": "assistant", "content": raw},
                        {"role": "user", "content": correction},
                    ]

            except RateLimitError:
                logger.warning("anthropic_rate_limit", attempt=attempt)
                raise
            except (APIStatusError, APITimeoutError) as e:
                logger.error("anthropic_api_error", error=str(e), attempt=attempt)
                raise

        # Both attempts failed — return NONE_OF_THESE as safe fallback
        logger.warning("anthropic_constrained_choice_fallback", options_count=len(options))
        sentinel = "NONE_OF_THESE" if "NONE_OF_THESE" in allow_sentinels else allow_sentinels[0]
        return ConstrainedChoiceResponse(
            chosen=sentinel,
            confidence=0.0,
            reasoning="Failed to produce a valid constrained response after 2 attempts",
            provider=self.provider_name,
            model=self.model_name,
        )

    async def free_text(
        self,
        system_prompt: str,
        messages: list[LLMMessage],
        temperature: float = 0.1,
    ) -> FreeTextResponse:
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=system_prompt,
                messages=api_messages,
                temperature=temperature,
            )
            text = response.content[0].text.strip()
            return FreeTextResponse(
                text=text,
                provider=self.provider_name,
                model=self.model_name,
                raw_response=text,
            )
        except (APIStatusError, APITimeoutError, RateLimitError) as e:
            logger.error("anthropic_free_text_error", error=str(e))
            raise

    @staticmethod
    def _parse_json_response(raw: str) -> dict | None:
        """Extract JSON from response, handling common LLM formatting issues."""
        text = raw.strip()
        # Strip markdown fences if present
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1]) if len(lines) > 2 else text
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON object within the text
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
        return None
