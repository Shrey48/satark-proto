"""
SATARK Layer 1 — DeepSeek LLM Provider

Used in: development, cost-effective testing.
Set LLM_PROVIDER=deepseek in .env to activate.

DeepSeek exposes an OpenAI-compatible API, so we use the openai Python SDK
pointed at DeepSeek's base URL. No DeepSeek-specific SDK needed.

Models:
  deepseek-chat     — DeepSeek-V3.  Fast, cheap. Good for most SATARK calls.
  deepseek-reasoner — DeepSeek-R1.  Slower, better on complex reasoning tasks.
                      Consider for Layer 4 name ambiguity resolution if needed.

Constraint enforcement strategy:
  Uses JSON output mode (response_format={"type": "json_object"}) which is
  supported by both deepseek-chat and deepseek-reasoner. This forces the model
  to always return valid JSON — cleaner than retry-based enforcement.
"""
import json
import structlog
from openai import AsyncOpenAI
from openai import APIStatusError, APITimeoutError, RateLimitError

from core.llm.base import (
    LLMProvider, LLMMessage, ConstrainedChoiceResponse, FreeTextResponse
)
from core.config import get_settings

logger = structlog.get_logger(__name__)


class DeepSeekProvider(LLMProvider):

    def __init__(self):
        settings = get_settings()
        if not settings.deepseek_api_key:
            raise ValueError(
                "DEEPSEEK_API_KEY is not set. "
                "Get a key from https://platform.deepseek.com and add it to .env"
            )
        # DeepSeek is OpenAI-compatible — just point the OpenAI client at DeepSeek's base URL
        self._client = AsyncOpenAI(
            api_key=settings.deepseek_api_key,
            base_url=settings.deepseek_base_url,
        )
        self._model = settings.deepseek_model
        self._max_tokens = settings.llm_max_tokens

    @property
    def provider_name(self) -> str:
        return "deepseek"

    @property
    def model_name(self) -> str:
        return self._model

    def _build_constrained_system_prompt(
        self, base_system: str, options: list[str], allow_sentinels: list[str]
    ) -> str:
        all_valid = options + allow_sentinels
        return f"""{base_system}

RESPONSE FORMAT — MANDATORY:
You MUST respond with ONLY a valid JSON object. No prose. No markdown.
Exactly three fields:

{{
  "chosen": "<exactly one value from the list below>",
  "confidence": <float between 0.0 and 1.0>,
  "reasoning": "<one sentence explaining your choice>"
}}

VALID VALUES FOR "chosen":
{chr(10).join(f'  - "{v}"' for v in all_valid)}"""

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
        api_messages = [{"role": "system", "content": system}]
        api_messages += [{"role": m.role, "content": m.content} for m in messages]

        for attempt in range(2):
            try:
                response = await self._client.chat.completions.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    messages=api_messages,
                    temperature=temperature,
                    response_format={"type": "json_object"},  # DeepSeek JSON mode
                )
                raw = response.choices[0].message.content.strip()
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
                    correction = (
                        f"Invalid response. '{parsed.get('chosen', '')}' is not in the valid options. "
                        f"Pick from: {list(all_valid)}. Respond with ONLY JSON."
                    )
                    api_messages.append({"role": "assistant", "content": raw})
                    api_messages.append({"role": "user", "content": correction})

            except RateLimitError:
                logger.warning("deepseek_rate_limit", attempt=attempt)
                raise
            except (APIStatusError, APITimeoutError) as e:
                logger.error("deepseek_api_error", error=str(e), attempt=attempt)
                raise

        logger.warning("deepseek_constrained_choice_fallback", options_count=len(options))
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
        api_messages = [{"role": "system", "content": system_prompt}]
        api_messages += [{"role": m.role, "content": m.content} for m in messages]
        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                max_tokens=self._max_tokens,
                messages=api_messages,
                temperature=temperature,
                # No JSON mode for free text — we want natural language output
            )
            text = response.choices[0].message.content.strip()
            return FreeTextResponse(
                text=text,
                provider=self.provider_name,
                model=self.model_name,
                raw_response=text,
            )
        except (APIStatusError, APITimeoutError, RateLimitError) as e:
            logger.error("deepseek_free_text_error", error=str(e))
            raise

    @staticmethod
    def _parse_json_response(raw: str) -> dict | None:
        text = raw.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1]) if len(lines) > 2 else text
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
        return None
