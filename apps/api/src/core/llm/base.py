"""
SATARK Layer 1 — LLM Abstract Interface

Every LLM call in the system goes through this interface.
Callers never import from anthropic.py or deepseek.py directly.
They import from factory.py and call the interface methods.

Three touchpoints in Track 1 (Section 4.1):
  1. Dynamic dispatch resolution     → constrained_choice()
  2. Name ambiguity resolution       → constrained_choice()
  3. Semantic summary generation     → free_text()

Three call types in Track 2 (Section 7.6):
  Type A  — narrow disambiguation    → constrained_choice()
  Type A* — new context + wider set  → constrained_choice()
  Type B  — full classification      → constrained_choice() with UNMAPPED allowed

All responses carry:
  - chosen: the selected value (entity_id, canonical_id, or text)
  - confidence: float 0.0–1.0 (LLM self-reported)
  - reasoning: brief explanation of why (for audit trail)
  - provider: which LLM provider produced this response
  - model: exact model name used
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LLMMessage:
    """A single message in the conversation. Role is 'user' or 'assistant'."""
    role: str        # "user" or "assistant"
    content: str


@dataclass
class ConstrainedChoiceResponse:
    """
    Response for calls where the LLM must pick from a supplied set of options.

    Used for:
    - Track 1 dynamic dispatch resolution (pick from candidate entity_ids or NONE_OF_THESE)
    - Track 1 name ambiguity resolution   (pick from candidate entity_ids or NONE_OF_THESE or UNCERTAIN)
    - Track 2 Type A narrow               (pick from candidate canonical_ids)
    - Track 2 Type A* new context         (pick a canonical_id from taxonomy)
    - Track 2 Type B full classification  (pick a canonical_id or UNMAPPED)

    The chosen field MUST be one of the values from the options list,
    or one of the reserved sentinel values (NONE_OF_THESE, UNCERTAIN, UNMAPPED).
    The provider implementation is responsible for enforcing this constraint.
    """
    chosen: str               # Selected option from the supplied set, or sentinel
    confidence: float         # 0.0–1.0 self-reported by the LLM
    reasoning: str            # Brief explanation for audit trail
    provider: str             # "anthropic" or "deepseek"
    model: str                # Exact model name, e.g. "claude-sonnet-4-6" or "deepseek-chat"
    raw_response: Optional[str] = None  # Full raw response text for debugging

    # Sentinel values — these are the only non-option values allowed in `chosen`
    NONE_OF_THESE = "NONE_OF_THESE"
    UNCERTAIN = "UNCERTAIN"
    UNMAPPED = "UNMAPPED"

    def is_sentinel(self) -> bool:
        return self.chosen in (self.NONE_OF_THESE, self.UNCERTAIN, self.UNMAPPED)

    def is_valid_selection(self, options: list[str]) -> bool:
        return self.chosen in options or self.is_sentinel()


@dataclass
class FreeTextResponse:
    """
    Response for calls where the LLM generates free text (no constraint).

    Used for:
    - Track 1 semantic summary generation (Section 3.4 node_metadata.semantic_summary)

    The text field is presentation-layer only — it NEVER feeds any scoring
    formula, edge creation decision, or downstream processing logic.
    Wrong text = bad UX, not wrong graph.
    """
    text: str
    provider: str
    model: str
    raw_response: Optional[str] = None


class LLMProvider(ABC):
    """
    Abstract base class for all LLM providers.
    Implement this for any new provider. Two methods. That's it.
    """

    @abstractmethod
    async def constrained_choice(
        self,
        system_prompt: str,
        messages: list[LLMMessage],
        options: list[str],
        allow_sentinels: list[str],
        temperature: float = 0.0,
    ) -> ConstrainedChoiceResponse:
        """
        Ask the LLM to pick from a closed set of options.

        The LLM must return exactly one of:
        - A value from the `options` list
        - One of the values in `allow_sentinels` (e.g. NONE_OF_THESE, UNMAPPED)

        temperature=0.0 by default — determinism matters for constrained choices.
        Implementations must retry with explicit re-prompting if the LLM returns
        a value not in the options list.
        """
        ...

    @abstractmethod
    async def free_text(
        self,
        system_prompt: str,
        messages: list[LLMMessage],
        temperature: float = 0.1,
    ) -> FreeTextResponse:
        """
        Ask the LLM to generate free text.
        Only used for semantic_summary generation. Not for any decision logic.
        """
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Returns the provider name: 'anthropic' or 'deepseek'."""
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Returns the exact model name being used."""
        ...
