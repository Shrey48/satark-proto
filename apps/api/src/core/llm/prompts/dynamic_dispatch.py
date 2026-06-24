"""
SATARK Layer 1 — Dynamic Dispatch LLM Prompt (Section 4.1 Touchpoint 1)

Called when a function is invoked through a variable and the AST parser
cannot determine the call target deterministically.

LLM context (from spec Section 4.1 — exactly 5 elements):
  1. Call site AST node + surrounding 3 lines of source context
  2. Variable type inference chain (if available from static type checker)
  3. Full signature of each candidate function (name, params, return type, file_path)
  4. source_location + node_metadata of each candidate
  5. 1-hop graph neighbourhood of each candidate (max 5 nodes per candidate)

All within the 100-node hard cap (Section 3.7).

Output: entity_id of the selected candidate OR NONE_OF_THESE
"""
from dataclasses import dataclass
from typing import Optional
from core.llm.base import LLMMessage


@dataclass
class CandidateFunction:
    entity_id: str
    name: str
    file_path: str
    start_line: int
    params: list[str]
    return_type: str
    semantic_summary: str
    neighbourhood_summary: str   # 1-hop neighbours, summarised


@dataclass
class DynamicDispatchContext:
    call_site_code: str          # The call site line + 3 lines context
    call_variable_name: str      # The variable being called (e.g. "handler", "fn")
    type_inference: Optional[str]  # Type system hint if available (None if not)
    candidates: list[CandidateFunction]  # Max 8 (hard cap from spec)
    language: str                # "python", "javascript", "typescript", "java", "go"
    file_path: str               # Where the call site is


SYSTEM_PROMPT = """You are analysing code to determine the most likely target of a dynamic function call.
A dynamic call is when a function is invoked through a variable (e.g. handler(request)) rather than
by name (e.g. process_payment(request)).

Your task: identify which of the candidate functions is the most likely target of this call.
Base your decision on: function signatures, parameter types, what the calling context suggests,
and what each function's neighbourhood in the call graph tells you about its role.

Be precise. Prefer a specific answer over NONE_OF_THESE unless you genuinely cannot determine it."""


def build_messages(ctx: DynamicDispatchContext) -> list[LLMMessage]:
    """Build the messages list for the dynamic dispatch LLM call."""
    candidates_text = []
    for i, c in enumerate(ctx.candidates, 1):
        candidates_text.append(
            f"Candidate {i}: {c.name}\n"
            f"  entity_id: {c.entity_id}\n"
            f"  file: {c.file_path} (line {c.start_line})\n"
            f"  signature: {c.name}({', '.join(c.params)}) -> {c.return_type}\n"
            f"  description: {c.semantic_summary}\n"
            f"  connected to: {c.neighbourhood_summary}"
        )

    type_hint = f"\nType inference chain: {ctx.type_inference}" if ctx.type_inference else ""

    user_message = f"""Language: {ctx.language}
File: {ctx.file_path}

Call site:
{ctx.call_site_code}

The variable '{ctx.call_variable_name}' is being called dynamically.{type_hint}

Candidate functions this variable could be calling:

{chr(10).join(candidates_text)}

Which of these is the most likely target of the dynamic call?"""

    return [LLMMessage(role="user", content=user_message)]


def get_options(ctx: DynamicDispatchContext) -> list[str]:
    """Returns the valid entity_id options for this call."""
    return [c.entity_id for c in ctx.candidates]
