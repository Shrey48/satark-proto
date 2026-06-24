"""
SATARK Layer 1 — Track 2 LLM Prompts (Section 7.6 Steps 4, 5, 6)

Three call types for the normalisation pipeline:

Type A  (Step 5) — narrow disambiguation
  The RawTerm is known but has multiple possible meanings.
  LLM picks from 2–4 known candidate canonical_ids (closed set).

Type A* (Step 4) — new context
  The RawTerm is known in other contexts but not in this (source_type, asset_type).
  LLM classifies with a wider candidate set + GKG CWE graph + CAPEC context.

Type B  (Step 6) — full classification
  The RawTerm is completely unknown. Full taxonomy slice + GKG context.
  UNMAPPED is a valid and expected output.
"""
from dataclasses import dataclass, field
from typing import Optional
from core.llm.base import LLMMessage


# ── SHARED SYSTEM PROMPT ──────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a security vulnerability classification expert.
Your task: classify a security finding from a tool into the correct canonical vulnerability class.

Rules:
- Choose the most specific matching vulnerability class
- If the finding describes multiple issues, choose the PRIMARY vulnerability
- Return UNMAPPED only if the finding genuinely does not match any provided class
- Never invent or use IDs not in the provided candidate list
- Confidence should reflect how certain you are, not how severe the finding is"""


# ── TYPE A: Narrow disambiguation ─────────────────────────────────────────────
@dataclass
class TypeAContext:
    raw_term: str                  # The exact finding title/description from the tool
    source_type: str               # SAST, DAST, Network_scan, IDS, etc.
    asset_type: str                # code, api, cloud, k8s, etc.
    candidates: list[dict]         # [{"canonical_id": ..., "display_name": ..., "description": ...}]


def build_type_a_messages(ctx: TypeAContext) -> list[LLMMessage]:
    """Step 5 — narrow disambiguation among 2–4 known candidates."""
    candidates_text = "\n".join(
        f'  - "{c["canonical_id"]}": {c["display_name"]} — {c["description"]}'
        for c in ctx.candidates
    )
    user_message = f"""Finding from tool:
  Text: "{ctx.raw_term}"
  Source type: {ctx.source_type}
  Asset type: {ctx.asset_type}

This finding text is known but ambiguous. Candidate classifications:
{candidates_text}

Which canonical_id best matches this finding in the context of a {ctx.source_type} scan on a {ctx.asset_type} asset?"""
    return [LLMMessage(role="user", content=user_message)]

def get_type_a_options(ctx: TypeAContext) -> list[str]:
    return [c["canonical_id"] for c in ctx.candidates]


# ── TYPE A*: New context ──────────────────────────────────────────────────────
@dataclass
class TypeAStarContext:
    raw_term: str
    source_type: str
    asset_type: str
    candidates: list[dict]         # Wider set than Type A
    gkg_context: Optional[str] = None  # CWE graph + CAPEC relationships from GKG


def build_type_a_star_messages(ctx: TypeAStarContext) -> list[LLMMessage]:
    """Step 4 — new context. Wider candidates + GKG context."""
    candidates_text = "\n".join(
        f'  - "{c["canonical_id"]}": {c["display_name"]} — {c["description"]}'
        for c in ctx.candidates
    )
    gkg_note = f"\nSecurity knowledge context:\n{ctx.gkg_context}" if ctx.gkg_context else ""
    user_message = f"""Finding from tool:
  Text: "{ctx.raw_term}"
  Source type: {ctx.source_type}
  Asset type: {ctx.asset_type}

This finding text has not been classified in this context before.{gkg_note}

Candidate classifications:
{candidates_text}

Choose the canonical_id that best fits this finding in this new context."""
    return [LLMMessage(role="user", content=user_message)]

def get_type_a_star_options(ctx: TypeAStarContext) -> list[str]:
    return [c["canonical_id"] for c in ctx.candidates]


# ── TYPE B: Full classification ───────────────────────────────────────────────
@dataclass
class TypeBContext:
    raw_term: str
    source_type: str
    asset_type: str
    taxonomy_slice: list[dict]     # Domain-filtered subset of the full taxonomy
    gkg_context: Optional[str] = None  # CWE parent-child graph + CAPEC attack patterns


def build_type_b_messages(ctx: TypeBContext) -> list[LLMMessage]:
    """Step 6 — full classification. UNMAPPED is a valid output."""
    taxonomy_text = "\n".join(
        f'  - "{c["canonical_id"]}": {c["display_name"]} — {c.get("description", "")[:120]}'
        for c in ctx.taxonomy_slice[:50]   # Limit to 50 entries in context
    )
    gkg_note = f"\nSecurity knowledge context:\n{ctx.gkg_context}" if ctx.gkg_context else ""
    user_message = f"""Finding from tool (previously unclassified):
  Text: "{ctx.raw_term}"
  Source type: {ctx.source_type}
  Asset type: {ctx.asset_type}{gkg_note}

Available vulnerability classes for {ctx.asset_type} assets:
{taxonomy_text}

Classify this finding. Return UNMAPPED if it genuinely does not match any class."""
    return [LLMMessage(role="user", content=user_message)]

def get_type_b_options(ctx: TypeBContext) -> list[str]:
    return [c["canonical_id"] for c in ctx.taxonomy_slice]
