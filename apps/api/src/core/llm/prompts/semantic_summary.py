"""
SATARK Layer 1 — Semantic Summary Prompt (Section 4.1 Touchpoint 3)

Called when a node's semantic_summary cannot be derived from:
  Step 1: native tags/labels in the file
  Step 2: structural inference from graph neighbourhood
Only then does this LLM call run as Step 3.

IMPORTANT: semantic_summary is presentation-layer ONLY.
It NEVER feeds any scoring formula, edge creation, or decision logic.
Wrong summary = bad UX, not wrong graph (Section 3.4).

LLM context (from spec Section 4.1 Touchpoint 3):
  1. Node type and domain_type
  2. source_location (file path and line range)
  3. Structural signature of the node
  4. GKG technology context (framework, domain, typical role of this construct type)
  5. 1-hop graph neighbourhood (source_location and domain_type only)

Output: free text, 1–3 sentences, plain English description.
"""
from dataclasses import dataclass
from typing import Optional
from core.llm.base import LLMMessage


@dataclass
class SummaryContext:
    node_type: str           # e.g. "Function", "Endpoint", "S3Bucket"
    domain_type: str         # One of the 12 domain types
    file_path: str
    start_line: int
    end_line: int
    structural_signature: str  # Serialised summary of structural properties
    gkg_context: Optional[str]  # Technology context from GKG (may be None if GKG has no knowledge)
    neighbourhood: str         # 1-hop neighbours: "calls X, called by Y, connected to Z"
    language: Optional[str] = None   # For code nodes


SYSTEM_PROMPT = """You are generating a brief plain English description of a node in a security knowledge graph.
The description will be shown in a security dashboard to help engineers understand what this component is and what it does.

Rules:
- 1 to 3 sentences maximum
- Plain English, no jargon unless necessary
- Focus on what the component DOES, not how it is implemented
- If it's a security-relevant component (firewall, auth handler, data processor), say so clearly
- Do not guess at specific business logic — describe based on structure only
- Do not reference internal variable names or implementation details"""


def build_messages(ctx: SummaryContext) -> list[LLMMessage]:
    lang_note = f"\nLanguage: {ctx.language}" if ctx.language else ""
    gkg_note = f"\nTechnology context (from knowledge base): {ctx.gkg_context}" if ctx.gkg_context else ""

    user_message = f"""Generate a brief description for this component.

Node type: {ctx.node_type}
Domain: {ctx.domain_type}{lang_note}
Location: {ctx.file_path} (lines {ctx.start_line}–{ctx.end_line})
Structural properties: {ctx.structural_signature}{gkg_note}
Connected to: {ctx.neighbourhood}

Write 1–3 plain English sentences describing what this component is and what it does."""

    return [LLMMessage(role="user", content=user_message)]
