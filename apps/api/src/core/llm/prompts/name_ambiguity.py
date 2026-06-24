"""
SATARK Layer 1 — Name Ambiguity Resolution Prompt (Section 4.1 Touchpoint 2)
                  Layer 4 of the 4-Layer Name-Keyed Linking Hierarchy (Section 4.4a)

Called when Registry lookup (Layer 2) and structural signature matching (Layer 3)
both fail to produce a confident match. This is the genuine residual (~2–5% of links).

LLM context (from spec Section 4.4a Layer 4):
  - Full structural signatures of both candidate nodes
  - All known aliases from Component 8 for both
  - 1-hop graph neighbourhood of both
  - source_location of both
  - Any documentation strings from node_metadata

Output: entity_id of the matched candidate, UNCERTAIN, or NONE_OF_THESE
  UNCERTAIN  → surface to Graph Link Review Interface (human decision needed)
  NONE_OF_THESE → no match found, stub node remains, gap flagged
"""
from dataclasses import dataclass, field
from typing import Optional
from core.llm.base import LLMMessage


@dataclass
class NodeContext:
    entity_id: str
    domain_type: str
    file_path: str
    block_identifier: str
    structural_signature: str      # Serialised summary of the structural signature
    known_aliases: list[str]       # All aliases from Component 8
    neighbourhood_summary: str     # 1-hop neighbours
    semantic_summary: str          # May be empty
    documentation: Optional[str] = None


SYSTEM_PROMPT = """You are resolving a cross-asset link in a security knowledge graph.
Two nodes from different source files may represent the same real-world service, component,
or resource. Earlier deterministic methods (name registry lookup, structural signature
matching) did not produce a confident match.

Your task: determine whether Node A and Node B represent the same real-world entity.
Analyse their structural signatures, known aliases, graph neighbourhoods, and source locations.

Answer UNCERTAIN only if you genuinely cannot tell — it is better to send to human review
than to make a confident wrong decision that corrupts the knowledge graph.
Never create links that are not clearly supported by the evidence."""


def build_messages(node_a: NodeContext, node_b: NodeContext) -> list[LLMMessage]:
    """Build the messages for the name ambiguity resolution call."""

    def format_node(label: str, n: NodeContext) -> str:
        aliases = ", ".join(n.known_aliases) if n.known_aliases else "none found"
        doc = f"\n  documentation: {n.documentation}" if n.documentation else ""
        return (
            f"{label}:\n"
            f"  entity_id: {n.entity_id}\n"
            f"  domain_type: {n.domain_type}\n"
            f"  location: {n.file_path} / {n.block_identifier}\n"
            f"  known aliases: {aliases}\n"
            f"  structural signature: {n.structural_signature}\n"
            f"  connected to: {n.neighbourhood_summary}\n"
            f"  description: {n.semantic_summary}{doc}"
        )

    user_message = f"""{format_node("Node A (source node seeking a link)", node_a)}

{format_node("Node B (candidate link target)", node_b)}

Do these two nodes represent the same real-world entity?
If yes: return the entity_id of Node B as 'chosen'.
If no: return NONE_OF_THESE.
If you cannot determine with reasonable confidence: return UNCERTAIN."""

    return [LLMMessage(role="user", content=user_message)]


def get_options(node_b: NodeContext) -> list[str]:
    return [node_b.entity_id]
