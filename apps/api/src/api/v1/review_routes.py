"""
SATARK Layer 1 — Graph Link Review Interface (spec Section 4.4b)

Serves edges created by fuzzy/LLM matching that need human confirmation.
Three responses:
  confirmed  → edge becomes human_confirmed, confidence 1.0, alias written to Component 8
  rejected   → edge deleted, exclusion rule written to Component 8
  unsure     → gap flagged, edge preserved for later
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from core.database.neo4j import tenant_session
from core.components.registry import write_alias, write_exclusion
import structlog

router = APIRouter()
logger = structlog.get_logger(__name__)


class ReviewDecision(BaseModel):
    edge_id: str          # "from_entity_id|edge_type|to_entity_id"
    decision: str         # "confirmed" | "rejected" | "unsure"
    reviewer_note: str = ""


@router.get("/queue")
async def get_review_queue(limit: int = 50):
    """
    Return all edges that need human review.
    Includes: fuzzy_matched edges, llm_inferred edges, low-confidence links.
    """
    async with tenant_session() as session:
        result = await session.run("""
            MATCH (a:Node)-[r:EDGE]->(b:Node)
            WHERE r.resolution_method IN ['fuzzy_matched', 'llm_inferred']
            AND a.valid_to IS NULL AND b.valid_to IS NULL
            RETURN
                a.entity_id AS from_id, a.name AS from_name,
                a.domain_type AS from_domain, a.node_type AS from_type,
                a.file_path AS from_file, a.semantic_summary AS from_summary,
                b.entity_id AS to_id, b.name AS to_name,
                b.domain_type AS to_domain, b.node_type AS to_type,
                b.file_path AS to_file, b.semantic_summary AS to_summary,
                r.edge_type AS edge_type, r.confidence AS confidence,
                r.resolution_method AS method, r.created_at AS created_at
            ORDER BY r.confidence ASC
            LIMIT $limit
        """, limit=limit)

        items = []
        async for rec in result:
            from_id   = rec["from_id"]
            to_id     = rec["to_id"]
            edge_type = rec["edge_type"]
            items.append({
                "edge_id": f"{from_id}|{edge_type}|{to_id}",
                "from": {
                    "entity_id":  from_id,
                    "name":       rec["from_name"],
                    "domain":     rec["from_domain"],
                    "type":       rec["from_type"],
                    "file":       rec["from_file"],
                    "summary":    rec["from_summary"],
                },
                "to": {
                    "entity_id":  to_id,
                    "name":       rec["to_name"],
                    "domain":     rec["to_domain"],
                    "type":       rec["to_type"],
                    "file":       rec["to_file"],
                    "summary":    rec["to_summary"],
                },
                "edge_type":  edge_type,
                "confidence": rec["confidence"],
                "method":     rec["method"],
                "created_at": str(rec["created_at"]),
            })

    return {"items": items, "count": len(items)}


@router.post("/decide")
async def submit_decision(decision: ReviewDecision):
    """
    Submit a human review decision for a pending edge.
    """
    parts = decision.edge_id.split("|")
    if len(parts) != 3:
        raise HTTPException(400, "edge_id must be from_id|edge_type|to_id")

    from_id, edge_type, to_id = parts

    if decision.decision not in ("confirmed", "rejected", "unsure"):
        raise HTTPException(400, "decision must be confirmed | rejected | unsure")

    async with tenant_session() as session:
        if decision.decision == "confirmed":
            # Promote edge to human_confirmed, confidence 1.0
            r = await session.run("""
                MATCH (a:Node {entity_id: $from_id})-[rel:EDGE {edge_type: $edge_type}]->(b:Node {entity_id: $to_id})
                SET rel.resolution_method = 'human_confirmed',
                    rel.confidence = 1.0,
                    rel.reviewed_at = datetime(),
                    rel.reviewer_note = $note
                RETURN a.name AS aname, b.name AS bname
            """, from_id=from_id, to_id=to_id,
                 edge_type=edge_type, note=decision.reviewer_note)
            rec = await r.single()
            if rec:
                # Write alias to Component 8 registry so this resolution is reused
                await write_alias(
                    org_id="prototype",
                    informal_name=rec["aname"],
                    canonical_entity_id=to_id,
                    context=edge_type,
                    source="human_confirmed",
                )
                logger.info("review_confirmed", from_name=rec["aname"],
                            to_name=rec["bname"], edge=edge_type)
            return {"status": "confirmed", "message": "Edge confirmed, alias written to registry"}

        elif decision.decision == "rejected":
            # Get node names before deleting
            r = await session.run("""
                MATCH (a:Node {entity_id: $from_id})-[rel:EDGE {edge_type: $edge_type}]->(b:Node {entity_id: $to_id})
                RETURN a.name AS aname, b.name AS bname
            """, from_id=from_id, to_id=to_id, edge_type=edge_type)
            rec = await r.single()

            # Delete the edge
            del_r = await session.run("""
                MATCH (a:Node {entity_id: $from_id})-[rel:EDGE {edge_type: $edge_type}]->(b:Node {entity_id: $to_id})
                DELETE rel
            """, from_id=from_id, to_id=to_id, edge_type=edge_type)
            await del_r.consume()

            # Write exclusion rule to Component 8
            if rec:
                await write_exclusion(
                    org_id="prototype",
                    name_a=rec["aname"],
                    name_b=rec["bname"],
                    context=edge_type,
                    confirmed_by="reviewer",
                )
                logger.info("review_rejected", from_name=rec["aname"],
                            to_name=rec["bname"], edge=edge_type)
            return {"status": "rejected", "message": "Edge deleted, exclusion rule written"}

        else:  # unsure
            # Flag edge as gap — preserve but mark for later
            r = await session.run("""
                MATCH (a:Node {entity_id: $from_id})-[rel:EDGE {edge_type: $edge_type}]->(b:Node {entity_id: $to_id})
                SET rel.gap_flagged = true, rel.reviewed_at = datetime(),
                    rel.reviewer_note = $note
            """, from_id=from_id, to_id=to_id,
                 edge_type=edge_type, note=decision.reviewer_note)
            await r.consume()
            logger.info("review_unsure", from_id=from_id, to_id=to_id)
            return {"status": "unsure", "message": "Gap flagged — no edge created, no exclusion"}


@router.get("/stats")
async def review_stats():
    """Queue statistics."""
    async with tenant_session() as session:
        r = await session.run("""
            MATCH ()-[rel:EDGE]->()
            RETURN
                count(CASE WHEN rel.resolution_method IN ['fuzzy_matched','llm_inferred'] AND rel.gap_flagged IS NULL THEN 1 END) AS pending,
                count(CASE WHEN rel.resolution_method = 'human_confirmed' THEN 1 END) AS confirmed,
                count(CASE WHEN rel.gap_flagged = true THEN 1 END) AS gaps
        """)
        rec = await r.single()
        return {
            "pending": rec["pending"] if rec else 0,
            "confirmed": rec["confirmed"] if rec else 0,
            "gaps": rec["gaps"] if rec else 0,
        }
