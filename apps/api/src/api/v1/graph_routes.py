"""SATARK Layer 1 — Graph Query + Linking Routes"""
from fastapi import APIRouter
from core.database.neo4j import tenant_session
from track1.pass2.linker import run_linking
import structlog

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.get("/nodes")
async def get_nodes(domain_type: str = None, limit: int = 500):
    async with tenant_session() as session:
        if domain_type:
            result = await session.run(
                "MATCH (n:Node {domain_type: $domain_type}) WHERE n.valid_to IS NULL RETURN n LIMIT $limit",
                domain_type=domain_type, limit=limit)
        else:
            result = await session.run(
                "MATCH (n:Node) WHERE n.valid_to IS NULL RETURN n LIMIT $limit", limit=limit)
        nodes = [dict(r["n"]) async for r in result]
    return {"nodes": nodes, "count": len(nodes)}


@router.get("/edges")
async def get_edges(limit: int = 1000):
    async with tenant_session() as session:
        result = await session.run(
            """
            MATCH (a:Node)-[r:EDGE]->(b:Node)
            WHERE a.valid_to IS NULL AND b.valid_to IS NULL
            RETURN a.entity_id AS source, b.entity_id AS target,
                   r.edge_type AS edge_type, r.confidence AS confidence
            LIMIT $limit
            """, limit=limit)
        edges = [dict(r) async for r in result]
    return {"edges": edges, "count": len(edges)}


@router.get("/stats")
async def get_stats():
    async with tenant_session() as session:
        result = await session.run(
            "MATCH (n:Node) WHERE n.valid_to IS NULL RETURN n.domain_type AS domain, count(n) AS count ORDER BY count DESC")
        by_domain = {}
        async for r in result:
            by_domain[r["domain"] or "unknown"] = r["count"]
        total_r = await session.run("MATCH ()-[r:EDGE]->() RETURN count(r) AS total")
        total_edges = 0
        async for r in total_r:
            total_edges = r["total"]
    return {"nodes_by_domain": by_domain, "total_nodes": sum(by_domain.values()), "total_edges": total_edges}


@router.get("/firewall-posture")
async def get_firewall_posture():
    async with tenant_session() as session:
        result = await session.run(
            """
            MATCH (n:Node) WHERE n.valid_to IS NULL AND n.domain_type IN ['cloud','k8s']
            RETURN n.entity_id AS id, n.name AS name,
                   n.resource_subtype AS subtype, n.firewall_posture AS posture,
                   n.domain_type AS domain
            ORDER BY n.firewall_posture
            """)
        nodes = [dict(r) async for r in result]
    return {"nodes": nodes, "count": len(nodes)}


@router.post("/link")
async def run_link():
    """
    Trigger Pass 2 + Pass 3 linking and Sub-step F firewall posture computation.
    Call this after uploading all your assets.
    """
    results = await run_linking()
    return {
        "status": "ok",
        "message": "Linking and firewall posture computation complete",
        **results,
    }
