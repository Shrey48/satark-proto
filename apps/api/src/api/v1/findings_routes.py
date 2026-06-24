"""SATARK Layer 1 — Track 2 Finding Ingestion + Query Routes"""
import json
from fastapi import APIRouter, UploadFile, File, HTTPException, Body
from track2.pipeline import normalise_finding
from core.database.neo4j import tenant_session
import structlog

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("/ingest")
async def ingest_finding(finding: dict = Body(...)):
    """
    Ingest a single finding directly as JSON.
    Required fields: tool_name, title (or name or check_id), asset_location
    Optional: severity, description, line, input_type (A/B/C)
    """
    result = await normalise_finding(finding)
    return {
        "status": "ok",
        "finding_id": result["finding_id"],
        "canonical_id": result["canonical_id"],
        "confidence": result["confidence"],
        "resolution_method": result["resolution_method"],
        "human_review_required": result["human_review_required"],
        "source_type": result["source_type"],
        "normalised_asset_location": result["normalised_asset_location"],
    }


@router.post("/ingest/batch")
async def ingest_batch(file: UploadFile = File(...)):
    """
    Upload a JSON file containing an array of findings.
    Accepts Semgrep, Trivy, Bandit, or generic format.
    """
    content = (await file.read()).decode("utf-8")
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON")

    findings = _extract_findings(data, file.filename)
    results = []
    for f in findings[:50]:  # Cap at 50 per batch for prototype
        try:
            result = await normalise_finding(f)
            results.append({
                "canonical_id": result["canonical_id"],
                "confidence": result["confidence"],
                "resolution_method": result["resolution_method"],
                "human_review_required": result["human_review_required"],
            })
        except Exception as e:
            logger.error("finding_normalisation_error", error=str(e))
            results.append({"error": str(e)})

    return {
        "status": "ok",
        "total_ingested": len(results),
        "file": file.filename,
        "results": results,
    }


def _extract_findings(data: dict | list, filename: str) -> list[dict]:
    """Extract findings from various tool output formats."""
    findings = []

    # Semgrep format
    if isinstance(data, dict) and "results" in data:
        for r in data["results"]:
            findings.append({
                "tool_name": "semgrep",
                "title": r.get("check_id", ""),
                "description": r.get("extra", {}).get("message", ""),
                "asset_location": r.get("path", ""),
                "line": r.get("start", {}).get("line"),
                "severity": r.get("extra", {}).get("severity", "medium"),
                "input_type": "B",
            })
        return findings

    # Trivy format
    if isinstance(data, dict) and "Results" in data:
        for result in data["Results"]:
            for vuln in result.get("Vulnerabilities") or []:
                findings.append({
                    "tool_name": "trivy",
                    "title": vuln.get("Title") or vuln.get("VulnerabilityID", ""),
                    "description": vuln.get("Description", ""),
                    "asset_location": result.get("Target", ""),
                    "severity": vuln.get("Severity", "medium").lower(),
                    "input_type": "B",
                })
        return findings

    # Bandit format
    if isinstance(data, dict) and "results" in data and "errors" in data:
        for r in data["results"]:
            findings.append({
                "tool_name": "bandit",
                "title": r.get("test_name", ""),
                "description": r.get("issue_text", ""),
                "asset_location": r.get("filename", ""),
                "line": r.get("line_number"),
                "severity": r.get("issue_severity", "medium").lower(),
                "input_type": "B",
            })
        return findings

    # Generic array format
    if isinstance(data, list):
        return data

    return findings


@router.get("/")
async def list_findings(limit: int = 100, human_review_only: bool = False):
    """List all findings in the normalised finding pool."""
    async with tenant_session() as session:
        if human_review_only:
            result = await session.run(
                """
                MATCH (f:Finding) WHERE f.valid_to IS NULL AND f.human_review_required = true
                RETURN f ORDER BY f.created_at DESC LIMIT $limit
                """, limit=limit)
        else:
            result = await session.run(
                "MATCH (f:Finding) WHERE f.valid_to IS NULL RETURN f ORDER BY f.created_at DESC LIMIT $limit",
                limit=limit)
        findings = [dict(r["f"]) async for r in result]
    return {"findings": findings, "count": len(findings)}


@router.get("/stats")
async def finding_stats():
    """Finding pool statistics."""
    async with tenant_session() as session:
        result = await session.run(
            """
            MATCH (f:Finding) WHERE f.valid_to IS NULL
            RETURN
                count(f) AS total,
                count(CASE WHEN f.human_review_required = true THEN 1 END) AS needs_review,
                count(CASE WHEN f.resolution_method = 'deterministic' THEN 1 END) AS deterministic,
                count(CASE WHEN f.resolution_method = 'llm_inferred' THEN 1 END) AS llm_inferred
            """
        )
        stats = {}
        async for r in result:
            stats = dict(r)

        by_canonical = await session.run(
            """
            MATCH (f:Finding) WHERE f.valid_to IS NULL
            RETURN f.canonical_id AS canonical_id, count(f) AS count
            ORDER BY count DESC LIMIT 10
            """
        )
        by_cid = {}
        async for r in by_canonical:
            by_cid[r["canonical_id"]] = r["count"]

    return {**stats, "by_canonical_id": by_cid}
