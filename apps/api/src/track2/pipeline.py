"""
SATARK Layer 1 — Track 2: Normalisation Pipeline (Prototype)
6-step normalisation funnel (spec Section 7.6).

Step 1: Exact RawTerm lookup
Step 2: Single MAY_MEAN edge → deterministic
Step 3: source_type context match → deterministic
Step 4: New context → LLM Call Type A* (with GKG context)
Step 5: Ambiguous → LLM Call Type A (narrow disambiguation)
Step 6: Unknown → LLM Call Type B (full classification, UNMAPPED allowed)

Prototype simplification: Steps 1-3 use the vulnerability_classes.json fixture
as the taxonomy. Steps 4-6 call DeepSeek/Claude via the LLM provider.
"""
import uuid
from datetime import datetime
from typing import Optional
from core.database.neo4j import tenant_session, shared_session
from core.llm import get_llm_provider, LLMMessage
from core.components.tool_lookup import get_source_type
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

# Exact keyword → canonical_id lookup (Step 1 hot path)
# Mirrors the RawTerm dictionary (Component 2)
RAWTERM_EXACT: dict[str, str] = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "cross site scripting": "CWE-79",
    "command injection": "CWE-78",
    "os command injection": "CWE-78",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "ssrf": "CWE-918",
    "server-side request forgery": "CWE-918",
    "csrf": "CWE-352",
    "cross-site request forgery": "CWE-352",
    "hardcoded credential": "CWE-798",
    "hardcoded password": "CWE-798",
    "hardcoded secret": "CWE-798",
    "hardcoded api key": "CWE-798",
    "missing encryption": "CWE-311",
    "cleartext transmission": "CWE-319",
    "cleartext storage": "CWE-312",
    "improper authentication": "CWE-287",
    "authentication bypass": "CWE-287",
    "privilege escalation": "CWE-269",
    "information disclosure": "CWE-200",
    "sensitive data exposure": "CWE-200",
    "insecure deserialization": "CWE-502",
    "deserialization": "CWE-502",
    "xxe": "CWE-611",
    "xml external entity": "CWE-611",
    "open redirect": "CWE-601",
    "unrestricted file upload": "CWE-434",
    "insufficient logging": "CWE-778",
    "missing logs": "CWE-778",
    "improper input validation": "CWE-20",
    "input validation": "CWE-20",
    "brute force": "CWE-307",
    "rate limiting": "CWE-307",
    "weak password": "CWE-521",
    "excessive privileges": "CWE-250",
}


def _normalise_term(raw: str) -> str:
    return raw.lower().strip().replace("_", " ").replace("-", " ")


async def _step1_exact_lookup(raw_term: str) -> Optional[str]:
    """Step 1: exact RawTerm lookup."""
    normalised = _normalise_term(raw_term)
    # Direct match
    if normalised in RAWTERM_EXACT:
        return RAWTERM_EXACT[normalised]
    # Substring match
    for key, cid in RAWTERM_EXACT.items():
        if key in normalised or normalised in key:
            return cid
    return None


async def _step6_llm_classify(raw_term: str, source_type: str) -> tuple[str, float]:
    """Step 6: LLM full classification. Returns (canonical_id, confidence)."""
    llm = get_llm_provider()

    # Build taxonomy options from our fixture
    options = list(set(RAWTERM_EXACT.values()))  # All known canonical_ids

    system = """You are a security vulnerability classifier.
Given a vulnerability finding from a security tool, classify it into the correct CWE identifier.
Choose the most specific and accurate match. Return UNMAPPED only if nothing fits."""

    user_content = f"""Vulnerability finding:
Tool type: {source_type}
Finding: "{raw_term}"

Available CWE identifiers:
{chr(10).join(f'- {cid}' for cid in sorted(options))}

Which CWE best matches this finding?"""

    response = await llm.constrained_choice(
        system_prompt=system,
        messages=[LLMMessage(role="user", content=user_content)],
        options=options,
        allow_sentinels=["UNMAPPED"],
        temperature=0.0,
    )
    return response.chosen, response.confidence


async def normalise_finding(
    raw_finding: dict,
    org_id: str = ORG_ID,
) -> dict:
    """
    Run a single finding through the 6-step normalisation funnel.
    Returns the normalised finding dict ready to store in Neo4j.
    """
    tool_name = raw_finding.get("tool_name", "manual")
    raw_term = raw_finding.get("title") or raw_finding.get("check_id") or raw_finding.get("name", "")
    asset_location = raw_finding.get("asset_location") or raw_finding.get("file") or ""
    line = raw_finding.get("line") or raw_finding.get("start_line")
    severity = raw_finding.get("severity", "medium")
    description = raw_finding.get("description") or raw_finding.get("message", "")
    input_type = raw_finding.get("input_type", "A")

    # Stage A: source_type lookup (Component 3, Redis cached)
    source_type = await get_source_type(tool_name) or "Manual"

    # Normalise asset_location to repo-relative path
    normalised_location = _normalise_asset_location(asset_location, line)

    # Run funnel
    canonical_id = None
    resolution_method = "deterministic"
    confidence = 1.0

    # Step 1: exact lookup
    canonical_id = await _step1_exact_lookup(raw_term)

    if canonical_id:
        resolution_method = "deterministic"
        confidence = 1.0
        logger.info("normalisation_step1_hit", term=raw_term, canonical_id=canonical_id)
    else:
        # Step 6: LLM full classification
        logger.info("normalisation_step6_llm", term=raw_term)
        canonical_id, confidence = await _step6_llm_classify(raw_term, source_type)
        resolution_method = "llm_inferred"

    # Build normalised finding
    finding_id = str(uuid.uuid4())
    finding = {
        "finding_id": finding_id,
        "canonical_id": canonical_id,
        "raw_term": raw_term,
        "source_type": source_type,
        "tool_name": tool_name,
        "normalised_asset_location": normalised_location,
        "input_type": input_type,
        "severity": severity,
        "description": description[:500],
        "confidence": confidence,
        "resolution_method": resolution_method,
        "temporal_status": "active",
        "human_review_required": confidence < 0.70,
        "created_at": datetime.utcnow().isoformat(),
        "org_id": org_id,
    }

    # Store in Neo4j finding pool
    await _store_finding(finding, org_id)

    return finding


def _normalise_asset_location(location: str, line: Optional[int]) -> str:
    """Normalise to repo-relative path with line number (spec Section 7.2)."""
    if not location:
        return "unknown"
    # Strip common prefixes
    for prefix in ("/app/", "/src/", "/home/", "./"):
        if location.startswith(prefix):
            location = location[len(prefix):]
    result = location.lower()
    if line:
        result = f"{result}:{line}"
    return result


async def _store_finding(finding: dict, org_id: str):
    """Store normalised finding in Neo4j finding pool."""
    async with tenant_session(org_id) as session:
        # Deduplication: merge by (canonical_id, normalised_asset_location)
        # Type A + B only — Type C always creates new
        if finding["input_type"] == "C":
            await session.run(
                """
                CREATE (f:Node:Finding {
                    entity_id: $finding_id,
                    node_type: 'Finding',
                    domain_type: 'finding',
                    name: $canonical_id,
                    canonical_id: $canonical_id,
                    raw_term: $raw_term,
                    source_type: $source_type,
                    tool_name: $tool_name,
                    asset_location: $asset_location,
                    input_type: $input_type,
                    severity: $severity,
                    description: $description,
                    confidence: $confidence,
                    resolution_method: $resolution_method,
                    temporal_status: $temporal_status,
                    human_review_required: $human_review_required,
                    created_at: datetime(),
                    valid_from: datetime(),
                    valid_to: null
                })
                """,
                finding_id=f"finding-{finding['finding_id']}",
                **{k: v for k, v in finding.items() if k not in ("finding_id", "created_at", "org_id")},
                asset_location=finding["normalised_asset_location"],
            )
        else:
            # Merge by dedup key
            await session.run(
                """
                MERGE (f:Node:Finding {
                    canonical_id: $canonical_id,
                    asset_location: $asset_location
                })
                ON CREATE SET
                    f.entity_id = $finding_id,
                    f.node_type = 'Finding',
                    f.domain_type = 'finding',
                    f.name = $canonical_id,
                    f.raw_term = $raw_term,
                    f.source_type = $source_type,
                    f.tool_name = $tool_name,
                    f.input_type = $input_type,
                    f.severity = $severity,
                    f.description = $description,
                    f.confidence = $confidence,
                    f.resolution_method = $resolution_method,
                    f.temporal_status = $temporal_status,
                    f.human_review_required = $human_review_required,
                    f.created_at = datetime(),
                    f.valid_from = datetime(),
                    f.valid_to = null
                ON MATCH SET
                    f.confidence = CASE WHEN $confidence > f.confidence THEN $confidence ELSE f.confidence END,
                    f.source_type = f.source_type + ',' + $source_type
                """,
                finding_id=f"finding-{finding['finding_id']}",
                asset_location=finding["normalised_asset_location"],
                **{k: v for k, v in finding.items() if k not in ("finding_id", "created_at", "org_id", "normalised_asset_location")},
            )
