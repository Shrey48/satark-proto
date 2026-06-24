"""
SATARK Layer 1 — Component 3: Tool Lookup Dictionary (P0-08)

Maps tool_name → source_type. Stage A of the Track 2 normalisation pipeline.
This is the HOT PATH — fires before normalisation begins on every single finding.

Design (from spec Section 8, Component 3):
  - Backed by Redis (in-memory cache, near-zero latency)
  - Neo4j is the durable source of truth
  - On cache miss: query Neo4j, populate cache (TTL = 24h)
  - On new tool registered: write to Neo4j + invalidate cache entry

Source types (from spec):
  SAST, DAST, Network_scan, Cloud_CSPM, IDS, Mobile_SAST,
  Container_scan, SCA, Secret_scan, Manual, Pentest, EASM, BAS
"""
from typing import Optional
from core.database.redis_client import get_redis
from core.database.neo4j import shared_session
import structlog

logger = structlog.get_logger(__name__)

REDIS_KEY_PREFIX = "satark:tool_lookup:"
CACHE_TTL_SECONDS = 86400   # 24 hours

# Seeded at Phase 0. Grows as new tools are registered.
INITIAL_TOOL_REGISTRY: dict[str, str] = {
    # SAST
    "semgrep": "SAST",
    "codeql": "SAST",
    "bandit": "SAST",
    "sonarqube": "SAST",
    "checkmarx": "SAST",
    "veracode": "SAST",
    "snyk_code": "SAST",
    "fortify": "SAST",
    "coverity": "SAST",
    # DAST
    "burp_suite": "DAST",
    "owasp_zap": "DAST",
    "acunetix": "DAST",
    "invicti": "DAST",
    "rapid7_insightappsec": "DAST",
    # Network scan
    "nessus": "Network_scan",
    "qualys": "Network_scan",
    "openvas": "Network_scan",
    "nmap": "Network_scan",
    "masscan": "Network_scan",
    # Cloud CSPM
    "wiz": "Cloud_CSPM",
    "lacework": "Cloud_CSPM",
    "prisma_cloud": "Cloud_CSPM",
    "checkov": "Cloud_CSPM",
    "tfsec": "Cloud_CSPM",
    "kics": "Cloud_CSPM",
    "aws_security_hub": "Cloud_CSPM",
    "azure_defender": "Cloud_CSPM",
    # IDS / IPS / Runtime
    "guardduty": "IDS",
    "snort": "IDS",
    "suricata": "IDS",
    "crowdstrike": "IDS",
    "sentinelone": "IDS",
    "darktrace": "IDS",
    "extrahop": "IDS",
    # Container
    "trivy": "Container_scan",
    "grype": "Container_scan",
    "clair": "Container_scan",
    "twistlock": "Container_scan",
    "snyk_container": "Container_scan",
    # SCA (dependency)
    "dependabot": "SCA",
    "snyk_sca": "SCA",
    "mend": "SCA",
    "owasp_dependency_check": "SCA",
    # Secret scanning
    "gitguardian": "Secret_scan",
    "trufflehog": "Secret_scan",
    "gitleaks": "Secret_scan",
    "detect_secrets": "Secret_scan",
    # Mobile
    "mobsf": "Mobile_SAST",
    # Manual / pentest
    "manual": "Manual",
    "pentest_report": "Pentest",
    "red_team": "Pentest",
    # Exposure management
    "censys": "EASM",
    "shodan": "EASM",
    "safebreach": "BAS",
    "attackiq": "BAS",
}


async def get_source_type(tool_name: str) -> Optional[str]:
    """
    Stage A hot path: look up source_type for a tool name.
    1. Check Redis cache (near-zero latency)
    2. On miss: check Neo4j
    3. On miss: return None (falls to Stage D LLM fallback after dedup)
    """
    if not tool_name:
        return None

    normalised = tool_name.lower().strip().replace(" ", "_").replace("-", "_")

    # 1. Redis cache (primary path)
    redis = await get_redis()
    cached = await redis.get(f"{REDIS_KEY_PREFIX}{normalised}")
    if cached:
        return cached

    # 2. Neo4j (secondary path)
    async with shared_session() as session:
        result = await session.run(
            "MATCH (t:ToolDefinition {name: $name}) RETURN t.source_type AS source_type",
            name=normalised,
        )
        record = await result.single()
        if record:
            source_type = record["source_type"]
            await redis.setex(f"{REDIS_KEY_PREFIX}{normalised}", CACHE_TTL_SECONDS, source_type)
            return source_type

    logger.debug("tool_lookup_miss", tool_name=normalised)
    return None


async def register_tool(tool_name: str, source_type: str) -> None:
    """Register a new tool. Writes to Neo4j + updates Redis cache."""
    normalised = tool_name.lower().strip().replace(" ", "_").replace("-", "_")

    async with shared_session(write=True) as session:
        await session.run(
            """
            MERGE (t:ToolDefinition {name: $name})
            SET t.source_type = $source_type, t.updated_at = datetime()
            """,
            name=normalised,
            source_type=source_type,
        )

    redis = await get_redis()
    await redis.setex(f"{REDIS_KEY_PREFIX}{normalised}", CACHE_TTL_SECONDS, source_type)
    logger.info("tool_registered", tool_name=normalised, source_type=source_type)


async def seed_tool_registry() -> int:
    """P0-08: Seed all known tools into Neo4j and warm the Redis cache."""
    count = 0
    async with shared_session(write=True) as session:
        for tool_name, source_type in INITIAL_TOOL_REGISTRY.items():
            await session.run(
                """
                MERGE (t:ToolDefinition {name: $name})
                SET t.source_type = $source_type, t.created_at = datetime()
                """,
                name=tool_name,
                source_type=source_type,
            )
            count += 1

    # Warm the Redis cache
    redis = await get_redis()
    pipe = redis.pipeline()
    for tool_name, source_type in INITIAL_TOOL_REGISTRY.items():
        pipe.setex(f"{REDIS_KEY_PREFIX}{tool_name}", CACHE_TTL_SECONDS, source_type)
    await pipe.execute()

    logger.info("tool_registry_seeded", count=count)
    return count
