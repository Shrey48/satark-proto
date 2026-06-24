"""
SATARK Layer 1 — Component 8: Canonical Service Registry (P0-10)
Also called: Name Alias Table (Section 4.5 + Section 8)

Per-tenant alias table. Maps every informal name variation of a service
to its canonical entity. Built automatically from plugin input space metadata
and pre-ingestion file scanning. Grows permanently via confirmed matches
and human Graph Link Review decisions.

Also stores permanent exclusion rules (confirmed non-links).

Used by Layer 2 of the 4-layer name-keyed linking funnel (Section 4.4a).

Neo4j node type: :ServiceAlias (in the tenant database)
Neo4j node type: :ExclusionRule (in the tenant database)
"""
from typing import Optional
from core.database.neo4j import tenant_session
import structlog

logger = structlog.get_logger(__name__)


# ── Schema creation ────────────────────────────────────────────────────────────

REGISTRY_SCHEMA_CYPHER = [
    # Alias table: informal name → canonical entity
    "CREATE INDEX service_alias_name IF NOT EXISTS FOR (n:ServiceAlias) ON (n.informal_name, n.context)",
    "CREATE INDEX service_alias_canonical IF NOT EXISTS FOR (n:ServiceAlias) ON (n.canonical_entity_id)",
    # Exclusion rules: confirmed non-links (never ask again)
    "CREATE INDEX exclusion_rule IF NOT EXISTS FOR (n:ExclusionRule) ON (n.name_a, n.name_b, n.context)",
]


async def ensure_registry_schema(org_id: str) -> None:
    """Create Component 8 indexes in the tenant database. Called at tenant provisioning."""
    async with tenant_session(org_id) as session:
        for query in REGISTRY_SCHEMA_CYPHER:
            await session.run(query)
    logger.info("component8_schema_created", org_id=org_id)


# ── Alias table read / write ───────────────────────────────────────────────────

async def lookup_alias(org_id: str, informal_name: str, context: str) -> Optional[str]:
    """
    Layer 2 of the 4-layer funnel: look up informal_name in the alias table.
    Returns canonical_entity_id if found, None if not.
    context is the plugin input space group (e.g. git repo URL, K8s cluster name).
    """
    async with tenant_session(org_id) as session:
        result = await session.run(
            """
            MATCH (a:ServiceAlias {informal_name: $name, context: $context})
            RETURN a.canonical_entity_id AS canonical_entity_id
            LIMIT 1
            """,
            name=informal_name.lower().strip(),
            context=context,
        )
        record = await result.single()
        if record:
            logger.debug("alias_lookup_hit", org_id=org_id, name=informal_name)
            return record["canonical_entity_id"]
    return None


async def write_alias(
    org_id: str,
    informal_name: str,
    canonical_entity_id: str,
    context: str,
    source: str,     # "pre_ingestion_scan" | "human_confirmed" | "llm_confirmed"
    confidence: float = 1.0,
) -> None:
    """
    Write an alias to the registry permanently.
    Called from:
      - Pre-ingestion scanner (source: pre_ingestion_scan)
      - Component 8 write-back after any confirmed 4-layer match (source: llm_confirmed)
      - Graph Link Review Interface after human confirms Yes (source: human_confirmed)
    """
    async with tenant_session(org_id) as session:
        await session.run(
            """
            MERGE (a:ServiceAlias {informal_name: $name, context: $context})
            SET a.canonical_entity_id = $canonical_id,
                a.source = $source,
                a.confidence = $confidence,
                a.updated_at = datetime()
            """,
            name=informal_name.lower().strip(),
            context=context,
            canonical_id=canonical_entity_id,
            source=source,
            confidence=confidence,
        )
    logger.info(
        "alias_written",
        org_id=org_id,
        informal_name=informal_name,
        canonical_entity_id=canonical_entity_id,
        source=source,
    )


# ── Exclusion rules ────────────────────────────────────────────────────────────

async def write_exclusion(
    org_id: str,
    name_a: str,
    name_b: str,
    context: str,
    confirmed_by: str,  # user_id who confirmed "Not the same"
) -> None:
    """
    Write a permanent exclusion rule.
    Called from Graph Link Review Interface when human confirms No (not the same entity).
    This pair will never be suggested for linking again.
    """
    async with tenant_session(org_id) as session:
        await session.run(
            """
            MERGE (e:ExclusionRule {name_a: $name_a, name_b: $name_b, context: $context})
            SET e.confirmed_by = $confirmed_by, e.created_at = datetime()
            """,
            name_a=min(name_a, name_b),   # Canonical order: alphabetical
            name_b=max(name_a, name_b),
            context=context,
            confirmed_by=confirmed_by,
        )
    logger.info("exclusion_rule_written", org_id=org_id, name_a=name_a, name_b=name_b)


async def is_excluded(org_id: str, name_a: str, name_b: str, context: str) -> bool:
    """Check if this pair has a permanent exclusion rule."""
    async with tenant_session(org_id) as session:
        result = await session.run(
            """
            MATCH (e:ExclusionRule {
                name_a: $name_a, name_b: $name_b, context: $context
            })
            RETURN count(e) AS cnt
            """,
            name_a=min(name_a, name_b),
            name_b=max(name_a, name_b),
            context=context,
        )
        record = await result.single()
        return record["cnt"] > 0 if record else False


# ── Registry statistics ────────────────────────────────────────────────────────

async def registry_stats(org_id: str) -> dict:
    """Returns Component 8 statistics for the tenant. Used in dashboard coverage view."""
    async with tenant_session(org_id) as session:
        result = await session.run(
            """
            RETURN
              size([(a:ServiceAlias) | a]) AS total_aliases,
              size([(e:ExclusionRule) | e]) AS total_exclusions,
              size([(a:ServiceAlias WHERE a.source = 'human_confirmed') | a]) AS human_confirmed,
              size([(a:ServiceAlias WHERE a.source = 'pre_ingestion_scan') | a]) AS pre_ingestion
            """
        )
        record = await result.single()
        return dict(record) if record else {}
