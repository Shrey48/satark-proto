"""
SATARK Layer 1 — Neo4j Connection

Prototype: single database named 'neo4j' (Community edition default)
Production: one database per tenant (vargplus_tenant_<org_id>)
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession
from core.config import get_settings
import structlog

logger = structlog.get_logger(__name__)
settings = get_settings()

_driver: Optional[AsyncDriver] = None
PROTOTYPE_DB = "neo4j"


async def get_driver() -> AsyncDriver:
    global _driver
    if _driver is None:
        _driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            max_connection_pool_size=20,
        )
        logger.info("neo4j_driver_created", uri=settings.neo4j_uri)
    return _driver


async def close_driver():
    global _driver
    if _driver:
        await _driver.close()
        _driver = None


@asynccontextmanager
async def tenant_session(org_id: str = "prototype") -> AsyncGenerator[AsyncSession, None]:
    driver = await get_driver()
    async with driver.session(database=PROTOTYPE_DB) as session:
        yield session


@asynccontextmanager
async def shared_session(write: bool = False) -> AsyncGenerator[AsyncSession, None]:
    driver = await get_driver()
    async with driver.session(database=PROTOTYPE_DB) as session:
        yield session


async def setup_prototype_schema():
    """Create all Neo4j indexes for the prototype. Section 9.4."""
    indexes = [
        "CREATE INDEX entity_id IF NOT EXISTS FOR (n:Node) ON (n.entity_id)",
        "CREATE INDEX node_valid_to IF NOT EXISTS FOR (n:Node) ON (n.entity_id, n.valid_to)",
        "CREATE INDEX node_domain_type IF NOT EXISTS FOR (n:Node) ON (n.domain_type)",
        "CREATE INDEX resource_arn IF NOT EXISTS FOR (n:Resource) ON (n.arn)",
        "CREATE INDEX resource_ip IF NOT EXISTS FOR (n:Resource) ON (n.ip_address)",
        "CREATE INDEX function_location IF NOT EXISTS FOR (n:Function) ON (n.file_path, n.start_line)",
        "CREATE INDEX firewall_posture IF NOT EXISTS FOR (n:Node) ON (n.firewall_posture)",
        "CREATE INDEX is_entry_point IF NOT EXISTS FOR (n:Node) ON (n.is_entry_point)",
        "CREATE INDEX service_alias IF NOT EXISTS FOR (n:ServiceAlias) ON (n.informal_name, n.context)",
        "CREATE INDEX exclusion_rule IF NOT EXISTS FOR (n:ExclusionRule) ON (n.name_a, n.name_b)",
        "CREATE INDEX vuln_class IF NOT EXISTS FOR (n:VulnerabilityClass) ON (n.canonical_id)",
        "CREATE INDEX taint_source IF NOT EXISTS FOR (n:TaintSource) ON (n.pattern, n.framework_name)",
        "CREATE INDEX alert_sig IF NOT EXISTS FOR (n:AlertSignature) ON (n.signature_id, n.source_tool)",
        "CREATE INDEX sensitive_port IF NOT EXISTS FOR (n:SensitivePort) ON (n.port, n.protocol)",
        "CREATE INDEX tool_def IF NOT EXISTS FOR (n:ToolDefinition) ON (n.name)",
        "CREATE INDEX finding_canonical IF NOT EXISTS FOR (n:Finding) ON (n.canonical_id, n.asset_location)",
        "CREATE INDEX finding_status IF NOT EXISTS FOR (n:Finding) ON (n.input_type, n.temporal_status)",
    ]
    async with shared_session(write=True) as session:
        for q in indexes:
            await session.run(q)
    logger.info("prototype_schema_ready", indexes=len(indexes))


async def provision_tenant_db(org_id: str) -> None:
    logger.info("prototype_single_db_mode", org_id=org_id)
