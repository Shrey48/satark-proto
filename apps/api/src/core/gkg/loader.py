"""
SATARK Layer 1 — GKG Fixture Loader (Prototype)

In prototype: loads GKG data from local JSON fixture files into Neo4j on startup.
In production: fetches live from MITRE CWE XML, CAPEC, ATT&CK STIX.

Fixture files live in: apps/api/src/gkg/fixtures/
"""
import json
import os
from pathlib import Path
from core.database.neo4j import shared_session
import structlog

logger = structlog.get_logger(__name__)

FIXTURES_DIR = Path(__file__).parent.parent.parent / "gkg" / "fixtures"


async def load_gkg_fixtures():
    """Load all GKG fixture files into Neo4j. Called once at startup."""
    if not FIXTURES_DIR.exists():
        logger.warning("gkg_fixtures_dir_missing", path=str(FIXTURES_DIR))
        return

    loaders = [
        ("vulnerability_classes.json", _load_vuln_classes),
        ("taint_sources.json", _load_taint_sources),
        ("sensitive_ports.json", _load_sensitive_ports),
        ("alert_signatures.json", _load_alert_signatures),
        ("compliance_controls.json", _load_compliance_controls),
    ]

    for filename, loader_fn in loaders:
        path = FIXTURES_DIR / filename
        if path.exists():
            with open(path) as f:
                data = json.load(f)
            count = await loader_fn(data)
            logger.info("gkg_fixture_loaded", file=filename, count=count)
        else:
            logger.warning("gkg_fixture_missing", file=filename)


async def _load_vuln_classes(data: list[dict]) -> int:
    async with shared_session(write=True) as session:
        for item in data:
            await session.run(
                """
                MERGE (v:VulnerabilityClass {canonical_id: $canonical_id})
                SET v.display_name = $display_name,
                    v.description = $description,
                    v.domain = $domain,
                    v.source_taxonomy = $source_taxonomy,
                    v.is_deprecated = false,
                    v.last_updated = datetime()
                """,
                **item,
            )
    return len(data)


async def _load_taint_sources(data: list[dict]) -> int:
    async with shared_session(write=True) as session:
        for item in data:
            await session.run(
                """
                MERGE (s:TaintSource {pattern: $pattern, framework_name: $framework_name})
                SET s.api_call = $api_call,
                    s.taint_class = $taint_class,
                    s.language = $language,
                    s.last_updated = datetime()
                WITH s
                MERGE (f:TechnologyFramework {name: $framework_name})
                MERGE (f)-[:is_taint_source_in]->(s)
                """,
                **item,
            )
    return len(data)


async def _load_sensitive_ports(data: list[dict]) -> int:
    async with shared_session(write=True) as session:
        for item in data:
            await session.run(
                """
                MERGE (p:SensitivePort {port: $port, protocol: $protocol})
                SET p.service_type = $service_type,
                    p.risk_level = $risk_level,
                    p.recommended_action = $recommended_action
                """,
                **item,
            )
    return len(data)


async def _load_alert_signatures(data: list[dict]) -> int:
    async with shared_session(write=True) as session:
        for item in data:
            cwe_id = item.pop("canonical_id", None)
            await session.run(
                """
                MERGE (a:AlertSignature {signature_id: $signature_id, source_tool: $source_tool})
                SET a.description = $description,
                    a.confidence = $confidence,
                    a.last_updated = datetime()
                """,
                **item,
            )
            if cwe_id:
                await session.run(
                    """
                    MATCH (a:AlertSignature {signature_id: $sig_id})
                    MATCH (v:VulnerabilityClass {canonical_id: $cwe_id})
                    MERGE (a)-[:maps_to_signature]->(v)
                    """,
                    sig_id=item["signature_id"],
                    cwe_id=cwe_id,
                )
    return len(data)


async def _load_compliance_controls(data: list[dict]) -> int:
    async with shared_session(write=True) as session:
        for item in data:
            cwe_ids = item.pop("cwe_ids", [])
            await session.run(
                """
                MERGE (c:ComplianceControl {framework: $framework, control_id: $control_id})
                SET c.control_name = $control_name,
                    c.obligation_level = $obligation_level,
                    c.source_version = $source_version
                """,
                **item,
            )
            for cwe_id in cwe_ids:
                await session.run(
                    """
                    MATCH (v:VulnerabilityClass {canonical_id: $cwe_id})
                    MATCH (c:ComplianceControl {framework: $framework, control_id: $control_id})
                    MERGE (v)-[:violates_control]->(c)
                    """,
                    cwe_id=cwe_id,
                    framework=item["framework"],
                    control_id=item["control_id"],
                )
    return len(data)
