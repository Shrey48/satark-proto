"""
SATARK Layer 1 — GKG Seeder (P0-11, P0-12, P0-13, P0-14, P0-15)

Seeds the General Knowledge Graph into the shared reference Neo4j database.
Run once at Phase 0 setup: `make seed-gkg`

Sources seeded here:
  - TechnologyFramework nodes + TaintSource nodes (framework-specific taint sources)
  - SensitivePort nodes (replaces hardcoded port lists in Sub-step F)
  - ComplianceControl nodes (PCI-DSS, HIPAA, SOC2, NIST)
  - AlertSignature nodes (GuardDuty finding types)
  NOTE: VulnerabilityClass (CWE), AttackPattern (CAPEC), AttackTechnique (ATT&CK)
        are fetched live from MITRE in seed_taxonomy.py — larger datasets.
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../apps/api/src"))

from core.database.neo4j import shared_session, get_driver, close_driver
from gkg.models import GKG_SCHEMA_QUERIES
import structlog

logger = structlog.get_logger(__name__)


# ── TechnologyFramework + TaintSource nodes ────────────────────────────────────

FRAMEWORKS = [
    {
        "name": "django", "language": "python", "version_range": ">=2.0",
        "taint_sources": [
            {"pattern": "request.GET", "api_call": "HttpRequest.GET.__getitem__", "taint_class": "external_untrusted"},
            {"pattern": "request.POST", "api_call": "HttpRequest.POST.__getitem__", "taint_class": "external_untrusted"},
            {"pattern": "request.data", "api_call": "HttpRequest.data", "taint_class": "external_untrusted"},
            {"pattern": "request.body", "api_call": "HttpRequest.body", "taint_class": "external_untrusted"},
            {"pattern": "request.FILES", "api_call": "HttpRequest.FILES.__getitem__", "taint_class": "external_untrusted"},
            {"pattern": "kwargs['pk']", "api_call": "URL kwargs", "taint_class": "external_untrusted"},
        ]
    },
    {
        "name": "flask", "language": "python", "version_range": ">=1.0",
        "taint_sources": [
            {"pattern": "request.args", "api_call": "flask.request.args.get", "taint_class": "external_untrusted"},
            {"pattern": "request.form", "api_call": "flask.request.form.get", "taint_class": "external_untrusted"},
            {"pattern": "request.json", "api_call": "flask.request.json", "taint_class": "external_untrusted"},
            {"pattern": "request.data", "api_call": "flask.request.data", "taint_class": "external_untrusted"},
            {"pattern": "request.files", "api_call": "flask.request.files.get", "taint_class": "external_untrusted"},
        ]
    },
    {
        "name": "spring", "language": "java", "version_range": ">=4.0",
        "taint_sources": [
            {"pattern": "@RequestParam", "api_call": "org.springframework.web.bind.annotation.RequestParam", "taint_class": "external_untrusted"},
            {"pattern": "@PathVariable", "api_call": "org.springframework.web.bind.annotation.PathVariable", "taint_class": "external_untrusted"},
            {"pattern": "@RequestBody", "api_call": "org.springframework.web.bind.annotation.RequestBody", "taint_class": "external_untrusted"},
            {"pattern": "HttpServletRequest.getParameter", "api_call": "javax.servlet.http.HttpServletRequest.getParameter", "taint_class": "external_untrusted"},
            {"pattern": "HttpServletRequest.getInputStream", "api_call": "javax.servlet.http.HttpServletRequest.getInputStream", "taint_class": "external_untrusted"},
        ]
    },
    {
        "name": "express", "language": "javascript", "version_range": ">=4.0",
        "taint_sources": [
            {"pattern": "req.query", "api_call": "express.Request.query", "taint_class": "external_untrusted"},
            {"pattern": "req.body", "api_call": "express.Request.body", "taint_class": "external_untrusted"},
            {"pattern": "req.params", "api_call": "express.Request.params", "taint_class": "external_untrusted"},
            {"pattern": "req.headers", "api_call": "express.Request.headers", "taint_class": "external_untrusted"},
            {"pattern": "req.files", "api_call": "express.Request.files", "taint_class": "external_untrusted"},
        ]
    },
    {
        "name": "rails", "language": "ruby", "version_range": ">=5.0",
        "taint_sources": [
            {"pattern": "params", "api_call": "ActionController::Parameters", "taint_class": "external_untrusted"},
            {"pattern": "request.body", "api_call": "ActionDispatch::Request.body", "taint_class": "external_untrusted"},
            {"pattern": "request.query_string", "api_call": "ActionDispatch::Request.query_string", "taint_class": "external_untrusted"},
        ]
    },
]


# ── SensitivePort nodes (replaces hardcoded list in Sub-step F) ────────────────

SENSITIVE_PORTS = [
    {"port": 22,    "protocol": "tcp", "service_type": "SSH",          "risk_level": "critical", "recommended_action": "Restrict to bastion/VPN CIDRs only"},
    {"port": 3389,  "protocol": "tcp", "service_type": "RDP",          "risk_level": "critical", "recommended_action": "Restrict to bastion/VPN CIDRs only"},
    {"port": 5432,  "protocol": "tcp", "service_type": "PostgreSQL",   "risk_level": "critical", "recommended_action": "No public access. VPC-internal only."},
    {"port": 3306,  "protocol": "tcp", "service_type": "MySQL",        "risk_level": "critical", "recommended_action": "No public access. VPC-internal only."},
    {"port": 27017, "protocol": "tcp", "service_type": "MongoDB",      "risk_level": "critical", "recommended_action": "No public access. VPC-internal only."},
    {"port": 6379,  "protocol": "tcp", "service_type": "Redis",        "risk_level": "critical", "recommended_action": "No public access. Auth required."},
    {"port": 9200,  "protocol": "tcp", "service_type": "Elasticsearch","risk_level": "critical", "recommended_action": "No public access. Auth required."},
    {"port": 9300,  "protocol": "tcp", "service_type": "Elasticsearch-cluster", "risk_level": "high", "recommended_action": "VPC-internal only."},
    {"port": 5601,  "protocol": "tcp", "service_type": "Kibana",       "risk_level": "high",     "recommended_action": "Auth required. Not publicly accessible."},
    {"port": 2181,  "protocol": "tcp", "service_type": "ZooKeeper",    "risk_level": "high",     "recommended_action": "VPC-internal only."},
    {"port": 9092,  "protocol": "tcp", "service_type": "Kafka",        "risk_level": "high",     "recommended_action": "VPC-internal only. SASL auth required."},
    {"port": 2379,  "protocol": "tcp", "service_type": "etcd",         "risk_level": "critical", "recommended_action": "K8s control plane only. Never externally exposed."},
    {"port": 10250, "protocol": "tcp", "service_type": "K8s kubelet",  "risk_level": "critical", "recommended_action": "No public access."},
    {"port": 8500,  "protocol": "tcp", "service_type": "Consul",       "risk_level": "high",     "recommended_action": "VPC-internal only. ACL required."},
    {"port": 4222,  "protocol": "tcp", "service_type": "NATS",         "risk_level": "high",     "recommended_action": "VPC-internal only."},
    {"port": 1433,  "protocol": "tcp", "service_type": "MSSQL",        "risk_level": "critical", "recommended_action": "No public access. VPC-internal only."},
    {"port": 1521,  "protocol": "tcp", "service_type": "Oracle DB",    "risk_level": "critical", "recommended_action": "No public access. VPC-internal only."},
    {"port": 8080,  "protocol": "tcp", "service_type": "HTTP alternate","risk_level": "medium",  "recommended_action": "If public, ensure it is intentional."},
    {"port": 4443,  "protocol": "tcp", "service_type": "HTTPS alternate","risk_level": "medium", "recommended_action": "If public, ensure it is intentional."},
]


# ── AlertSignature nodes (GuardDuty finding types → CWE) ──────────────────────

GUARDDUTY_SIGNATURES = [
    {"signature_id": "UnauthorizedAccess:EC2/TorIPCaller", "source_tool": "guardduty", "canonical_id": "CWE-284", "confidence": 0.75},
    {"signature_id": "UnauthorizedAccess:IAMUser/TorIPCaller", "source_tool": "guardduty", "canonical_id": "CWE-284", "confidence": 0.75},
    {"signature_id": "Recon:EC2/PortProbeUnprotectedPort", "source_tool": "guardduty", "canonical_id": "CWE-200", "confidence": 0.60},
    {"signature_id": "UnauthorizedAccess:EC2/SSHBruteForce", "source_tool": "guardduty", "canonical_id": "CWE-307", "confidence": 0.85},
    {"signature_id": "UnauthorizedAccess:EC2/RDPBruteForce", "source_tool": "guardduty", "canonical_id": "CWE-307", "confidence": 0.85},
    {"signature_id": "CryptoCurrency:EC2/BitcoinTool.B", "source_tool": "guardduty", "canonical_id": "CWE-829", "confidence": 0.90},
    {"signature_id": "Backdoor:EC2/C&CActivity.B", "source_tool": "guardduty", "canonical_id": "CWE-506", "confidence": 0.85},
    {"signature_id": "Trojan:EC2/BlackholeTraffic", "source_tool": "guardduty", "canonical_id": "CWE-506", "confidence": 0.80},
    {"signature_id": "Policy:IAMUser/RootCredentialUsage", "source_tool": "guardduty", "canonical_id": "CWE-250", "confidence": 0.90},
    {"signature_id": "PrivilegeEscalation:IAMUser/AdministrativePermissions", "source_tool": "guardduty", "canonical_id": "CWE-269", "confidence": 0.85},
    {"signature_id": "Stealth:IAMUser/CloudTrailLoggingDisabled", "source_tool": "guardduty", "canonical_id": "CWE-778", "confidence": 0.90},
    {"signature_id": "Impact:S3/ObjectDelete.Unusual", "source_tool": "guardduty", "canonical_id": "CWE-400", "confidence": 0.65},
    {"signature_id": "Discovery:S3/MaliciousIPCaller", "source_tool": "guardduty", "canonical_id": "CWE-200", "confidence": 0.70},
]


# ── Compliance Controls ────────────────────────────────────────────────────────

COMPLIANCE_CONTROLS = [
    # PCI-DSS v4
    {"framework": "PCI-DSS", "control_id": "6.3.1", "control_name": "Security vulnerabilities are identified and managed", "obligation_level": "mandatory", "source_version": "4.0", "cwe_ids": ["CWE-89", "CWE-79", "CWE-78"]},
    {"framework": "PCI-DSS", "control_id": "6.2.4", "control_name": "Software development practices prevent introduction of vulnerabilities", "obligation_level": "mandatory", "source_version": "4.0", "cwe_ids": ["CWE-89", "CWE-79", "CWE-352"]},
    {"framework": "PCI-DSS", "control_id": "8.3.1", "control_name": "All user IDs and authentication factors are managed", "obligation_level": "mandatory", "source_version": "4.0", "cwe_ids": ["CWE-287", "CWE-307", "CWE-798"]},
    # HIPAA Security Rule
    {"framework": "HIPAA", "control_id": "164.312(a)(1)", "control_name": "Access Control — unique user identification", "obligation_level": "mandatory", "source_version": "2023", "cwe_ids": ["CWE-284", "CWE-287"]},
    {"framework": "HIPAA", "control_id": "164.312(e)(1)", "control_name": "Transmission Security — encrypt PHI in transit", "obligation_level": "mandatory", "source_version": "2023", "cwe_ids": ["CWE-311", "CWE-319"]},
    {"framework": "HIPAA", "control_id": "164.312(a)(2)(iv)", "control_name": "Encryption and Decryption of stored PHI", "obligation_level": "addressable", "source_version": "2023", "cwe_ids": ["CWE-312", "CWE-311"]},
    # SOC2 Trust Services Criteria
    {"framework": "SOC2", "control_id": "CC6.1", "control_name": "Logical access security software, infrastructure, and architectures", "obligation_level": "mandatory", "source_version": "2017", "cwe_ids": ["CWE-284", "CWE-269"]},
    {"framework": "SOC2", "control_id": "CC6.7", "control_name": "Restrict transmission of information to authorised parties", "obligation_level": "mandatory", "source_version": "2017", "cwe_ids": ["CWE-319", "CWE-311"]},
    # NIST SP 800-53
    {"framework": "NIST-800-53", "control_id": "AC-3", "control_name": "Access Enforcement", "obligation_level": "mandatory", "source_version": "Rev5", "cwe_ids": ["CWE-284", "CWE-285"]},
    {"framework": "NIST-800-53", "control_id": "SI-10", "control_name": "Information Input Validation", "obligation_level": "mandatory", "source_version": "Rev5", "cwe_ids": ["CWE-20", "CWE-89", "CWE-79"]},
]


# ── Seeder functions ───────────────────────────────────────────────────────────

async def seed_schema():
    """Create GKG indexes in the shared reference database."""
    async with shared_session(write=True) as session:
        for query in GKG_SCHEMA_QUERIES:
            await session.run(query)
    logger.info("gkg_schema_created")


async def seed_frameworks_and_taint_sources() -> int:
    """P0-13: Seed TechnologyFramework + TaintSource nodes."""
    count = 0
    async with shared_session(write=True) as session:
        for fw in FRAMEWORKS:
            await session.run(
                """
                MERGE (f:TechnologyFramework {name: $name, language: $language})
                SET f.version_range = $version_range,
                    f.source_version = 'manual_v1',
                    f.last_updated = datetime(),
                    f.is_deprecated = false
                """,
                name=fw["name"], language=fw["language"], version_range=fw["version_range"],
            )
            for ts in fw.get("taint_sources", []):
                await session.run(
                    """
                    MERGE (s:TaintSource {pattern: $pattern, framework_name: $fw_name})
                    SET s.api_call = $api_call,
                        s.taint_class = $taint_class,
                        s.language = $language,
                        s.source_version = 'manual_v1',
                        s.last_updated = datetime()
                    WITH s
                    MATCH (f:TechnologyFramework {name: $fw_name})
                    MERGE (f)-[:is_taint_source_in]->(s)
                    """,
                    pattern=ts["pattern"], fw_name=fw["name"],
                    api_call=ts["api_call"], taint_class=ts["taint_class"],
                    language=fw["language"],
                )
                count += 1
    logger.info("frameworks_and_taint_sources_seeded", count=count)
    return count


async def seed_sensitive_ports() -> int:
    """Seed SensitivePort nodes (replaces hardcoded port list in Sub-step F)."""
    count = 0
    async with shared_session(write=True) as session:
        for sp in SENSITIVE_PORTS:
            await session.run(
                """
                MERGE (p:SensitivePort {port: $port, protocol: $protocol})
                SET p.service_type = $service_type,
                    p.risk_level = $risk_level,
                    p.recommended_action = $recommended_action,
                    p.source_version = 'manual_v1',
                    p.last_updated = datetime()
                """,
                **sp,
            )
            count += 1
    logger.info("sensitive_ports_seeded", count=count)
    return count


async def seed_alert_signatures() -> int:
    """P0-14: Seed AlertSignature nodes (GuardDuty finding types → CWE)."""
    count = 0
    async with shared_session(write=True) as session:
        for sig in GUARDDUTY_SIGNATURES:
            await session.run(
                """
                MERGE (a:AlertSignature {signature_id: $signature_id, source_tool: $source_tool})
                SET a.confidence = $confidence,
                    a.source_version = 'guardduty_2024',
                    a.last_updated = datetime()
                WITH a
                MATCH (v:VulnerabilityClass {canonical_id: $canonical_id})
                MERGE (a)-[:maps_to_signature]->(v)
                """,
                signature_id=sig["signature_id"],
                source_tool=sig["source_tool"],
                confidence=sig["confidence"],
                canonical_id=sig["canonical_id"],
            )
            count += 1
    logger.info("alert_signatures_seeded", count=count)
    return count


async def seed_compliance_controls() -> int:
    """P0-15: Seed ComplianceControl nodes with violates_control edges to VulnerabilityClass."""
    count = 0
    async with shared_session(write=True) as session:
        for ctrl in COMPLIANCE_CONTROLS:
            cwe_ids = ctrl.pop("cwe_ids", [])
            await session.run(
                """
                MERGE (c:ComplianceControl {framework: $framework, control_id: $control_id})
                SET c.control_name = $control_name,
                    c.obligation_level = $obligation_level,
                    c.source_version = $source_version,
                    c.last_updated = datetime()
                """,
                **ctrl,
            )
            for cwe_id in cwe_ids:
                await session.run(
                    """
                    MATCH (v:VulnerabilityClass {canonical_id: $cwe_id})
                    MATCH (c:ComplianceControl {framework: $framework, control_id: $control_id})
                    MERGE (v)-[:violates_control]->(c)
                    """,
                    cwe_id=cwe_id,
                    framework=ctrl["framework"],
                    control_id=ctrl["control_id"],
                )
            count += 1
    logger.info("compliance_controls_seeded", count=count)
    return count


async def run_all():
    """Run all GKG seeders in order. Called by `make seed-gkg`."""
    print("═" * 60)
    print("SATARK — GKG Seeder (Phase 0)")
    print("═" * 60)

    await seed_schema()
    print("✓ GKG schema indexes created")

    n = await seed_frameworks_and_taint_sources()
    print(f"✓ Seeded {n} TaintSource nodes (5 frameworks)")

    n = await seed_sensitive_ports()
    print(f"✓ Seeded {n} SensitivePort nodes")

    n = await seed_alert_signatures()
    print(f"✓ Seeded {n} AlertSignature nodes (GuardDuty)")

    n = await seed_compliance_controls()
    print(f"✓ Seeded {n} ComplianceControl nodes (PCI-DSS, HIPAA, SOC2, NIST)")

    print("\n⚠  VulnerabilityClass (CWE), AttackPattern (CAPEC), AttackTechnique (ATT&CK)")
    print("   are seeded by seed_taxonomy.py which fetches from MITRE directly.")
    print("   Run: make seed-taxonomy")
    print("═" * 60)
    await close_driver()


if __name__ == "__main__":
    asyncio.run(run_all())
