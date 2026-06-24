"""
SATARK Layer 1 — GKG Node and Edge Schema (P0-11)

The General Knowledge Graph lives in the shared reference database.
All tenants read from it. No tenant writes to it.

Node types (Section 14.2):
  TechnologyFramework, VulnerabilityClass, AttackPattern, AttackTechnique,
  ComplianceControl, TaintSource, AlertSignature, SensitivePort

Internal edge types (Section 14.2 — NOT the 9 KG edge types):
  leads_to, manifests_as, uses_technique, violates_control,
  is_taint_source_in, maps_to_signature, has_affinity_for

Each node carries versioning fields (Section 14.5):
  source_taxonomy, source_version, last_updated, is_deprecated, superseded_by
"""

# ── GKG Schema Cypher (run once at Phase 0 seeding) ──────────────────────────

GKG_SCHEMA_QUERIES = [
    # VulnerabilityClass — CWE entries
    "CREATE INDEX vuln_class_id IF NOT EXISTS FOR (n:VulnerabilityClass) ON (n.canonical_id)",
    "CREATE INDEX vuln_class_domain IF NOT EXISTS FOR (n:VulnerabilityClass) ON (n.domain)",
    # AttackPattern — CAPEC entries
    "CREATE INDEX attack_pattern_id IF NOT EXISTS FOR (n:AttackPattern) ON (n.capec_id)",
    # AttackTechnique — ATT&CK techniques
    "CREATE INDEX attack_technique_id IF NOT EXISTS FOR (n:AttackTechnique) ON (n.technique_id)",
    # ComplianceControl — PCI-DSS, HIPAA, SOC2, NIST, etc.
    "CREATE INDEX compliance_control IF NOT EXISTS FOR (n:ComplianceControl) ON (n.framework, n.control_id)",
    # TaintSource — framework-specific known taint entry points
    "CREATE INDEX taint_source_pattern IF NOT EXISTS FOR (n:TaintSource) ON (n.pattern)",
    "CREATE INDEX taint_source_framework IF NOT EXISTS FOR (n:TaintSource) ON (n.framework_name)",
    # AlertSignature — Snort SIDs, Suricata SIDs, GuardDuty finding types
    "CREATE INDEX alert_sig_id IF NOT EXISTS FOR (n:AlertSignature) ON (n.signature_id, n.source_tool)",
    # SensitivePort — technology-aware port registry (replaces hardcoded port lists)
    "CREATE INDEX sensitive_port IF NOT EXISTS FOR (n:SensitivePort) ON (n.port, n.protocol)",
    # TechnologyFramework
    "CREATE INDEX tech_framework IF NOT EXISTS FOR (n:TechnologyFramework) ON (n.name, n.language)",
]


# ── Node schema definitions (for seeder validation) ───────────────────────────

VULNERABILITY_CLASS_REQUIRED_FIELDS = {
    "canonical_id",    # CWE-89, CWE-79, etc.
    "display_name",    # SQL Injection
    "description",     # Brief description
    "domain",          # code, api, cloud, etc.
    "source_taxonomy", # CWE-4.14
    "source_version",  # 4.14
    "last_updated",    # datetime
    "is_deprecated",   # boolean
}

ATTACK_PATTERN_REQUIRED_FIELDS = {
    "capec_id",        # CAPEC-66
    "name",            # SQL Injection
    "description",
    "prerequisites",
    "source_version",
    "last_updated",
    "is_deprecated",
}

TAINT_SOURCE_REQUIRED_FIELDS = {
    "pattern",         # request.GET, request.args, @RequestParam, etc.
    "api_call",        # The actual API call pattern
    "taint_class",     # external_untrusted
    "framework_name",  # django, flask, spring, rails
    "language",        # python, java, ruby
    "description",
}

ALERT_SIGNATURE_REQUIRED_FIELDS = {
    "signature_id",    # SID number or GuardDuty finding type
    "source_tool",     # snort, suricata, guardduty
    "description",
    "confidence",      # float 0.0–1.0
    "last_updated",
}

COMPLIANCE_CONTROL_REQUIRED_FIELDS = {
    "framework",       # PCI-DSS, HIPAA, SOC2, NIST-800-53, CIS
    "control_id",      # Requirement 6.3.1, §164.312, CC6.1, AC-3
    "control_name",
    "obligation_level",  # mandatory, recommended
    "source_version",
}

SENSITIVE_PORT_REQUIRED_FIELDS = {
    "port",            # 22, 3389, 5432, etc.
    "protocol",        # tcp, udp
    "service_type",    # SSH, RDP, PostgreSQL, etc.
    "risk_level",      # critical, high, medium
    "recommended_action",
}
