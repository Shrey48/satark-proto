"""
SATARK Layer 1 — Compliance Declarations Parser (D1)
Handles: JSON/YAML compliance declarations, framework-specific exports.

Produces per spec Section 2.3:
  ComplianceRule nodes in KG fact layer
  BusinessUnit nodes (if declared)
  E_governs edges via 4-step decision tree (applied in Pass 3)

Supported formats:
  1. SATARK native format: {framework, controls: [{id, name, scope, ...}]}
  2. PCI-DSS export, HIPAA, SOC2, NIST-800-53 common formats
  3. Generic: any JSON/YAML with 'controls' or 'requirements' array
"""
import json
import yaml
import re
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"


def _make_entity_id(*parts: str) -> str:
    safe = ".".join(re.sub(r'[^a-z0-9._-]', '_', str(p).lower()) for p in parts)
    return f"{ORG_ID}::grc::compliance::{safe}"


def _extract_controls(spec: dict, file_path: str) -> tuple[str, str, list[dict]]:
    """
    Extract (org_name, framework, controls_list) from any compliance JSON/YAML.
    Controls are normalised to: {id, name, obligation_level, scope, applies_to}
    """
    # Format 1: SATARK native
    # {"org": "...", "framework": "PCI-DSS", "version": "4.0", "controls": [...]}
    if "controls" in spec:
        return (
            spec.get("org", "unknown"),
            spec.get("framework", "generic"),
            spec["controls"] if isinstance(spec["controls"], list) else [],
        )

    # Format 2: "requirements" key
    if "requirements" in spec:
        return (
            spec.get("org", "unknown"),
            spec.get("framework", spec.get("standard", "generic")),
            spec["requirements"] if isinstance(spec["requirements"], list) else [],
        )

    # Format 3: {"framework": {..., "requirements": [...]}}
    if "framework" in spec and isinstance(spec["framework"], dict):
        fw = spec["framework"]
        return (
            spec.get("org", "unknown"),
            fw.get("name", "generic"),
            fw.get("requirements", fw.get("controls", [])),
        )

    # Format 4: Top-level array of controls
    if isinstance(spec, list):
        return "unknown", "generic", spec

    raise ValueError(f"unrecognised compliance format — keys: {sorted(spec.keys())}")


def _normalise_control(raw: dict) -> dict:
    """Normalise a control dict to a common schema."""
    return {
        "control_id":        raw.get("id") or raw.get("control_id") or raw.get("rule_id", "UNKNOWN"),
        "name":              raw.get("name") or raw.get("title") or raw.get("description", "")[:100],
        "obligation_level":  raw.get("obligation_level") or raw.get("level") or raw.get("severity", "mandatory"),
        "scope":             raw.get("scope") or raw.get("applies_to") or raw.get("asset_types", []),
        "description":       (raw.get("description") or raw.get("text", ""))[:300],
        "cwe_ids":           raw.get("cwe_ids") or raw.get("cwe", []),
    }


def parse_compliance_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="grc")

    # Parse JSON or YAML
    try:
        spec = json.loads(content)
    except json.JSONDecodeError:
        try:
            spec = yaml.safe_load(content)
        except yaml.YAMLError as e:
            logger.error("compliance_parse_error", file=file_path, error=str(e))
            return fragment

    if not spec:
        return fragment

    try:
        org_name, framework, raw_controls = _extract_controls(spec, file_path)
    except ValueError as e:
        logger.warning("compliance_unrecognised_format", file=file_path, reason=str(e))
        return fragment

    # Framework root node
    fw_id = _make_entity_id(framework, "framework")
    fragment.nodes.append(KGNode(
        entity_id=fw_id, node_type="ComplianceFramework", domain_type="grc",
        name=framework,
        source_location=SourceLocation(file_path=file_path, block_identifier="framework"),
        metadata=NodeMetadata(
            semantic_summary=f"Compliance framework: {framework} (org: {org_name})",
            resolved_by="deterministic",
        ),
        properties={"framework": framework, "org": org_name,
                    "version": spec.get("version", "unknown")},
        org_id=ORG_ID,
    ))

    # ComplianceRule nodes — one per control
    for raw in raw_controls:
        if not isinstance(raw, dict):
            continue
        ctrl = _normalise_control(raw)

        rule_id = _make_entity_id(framework, "rule", ctrl["control_id"])
        scope   = ctrl["scope"]
        if isinstance(scope, str):
            scope = [scope]

        fragment.nodes.append(KGNode(
            entity_id=rule_id, node_type="ComplianceRule", domain_type="grc",
            name=f"{framework} {ctrl['control_id']}",
            source_location=SourceLocation(
                file_path=file_path,
                block_identifier=f"controls.{ctrl['control_id']}"),
            metadata=NodeMetadata(
                semantic_summary=f"{framework} {ctrl['control_id']}: {ctrl['name']}",
                resolved_by="deterministic",
            ),
            properties={
                "framework":        framework,
                "control_id":       ctrl["control_id"],
                "control_name":     ctrl["name"],
                "obligation_level": ctrl["obligation_level"],
                "scope":            scope,
                "description":      ctrl["description"],
                "cwe_ids":          ctrl["cwe_ids"],
            },
            org_id=ORG_ID,
        ))
        fragment.edges.append(KGEdge(
            from_entity_id=fw_id, to_entity_id=rule_id,
            edge_type="E_contain", source_asset_ids=[asset_id],
        ))

    logger.info("compliance_fragment_built", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges),
                framework=framework, controls=len(raw_controls))
    return fragment
