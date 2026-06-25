"""
SATARK Layer 1 — Terraform IaC Parser (B1) — FIXED v2

Key fixes vs original:
  1. Reads domain_configs/terraform.yaml — no hardcoded resource type logic
  2. RELATION resources (aws_wafv2_web_acl_association) → NOT a node, emitted
     as a deferred relation for Pass 3 linker to create E_routes_to
  3. Security group ingress/egress blocks → structured rules[] array (was null)
  4. display_name correctly uses tags.Name (uppercase N) only
  5. resource_subtype follows spec Section 3.3 — from config, not hardcoded
  6. ARN properties extracted to top-level properties for Pass 3 identifier-keyed linking
  7. Ignore list prevents nested WAF rule blocks from becoming nodes
"""
from __future__ import annotations
import re
import os
import yaml
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

# ── Load domain config ────────────────────────────────────────────────────────

_DOMAIN_CONFIG_DIRS = [
    "/app/domain_configs",                          # Docker container path
    os.path.join(os.path.dirname(__file__), "../../../../../domain_configs"),  # local dev
    os.path.join(os.path.dirname(__file__), "../../../../../../domain_configs"),
]

def _load_config() -> dict:
    for d in _DOMAIN_CONFIG_DIRS:
        p = os.path.join(d, "terraform.yaml")
        if os.path.exists(p):
            with open(p) as f:
                return yaml.safe_load(f)
    dirs_str = ", ".join(_DOMAIN_CONFIG_DIRS)
    raise FileNotFoundError(
        "domain_configs YAML not found. Looked in: " + dirs_str +
        " -- Copy domain_configs/ to repo root and add volume mount."
    )

_CFG = _load_config()

# Build lookup structures from config
_RESOURCE_MAP: dict[str, dict] = {
    m["terraform_type"]: m for m in _CFG.get("resource_mappings", [])
}
_RELATION_MAP: dict[str, dict] = {
    m["terraform_type"]: m for m in _CFG.get("relation_mappings", [])
}
_IGNORE_TYPES: set[str] = set(_CFG.get("ignore_resource_types", []))
_ENTRY_POINT_TYPES: set[str] = {
    m["terraform_type"] for m in _CFG.get("resource_mappings", [])
    if m.get("is_entry_point_type")
}


# ── Entity ID ─────────────────────────────────────────────────────────────────

def _make_entity_id(res_type: str, res_name: str) -> str:
    return f"{ORG_ID}::cloud::terraform::{res_type}.{res_name}"


# ── Block parser ─────────────────────────────────────────────────────────────

def _parse_blocks(content: str) -> list[dict]:
    """Extract top-level resource blocks only."""
    blocks = []
    lines = content.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        m = re.match(r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', line)
        if m:
            res_type, res_name = m.group(1), m.group(2)
            start_line = i + 1
            depth, body_lines = 1, []
            i += 1
            while i < len(lines) and depth > 0:
                l = lines[i]
                depth += l.count("{") - l.count("}")
                if depth > 0:
                    body_lines.append(l)
                i += 1
            blocks.append({
                "type": res_type,
                "name": res_name,
                "body": "\n".join(body_lines),
                "start_line": start_line,
                "end_line": i,
            })
            continue
        i += 1
    return blocks


# ── Property extractors ───────────────────────────────────────────────────────

def _extract_aws_tags(body: str) -> dict:
    """Extract only AWS-style tags { } block — avoids nested block name bleed."""
    tags = {}
    m = re.search(r'\btags\s*=\s*\{([^}]*)\}', body, re.DOTALL)
    if m:
        for tm in re.finditer(r'"?(\w+)"?\s*=\s*"([^"]*)"', m.group(1)):
            tags[tm.group(1)] = tm.group(2)
    return tags


def _extract_property(body: str, key: str) -> Optional[str]:
    """Extract a top-level property value (not inside nested blocks)."""
    m = re.search(rf'\b{re.escape(key)}\b\s*=\s*"([^"]+)"', body)
    return m.group(1).strip() if m else None


def _extract_cidr(body: str) -> Optional[str]:
    """Extract most permissive CIDR from body."""
    for m in re.finditer(r'cidr_blocks\s*=\s*\[([^\]]*)\]', body):
        cidrs_str = m.group(1)
        if "0.0.0.0/0" in cidrs_str or "::/0" in cidrs_str:
            return "0.0.0.0/0"
        first = re.search(r'"([^"]+)"', cidrs_str)
        if first:
            return first.group(1)
    m = re.search(r'\bcidr_block\b\s*=\s*"([^"]+)"', body)
    return m.group(1) if m else None


def _extract_security_group_rules(body: str) -> list[dict]:
    """
    FIX: Extract structured ingress/egress rules from a security group body.

    Each block looks like:
      ingress {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
        description = "HTTPS"
      }

    Returns a list of rule dicts:
      {direction, from_port, to_port, protocol, cidr_blocks, description}
    """
    rules = []
    # Match all ingress/egress blocks including nested content
    for direction in ("ingress", "egress"):
        for block_match in re.finditer(
            rf'\b{direction}\s*\{{([^}}]*)\}}',
            body,
            re.DOTALL,
        ):
            block = block_match.group(1)
            rule: dict = {"direction": direction}

            # from_port / to_port
            for port_key in ("from_port", "to_port"):
                pm = re.search(rf'\b{port_key}\b\s*=\s*(\d+)', block)
                if pm:
                    rule[port_key] = int(pm.group(1))

            # protocol
            pm = re.search(r'\bprotocol\b\s*=\s*"([^"]+)"', block)
            if pm:
                rule["protocol"] = pm.group(1)

            # cidr_blocks = ["..."]
            cm = re.search(r'cidr_blocks\s*=\s*\[([^\]]*)\]', block)
            if cm:
                cidrs = re.findall(r'"([^"]+)"', cm.group(1))
                rule["cidr_blocks"] = cidrs
                # Flag open-world
                if "0.0.0.0/0" in cidrs or "::/0" in cidrs:
                    rule["open_world"] = True

            # description
            dm = re.search(r'\bdescription\b\s*=\s*"([^"]*)"', block)
            if dm:
                rule["description"] = dm.group(1)

            rules.append(rule)

    return rules


def _extract_relation_fields(body: str, relation_cfg: dict) -> dict:
    """Extract source_field and target_field for a relation mapping."""
    result = {}
    for field in [relation_cfg.get("source_field"), relation_cfg.get("target_field")]:
        if field:
            val = _extract_property(body, field)
            if val:
                result[field] = val
    return result


# ── Main parser ───────────────────────────────────────────────────────────────

def parse_terraform_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="cloud")

    # Workspace root node
    workspace_id = f"{ORG_ID}::cloud::{asset_id}::workspace"
    fragment.nodes.append(KGNode(
        entity_id=workspace_id,
        node_type="TerraformWorkspace",
        domain_type="cloud",
        name=asset_id,
        source_location=SourceLocation(
            file_path=file_path,
            block_identifier="workspace",
        ),
        org_id=ORG_ID,
    ))

    blocks = _parse_blocks(content)
    logger.info("terraform_blocks_found", file=file_path, count=len(blocks))

    for block in blocks:
        res_type = block["type"]
        res_name = block["name"]
        body = block["body"]

        # ── Skip ignored types ────────────────────────────────────────────────
        if res_type in _IGNORE_TYPES:
            logger.debug("terraform_block_ignored", type=res_type, name=res_name)
            continue

        # ── Handle relation types (WAF association, etc.) ─────────────────────
        if res_type in _RELATION_MAP:
            rel_cfg = _RELATION_MAP[res_type]
            fields = _extract_relation_fields(body, rel_cfg)
            # Store as deferred relation in fragment for Pass 3 linker
            fragment.deferred_relations.append({
                "terraform_type": res_type,
                "terraform_name": res_name,
                "edge_type": rel_cfg["edge_type"],
                "resolution_method": rel_cfg.get("resolution_method", "identifier_keyed"),
                "confidence": rel_cfg.get("confidence", 1.0),
                "source_field": rel_cfg.get("source_field"),
                "target_field": rel_cfg.get("target_field"),
                **fields,
            })
            logger.debug(
                "terraform_relation_deferred",
                type=res_type,
                name=res_name,
                fields=fields,
            )
            continue

        # ── Unknown resource types (not in whitelist, not in relations) ────────
        if res_type not in _RESOURCE_MAP:
            logger.debug("terraform_block_unknown", type=res_type, name=res_name)
            # Create a minimal stub so we don't silently lose it
            # but mark it clearly as unclassified
            entity_id = _make_entity_id(res_type, res_name)
            fragment.nodes.append(KGNode(
                entity_id=entity_id,
                node_type="Resource",
                domain_type="cloud",
                name=res_name,
                source_location=SourceLocation(
                    file_path=file_path,
                    start_line=block["start_line"],
                    end_line=block["end_line"],
                    block_identifier=f"resource.{res_type}.{res_name}",
                ),
                metadata=NodeMetadata(
                    semantic_summary=f"Unclassified Terraform resource: {res_type} '{res_name}'",
                    resolved_by="deterministic",
                    confidence=1.0,
                ),
                properties={"resource_type": res_type, "terraform_name": res_name},
                org_id=ORG_ID,
            ))
            fragment.edges.append(KGEdge(
                from_entity_id=workspace_id,
                to_entity_id=entity_id,
                edge_type="E_contain",
                source_asset_ids=[asset_id],
            ))
            continue

        # ── Known resource type — create node ─────────────────────────────────
        res_cfg = _RESOURCE_MAP[res_type]
        entity_id = _make_entity_id(res_type, res_name)
        tags = _extract_aws_tags(body)
        resource_subtype = res_cfg.get("resource_subtype")
        is_entry = res_type in _ENTRY_POINT_TYPES
        display_name = tags.get("Name") or res_name

        summary = f"{res_type} named '{display_name}'"
        if resource_subtype:
            summary += f" ({resource_subtype})"

        props: dict = {
            "resource_type": res_type,
            "terraform_name": res_name,
            "tags": tags,
        }

        # ── Security group rules (FIX: was always null) ───────────────────────
        if res_cfg.get("extract_rules", {}).get("enabled"):
            rules = _extract_security_group_rules(body)
            if rules:
                props["rules"] = rules
                # Also extract most permissive CIDR at top level for posture
                for rule in rules:
                    if rule.get("open_world"):
                        props["cidr_block"] = "0.0.0.0/0"
                        break
                if "cidr_block" not in props:
                    cidr = _extract_cidr(body)
                    if cidr:
                        props["cidr_block"] = cidr

        # ── CIDR (non-rule resources like VPC, subnet) ────────────────────────
        if "cidr_block" not in props:
            cidr = _extract_cidr(body)
            if cidr:
                props["cidr_block"] = cidr

        # ── ARN properties for Pass 3 identifier-keyed linking ────────────────
        for arn_key in _CFG.get("arn_properties", []):
            val = _extract_property(body, arn_key)
            if val and "arn:aws" in val:
                props[arn_key] = val

        # Unify: role= and execution_role_arn= and task_role_arn= → role_arn
        for role_field in ("role", "execution_role_arn", "task_role_arn"):
            if role_field in props:
                if "arn:aws" in props[role_field]:
                    props["role_arn"] = props[role_field]
                    break

        # ── Resource-specific extra properties ────────────────────────────────
        for key in ("bucket", "function_name", "name"):
            val = _extract_property(body, key)
            if val and not val.startswith("var.") and not val.startswith("local."):
                props[key] = val

        # VPC SG references (for posture graph)
        sg_refs = re.findall(r'aws_security_group\.\w+\.id', body)
        if sg_refs:
            props["security_group_refs"] = sg_refs

        # ── Create node ───────────────────────────────────────────────────────
        fragment.nodes.append(KGNode(
            entity_id=entity_id,
            node_type="Resource",
            domain_type="cloud",
            resource_subtype=resource_subtype,
            name=display_name,
            source_location=SourceLocation(
                file_path=file_path,
                start_line=block["start_line"],
                end_line=block["end_line"],
                block_identifier=f"resource.{res_type}.{res_name}",
            ),
            metadata=NodeMetadata(
                is_entry_point=is_entry,
                semantic_summary=summary,
                resolved_by="deterministic",
                confidence=1.0,
            ),
            properties=props,
            org_id=ORG_ID,
        ))

        # Workspace → resource containment
        fragment.edges.append(KGEdge(
            from_entity_id=workspace_id,
            to_entity_id=entity_id,
            edge_type="E_contain",
            source_asset_ids=[asset_id],
        ))

    logger.info(
        "terraform_parse_complete",
        file=file_path,
        nodes=len(fragment.nodes),
        edges=len(fragment.edges),
        deferred_relations=len(getattr(fragment, "deferred_relations", [])),
    )
    return fragment
