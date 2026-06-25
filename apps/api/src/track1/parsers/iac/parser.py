"""
SATARK Layer 1 — Terraform IaC Parser (B1) — v3

ROOT CAUSE FIXES:
  1. WAF association: extracts web_acl_arn and resource_arn even when they are
     Terraform cross-references (aws_wafv2_web_acl.X.arn). Resolves these to the
     terraform_name of the referenced resource so the linker can match by name.
     Also stores the raw reference for fallback.
  2. Role ARN: Lambda `role = aws_iam_role.X.arn` — also a Terraform reference.
     Parser now extracts BOTH the raw value and the terraform_name it points to.
  3. Security group rules: ingress/egress blocks → structured rules[] array.
  4. IAM Role nodes get a `role_name` top-level property (the terraform_name)
     so the linker can match by name when no real ARN is present.
  5. aws_wafv2_web_acl_association is stored as DeferredRelation (not a node)
     with terraform_name references so the linker can resolve them.
"""
from __future__ import annotations
import re
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

NETWORK_FIREWALL_TYPES = {
    "aws_security_group", "aws_network_acl", "aws_default_security_group",
    "google_compute_firewall", "azurerm_network_security_group",
}
APPLICATION_FIREWALL_TYPES = {
    "aws_wafv2_web_acl", "aws_waf_web_acl",
    "azurerm_web_application_firewall_policy", "google_compute_security_policy",
}
PUBLIC_RESOURCE_INDICATORS = {
    "aws_s3_bucket", "aws_api_gateway_rest_api", "aws_api_gateway_v2_api",
    "aws_lb", "aws_alb", "aws_cloudfront_distribution",
}
# These become DeferredRelation stubs, not real nodes
RELATION_TYPES = {
    "aws_wafv2_web_acl_association",
    "aws_iam_role_policy_attachment",
    "aws_iam_policy_attachment",
}


def _get_resource_subtype(resource_type: str) -> Optional[str]:
    if resource_type in NETWORK_FIREWALL_TYPES:
        return "network_firewall"
    if resource_type in APPLICATION_FIREWALL_TYPES:
        return "application_firewall"
    return None


def _make_entity_id(res_type: str, res_name: str) -> str:
    return f"{ORG_ID}::cloud::terraform::{res_type}.{res_name}"


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
                "type": res_type, "name": res_name,
                "body": "\n".join(body_lines),
                "start_line": start_line, "end_line": i,
            })
            continue
        i += 1
    return blocks


def _extract_aws_tags(body: str) -> dict:
    tags = {}
    m = re.search(r'\btags\s*=\s*\{([^}]*)\}', body, re.DOTALL)
    if m:
        for tm in re.finditer(r'"?(\w+)"?\s*=\s*"([^"]*)"', m.group(1)):
            tags[tm.group(1)] = tm.group(2)
    return tags


def _extract_property(body: str, key: str) -> Optional[str]:
    """Extract a top-level property — quoted string value."""
    m = re.search(rf'\b{re.escape(key)}\b\s*=\s*"([^"]+)"', body)
    return m.group(1).strip() if m else None


def _extract_property_unquoted(body: str, key: str) -> Optional[str]:
    """
    Extract a property value that may be a Terraform reference (unquoted).
    e.g. role = aws_iam_role.payment_processor_role.arn
         web_acl_arn = aws_wafv2_web_acl.payments_waf.arn
    Returns the raw value (quoted or unquoted).
    """
    # Try quoted first
    m = re.search(rf'\b{re.escape(key)}\b\s*=\s*"([^"]+)"', body)
    if m:
        return m.group(1).strip()
    # Try unquoted reference (Terraform cross-reference)
    m = re.search(rf'\b{re.escape(key)}\b\s*=\s*([a-zA-Z_][a-zA-Z0-9_.]+)', body)
    if m:
        return m.group(1).strip()
    return None


def _resolve_tf_reference(ref: str) -> Optional[str]:
    """
    Given a Terraform reference like 'aws_wafv2_web_acl.payments_waf.arn',
    extract the terraform_name (middle segment) so linker can match by name.
    Returns None if not a reference.
    """
    if not ref or ref.startswith("arn:") or ref.startswith("var.") or ref.startswith("local."):
        return None
    parts = ref.split(".")
    # aws_wafv2_web_acl.payments_waf.arn → payments_waf
    if len(parts) >= 3:
        return parts[1]
    return None


def _extract_cidr(body: str) -> Optional[str]:
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
    """Extract structured ingress/egress rules from a security group body."""
    rules = []
    for direction in ("ingress", "egress"):
        for block_match in re.finditer(
            rf'\b{direction}\s*\{{([^}}]*)\}}', body, re.DOTALL
        ):
            block = block_match.group(1)
            rule: dict = {"direction": direction}
            for port_key in ("from_port", "to_port"):
                pm = re.search(rf'\b{port_key}\b\s*=\s*(\d+)', block)
                if pm:
                    rule[port_key] = int(pm.group(1))
            pm = re.search(r'\bprotocol\b\s*=\s*"([^"]+)"', block)
            if pm:
                rule["protocol"] = pm.group(1)
            cm = re.search(r'cidr_blocks\s*=\s*\[([^\]]*)\]', block)
            if cm:
                cidrs = re.findall(r'"([^"]+)"', cm.group(1))
                rule["cidr_blocks"] = cidrs
                if "0.0.0.0/0" in cidrs or "::/0" in cidrs:
                    rule["open_world"] = True
            dm = re.search(r'\bdescription\b\s*=\s*"([^"]*)"', block)
            if dm:
                rule["description"] = dm.group(1)
            rules.append(rule)
    return rules


def parse_terraform_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="cloud")

    workspace_id = f"{ORG_ID}::cloud::{asset_id}::workspace"
    fragment.nodes.append(KGNode(
        entity_id=workspace_id, node_type="TerraformWorkspace", domain_type="cloud",
        name=asset_id,
        source_location=SourceLocation(file_path=file_path, block_identifier="workspace"),
        org_id=ORG_ID,
    ))

    blocks = _parse_blocks(content)

    # ── Build a name→entity_id index of all blocks in this file ───────────────
    # Used to resolve Terraform cross-references within the same file
    local_index: dict[str, str] = {
        b["name"]: _make_entity_id(b["type"], b["name"]) for b in blocks
    }

    logger.info("terraform_blocks_found", file=file_path, count=len(blocks))

    for block in blocks:
        res_type = block["type"]
        res_name = block["name"]
        body = block["body"]
        entity_id = _make_entity_id(res_type, res_name)

        # ── DeferredRelation types (become edges in Pass 3, not nodes) ────────
        if res_type in RELATION_TYPES:
            if res_type == "aws_wafv2_web_acl_association":
                # Extract both quoted ARNs and Terraform cross-references
                web_acl_raw = _extract_property_unquoted(body, "web_acl_arn")
                resource_raw = _extract_property_unquoted(body, "resource_arn")

                # Resolve Terraform references to terraform_names
                web_acl_tf_name = _resolve_tf_reference(web_acl_raw) if web_acl_raw else None
                resource_tf_name = _resolve_tf_reference(resource_raw) if resource_raw else None

                fragment.deferred_relations.append({
                    "terraform_type": res_type,
                    "terraform_name": res_name,
                    "edge_type": "E_routes_to",
                    "resolution_method": "identifier_keyed",
                    "confidence": 1.0,
                    # Raw values (real ARNs if present)
                    "web_acl_arn_raw": web_acl_raw or "",
                    "resource_arn_raw": resource_raw or "",
                    # Resolved terraform names (for name-keyed fallback)
                    "web_acl_tf_name": web_acl_tf_name or "",
                    "resource_tf_name": resource_tf_name or "",
                })
                logger.debug("waf_assoc_deferred", name=res_name,
                             waf=web_acl_tf_name, target=resource_tf_name)
            continue

        tags = _extract_aws_tags(body)
        resource_subtype = _get_resource_subtype(res_type)
        is_entry = res_type in PUBLIC_RESOURCE_INDICATORS
        display_name = tags.get("Name") or res_name

        props: dict = {
            "resource_type": res_type,
            "terraform_name": res_name,
            "tags": tags,
        }

        # ── Security group rules ───────────────────────────────────────────────
        if resource_subtype == "network_firewall":
            rules = _extract_security_group_rules(body)
            if rules:
                props["rules"] = rules
            cidr = _extract_cidr(body)
            if cidr:
                props["cidr_block"] = cidr
            elif any(r.get("open_world") for r in rules):
                props["cidr_block"] = "0.0.0.0/0"

        if "cidr_block" not in props:
            cidr = _extract_cidr(body)
            if cidr:
                props["cidr_block"] = cidr

        # ── Role ARN (Lambda/EC2/ECS → IAM Role bridge) ───────────────────────
        # May be a real ARN or a Terraform reference like aws_iam_role.X.arn
        for role_field in ("role", "execution_role_arn", "task_role_arn"):
            role_raw = _extract_property_unquoted(body, role_field)
            if role_raw:
                if role_raw.startswith("arn:aws"):
                    props["role_arn"] = role_raw
                else:
                    # Terraform cross-reference: resolve to terraform_name
                    tf_name = _resolve_tf_reference(role_raw)
                    if tf_name:
                        props["role_tf_name"] = tf_name  # e.g. "payment_processor_role"
                        # Construct the entity_id it would have
                        props["role_entity_id"] = _make_entity_id("aws_iam_role", tf_name)
                break

        # ── WAF ARN for the WAF node itself ───────────────────────────────────
        resource_arn = _extract_property(body, "resource_arn")
        if resource_arn:
            props["resource_arn"] = resource_arn

        # ── Bucket / function name ─────────────────────────────────────────────
        for key in ("bucket", "function_name"):
            val = _extract_property(body, key)
            if val and not val.startswith("var.") and not val.startswith("local."):
                props[key] = val

        # ── SG references ──────────────────────────────────────────────────────
        sg_refs = re.findall(r'aws_security_group\.\w+\.id', body)
        if sg_refs:
            props["security_group_refs"] = sg_refs

        summary = f"{res_type} named '{display_name}'"
        if resource_subtype:
            summary += f" ({resource_subtype})"

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

        fragment.edges.append(KGEdge(
            from_entity_id=workspace_id,
            to_entity_id=entity_id,
            edge_type="E_contain",
            source_asset_ids=[asset_id],
        ))

    logger.info("terraform_parse_complete", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges),
                deferred=len(fragment.deferred_relations))
    return fragment
