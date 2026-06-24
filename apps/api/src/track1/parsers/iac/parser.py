"""
SATARK Layer 1 — Terraform IaC Parser (B1)

Fix: aws_wafv2_web_acl_association removed from APPLICATION_FIREWALL_TYPES.
It is an attachment resource, not a firewall itself. Keeping it as a plain
Resource allows the linker's has_waf_association check to detect it by
terraform_resource_type, without over-stamping it as a firewall.
"""
import re
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

NETWORK_FIREWALL_TYPES = {
    "aws_security_group", "aws_network_acl", "aws_default_security_group",
    "google_compute_firewall", "google_compute_network_firewall_policy",
    "azurerm_network_security_group", "azurerm_network_security_rule",
}

# NOTE: aws_wafv2_web_acl_association is intentionally NOT here.
# It is an association/attachment resource. The linker detects it separately.
APPLICATION_FIREWALL_TYPES = {
    "aws_wafv2_web_acl", "aws_waf_web_acl",
    "azurerm_web_application_firewall_policy",
    "google_compute_security_policy",
    "cloudflare_waf_rule",
}

PUBLIC_RESOURCE_INDICATORS = {
    "aws_s3_bucket", "aws_api_gateway_rest_api", "aws_api_gateway_v2_api",
    "aws_lb", "aws_alb", "aws_cloudfront_distribution",
    "google_compute_global_forwarding_rule", "azurerm_public_ip",
}


def _get_resource_subtype(resource_type: str) -> Optional[str]:
    if resource_type in NETWORK_FIREWALL_TYPES:
        return "network_firewall"
    if resource_type in APPLICATION_FIREWALL_TYPES:
        return "application_firewall"
    return None


def _parse_blocks(content: str) -> list[dict]:
    blocks = []
    lines  = content.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        m = re.match(r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', line)
        if m:
            res_type   = m.group(1)
            res_name   = m.group(2)
            start_line = i + 1
            depth      = 1
            body_lines = []
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


def _extract_tags(body: str) -> dict:
    tags = {}
    for m in re.finditer(r'"?(\w+)"?\s*=\s*"([^"]*)"', body):
        tags[m.group(1)] = m.group(2)
    return tags


def _extract_property(body: str, key: str) -> Optional[str]:
    m = re.search(rf'\b{key}\s*=\s*"?([^"\n]+)"?', body)
    return m.group(1).strip().strip('"') if m else None


def _make_entity_id(res_type: str, res_name: str) -> str:
    return f"{ORG_ID}::cloud::terraform::{res_type}.{res_name}"


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
    logger.info("terraform_blocks_found", file=file_path, count=len(blocks))

    for block in blocks:
        res_type  = block["type"]
        res_name  = block["name"]
        body      = block["body"]
        entity_id = _make_entity_id(res_type, res_name)

        tags             = _extract_tags(body)
        resource_subtype = _get_resource_subtype(res_type)
        is_entry         = res_type in PUBLIC_RESOURCE_INDICATORS

        display_name = tags.get("Name") or tags.get("name") or res_name
        summary = f"{res_type} named '{display_name}'"
        if resource_subtype:
            summary += f" ({resource_subtype})"

        # Extract cidr_block for firewall posture computation
        cidr = _extract_property(body, "cidr_block")
        # Also check cidr_blocks array (security group ingress/egress rules)
        if not cidr:
            m = re.search(r'cidr_blocks\s*=\s*\["([^"]+)"', body)
            if m:
                cidr = m.group(1)

        props = {
            "resource_type": res_type,
            "terraform_name": res_name,
            "tags": tags,
        }
        if cidr:
            props["cidr_block"] = cidr
        for key in ("bucket", "function_name", "name"):
            val = _extract_property(body, key)
            if val and not val.startswith("var.") and not val.startswith("local."):
                props[key] = val
                break

        fragment.nodes.append(KGNode(
            entity_id=entity_id, node_type="Resource", domain_type="cloud",
            resource_subtype=resource_subtype, name=display_name, org_id=ORG_ID,
            source_location=SourceLocation(
                file_path=file_path, start_line=block["start_line"], end_line=block["end_line"],
                block_identifier=f"resource.{res_type}.{res_name}",
            ),
            metadata=NodeMetadata(
                is_entry_point=is_entry, semantic_summary=summary,
                resolved_by="deterministic", confidence=1.0,
            ),
            properties=props,
        ))

        if is_entry:
            fragment.entry_points.append(entity_id)

        fragment.edges.append(KGEdge(
            from_entity_id=workspace_id, to_entity_id=entity_id,
            edge_type="E_contain", source_asset_ids=[asset_id],
        ))

    logger.info("terraform_fragment_built", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges))
    return fragment
