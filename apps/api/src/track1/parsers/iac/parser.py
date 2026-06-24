"""
SATARK Layer 1 — Terraform IaC Parser (B1)

Fix: display_name uses tags.Name only (uppercase N = AWS tag convention).
     tags.name (lowercase) matches nested block properties like
     rule { name = "AWSManagedRulesSQLiRuleSet" } and must NOT be used for display_name.

resource_subtype per spec Section 3.3:
  network_firewall: aws_security_group, aws_network_acl, ...
  application_firewall: aws_wafv2_web_acl, aws_wafv2_web_acl_association, ...
  (aws_wafv2_web_acl_association is correctly application_firewall per spec)
"""
import re
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

# Per spec Section 3.3
NETWORK_FIREWALL_TYPES = {
    "aws_security_group", "aws_network_acl", "aws_default_security_group",
    "google_compute_firewall", "google_compute_network_firewall_policy",
    "azurerm_network_security_group", "azurerm_network_security_rule",
}
APPLICATION_FIREWALL_TYPES = {
    "aws_wafv2_web_acl", "aws_wafv2_web_acl_association", "aws_waf_web_acl",
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
    """Extract top-level resource blocks only."""
    blocks = []
    lines  = content.split("\n")
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
    """
    Extract only AWS-style tags block key-value pairs.
    Looks specifically for a tags { ... } block to avoid picking up
    nested resource block properties like rule { name = "..." }.
    """
    tags = {}
    # Find a tags block
    m = re.search(r'\btags\s*=\s*\{([^}]*)\}', body, re.DOTALL)
    if m:
        tag_block = m.group(1)
        for tm in re.finditer(r'"?(\w+)"?\s*=\s*"([^"]*)"', tag_block):
            tags[tm.group(1)] = tm.group(2)
    return tags


def _extract_property(body: str, key: str) -> Optional[str]:
    """Extract a top-level property value (not inside nested blocks)."""
    # Use word boundary to avoid partial matches (cidr_block vs cidr_blocks)
    m = re.search(rf'\b{re.escape(key)}\b\s*=\s*"([^"]+)"', body)
    return m.group(1).strip() if m else None


def _extract_cidr(body: str) -> Optional[str]:
    """
    Extract CIDR from security group rules.
    Checks both cidr_block = "x.x.x.x/x" and cidr_blocks = ["x.x.x.x/x"].
    Returns the most permissive CIDR found.
    """
    # cidr_blocks = ["0.0.0.0/0"] or cidr_blocks = ["..."]
    for m in re.finditer(r'cidr_blocks\s*=\s*\[([^\]]*)\]', body):
        cidrs_str = m.group(1)
        if "0.0.0.0/0" in cidrs_str or "::/0" in cidrs_str:
            return "0.0.0.0/0"
        # Return first CIDR found
        first = re.search(r'"([^"]+)"', cidrs_str)
        if first:
            return first.group(1)

    # cidr_block = "x.x.x.x/x"
    m = re.search(r'\bcidr_block\b\s*=\s*"([^"]+)"', body)
    return m.group(1) if m else None


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

        # Extract AWS tags block only — avoids nested block property bleed
        tags = _extract_aws_tags(body)

        resource_subtype = _get_resource_subtype(res_type)
        is_entry         = res_type in PUBLIC_RESOURCE_INDICATORS

        # display_name: AWS tag "Name" (uppercase N) → resource label
        # Do NOT use tags.get("name") — it matches nested block properties
        display_name = tags.get("Name") or res_name

        summary = f"{res_type} named '{display_name}'"
        if resource_subtype:
            summary += f" ({resource_subtype})"

        # CIDR extraction for firewall posture Sub-step F
        cidr = _extract_cidr(body)

        props = {
            "resource_type": res_type,
            "terraform_name": res_name,
            "tags": tags,
        }
        if cidr:
            props["cidr_block"] = cidr

        # Extract resource_arn for WAF association (used in Pass 3 E_routes_to)
        resource_arn = _extract_property(body, "resource_arn")
        if resource_arn:
            props["resource_arn"] = resource_arn

        # Extract execution role ARN for Lambda/EC2/ECS (used in Pass 3 E_trust)
        role_arn = _extract_property(body, "role")
        if not role_arn:
            role_arn = _extract_property(body, "execution_role_arn")
        if not role_arn:
            role_arn = _extract_property(body, "task_role_arn")
        if role_arn and "arn:aws" in role_arn:
            props["role_arn"] = role_arn

        # Extract VPC security group references (used in Pass 3 posture)
        sg_refs = re.findall(r'aws_security_group\.\w+\.id', body)
        if sg_refs:
            props["security_group_refs"] = sg_refs

        # Capture bucket/function name as secondary display info
        for key in ("bucket", "function_name"):
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
