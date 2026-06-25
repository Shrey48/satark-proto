"""
SATARK Layer 1 — Graph Fragment Writer — FIXED v2

Key fixes vs original:
  1. Handles deferred_relations (WAF association, etc.) — stores them as
     stub nodes with special node_type='DeferredRelation' so Pass 3 linker
     can query and resolve them into real edges.
  2. Extracts pod_template_app_label and pod_template_app_label from K8s nodes
     as top-level props for Cypher matching in the linker.
  3. Extracts arn from IAM Principal nodes for identifier-keyed matching.
  4. Extracts irsa_role_arn as top-level property for K8s ServiceAccount nodes.
  5. Extracts web_acl_arn and resource_arn from WAF DeferredRelation stubs.
  6. All existing extractions preserved.
"""
from models.nodes import GraphFragment
from core.database.neo4j import tenant_session
import structlog
import json

logger = structlog.get_logger(__name__)


def _extract_top_level(domain_type: str, node_type: str, props: dict) -> dict:
    """
    Extract key identifiers from the properties dict as top-level Neo4j properties.
    These are directly queryable with Cypher — unlike the stringified props bag.
    """
    out = {}
    if not props:
        return out

    # ── IAM ───────────────────────────────────────────────────────────────────
    if domain_type == "iam":
        if "actions" in props:
            out["iam_actions"] = props["actions"] if isinstance(props["actions"], list) else [props["actions"]]
        if "effect" in props:
            out["iam_effect"] = props["effect"]
        if "resource_count" in props:
            out["iam_resource_count"] = props["resource_count"]
        if "arn" in props:
            out["arn"] = props["arn"]
        if "wildcard_pattern" in props:
            out["wildcard_pattern"] = props["wildcard_pattern"]
        # FIX: Extract principal_type and principal_value for Principal nodes
        if node_type == "Principal":
            if "principal_type" in props:
                out["principal_type"] = props["principal_type"]
            if "principal_value" in props:
                out["principal_value"] = props["principal_value"]
                # If the principal_value is an ARN, also store as arn
                pval = props["principal_value"]
                if isinstance(pval, str) and pval.startswith("arn:"):
                    out["arn"] = pval

    # ── Cloud (Terraform) ─────────────────────────────────────────────────────
    if domain_type == "cloud":
        if "arn" in props:
            out["arn"] = props["arn"]
        if "resource_arn" in props:
            out["resource_arn"] = props["resource_arn"]
        if "role_arn" in props:
            out["role_arn"] = props["role_arn"]
        if "resource_type" in props:
            out["terraform_resource_type"] = props["resource_type"]
        tags = props.get("tags", {})
        if isinstance(tags, dict):
            if "service" in tags:
                out["tag_service"] = tags["service"]
            if "Name" in tags:
                out["tag_name"] = tags["Name"]
            if "app" in tags:
                out["tag_app"] = tags["app"]
        for k in ("bucket", "function_name", "cidr_block", "name"):
            if k in props:
                out[k] = props[k]
        # FIX: WAF-specific ARN fields for Pass 3 resolution
        if "web_acl_arn" in props:
            out["web_acl_arn"] = props["web_acl_arn"]
        # Security group rules (structured) for posture Sub-step F
        if "rules" in props and isinstance(props["rules"], list):
            # Serialize rules as JSON string for Neo4j storage
            out["rules"] = json.dumps(props["rules"])

    # ── K8s ───────────────────────────────────────────────────────────────────
    if domain_type == "k8s":
        if "irsa_role_arn" in props:
            out["irsa_role_arn"] = props["irsa_role_arn"]
        labels = props.get("labels", {})
        if isinstance(labels, dict):
            if "app" in labels:
                out["k8s_app_label"] = labels["app"]
            elif "app.kubernetes.io/name" in labels:
                out["k8s_app_label"] = labels["app.kubernetes.io/name"]
        # FIX: pod_template_app_label — key for Service→Deployment matching
        if "pod_template_app_label" in props:
            out["pod_template_app_label"] = props["pod_template_app_label"]
            # Also set k8s_app_label from pod template if not set from node labels
            if "k8s_app_label" not in out:
                out["k8s_app_label"] = props["pod_template_app_label"]
        if "kind" in props:
            out["k8s_kind"] = props["kind"]
        if "namespace" in props:
            out["k8s_namespace"] = props["namespace"]
        ports = props.get("ports", [])
        if ports:
            out["ports"] = [p for p in ports if p]
        # Service selector
        selector = props.get("selector", {})
        if isinstance(selector, dict) and selector:
            selector_app = (
                selector.get("app")
                or selector.get("app.kubernetes.io/name")
                or selector.get("name")
            )
            if selector_app:
                out["k8s_selector_app"] = selector_app
        # Service account name (for within-asset linking)
        if "service_account_name" in props:
            out["service_account_name"] = props["service_account_name"]

    # ── Code ──────────────────────────────────────────────────────────────────
    if domain_type == "code":
        if "taint_class" in props:
            out["taint_class"] = props["taint_class"]
        if "class" in props and props["class"]:
            out["class_name"] = props["class"]

    # ── DeferredRelation (WAF association and other relation types) ────────────
    if node_type == "DeferredRelation":
        for field in ("edge_type", "source_field", "target_field",
                      "web_acl_arn", "resource_arn", "resolution_method",
                      "confidence", "terraform_type", "terraform_name"):
            if field in props:
                out[field] = props[field]

    return out


async def write_fragment(fragment: GraphFragment, org_id: str = "prototype") -> dict:
    """Write a graph fragment (nodes + edges + deferred relations) to Neo4j."""
    nodes_written = 0
    edges_written = 0

    async with tenant_session(org_id) as session:

        # ── Write nodes ───────────────────────────────────────────────────────
        for node in fragment.nodes:
            top_level = _extract_top_level(
                node.domain_type or "",
                node.node_type or "",
                node.properties or {},
            )

            props_json = json.dumps(node.properties or {})
            metadata_dict = {}
            if node.metadata:
                metadata_dict = {
                    "semantic_summary": node.metadata.semantic_summary,
                    "is_entry_point": node.metadata.is_entry_point or False,
                    "resolved_by": node.metadata.resolved_by or "deterministic",
                    "confidence": node.metadata.confidence or 1.0,
                    "status": getattr(node.metadata, "status", None),
                }

            source_loc = {}
            if node.source_location:
                source_loc = {
                    "file_path": node.source_location.file_path,
                    "start_line": node.source_location.start_line,
                    "end_line": node.source_location.end_line,
                    "block_identifier": node.source_location.block_identifier,
                }

            await session.run("""
                MERGE (n:Node {entity_id: $entity_id})
                SET n.node_type = $node_type,
                    n.domain_type = $domain_type,
                    n.resource_subtype = $resource_subtype,
                    n.name = $name,
                    n.org_id = $org_id,
                    n.props_json = $props_json,
                    n.valid_from = coalesce(n.valid_from, datetime()),
                    n.valid_to = null,
                    n += $source_loc,
                    n += $metadata,
                    n += $top_level
            """,
                entity_id=node.entity_id,
                node_type=node.node_type,
                domain_type=node.domain_type,
                resource_subtype=node.resource_subtype,
                name=node.name,
                org_id=org_id,
                props_json=props_json,
                source_loc=source_loc,
                metadata=metadata_dict,
                top_level=top_level,
            )
            nodes_written += 1

        # ── Write edges ───────────────────────────────────────────────────────
        for edge in fragment.edges:
            edge_props = {
                "edge_type": edge.edge_type,
                "resolution_method": getattr(edge, "resolution_method", "deterministic_parse"),
                "confidence": getattr(edge, "confidence", 1.0),
                "source_asset_ids": getattr(edge, "source_asset_ids", [fragment.asset_id]),
            }
            # Merge additional edge properties (effect, actions, etc.)
            extra = getattr(edge, "properties", None) or {}
            for k, v in extra.items():
                if isinstance(v, (str, int, float, bool)):
                    edge_props[f"prop_{k}"] = v
                elif isinstance(v, list):
                    edge_props[f"prop_{k}"] = json.dumps(v)

            await session.run("""
                MATCH (a:Node {entity_id: $from_id})
                MATCH (b:Node {entity_id: $to_id})
                MERGE (a)-[r:EDGE {edge_type: $edge_type}]->(b)
                SET r += $props,
                    r.created_at = coalesce(r.created_at, datetime())
            """,
                from_id=edge.from_entity_id,
                to_id=edge.to_entity_id,
                edge_type=edge.edge_type,
                props=edge_props,
            )
            edges_written += 1

        # ── Write deferred relations as queryable stub nodes ──────────────────
        # The linker will query these in Pass 3 and create the real edges.
        for rel in getattr(fragment, "deferred_relations", []):
            dr_entity_id = (
                f"{fragment.asset_id}::deferred_relation::"
                f"{rel.get('terraform_type','')}.{rel.get('terraform_name','')}"
            )
            top_level = _extract_top_level("cloud", "DeferredRelation", rel)

            await session.run("""
                MERGE (n:Node {entity_id: $entity_id})
                SET n.node_type = 'DeferredRelation',
                    n.domain_type = 'cloud',
                    n.name = $name,
                    n.org_id = $org_id,
                    n.valid_from = coalesce(n.valid_from, datetime()),
                    n.valid_to = null,
                    n += $top_level
            """,
                entity_id=dr_entity_id,
                name=rel.get("terraform_name", "deferred_relation"),
                org_id=org_id,
                top_level={**top_level, **{
                    k: v for k, v in rel.items()
                    if isinstance(v, (str, int, float, bool))
                }},
            )

        logger.info(
            "fragment_written",
            asset_id=fragment.asset_id,
            nodes=nodes_written,
            edges=edges_written,
            deferred=len(getattr(fragment, "deferred_relations", [])),
        )
    return {"nodes": nodes_written, "edges": edges_written}
