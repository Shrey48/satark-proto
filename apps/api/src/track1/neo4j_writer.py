"""
SATARK Layer 1 — Graph Fragment Writer — FINAL

Matches original write_fragment(fragment, org_id="prototype") -> dict signature.
Adds: terraform_name, terraform_resource_type, role_tf_name, role_entity_id,
      web_acl_tf_name, resource_tf_name as top-level Neo4j properties.
These are what the linker queries on.
"""
from models.nodes import GraphFragment
from core.database.neo4j import tenant_session
import structlog
import json

logger = structlog.get_logger(__name__)

ORG_ID = "prototype"


def _extract_top_level(domain_type: str, node_type: str, props: dict) -> dict:
    out = {}
    if not props:
        return out

    # ── IAM ───────────────────────────────────────────────────────────────────
    if domain_type == "iam":
        for k in ("arn", "wildcard_pattern"):
            if props.get(k):
                out[k] = props[k]
        if "actions" in props:
            out["iam_actions"] = (props["actions"] if isinstance(props["actions"], list)
                                  else [props["actions"]])
        if "effect" in props:
            out["iam_effect"] = props["effect"]
        if "resource_count" in props:
            out["iam_resource_count"] = props["resource_count"]

    # ── Cloud (Terraform) ─────────────────────────────────────────────────────
    if domain_type == "cloud":
        for k in ("arn", "resource_arn", "role_arn",
                  "role_tf_name", "role_entity_id",         # new: IAM role resolution
                  "function_name", "bucket", "cidr_block"):
            if props.get(k):
                out[k] = props[k]

        # terraform metadata — CRITICAL for linker
        if props.get("resource_type"):
            out["terraform_resource_type"] = props["resource_type"]
        if props.get("terraform_name"):
            out["terraform_name"] = props["terraform_name"]

        # Tags
        tags = props.get("tags") or {}
        if isinstance(tags, dict):
            for tag_key in ("service", "Name", "app"):
                if tags.get(tag_key):
                    out[f"tag_{tag_key.lower()}"] = tags[tag_key]

        # Security group rules — serialize list for Neo4j
        if "rules" in props and isinstance(props["rules"], list):
            out["rules"] = json.dumps(props["rules"])

    # ── K8s ───────────────────────────────────────────────────────────────────
    if domain_type == "k8s":
        if props.get("irsa_role_arn"):
            out["irsa_role_arn"] = props["irsa_role_arn"]
        if props.get("kind"):
            out["k8s_kind"] = props["kind"]
        if props.get("namespace"):
            out["k8s_namespace"] = props["namespace"]

        labels = props.get("labels") or {}
        if isinstance(labels, dict):
            app = (labels.get("app")
                   or labels.get("app.kubernetes.io/name")
                   or labels.get("name"))
            if app:
                out["k8s_app_label"] = app

        ports = props.get("ports") or []
        if ports:
            out["ports"] = [p for p in ports if p]

        selector = props.get("selector") or {}
        if isinstance(selector, dict) and selector:
            sel = (selector.get("app")
                   or selector.get("app.kubernetes.io/name")
                   or selector.get("name"))
            if sel:
                out["k8s_selector_app"] = sel

    # ── Code ──────────────────────────────────────────────────────────────────
    if domain_type == "code":
        if props.get("taint_class"):
            out["taint_class"] = props["taint_class"]
        if props.get("class"):
            out["class_name"] = props["class"]

    # ── DeferredRelation ──────────────────────────────────────────────────────
    if node_type == "DeferredRelation":
        for k in ("edge_type", "web_acl_tf_name", "resource_tf_name",
                  "web_acl_arn_raw", "resource_arn_raw",
                  "terraform_type", "terraform_name",
                  "resolution_method", "confidence"):
            if props.get(k) is not None:
                out[k] = props[k]

    return out


async def write_fragment(fragment: GraphFragment, org_id: str = "prototype") -> dict:
    """
    Write a graph fragment to Neo4j. Idempotent (MERGE-based).
    Returns {"nodes": N, "edges": N}
    """
    nodes_written = 0
    edges_written = 0

    async with tenant_session(org_id) as session:

        for node in fragment.nodes:
            top = _extract_top_level(
                node.domain_type or "",
                node.node_type or "",
                node.properties or {},
            )

            sl = node.source_location
            meta = node.metadata

            await session.run("""
                MERGE (n:Node {entity_id: $entity_id})
                SET n.node_type = $node_type,
                    n.domain_type = $domain_type,
                    n.resource_subtype = $resource_subtype,
                    n.name = $name,
                    n.file_path = $file_path,
                    n.start_line = $start_line,
                    n.end_line = $end_line,
                    n.block_identifier = $block_identifier,
                    n.is_entry_point = $is_entry_point,
                    n.semantic_summary = $semantic_summary,
                    n.resolved_by = $resolved_by,
                    n.confidence = $confidence,
                    n.firewall_posture = null,
                    n.org_id = $org_id,
                    n.valid_from = coalesce(n.valid_from, datetime()),
                    n.valid_to = null
            """,
                entity_id=node.entity_id,
                node_type=node.node_type,
                domain_type=node.domain_type,
                resource_subtype=node.resource_subtype,
                name=node.name,
                file_path=sl.file_path if sl else None,
                start_line=sl.start_line if sl else None,
                end_line=sl.end_line if sl else None,
                block_identifier=sl.block_identifier if sl else None,
                is_entry_point=meta.is_entry_point if meta else False,
                semantic_summary=meta.semantic_summary if meta else None,
                resolved_by=meta.resolved_by if meta else "deterministic",
                confidence=meta.confidence if meta else 1.0,
                org_id=org_id,
            )

            if top:
                set_clauses = ", ".join(f"n.{k} = ${k}" for k in top)
                await session.run(
                    f"MATCH (n:Node {{entity_id: $entity_id}}) SET {set_clauses}",
                    entity_id=node.entity_id, **top,
                )

            nodes_written += 1

        for edge in fragment.edges:
            await session.run("""
                MATCH (a:Node {entity_id: $from_id})
                MATCH (b:Node {entity_id: $to_id})
                MERGE (a)-[r:EDGE {edge_type: $edge_type}]->(b)
                SET r.resolution_method = $method,
                    r.confidence = $confidence,
                    r.gkg_assisted = false,
                    r.created_at = coalesce(r.created_at, datetime())
            """,
                from_id=edge.from_entity_id,
                to_id=edge.to_entity_id,
                edge_type=edge.edge_type,
                method=getattr(edge, "resolution_method", "deterministic_parse"),
                confidence=getattr(edge, "confidence", 1.0),
            )
            edges_written += 1

        # Write deferred relations as queryable stub nodes
        for rel in getattr(fragment, "deferred_relations", []):
            dr_id = (
                f"{ORG_ID}::cloud::deferred::"
                f"{rel.get('terraform_type', 'unknown')}."
                f"{rel.get('terraform_name', 'unknown')}"
            )
            await session.run("""
                MERGE (n:Node {entity_id: $entity_id})
                SET n.node_type = 'DeferredRelation',
                    n.domain_type = 'cloud',
                    n.name = $name,
                    n.org_id = $org_id,
                    n.valid_from = coalesce(n.valid_from, datetime()),
                    n.valid_to = null
            """, entity_id=dr_id,
                 name=rel.get("terraform_name", "deferred"),
                 org_id=org_id)

            # Stamp all deferred relation fields as top-level props
            dr_props = {k: v for k, v in rel.items()
                        if isinstance(v, (str, int, float, bool)) and v}
            if dr_props:
                set_clauses = ", ".join(f"n.{k} = ${k}" for k in dr_props)
                await session.run(
                    f"MATCH (n:Node {{entity_id: $entity_id}}) SET {set_clauses}",
                    entity_id=dr_id, **dr_props,
                )

    logger.info("fragment_written", asset_id=fragment.asset_id,
                nodes=nodes_written, edges=edges_written,
                deferred=len(getattr(fragment, "deferred_relations", [])))
    return {"nodes": nodes_written, "edges": edges_written}
