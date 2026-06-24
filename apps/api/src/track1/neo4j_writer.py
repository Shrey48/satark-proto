"""
SATARK Layer 1 — Graph Fragment Writer
Writes Pass 1 graph fragments into Neo4j.
Key identifiers stored as top-level properties for Cypher querying.
"""
from models.nodes import GraphFragment
from core.database.neo4j import tenant_session
import structlog, json

logger = structlog.get_logger(__name__)


def _extract_top_level(domain_type: str, node_type: str, props: dict) -> dict:
    """
    Extract key identifiers from the properties dict as top-level Neo4j properties.
    These can be queried directly with Cypher — unlike the stringified props bag.
    """
    out = {}
    if not props:
        return out

    # IAM
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

    # Cloud (Terraform)
    if domain_type == "cloud":
        if "arn" in props:
            out["arn"] = props["arn"]
        if "resource_arn" in props:
            out["resource_arn"] = props["resource_arn"]
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
        for k in ("bucket", "function_name", "cidr_block"):
            if k in props:
                out[k] = props[k]

    # K8s
    if domain_type == "k8s":
        if "irsa_role_arn" in props:
            out["irsa_role_arn"] = props["irsa_role_arn"]
        labels = props.get("labels", {})
        if isinstance(labels, dict) and "app" in labels:
            out["k8s_app_label"] = labels["app"]
        if "kind" in props:
            out["k8s_kind"] = props["kind"]
        if "namespace" in props:
            out["k8s_namespace"] = props["namespace"]
        ports = props.get("ports", [])
        if ports:
            out["ports"] = [p for p in ports if p]
        # Service selector — used for Service→Deployment E_invoke in linker
        selector = props.get("selector", {})
        if isinstance(selector, dict) and selector:
            out["k8s_selector_app"] = selector.get("app") or selector.get("app.kubernetes.io/name")

    # Code
    if domain_type == "code":
        if "taint_class" in props:
            out["taint_class"] = props["taint_class"]
        decorators = props.get("decorators", [])
        if decorators:
            out["decorators"] = decorators

    # API
    if domain_type == "api":
        if "http_method" in props:
            out["http_method"] = props["http_method"]
        if "path" in props:
            out["api_path"] = props["path"]
        if "param_in" in props:
            out["param_in"] = props["param_in"]

    return out


async def write_fragment(fragment: GraphFragment, org_id: str = "prototype") -> dict:
    nodes_written = 0
    edges_written = 0

    async with tenant_session(org_id) as session:
        for node in fragment.nodes:
            top = _extract_top_level(node.domain_type, node.node_type, node.properties)

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
                    n.valid_from = datetime(),
                    n.valid_to = null
                """,
                entity_id=node.entity_id,
                node_type=node.node_type,
                domain_type=node.domain_type,
                resource_subtype=node.resource_subtype,
                name=node.name,
                file_path=node.source_location.file_path,
                start_line=node.source_location.start_line,
                end_line=node.source_location.end_line,
                block_identifier=node.source_location.block_identifier,
                is_entry_point=node.metadata.is_entry_point,
                semantic_summary=node.metadata.semantic_summary,
                resolved_by=node.metadata.resolved_by,
                confidence=node.metadata.confidence,
                org_id=node.org_id,
            )

            # Set top-level queryable properties
            if top:
                set_clauses = ", ".join(f"n.{k} = ${k}" for k in top)
                await session.run(
                    f"MATCH (n:Node {{entity_id: $entity_id}}) SET {set_clauses}",
                    entity_id=node.entity_id,
                    **top,
                )

            nodes_written += 1

        for edge in fragment.edges:
            await session.run("""
                MATCH (a:Node {entity_id: $from_id})
                MATCH (b:Node {entity_id: $to_id})
                MERGE (a)-[r:EDGE {edge_type: $edge_type}]->(b)
                SET r.resolution_method = $resolution_method,
                    r.confidence = $confidence,
                    r.gkg_assisted = $gkg_assisted,
                    r.created_at = datetime()
                """,
                from_id=edge.from_entity_id,
                to_id=edge.to_entity_id,
                edge_type=edge.edge_type,
                resolution_method=edge.resolution_method,
                confidence=edge.confidence,
                gkg_assisted=edge.gkg_assisted,
            )
            edges_written += 1

    logger.info("fragment_written", nodes=nodes_written, edges=edges_written)
    return {"nodes": nodes_written, "edges": edges_written}
