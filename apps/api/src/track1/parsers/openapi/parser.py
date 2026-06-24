"""
SATARK Layer 1 — OpenAPI Spec Parser (A5)
Pass 1: parses OpenAPI 3.x YAML/JSON specs into a graph fragment.

Produces:
- API node (from info.title)
- Endpoint nodes (one per path)
- Method nodes (GET, POST, PUT, DELETE etc.)
- Parameter nodes (query, path, header, body)

Entry points: ALL endpoint nodes (every API endpoint is externally reachable)
"""
import yaml
import json
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


def _make_entity_id(api_name: str, *parts: str) -> str:
    safe = api_name.lower().replace(" ", "_").replace("-", "_")
    path = ".".join(p.replace("/", "_").replace("{", "").replace("}", "") for p in parts)
    return f"{ORG_ID}::api::{safe}::{path}"


def parse_openapi_file(
    content: str,
    file_path: str,
    asset_id: str,
) -> GraphFragment:
    """Parse an OpenAPI 3.x YAML or JSON spec into a graph fragment."""
    fragment = GraphFragment(
        asset_id=asset_id,
        file_path=file_path,
        domain_type="api",
    )

    # Parse YAML or JSON
    try:
        if file_path.endswith(".json"):
            spec = json.loads(content)
        else:
            spec = yaml.safe_load(content)
    except Exception as e:
        logger.error("openapi_parse_error", file=file_path, error=str(e))
        return fragment

    if not spec or not isinstance(spec, dict):
        return fragment

    info = spec.get("info", {})
    api_title = info.get("title", "Unknown API")
    api_version = info.get("version", "unknown")
    api_desc = info.get("description", "")

    # API root node
    api_id = _make_entity_id(api_title, "api")
    api_node = KGNode(
        entity_id=api_id,
        node_type="API",
        domain_type="api",
        name=api_title,
        source_location=SourceLocation(
            file_path=file_path,
            block_identifier="info",
        ),
        metadata=NodeMetadata(
            semantic_summary=f"API: {api_title} v{api_version}. {api_desc[:120]}",
            resolved_by="deterministic",
        ),
        properties={"version": api_version, "title": api_title},
        org_id=ORG_ID,
    )
    fragment.nodes.append(api_node)

    # Paths
    paths = spec.get("paths", {}) or {}
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Endpoint node (one per path)
        endpoint_id = _make_entity_id(api_title, "endpoint", path)
        endpoint_node = KGNode(
            entity_id=endpoint_id,
            node_type="Endpoint",
            domain_type="api",
            name=path,
            source_location=SourceLocation(
                file_path=file_path,
                block_identifier=f"paths.{path}",
            ),
            metadata=NodeMetadata(
                is_entry_point=True,   # ALL API endpoints are entry points
                semantic_summary=f"API endpoint {path}",
                resolved_by="deterministic",
            ),
            properties={"path": path},
            org_id=ORG_ID,
        )
        fragment.nodes.append(endpoint_node)
        fragment.entry_points.append(endpoint_id)

        # API → Endpoint
        fragment.edges.append(KGEdge(
            from_entity_id=api_id,
            to_entity_id=endpoint_id,
            edge_type="E_contain",
            source_asset_ids=[asset_id],
        ))

        # Methods (GET, POST, etc.)
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            op_id = operation.get("operationId", f"{method}_{path}")
            summary = operation.get("summary", "")
            description = operation.get("description", "")
            tags = operation.get("tags", [])

            method_id = _make_entity_id(api_title, "method", path, method)
            method_node = KGNode(
                entity_id=method_id,
                node_type="Method",
                domain_type="api",
                name=f"{method.upper()} {path}",
                source_location=SourceLocation(
                    file_path=file_path,
                    block_identifier=f"paths.{path}.{method}",
                ),
                metadata=NodeMetadata(
                    is_entry_point=True,
                    semantic_summary=summary or f"{method.upper()} operation on {path}",
                    resolved_by="deterministic",
                ),
                properties={
                    "http_method": method.upper(),
                    "operation_id": op_id,
                    "tags": tags,
                    "description": description[:200],
                },
                org_id=ORG_ID,
            )
            fragment.nodes.append(method_node)
            fragment.entry_points.append(method_id)

            # Endpoint → Method
            fragment.edges.append(KGEdge(
                from_entity_id=endpoint_id,
                to_entity_id=method_id,
                edge_type="E_contain",
                source_asset_ids=[asset_id],
            ))

            # Parameters
            parameters = operation.get("parameters", []) or []
            # Also add path-level parameters
            parameters += path_item.get("parameters", []) or []

            for param in parameters:
                if not isinstance(param, dict):
                    continue
                param_name = param.get("name", "unknown")
                param_in = param.get("in", "query")   # query, path, header, cookie
                required = param.get("required", False)
                schema = param.get("schema", {}) or {}
                param_type = schema.get("type", "string")

                param_id = _make_entity_id(api_title, "param", path, method, param_name)
                param_node = KGNode(
                    entity_id=param_id,
                    node_type="Parameter",
                    domain_type="api",
                    name=param_name,
                    source_location=SourceLocation(
                        file_path=file_path,
                        block_identifier=f"paths.{path}.{method}.parameters.{param_name}",
                    ),
                    metadata=NodeMetadata(
                        semantic_summary=f"{param_in} parameter '{param_name}' ({param_type}{'  required' if required else ''})",
                        resolved_by="deterministic",
                    ),
                    properties={
                        "param_in": param_in,
                        "param_type": param_type,
                        "required": required,
                        # All external API parameters are potential taint sources
                        "taint_class": "external_untrusted",
                    },
                    org_id=ORG_ID,
                )
                fragment.nodes.append(param_node)

                # Method → Parameter
                fragment.edges.append(KGEdge(
                    from_entity_id=method_id,
                    to_entity_id=param_id,
                    edge_type="E_contain",
                    source_asset_ids=[asset_id],
                ))

            # Request body parameters
            req_body = operation.get("requestBody", {}) or {}
            if req_body:
                body_id = _make_entity_id(api_title, "param", path, method, "body")
                content_types = list((req_body.get("content") or {}).keys())
                body_node = KGNode(
                    entity_id=body_id,
                    node_type="Parameter",
                    domain_type="api",
                    name="requestBody",
                    source_location=SourceLocation(
                        file_path=file_path,
                        block_identifier=f"paths.{path}.{method}.requestBody",
                    ),
                    metadata=NodeMetadata(
                        semantic_summary=f"Request body ({', '.join(content_types)})",
                        resolved_by="deterministic",
                    ),
                    properties={
                        "param_in": "body",
                        "required": req_body.get("required", False),
                        "content_types": content_types,
                        "taint_class": "external_untrusted",
                    },
                    org_id=ORG_ID,
                )
                fragment.nodes.append(body_node)
                fragment.edges.append(KGEdge(
                    from_entity_id=method_id,
                    to_entity_id=body_id,
                    edge_type="E_contain",
                    source_asset_ids=[asset_id],
                ))

    logger.info("openapi_fragment_built",
                file=file_path, nodes=len(fragment.nodes),
                edges=len(fragment.edges), entry_points=len(fragment.entry_points))
    return fragment
