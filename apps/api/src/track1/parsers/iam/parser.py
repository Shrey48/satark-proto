"""
SATARK Layer 1 — IAM Policy Parser (B3)

Handles all known AWS IAM JSON layouts including LLM-generated wrappers.
"""
import json
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"


def _make_entity_id(*parts: str) -> str:
    safe = ".".join(
        p.replace(":", "_").replace("/", "_").replace("*", "wildcard")
        for p in parts
    )
    return f"{ORG_ID}::iam::policy::{safe}"


def _is_wildcard(resource: str) -> bool:
    return resource in ("*",) or resource.endswith(":*") or "/*" in resource


def _extract_policy(raw: any, file_path: str, _depth: int = 0) -> tuple[str, dict, str]:
    """
    Return (policy_name, policy_document, format_label).
    Raises ValueError with description if no format matches.
    _depth prevents infinite recursion.
    """
    if _depth > 3:
        raise ValueError("recursion limit reached")

    basename = file_path.replace(".json", "")

    # Format 4: array — unwrap first element
    if isinstance(raw, list):
        if not raw:
            raise ValueError("empty array")
        return _extract_policy(raw[0], file_path, _depth + 1)

    if not isinstance(raw, dict):
        raise ValueError(f"expected dict, got {type(raw).__name__}")

    # Format 5: {"Policy": {"PolicyName": ..., "Document": ...}}
    if "Policy" in raw and isinstance(raw["Policy"], dict):
        inner = raw["Policy"]
        name = inner.get("PolicyName") or inner.get("name") or basename
        doc_raw = inner.get("Document", "{}")
        doc = json.loads(doc_raw) if isinstance(doc_raw, str) else doc_raw
        return name, doc, "format5_policy_wrapper"

    # Format 1: {"PolicyDocument": {...}, "PolicyName": "..."}
    if "PolicyDocument" in raw:
        name = raw.get("PolicyName") or raw.get("name") or basename
        doc = raw["PolicyDocument"]
        if not isinstance(doc, dict):
            raise ValueError("PolicyDocument is not a dict")
        return name, doc, "format1_policy_document_wrapper"

    # Format 2+3: top-level has "Statement" directly
    if "Statement" in raw:
        name = raw.get("PolicyName") or raw.get("name") or basename
        return name, raw, "format2_raw_statement"

    # Format 6: {"policies": [...]}
    if "policies" in raw and isinstance(raw["policies"], list) and raw["policies"]:
        return _extract_policy(raw["policies"][0], file_path, _depth + 1)

    # Format 8: {"content": {actual_policy}, "metadata": {"PolicyName": ...}}
    # The LLM-generated file has this structure inside the filename wrapper
    if "content" in raw and isinstance(raw["content"], dict):
        metadata = raw.get("metadata") or {}
        name = (metadata.get("PolicyName") or
                metadata.get("name") or
                basename)
        _, doc, inner_fmt = _extract_policy(raw["content"], file_path, _depth + 1)
        return name, doc, f"format8_content_wrapper"

    # Format 7: single-key wrapper {"filename.json": {actual_policy}}
    # Try unwrapping if only one key and it's not a known IAM field
    known_keys = {"Statement", "Version", "Id", "PolicyName", "PolicyDocument",
                  "Policy", "policies", "content", "metadata"}
    if len(raw) == 1:
        only_key = list(raw.keys())[0]
        if only_key not in known_keys:
            return _extract_policy(raw[only_key], file_path, _depth + 1)

    raise ValueError(f"no known format — top-level keys: {sorted(raw.keys())}")


def parse_iam_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="iam")

    try:
        raw = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error("iam_json_decode_error", file=file_path, error=str(e))
        return fragment

    try:
        policy_name, doc, fmt = _extract_policy(raw, file_path)
    except ValueError as e:
        logger.warning("iam_unrecognised_format", file=file_path, reason=str(e))
        return fragment

    logger.info("iam_format_detected", file=file_path, format=fmt, policy=policy_name)

    policy_id = _make_entity_id(policy_name, "policy")
    fragment.nodes.append(KGNode(
        entity_id=policy_id, node_type="Policy", domain_type="iam", name=policy_name,
        source_location=SourceLocation(file_path=file_path, block_identifier="policy"),
        metadata=NodeMetadata(
            semantic_summary=f"IAM policy '{policy_name}'",
            resolved_by="deterministic",
        ),
        properties={"version": doc.get("Version", "2012-10-17")},
        org_id=ORG_ID,
    ))

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for i, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue

        effect    = stmt.get("Effect", "Allow")
        actions   = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        sid       = stmt.get("Sid", f"Stmt{i+1}")

        if isinstance(actions,   str): actions   = [actions]
        if isinstance(resources, str): resources = [resources]

        stmt_id = _make_entity_id(policy_name, "statement", sid)
        action_summary = ", ".join(actions[:3]) + ("..." if len(actions) > 3 else "")

        fragment.nodes.append(KGNode(
            entity_id=stmt_id, node_type="Statement", domain_type="iam", name=sid,
            source_location=SourceLocation(
                file_path=file_path, block_identifier=f"Statement[{i}]"),
            metadata=NodeMetadata(
                semantic_summary=f"{effect}s {action_summary} on {len(resources)} resource(s)",
                resolved_by="deterministic",
            ),
            properties={
                "effect": effect,
                "actions": actions,
                "resource_count": len(resources),
                "has_wildcard": any(_is_wildcard(r) for r in resources),
            },
            org_id=ORG_ID,
        ))

        fragment.edges.append(KGEdge(
            from_entity_id=policy_id, to_entity_id=stmt_id,
            edge_type="E_contain", source_asset_ids=[asset_id],
        ))

        for resource in resources:
            if _is_wildcard(resource):
                resource_id = _make_entity_id(policy_name, "wildcard", sid, resource[:30])
                if not any(n.entity_id == resource_id for n in fragment.nodes):
                    fragment.nodes.append(KGNode(
                        entity_id=resource_id, node_type="WildcardScope", domain_type="iam",
                        name=f"WildcardScope ({resource})",
                        source_location=SourceLocation(
                            file_path=file_path,
                            block_identifier=f"Statement[{i}].Resource"),
                        metadata=NodeMetadata(
                            semantic_summary=f"Wildcard resource scope '{resource}'",
                            resolved_by="deterministic",
                        ),
                        properties={"wildcard_pattern": resource, "actions": actions},
                        org_id=ORG_ID,
                    ))
            else:
                resource_id = (f"{ORG_ID}::cloud::terraform::"
                               f"arn_ref.{resource.replace(':', '_').replace('/', '_')}")
                if not any(n.entity_id == resource_id for n in fragment.nodes):
                    fragment.nodes.append(KGNode(
                        entity_id=resource_id, node_type="Resource", domain_type="cloud",
                        name=resource.split(":")[-1] or resource,
                        source_location=SourceLocation(
                            file_path=file_path,
                            block_identifier=f"Statement[{i}].Resource"),
                        metadata=NodeMetadata(
                            semantic_summary=f"ARN reference: {resource}",
                            resolved_by="deterministic",
                        ),
                        properties={"arn": resource},
                        org_id=ORG_ID,
                    ))

            fragment.edges.append(KGEdge(
                from_entity_id=stmt_id, to_entity_id=resource_id,
                edge_type="E_trust", source_asset_ids=[asset_id],
            ))

    logger.info("iam_fragment_built", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges),
                policy=policy_name, statements=len(statements))
    return fragment
