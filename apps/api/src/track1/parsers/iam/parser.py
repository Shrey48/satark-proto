"""
SATARK Layer 1 — IAM Policy Parser (B3)

Fix: handles multiple AWS IAM JSON formats:
  Format 1: {"PolicyDocument": {"Statement": [...]}, "PolicyName": "..."}
  Format 2: {"Statement": [...], "PolicyName": "..."}
  Format 3: {"Version": "...", "Statement": [...]}  (no PolicyName)
  Format 4: [{"PolicyName": "...", "PolicyDocument": {...}}]  (array)
  Format 5: {"Policy": {"PolicyName": "...", "Document": "..."}}  (AWS CLI)
"""
import json
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"


def _make_entity_id(*parts: str) -> str:
    safe = ".".join(p.replace(":", "_").replace("/", "_").replace("*", "wildcard")
                    for p in parts)
    return f"{ORG_ID}::iam::policy::{safe}"


def _is_wildcard(resource: str) -> bool:
    return resource in ("*",) or resource.endswith(":*") or "/*" in resource


def _extract_doc(raw: dict | list, file_path: str) -> tuple[str, dict]:
    """
    Extract (policy_name, policy_document) from any common IAM JSON format.
    Returns (name, doc_dict_with_Statement_key) or raises ValueError.
    """
    # Format 4: array — unwrap first element
    if isinstance(raw, list):
        if not raw:
            raise ValueError("empty array")
        raw = raw[0]

    if not isinstance(raw, dict):
        raise ValueError("not a dict")

    basename = file_path.replace(".json", "")

    # Format 5: {"Policy": {...}}
    if "Policy" in raw and isinstance(raw["Policy"], dict):
        inner = raw["Policy"]
        name  = inner.get("PolicyName", basename)
        doc_str = inner.get("Document", "{}")
        try:
            doc = json.loads(doc_str) if isinstance(doc_str, str) else doc_str
        except Exception:
            doc = {"Statement": []}
        return name, doc

    # Format 1: {"PolicyDocument": {...}}
    if "PolicyDocument" in raw:
        name = raw.get("PolicyName", basename)
        doc  = raw["PolicyDocument"]
        if not isinstance(doc, dict):
            raise ValueError("PolicyDocument is not a dict")
        return name, doc

    # Format 2 + 3: {"Statement": [...]}
    if "Statement" in raw:
        name = raw.get("PolicyName", raw.get("name", basename))
        return name, raw

    raise ValueError(f"unrecognised IAM format — keys: {list(raw.keys())}")


def parse_iam_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="iam")

    try:
        raw = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error("iam_json_parse_error", file=file_path, error=str(e))
        return fragment

    try:
        policy_name, doc = _extract_doc(raw, file_path)
    except ValueError as e:
        logger.warning("iam_unrecognised_format", file=file_path, reason=str(e))
        return fragment

    # Policy root node
    policy_id = _make_entity_id(policy_name, "policy")
    fragment.nodes.append(KGNode(
        entity_id=policy_id, node_type="Policy", domain_type="iam", name=policy_name,
        source_location=SourceLocation(file_path=file_path, block_identifier="policy"),
        metadata=NodeMetadata(
            semantic_summary=f"IAM policy '{policy_name}' — defines permissions granted to identities",
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
        sid       = stmt.get("Sid", f"Statement{i+1}")

        if isinstance(actions,   str): actions   = [actions]
        if isinstance(resources, str): resources = [resources]

        stmt_id = _make_entity_id(policy_name, "statement", sid)
        action_summary = ", ".join(actions[:3]) + ("..." if len(actions) > 3 else "")

        fragment.nodes.append(KGNode(
            entity_id=stmt_id, node_type="Statement", domain_type="iam", name=sid,
            source_location=SourceLocation(file_path=file_path,
                                           block_identifier=f"Statement[{i}]"),
            metadata=NodeMetadata(
                semantic_summary=f"{effect}s: {action_summary} on {len(resources)} resource(s)",
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
                resource_id = _make_entity_id(policy_name, "wildcard_scope", str(i), resource[:40])
                if not any(n.entity_id == resource_id for n in fragment.nodes):
                    fragment.nodes.append(KGNode(
                        entity_id=resource_id, node_type="WildcardScope", domain_type="iam",
                        name=f"WildcardScope ({resource})",
                        source_location=SourceLocation(file_path=file_path,
                                                       block_identifier=f"Statement[{i}].Resource"),
                        metadata=NodeMetadata(
                            semantic_summary=f"Wildcard resource scope '{resource}'",
                            resolved_by="deterministic",
                        ),
                        properties={"wildcard_pattern": resource, "actions": actions},
                        org_id=ORG_ID,
                    ))
            else:
                resource_id = f"{ORG_ID}::cloud::terraform::arn_ref.{resource.replace(':', '_').replace('/', '_')}"
                if not any(n.entity_id == resource_id for n in fragment.nodes):
                    fragment.nodes.append(KGNode(
                        entity_id=resource_id, node_type="Resource", domain_type="cloud",
                        name=resource.split(":")[-1] or resource,
                        source_location=SourceLocation(file_path=file_path,
                                                       block_identifier=f"Statement[{i}].Resource"),
                        metadata=NodeMetadata(semantic_summary=f"ARN reference: {resource}",
                                              resolved_by="deterministic"),
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
