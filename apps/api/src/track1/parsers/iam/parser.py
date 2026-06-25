"""
SATARK Layer 1 — IAM Policy Parser (B3) — FIXED v2

Key fixes vs original:
  1. ALL inter-node edges are E_trust (NEVER generic "EDGE", NEVER "E_contain" for
     permission relationships). Effect=Deny still creates E_trust with effect prop.
  2. Reads domain_configs/iam.yaml for edge rules and dangerous action patterns
  3. Correctly creates Principal nodes with principal_type and principal_value
  4. Wildcard Resource ("*") → WildcardScope stub node, NOT skipped
  5. edge_type stored as property ON the edge rel, not as node label

Per spec Section 4.6:
  E_trust = a permission/capability relationship exists
  E_trust chain = privilege escalation analysis path
  NEVER use generic EDGE for IAM — breaks privilege escalation mode (Mode 3)
"""
from __future__ import annotations
import json
import os
import re
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
        p = os.path.join(d, "iam.yaml")
        if os.path.exists(p):
            with open(p) as f:
                return yaml.safe_load(f)
    dirs_str = ", ".join(_DOMAIN_CONFIG_DIRS)
    raise FileNotFoundError(
        "domain_configs YAML not found. Looked in: " + dirs_str +
        " -- Copy domain_configs/ to repo root and add volume mount."
    )

_CFG = _load_config()

# Dangerous action patterns for semantic summary enrichment
_DANGEROUS_ACTIONS: list[dict] = _CFG.get("dangerous_actions", [])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_entity_id(asset_id: str, kind: str, name: str) -> str:
    safe = name.replace("/", "_").replace(":", "_").replace("*", "WILDCARD")
    return f"{ORG_ID}::iam::{asset_id}::{kind}.{safe}"


def _normalize_list(value) -> list:
    """Normalize AWS policy field: string or list → list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _flatten_principal(principal) -> list[dict]:
    """
    Flatten Principal field to list of {principal_type, principal_value} dicts.
    Handles: "*", {"AWS": "arn:..."}, {"Service": "..."}, {"Federated": "..."}
    """
    if principal == "*":
        return [{"principal_type": "wildcard", "principal_value": "*"}]
    if isinstance(principal, str):
        return [{"principal_type": "AWS", "principal_value": principal}]
    if isinstance(principal, dict):
        result = []
        for ptype, pvals in principal.items():
            for pval in _normalize_list(pvals):
                result.append({"principal_type": ptype, "principal_value": pval})
        return result
    return []


def _classify_actions(actions: list[str]) -> dict:
    """Classify actions against dangerous action patterns."""
    risks = []
    for action in actions:
        for pattern in _DANGEROUS_ACTIONS:
            pat = pattern.get("pattern", "")
            if pat == "*" and action == "*":
                risks.append(pattern.get("risk"))
            elif pat.endswith("*") and action.lower().startswith(pat[:-1].lower()):
                risks.append(pattern.get("risk"))
            elif action.lower() == pat.lower():
                risks.append(pattern.get("risk"))
    return {"risk_flags": list(set(r for r in risks if r))}


def _resource_summary(entity_id: str) -> str:
    """Generate stub semantic summary for WildcardScope nodes."""
    return f"Wildcard resource scope — all resources matching '{entity_id}'"


# ── Main parser ───────────────────────────────────────────────────────────────

def parse_iam_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    """
    Parse an IAM policy JSON file into a graph fragment.

    Node types created:
      Policy — root policy document
      Statement — each Statement block
      Principal — each principal in a Statement
      WildcardScope — stub for wildcard Resource ("*")

    Edge types created:
      E_contain — Policy → Statement (structural containment)
      E_trust — ALL permission relationships (Statement → Principal, Statement → Resource)
      NEVER generic "EDGE"
    """
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="iam")

    try:
        doc = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error("iam_json_parse_error", file=file_path, error=str(e))
        return fragment

    statements = doc.get("Statement", [])
    version = doc.get("Version", "2012-10-17")
    policy_id = doc.get("Id", asset_id)

    # ── Policy root node ──────────────────────────────────────────────────────
    policy_entity_id = _make_entity_id(asset_id, "Policy", policy_id)
    fragment.nodes.append(KGNode(
        entity_id=policy_entity_id,
        node_type="Policy",
        domain_type="iam",
        name=policy_id,
        source_location=SourceLocation(
            file_path=file_path,
            start_line=1,
            block_identifier="policy.root",
        ),
        metadata=NodeMetadata(
            semantic_summary=f"IAM Policy document (Version: {version})",
            resolved_by="deterministic",
            confidence=1.0,
        ),
        properties={"version": version, "statement_count": len(statements)},
        org_id=ORG_ID,
    ))

    for stmt_idx, stmt in enumerate(statements):
        effect = stmt.get("Effect", "Allow")
        actions = _normalize_list(stmt.get("Action", []))
        resources = _normalize_list(stmt.get("Resource", []))
        principals = _flatten_principal(stmt.get("Principal", {}))
        sid = stmt.get("Sid", f"Statement{stmt_idx}")
        condition = stmt.get("Condition", {})

        action_classification = _classify_actions(actions)

        # Semantic summary for the statement
        summary_parts = [f"IAM Statement '{sid}': Effect={effect}"]
        if action_classification.get("risk_flags"):
            summary_parts.append(f"⚠️ Risk flags: {', '.join(action_classification['risk_flags'])}")
        summary = " — ".join(summary_parts)

        # ── Statement node ────────────────────────────────────────────────────
        stmt_entity_id = _make_entity_id(asset_id, "Statement", f"{policy_id}.{sid}")
        fragment.nodes.append(KGNode(
            entity_id=stmt_entity_id,
            node_type="Statement",
            domain_type="iam",
            name=sid,
            source_location=SourceLocation(
                file_path=file_path,
                block_identifier=f"Statement[{stmt_idx}]",
            ),
            metadata=NodeMetadata(
                semantic_summary=summary,
                resolved_by="deterministic",
                confidence=1.0,
            ),
            properties={
                "effect": effect,
                "actions": actions,
                "resources": resources,
                "condition": condition,
                **action_classification,
            },
            org_id=ORG_ID,
        ))

        # Policy → Statement: E_contain (structural, not permission)
        fragment.edges.append(KGEdge(
            from_entity_id=policy_entity_id,
            to_entity_id=stmt_entity_id,
            edge_type="E_contain",
            resolution_method="deterministic_parse",
            confidence=1.0,
            source_asset_ids=[asset_id],
        ))

        # ── Principal nodes + E_trust edges ───────────────────────────────────
        for principal in principals:
            ptype = principal["principal_type"]
            pval = principal["principal_value"]
            principal_entity_id = _make_entity_id(
                asset_id, "Principal", f"{ptype}.{pval}"
            )

            # Avoid duplicate principal nodes across statements
            existing_ids = {n.entity_id for n in fragment.nodes}
            if principal_entity_id not in existing_ids:
                fragment.nodes.append(KGNode(
                    entity_id=principal_entity_id,
                    node_type="Principal",
                    domain_type="iam",
                    name=pval,
                    source_location=SourceLocation(
                        file_path=file_path,
                        block_identifier=f"Statement[{stmt_idx}].Principal",
                    ),
                    metadata=NodeMetadata(
                        semantic_summary=f"IAM Principal — {ptype}: {pval}",
                        resolved_by="deterministic",
                        confidence=1.0,
                    ),
                    properties={
                        "principal_type": ptype,
                        "principal_value": pval,
                        "arn": pval if pval.startswith("arn:") else None,
                    },
                    org_id=ORG_ID,
                ))

            # CRITICAL FIX: E_trust, NEVER generic "EDGE"
            fragment.edges.append(KGEdge(
                from_entity_id=stmt_entity_id,
                to_entity_id=principal_entity_id,
                edge_type="E_trust",          # ← WAS "EDGE" — FIXED
                resolution_method="deterministic_parse",
                confidence=1.0,
                source_asset_ids=[asset_id],
                properties={
                    "effect": effect,
                    "actions": actions,
                },
            ))

        # ── Resource nodes + E_trust edges ────────────────────────────────────
        for resource in resources:
            if resource == "*":
                # Wildcard → WildcardScope stub
                resource_entity_id = _make_entity_id(
                    asset_id, "WildcardScope", f"{sid}.wildcard"
                )
                existing_ids = {n.entity_id for n in fragment.nodes}
                if resource_entity_id not in existing_ids:
                    fragment.nodes.append(KGNode(
                        entity_id=resource_entity_id,
                        node_type="WildcardScope",
                        domain_type="iam",
                        name="* (all resources)",
                        source_location=SourceLocation(
                            file_path=file_path,
                            block_identifier=f"Statement[{stmt_idx}].Resource.*",
                        ),
                        metadata=NodeMetadata(
                            semantic_summary="Wildcard resource — this statement applies to ALL resources. High privilege escalation risk.",
                            resolved_by="deterministic",
                            confidence=1.0,
                        ),
                        properties={"wildcard_pattern": "*"},
                        org_id=ORG_ID,
                    ))

                fragment.edges.append(KGEdge(
                    from_entity_id=stmt_entity_id,
                    to_entity_id=resource_entity_id,
                    edge_type="E_trust",      # ← CRITICAL: E_trust
                    resolution_method="deterministic_parse",
                    confidence=1.0,
                    source_asset_ids=[asset_id],
                    properties={
                        "effect": effect,
                        "actions": actions,
                        "resource": resource,
                    },
                ))
            elif resource.startswith("arn:"):
                # Specific ARN → create stub or link to existing node in Pass 3
                resource_entity_id = _make_entity_id(
                    asset_id, "ResourceRef", resource
                )
                existing_ids = {n.entity_id for n in fragment.nodes}
                if resource_entity_id not in existing_ids:
                    fragment.nodes.append(KGNode(
                        entity_id=resource_entity_id,
                        node_type="ResourceRef",
                        domain_type="iam",
                        name=resource,
                        source_location=SourceLocation(
                            file_path=file_path,
                            block_identifier=f"Statement[{stmt_idx}].Resource",
                        ),
                        metadata=NodeMetadata(
                            semantic_summary=f"ARN resource reference: {resource}",
                            resolved_by="deterministic",
                            confidence=1.0,
                            status="unresolved_reference",
                        ),
                        properties={"arn": resource},
                        org_id=ORG_ID,
                    ))

                fragment.edges.append(KGEdge(
                    from_entity_id=stmt_entity_id,
                    to_entity_id=resource_entity_id,
                    edge_type="E_trust",      # ← CRITICAL: E_trust
                    resolution_method="deterministic_parse",
                    confidence=1.0,
                    source_asset_ids=[asset_id],
                    properties={
                        "effect": effect,
                        "actions": actions,
                        "resource": resource,
                    },
                ))

    logger.info(
        "iam_parse_complete",
        file=file_path,
        nodes=len(fragment.nodes),
        edges=len(fragment.edges),
        statements=len(statements),
    )
    return fragment
