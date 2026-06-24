"""
SATARK Layer 1 — Kubernetes Manifest Parser (B5)

Deduplication fix:
  cluster entity_id: global (not per-asset) → one cluster node for all K8s files
  namespace entity_id: global (not per-asset) → one namespace node across files
"""
import yaml
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

# Global IDs — same across all K8s file uploads
GLOBAL_CLUSTER_ID = f"{ORG_ID}::k8s::global::cluster"

WORKLOAD_FIREWALL_KINDS = {"NetworkPolicy"}


def _ns_id(namespace: str) -> str:
    return f"{ORG_ID}::k8s::global::namespace.{namespace}"


def _resource_id(namespace: str, kind: str, name: str) -> str:
    return f"{ORG_ID}::k8s::cluster::{namespace}.{kind.lower()}.{name}"


def _get_resource_subtype(kind: str) -> Optional[str]:
    return "workload_firewall" if kind in WORKLOAD_FIREWALL_KINDS else None


def _is_entry_point(kind: str, spec: dict) -> bool:
    if kind == "Ingress":
        return True
    if kind == "Service":
        return spec.get("type", "ClusterIP") in ("LoadBalancer", "NodePort")
    return False


def _summary(kind: str, name: str, namespace: str, spec: dict) -> str:
    base = f"{kind} '{name}' in namespace '{namespace}'"
    if kind == "Deployment":
        base += f" — {spec.get('replicas', 1)} replica(s)"
    elif kind == "Service":
        base += f" — type {spec.get('type', 'ClusterIP')}"
    elif kind == "NetworkPolicy":
        base += " (workload firewall — controls pod-to-pod traffic)"
    elif kind == "Ingress":
        base += " (external entry point)"
    elif kind == "ServiceAccount":
        base += " — workload identity (check IRSA annotation for cloud privileges)"
    return base


def parse_k8s_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="k8s")

    # One global cluster node — MERGE in Neo4j will deduplicate
    fragment.nodes.append(KGNode(
        entity_id=GLOBAL_CLUSTER_ID,
        node_type="K8sCluster", domain_type="k8s", name="k8s-cluster",
        source_location=SourceLocation(file_path=file_path, block_identifier="cluster"),
        org_id=ORG_ID,
    ))

    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        logger.error("k8s_yaml_parse_error", file=file_path, error=str(e))
        return fragment

    seen_namespaces: set[str] = set()

    for doc in docs:
        if not doc or not isinstance(doc, dict):
            continue

        kind        = doc.get("kind", "")
        metadata    = doc.get("metadata", {})
        spec        = doc.get("spec", {}) or {}
        name        = metadata.get("name", "unknown")
        namespace   = metadata.get("namespace", "default")
        labels      = metadata.get("labels") or {}
        annotations = metadata.get("annotations") or {}

        if not kind or not name:
            continue

        # One namespace node globally — deduplicated by entity_id in Neo4j MERGE
        if namespace not in seen_namespaces:
            fragment.nodes.append(KGNode(
                entity_id=_ns_id(namespace),
                node_type="Namespace", domain_type="k8s", name=namespace,
                source_location=SourceLocation(file_path=file_path,
                                               block_identifier=f"namespace.{namespace}"),
                metadata=NodeMetadata(semantic_summary=f"Kubernetes namespace '{namespace}'"),
                org_id=ORG_ID,
            ))
            fragment.edges.append(KGEdge(
                from_entity_id=GLOBAL_CLUSTER_ID,
                to_entity_id=_ns_id(namespace),
                edge_type="E_contain", source_asset_ids=[asset_id],
            ))
            seen_namespaces.add(namespace)

        entity_id        = _resource_id(namespace, kind, name)
        resource_subtype = _get_resource_subtype(kind)
        is_entry         = _is_entry_point(kind, spec)
        irsa_role        = annotations.get("eks.amazonaws.com/role-arn")

        ports = []
        if kind == "Service":
            ports = [p.get("port") for p in (spec.get("ports") or []) if p.get("port")]
        elif kind == "Deployment":
            for c in ((spec.get("template") or {}).get("spec", {}).get("containers") or []):
                ports += [p.get("containerPort") for p in (c.get("ports") or []) if p.get("containerPort")]

        props = {"kind": kind, "namespace": namespace, "labels": labels,
                 "annotations": annotations, "ports": ports}
        if irsa_role:
            props["irsa_role_arn"] = irsa_role
        if kind == "NetworkPolicy":
            props["pod_selector"] = spec.get("podSelector", {})
            props["policy_types"] = spec.get("policyTypes", [])

        fragment.nodes.append(KGNode(
            entity_id=entity_id, node_type=kind, domain_type="k8s",
            resource_subtype=resource_subtype, name=name, org_id=ORG_ID,
            source_location=SourceLocation(file_path=file_path,
                                           block_identifier=f"{kind}.{namespace}.{name}"),
            metadata=NodeMetadata(is_entry_point=is_entry,
                                  semantic_summary=_summary(kind, name, namespace, spec),
                                  resolved_by="deterministic", confidence=1.0),
            properties=props,
        ))

        if is_entry:
            fragment.entry_points.append(entity_id)

        fragment.edges.append(KGEdge(
            from_entity_id=_ns_id(namespace),
            to_entity_id=entity_id,
            edge_type="E_contain", source_asset_ids=[asset_id],
        ))

    logger.info("k8s_fragment_built", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges))
    return fragment
