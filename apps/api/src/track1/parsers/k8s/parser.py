"""
SATARK Layer 1 — Kubernetes Manifest Parser (B5)

Fix: kind: Namespace resources now use _ns_id(name) as entity_id.
     Previously they were created as cluster::default.namespace.{name}
     causing duplication with global::namespace.{name} from other resources.
"""
import yaml
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

GLOBAL_CLUSTER_ID = f"{ORG_ID}::k8s::global::cluster"
WORKLOAD_FIREWALL_KINDS = {"NetworkPolicy"}


def _ns_id(namespace: str) -> str:
    """Global namespace entity_id — consistent across all K8s files."""
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
    base = f"{kind} '{name}'"
    if namespace and kind != "Namespace":
        base += f" in namespace '{namespace}'"
    if kind == "Deployment":
        base += f" — {spec.get('replicas', 1)} replica(s)"
    elif kind == "Service":
        base += f" — type {spec.get('type', 'ClusterIP')}"
    elif kind == "NetworkPolicy":
        base += " (workload firewall — controls pod-to-pod traffic)"
    elif kind == "Ingress":
        base += " (external entry point)"
    elif kind == "ServiceAccount":
        base += " — workload identity"
    return base


def _ensure_namespace_node(fragment: GraphFragment, namespace: str,
                            file_path: str, asset_id: str,
                            seen_namespaces: set):
    """Create namespace node + cluster→namespace edge if not already done."""
    if namespace in seen_namespaces:
        return
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


def parse_k8s_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="k8s")

    # One global cluster node — MERGE deduplicates across files
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
        labels      = metadata.get("labels") or {}
        annotations = metadata.get("annotations") or {}

        if not kind or not name:
            continue

        # ── Special case: kind: Namespace ─────────────────────────────────────
        # A Namespace resource IS the namespace itself.
        # Use _ns_id(name) as entity_id so it deduplicates with the namespace
        # container node that other resources create via _ensure_namespace_node.
        if kind == "Namespace":
            _ensure_namespace_node(fragment, name, file_path, asset_id, seen_namespaces)
            # Update the node we just created with richer metadata
            for node in fragment.nodes:
                if node.entity_id == _ns_id(name):
                    node.metadata.semantic_summary = _summary(kind, name, "", spec)
                    node.metadata.is_entry_point = False
                    node.properties = {"kind": kind, "labels": labels, "annotations": annotations}
            continue  # namespace node already added by _ensure_namespace_node

        # ── All other resources ────────────────────────────────────────────────
        namespace = metadata.get("namespace", "default")

        # Ensure parent namespace exists
        _ensure_namespace_node(fragment, namespace, file_path, asset_id, seen_namespaces)

        entity_id        = _resource_id(namespace, kind, name)
        resource_subtype = _get_resource_subtype(kind)
        is_entry         = _is_entry_point(kind, spec)
        irsa_role        = annotations.get("eks.amazonaws.com/role-arn")

        ports = []
        selector = {}
        if kind == "Service":
            ports = [p.get("port") for p in (spec.get("ports") or []) if p.get("port")]
            selector = spec.get("selector") or {}
        elif kind == "Deployment":
            for c in ((spec.get("template") or {}).get("spec", {}).get("containers") or []):
                ports += [p.get("containerPort") for p in (c.get("ports") or [])
                          if p.get("containerPort")]

        props = {"kind": kind, "namespace": namespace,
                 "labels": labels, "annotations": annotations,
                 "ports": ports, "selector": selector}
        if irsa_role:
            props["irsa_role_arn"] = irsa_role
        if kind == "NetworkPolicy":
            props["pod_selector"] = spec.get("podSelector", {})
            props["policy_types"] = spec.get("policyTypes", [])

        fragment.nodes.append(KGNode(
            entity_id=entity_id, node_type=kind, domain_type="k8s",
            resource_subtype=resource_subtype, name=name, org_id=ORG_ID,
            source_location=SourceLocation(
                file_path=file_path,
                block_identifier=f"{kind}.{namespace}.{name}"),
            metadata=NodeMetadata(
                is_entry_point=is_entry,
                semantic_summary=_summary(kind, name, namespace, spec),
                resolved_by="deterministic", confidence=1.0,
            ),
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
