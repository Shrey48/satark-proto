"""
SATARK Layer 1 — Kubernetes Manifest Parser (B5) — FIXED v2

Key fixes vs original:
  1. Reads domain_configs/k8s.yaml — scalable, config-driven
  2. Pod template labels extracted as k8s_app_label for Service→Deployment matching
  3. Service selector extracted as k8s_selector_app (already partially there, now robust)
  4. IRSA annotation (eks.amazonaws.com/role-arn) stored as irsa_role_arn for Pass 3
  5. Deployment serviceAccountName extracted → within-asset E_trust to ServiceAccount
  6. Ignored kinds (ClusterRole, RoleBinding, etc.) silently skipped
  7. kind: Namespace deduplication fix preserved from original

Per spec Section 4.6 Pass 3 join point:
  K8s ServiceAccount → IAM role (IRSA): identifier-keyed via irsa_role_arn → E_trust
  K8s Service → Deployment: name-keyed via selector/label match → E_invoke
"""
from __future__ import annotations
import os
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
        p = os.path.join(d, "k8s.yaml")
        if os.path.exists(p):
            with open(p) as f:
                return yaml.safe_load(f)
    dirs_str = ", ".join(_DOMAIN_CONFIG_DIRS)
    raise FileNotFoundError(
        "domain_configs YAML not found. Looked in: " + dirs_str +
        " -- Copy domain_configs/ to repo root and add volume mount."
    )

_CFG = _load_config()

_RESOURCE_MAP: dict[str, dict] = {
    m["kind"]: m for m in _CFG.get("resource_mappings", [])
}
_IGNORE_KINDS: set[str] = set(_CFG.get("ignore_kinds", []))

GLOBAL_CLUSTER_ID = f"{ORG_ID}::k8s::global::cluster"


# ── Entity ID helpers ─────────────────────────────────────────────────────────

def _ns_id(namespace: str) -> str:
    """Consistent namespace entity_id across all K8s files."""
    return f"{ORG_ID}::k8s::global::namespace.{namespace}"


def _resource_id(namespace: str, kind: str, name: str) -> str:
    return f"{ORG_ID}::k8s::cluster::{namespace}.{kind.lower()}.{name}"


# ── Resource subtype ──────────────────────────────────────────────────────────

def _get_resource_subtype(kind: str) -> Optional[str]:
    cfg = _RESOURCE_MAP.get(kind, {})
    return cfg.get("resource_subtype")


# ── Entry point detection ─────────────────────────────────────────────────────

def _is_entry_point(kind: str, spec: dict) -> bool:
    cfg = _RESOURCE_MAP.get(kind, {})
    if cfg.get("is_entry_point"):
        return True
    entry_types = cfg.get("is_entry_point_types", [])
    if entry_types and kind == "Service":
        return spec.get("type", "ClusterIP") in entry_types
    return False


# ── Namespace helper ──────────────────────────────────────────────────────────

def _ensure_namespace_node(
    fragment: GraphFragment,
    namespace: str,
    file_path: str,
    asset_id: str,
    seen_namespaces: set,
) -> None:
    if namespace in seen_namespaces:
        return
    seen_namespaces.add(namespace)
    ns_id = _ns_id(namespace)
    fragment.nodes.append(KGNode(
        entity_id=ns_id,
        node_type="Namespace",
        domain_type="k8s",
        name=namespace,
        source_location=SourceLocation(
            file_path=file_path,
            block_identifier=f"namespace.{namespace}",
        ),
        metadata=NodeMetadata(
            semantic_summary=f"Kubernetes namespace '{namespace}'",
            resolved_by="deterministic",
            confidence=1.0,
        ),
        org_id=ORG_ID,
    ))
    # Cluster → Namespace containment
    fragment.edges.append(KGEdge(
        from_entity_id=GLOBAL_CLUSTER_ID,
        to_entity_id=ns_id,
        edge_type="E_contain",
        resolution_method="deterministic_parse",
        confidence=1.0,
        source_asset_ids=[asset_id],
    ))


# ── Extract selector / label helpers ─────────────────────────────────────────

def _extract_selector_app(selector: dict) -> Optional[str]:
    """Normalize selector to its app label for matching."""
    if not selector:
        return None
    return (
        selector.get("app")
        or selector.get("app.kubernetes.io/name")
        or selector.get("name")
    )


def _extract_pod_template_app_label(spec: dict) -> Optional[str]:
    """Extract app label from pod template metadata labels."""
    template = spec.get("template") or {}
    template_meta = template.get("metadata") or {}
    labels = template_meta.get("labels") or {}
    return (
        labels.get("app")
        or labels.get("app.kubernetes.io/name")
        or labels.get("name")
    )


def _extract_container_images(spec: dict) -> list[str]:
    """Extract all container image references from a workload spec."""
    images = []
    template = spec.get("template") or spec
    pod_spec = template.get("spec") or {}
    for container_key in ("containers", "initContainers"):
        for c in (pod_spec.get(container_key) or []):
            img = c.get("image")
            if img:
                images.append(img)
    return images


def _extract_container_ports(spec: dict) -> list[int]:
    """Extract container port numbers from a workload spec."""
    ports = []
    template = spec.get("template") or spec
    pod_spec = template.get("spec") or {}
    for c in (pod_spec.get("containers") or []):
        for p in (c.get("ports") or []):
            port = p.get("containerPort")
            if port:
                ports.append(port)
    return ports


def _extract_service_account_name(spec: dict) -> Optional[str]:
    """Extract serviceAccountName from a workload pod spec."""
    template = spec.get("template") or {}
    pod_spec = template.get("spec") or {}
    return pod_spec.get("serviceAccountName")


# ── Summary helper ────────────────────────────────────────────────────────────

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


# ── Main parser ───────────────────────────────────────────────────────────────

def parse_k8s_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="k8s")
    seen_namespaces: set[str] = set()

    # Ensure global cluster node exists
    fragment.nodes.append(KGNode(
        entity_id=GLOBAL_CLUSTER_ID,
        node_type="Cluster",
        domain_type="k8s",
        name="k8s-cluster",
        source_location=SourceLocation(file_path=file_path, block_identifier="cluster"),
        metadata=NodeMetadata(
            semantic_summary="Kubernetes cluster root",
            resolved_by="deterministic",
            confidence=1.0,
        ),
        org_id=ORG_ID,
    ))

    # Parse multi-document YAML
    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        logger.error("k8s_yaml_parse_error", file=file_path, error=str(e))
        return fragment

    for doc in docs:
        if not isinstance(doc, dict):
            continue

        kind = doc.get("kind")
        metadata = doc.get("metadata") or {}
        spec = doc.get("spec") or {}
        name = metadata.get("name", "unknown")
        labels = metadata.get("labels") or {}
        annotations = metadata.get("annotations") or {}

        if not kind:
            continue

        # ── Ignored kinds ─────────────────────────────────────────────────────
        if kind in _IGNORE_KINDS:
            logger.debug("k8s_kind_ignored", kind=kind, name=name)
            continue

        # ── Unknown kind (not in config) ──────────────────────────────────────
        if kind not in _RESOURCE_MAP and kind != "Namespace":
            logger.debug("k8s_kind_unknown", kind=kind, name=name)
            # Silently skip — don't create junk nodes
            continue

        # ── Namespace special case ────────────────────────────────────────────
        if kind == "Namespace":
            _ensure_namespace_node(fragment, name, file_path, asset_id, seen_namespaces)
            for node in fragment.nodes:
                if node.entity_id == _ns_id(name):
                    node.metadata.semantic_summary = _summary(kind, name, "", spec)
                    node.properties = {"kind": kind, "labels": labels, "annotations": annotations}
            continue

        # ── All other resources ───────────────────────────────────────────────
        namespace = metadata.get("namespace", "default")
        _ensure_namespace_node(fragment, namespace, file_path, asset_id, seen_namespaces)

        entity_id = _resource_id(namespace, kind, name)
        resource_subtype = _get_resource_subtype(kind)
        is_entry = _is_entry_point(kind, spec)
        irsa_role = annotations.get("eks.amazonaws.com/role-arn")

        # Base properties
        props: dict = {
            "kind": kind,
            "namespace": namespace,
            "labels": labels,
            "annotations": annotations,
        }

        # ── Selector (Service → Deployment matching key) ──────────────────────
        selector = {}
        if kind == "Service":
            selector = spec.get("selector") or {}
            service_ports = [p.get("port") for p in (spec.get("ports") or []) if p.get("port")]
            props["selector"] = selector
            props["ports"] = service_ports
            selector_app = _extract_selector_app(selector)
            if selector_app:
                props["k8s_selector_app_raw"] = selector_app  # For logging
        elif kind in ("Deployment", "StatefulSet", "DaemonSet"):
            # Extract port info
            container_ports = _extract_container_ports(spec)
            if container_ports:
                props["ports"] = container_ports

        # FIX: Extract pod template labels for Service→Deployment matching
        pod_template_app_label = None
        if kind in ("Deployment", "StatefulSet", "DaemonSet"):
            pod_template_app_label = _extract_pod_template_app_label(spec)
            if pod_template_app_label:
                props["pod_template_app_label"] = pod_template_app_label

        # ── IRSA ARN (ServiceAccount → IAM bridge) ────────────────────────────
        if irsa_role:
            props["irsa_role_arn"] = irsa_role

        # ── Container images (for Pass 3 E_invoke to ContainerImage) ─────────
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Pod", "CronJob", "Job"):
            images = _extract_container_images(spec)
            if images:
                props["container_images"] = images

        # ── ServiceAccount reference (for within-asset E_trust) ───────────────
        if kind in ("Deployment", "StatefulSet", "DaemonSet"):
            sa_name = _extract_service_account_name(spec)
            if sa_name:
                props["service_account_name"] = sa_name

        # ── NetworkPolicy rules ───────────────────────────────────────────────
        if kind == "NetworkPolicy":
            props["pod_selector"] = spec.get("podSelector", {})
            props["policy_types"] = spec.get("policyTypes", [])
            # Extract ingress/egress rules
            rules = []
            for direction in ("ingress", "egress"):
                for rule in (spec.get(direction) or []):
                    rules.append({"direction": direction, **rule})
            if rules:
                props["rules"] = rules

        # ── Ingress backend references ────────────────────────────────────────
        if kind == "Ingress":
            backend_services = []
            for rule in (spec.get("rules") or []):
                http = rule.get("http") or {}
                for path in (http.get("paths") or []):
                    backend = path.get("backend") or {}
                    svc = backend.get("service") or {}
                    svc_name = svc.get("name")
                    if svc_name:
                        backend_services.append(svc_name)
            if backend_services:
                props["backend_services"] = backend_services

        # ── Create node ───────────────────────────────────────────────────────
        fragment.nodes.append(KGNode(
            entity_id=entity_id,
            node_type=kind,
            domain_type="k8s",
            resource_subtype=resource_subtype,
            name=name,
            source_location=SourceLocation(
                file_path=file_path,
                block_identifier=f"{kind}.{namespace}.{name}",
            ),
            metadata=NodeMetadata(
                is_entry_point=is_entry,
                semantic_summary=_summary(kind, name, namespace, spec),
                resolved_by="deterministic",
                confidence=1.0,
            ),
            properties=props,
            org_id=ORG_ID,
        ))

        # Namespace → resource containment
        fragment.edges.append(KGEdge(
            from_entity_id=_ns_id(namespace),
            to_entity_id=entity_id,
            edge_type="E_contain",
            resolution_method="deterministic_parse",
            confidence=1.0,
            source_asset_ids=[asset_id],
        ))

    # ── Within-asset Pass 2: Service → Deployment E_invoke ───────────────────
    # Run inside parser so it's available immediately (before Pass 2 linker)
    _link_services_to_deployments(fragment, asset_id)

    # ── Within-asset: Deployment → ServiceAccount E_trust ────────────────────
    _link_deployments_to_service_accounts(fragment, asset_id)

    logger.info(
        "k8s_parse_complete",
        file=file_path,
        nodes=len(fragment.nodes),
        edges=len(fragment.edges),
    )
    return fragment


def _link_services_to_deployments(fragment: GraphFragment, asset_id: str) -> None:
    """
    Within-asset: Service selector matches Deployment pod template labels → E_invoke.
    This is the key linkage that shows which Service routes traffic to which Deployment.
    """
    services = [
        n for n in fragment.nodes
        if n.node_type == "Service" and n.properties.get("selector")
    ]
    workloads = [
        n for n in fragment.nodes
        if n.node_type in ("Deployment", "StatefulSet", "DaemonSet")
    ]

    existing_edges = {
        (e.from_entity_id, e.to_entity_id) for e in fragment.edges
    }

    for svc in services:
        selector = svc.properties.get("selector", {})
        svc_namespace = svc.properties.get("namespace", "default")
        selector_app = _extract_selector_app(selector)
        if not selector_app:
            continue

        for workload in workloads:
            workload_namespace = workload.properties.get("namespace", "default")
            if svc_namespace != workload_namespace:
                continue

            # Match via pod template labels
            pod_label = workload.properties.get("pod_template_app_label")
            # Also check node-level app label
            node_labels = workload.properties.get("labels", {})
            node_app = node_labels.get("app") or node_labels.get("name")

            if selector_app in (pod_label, node_app):
                key = (svc.entity_id, workload.entity_id)
                if key not in existing_edges:
                    fragment.edges.append(KGEdge(
                        from_entity_id=svc.entity_id,
                        to_entity_id=workload.entity_id,
                        edge_type="E_invoke",
                        resolution_method="deterministic_parse",
                        confidence=1.0,
                        source_asset_ids=[asset_id],
                    ))
                    existing_edges.add(key)
                    logger.debug(
                        "k8s_service_deployment_linked",
                        service=svc.name,
                        workload=workload.name,
                        match_via=selector_app,
                    )


def _link_deployments_to_service_accounts(fragment: GraphFragment, asset_id: str) -> None:
    """
    Within-asset: Deployment.spec.serviceAccountName → ServiceAccount → E_trust.
    This enables IRSA privilege path: Deployment → ServiceAccount → IAM Role.
    """
    deployments = [
        n for n in fragment.nodes
        if n.node_type in ("Deployment", "StatefulSet", "DaemonSet")
        and n.properties.get("service_account_name")
    ]
    service_accounts = {
        (n.properties.get("namespace", "default"), n.name): n
        for n in fragment.nodes
        if n.node_type == "ServiceAccount"
    }

    existing_edges = {
        (e.from_entity_id, e.to_entity_id) for e in fragment.edges
    }

    for dep in deployments:
        sa_name = dep.properties.get("service_account_name")
        dep_namespace = dep.properties.get("namespace", "default")
        key = (dep_namespace, sa_name)
        sa_node = service_accounts.get(key)
        if sa_node:
            edge_key = (dep.entity_id, sa_node.entity_id)
            if edge_key not in existing_edges:
                fragment.edges.append(KGEdge(
                    from_entity_id=dep.entity_id,
                    to_entity_id=sa_node.entity_id,
                    edge_type="E_trust",
                    resolution_method="deterministic_parse",
                    confidence=1.0,
                    source_asset_ids=[asset_id],
                ))
                existing_edges.add(edge_key)
