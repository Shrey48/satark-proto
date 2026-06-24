"""
SATARK Layer 1 — Node Pydantic Models
Matches the universal node schema from spec Section 3.
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class SourceLocation(BaseModel):
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    block_identifier: Optional[str] = None


class NodeMetadata(BaseModel):
    firewall_posture: Optional[str] = None       # computed in Pass 3 Sub-step F
    firewall_detail: Optional[dict] = None
    is_entry_point: bool = False
    semantic_summary: Optional[str] = None
    visibility: Optional[str] = None
    dynamic_dispatch_gap: bool = False
    resolved_by: str = "deterministic"
    confidence: float = 1.0


class KGNode(BaseModel):
    entity_id: str
    node_type: str                               # Resource, Function, Endpoint, etc.
    domain_type: str                             # cloud, code, k8s, iam, api, etc.
    resource_subtype: Optional[str] = None       # network_firewall, application_firewall, workload_firewall
    name: str
    source_location: SourceLocation
    metadata: NodeMetadata = NodeMetadata()
    properties: dict = {}                        # Resource-specific properties
    valid_from: datetime = datetime.utcnow()
    valid_to: Optional[datetime] = None
    org_id: str = "prototype"


class KGEdge(BaseModel):
    from_entity_id: str
    to_entity_id: str
    edge_type: str                               # E_invoke, E_contain, E_data_flow, etc.
    resolution_method: str = "deterministic_parse"
    confidence: float = 1.0
    gkg_assisted: bool = False
    source_asset_ids: list[str] = []


class GraphFragment(BaseModel):
    """Output of Pass 1 — one fragment per file."""
    asset_id: str
    file_path: str
    domain_type: str
    nodes: list[KGNode] = []
    edges: list[KGEdge] = []
    entry_points: list[str] = []                 # entity_ids of entry point nodes
