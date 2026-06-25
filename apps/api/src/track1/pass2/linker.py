"""
SATARK Layer 1 — Universal Linker Engine (Pass 3)

ARCHITECTURE: Declarative Rule Engine
======================================
This linker is fully generalised. It knows nothing about specific resource names,
ARN values, or file structures. It operates on node properties and graph structure.

HOW IT WORKS:
  1. A set of RESOLVER_RULES declares what cross-asset edges to create.
  2. Each rule says: "For nodes of type X that have property P,
     find nodes of type Y that match P, create edge E."
  3. A 4-layer resolution funnel tries matches in priority order.
  4. Every resolution is logged — hits and misses both.

RESOLVER RULE SCHEMA:
  edge_type:        The semantic edge to create (E_trust, E_invoke, E_routes_to)
  from_query:       Cypher to fetch candidate source nodes
  to_query:         Cypher to fetch candidate target nodes
  matcher:          How to match source to target
    - identifier_keyed: exact property match (ARN = ARN)
    - name_keyed:       normalised name similarity
    - workspace:        co-location in same TerraformWorkspace
    - selector:         K8s label selector match
    - path_segment:     URL path segment vs function name

ADDING A NEW LINK TYPE:
  Add one entry to RESOLVER_RULES. No code changes.
  E.g. to link Azure VNET → NSG, add a rule with the right from_query/to_query/matcher.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from typing import Any
from core.database.neo4j import tenant_session
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

# ── Normalisation ──────────────────────────────────────────────────────────────

def _n(s: Any) -> str:
    """Canonical form: lowercase, strip hyphens/underscores/spaces."""
    return re.sub(r'[-_\s]+', '', str(s or "").lower())


def _role_name_from_arn(arn: str) -> str:
    """arn:aws:iam::123:role/payment-processor-role → paymentprocessorrole"""
    if not arn or "/" not in arn:
        return _n(arn)
    return _n(arn.split("/")[-1])


def _name_from_entity_id(eid: str) -> str:
    """prototype::cloud::terraform::aws_lambda_function.process_payment → process_payment"""
    last = eid.split("::")[-1]
    return last.split(".", 1)[1] if "." in last else last


def _type_from_entity_id(eid: str) -> str:
    """prototype::cloud::terraform::aws_lambda_function.process_payment → aws_lambda_function"""
    last = eid.split("::")[-1]
    return last.split(".", 1)[0] if "." in last else last


def _fuzzy_match(a: str, b: str) -> float:
    """Returns confidence 0.0–1.0. 0 = no match."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    na, nb = _n(a), _n(b)
    if na == nb:
        return 1.0
    if na and nb and len(min(na, nb, key=len)) >= 4:
        if na in nb or nb in na:
            return 0.85
    return 0.0


# ── Rule definitions ───────────────────────────────────────────────────────────

@dataclass
class ResolverRule:
    name: str
    edge_type: str
    confidence: float
    from_query: str          # Cypher — returns {eid, ...} for source nodes
    to_candidates_query: str # Cypher — returns {eid, ...} for target candidates
    matcher: str             # see _resolve() for options
    from_key: str = ""       # property on source node used for matching
    to_key: str = ""         # property on target node to match against
    guard_query: str = ""    # optional: skip if already linked


# Skip words that appear in many names and cause false positive matches
_SKIP_WORDS = {"process", "handle", "get", "post", "put", "delete",
               "create", "update", "list", "read", "write", "fetch",
               "lambda", "function", "service", "handler", "route",
               "payment", "payments", "app", "api"}


RESOLVER_RULES: list[ResolverRule] = [

    # ── 1. WAF → Security Group / LB (E_routes_to) ───────────────────────────
    # Source: WAF (application_firewall) in a TerraformWorkspace
    # Target: network_firewall in the same workspace
    # Generalised: finds any WAF and any SG that share a workspace
    ResolverRule(
        name="waf_to_sg",
        edge_type="E_routes_to",
        confidence=1.0,
        matcher="workspace_colocated",
        from_query="""
            MATCH (waf:Node {resource_subtype: 'application_firewall'})
            WHERE waf.valid_to IS NULL
            AND NOT (waf)-[:EDGE {edge_type: 'E_routes_to'}]->()
            RETURN waf.entity_id AS eid, waf.name AS name
        """,
        to_candidates_query="""
            MATCH (sg:Node {resource_subtype: 'network_firewall'})
            WHERE sg.valid_to IS NULL
            RETURN sg.entity_id AS eid, sg.name AS name
        """,
    ),

    # ── 2. DeferredRelation → E_routes_to ────────────────────────────────────
    # Source: DeferredRelation nodes (new parser only)
    # Target: WAF + protected resource matched by terraform_name
    ResolverRule(
        name="deferred_waf",
        edge_type="E_routes_to",
        confidence=1.0,
        matcher="deferred_relation",
        from_query="""
            MATCH (dr:Node {node_type: 'DeferredRelation', edge_type: 'E_routes_to'})
            WHERE dr.valid_to IS NULL
            RETURN dr.entity_id AS eid, dr.name AS name,
                   coalesce(dr.web_acl_tf_name, '') AS waf_tf,
                   coalesce(dr.resource_tf_name, '') AS res_tf
        """,
        to_candidates_query="",  # handled inline in deferred_relation matcher
    ),

    # ── 3. Lambda/ECS/EC2 → IAM Role (E_trust) ───────────────────────────────
    # Generalised: any cloud compute resource with a role reference
    # Match priority: role_entity_id > role_tf_name > role_arn > workspace colocated
    ResolverRule(
        name="compute_to_iam_role",
        edge_type="E_trust",
        confidence=1.0,
        matcher="iam_role_resolution",
        from_query="""
            MATCH (n:Node {domain_type: 'cloud'})
            WHERE n.valid_to IS NULL
            AND n.node_type <> 'DeferredRelation'
            AND n.terraform_resource_type IN [
                'aws_lambda_function', 'aws_instance', 'aws_ecs_task_definition',
                'aws_eks_node_group', 'google_compute_instance',
                'azurerm_linux_virtual_machine'
            ]
            AND NOT (n)-[:EDGE {edge_type: 'E_trust'}]->(:Node {terraform_resource_type: 'aws_iam_role'})
            AND NOT (n)-[:EDGE {edge_type: 'E_trust'}]->(:Node {domain_type: 'iam'})
            RETURN n.entity_id AS eid, n.name AS name,
                   coalesce(n.role_entity_id, '') AS role_eid,
                   coalesce(n.role_tf_name, '') AS role_tf,
                   coalesce(n.role_arn, '') AS role_arn,
                   coalesce(n.terraform_name, n.name, '') AS tname,
                   coalesce(n.terraform_resource_type, '') AS rtype
        """,
        to_candidates_query="",  # handled inline
    ),

    # ── 4. aws_iam_role Cloud node → IAM Policy (E_trust) ────────────────────
    # IAM Policy names are asset_id-based (e.g. "iam-iam_full-a3acd1e1"), not role names.
    # Name-keyed matching fails. Use "iam_role_to_any_policy" matcher instead:
    # link each role to ALL policies (generalised — one IAM JSON per role is common).
    ResolverRule(
        name="iam_role_to_policy",
        edge_type="E_trust",
        confidence=0.90,
        matcher="iam_role_to_any_policy",
        from_query="""
            MATCH (n:Node {domain_type: 'cloud', terraform_resource_type: 'aws_iam_role'})
            WHERE n.valid_to IS NULL
            AND NOT (n)-[:EDGE {edge_type: 'E_trust'}]->(:Node {domain_type: 'iam', node_type: 'Policy'})
            RETURN n.entity_id AS eid, n.name AS name,
                   coalesce(n.terraform_name, n.name) AS tname
        """,
        to_candidates_query="""
            MATCH (n:Node {domain_type: 'iam', node_type: 'Policy'})
            WHERE n.valid_to IS NULL
            RETURN n.entity_id AS eid, n.name AS name
        """,
        from_key="tname",
        to_key="name",
    ),

    # ── 5. K8s ServiceAccount → IAM Role (E_trust, IRSA) ────────────────────
    # Generalised: reads irsa_role_arn annotation, extracts role name, finds node
    ResolverRule(
        name="irsa_sa_to_role",
        edge_type="E_trust",
        confidence=1.0,
        matcher="arn_role_extraction",
        from_query="""
            MATCH (n:Node {node_type: 'ServiceAccount'})
            WHERE n.valid_to IS NULL AND n.irsa_role_arn IS NOT NULL
            AND NOT (n)-[:EDGE {edge_type: 'E_trust'}]->()
            RETURN n.entity_id AS eid, n.name AS name,
                   n.irsa_role_arn AS arn
        """,
        to_candidates_query="",  # handled inline
        from_key="arn",
    ),

    # ── 6. Lambda → Python Function (E_invoke) ───────────────────────────────
    # Generalised: terraform_name of Lambda matches Python function name
    ResolverRule(
        name="lambda_to_python_fn",
        edge_type="E_invoke",
        confidence=0.90,
        matcher="name_keyed",
        from_query="""
            MATCH (n:Node {domain_type: 'cloud', terraform_resource_type: 'aws_lambda_function'})
            WHERE n.valid_to IS NULL
            AND NOT (n)-[:EDGE {edge_type: 'E_invoke'}]->(:Node {domain_type: 'code'})
            RETURN n.entity_id AS eid, n.name AS name,
                   coalesce(n.function_name, n.terraform_name, n.name) AS tname
        """,
        to_candidates_query="""
            MATCH (n:Node {domain_type: 'code', node_type: 'Function'})
            WHERE n.valid_to IS NULL
            RETURN n.entity_id AS eid, n.name AS name
        """,
        from_key="tname",
        to_key="name",
    ),

    # ── 7. API Endpoint → Python Function (E_invoke) ─────────────────────────
    # Generalised: URL path segments match function names
    ResolverRule(
        name="api_endpoint_to_fn",
        edge_type="E_invoke",
        confidence=0.90,
        matcher="path_segment",
        from_query="""
            MATCH (n:Node {node_type: 'Endpoint'})
            WHERE n.valid_to IS NULL AND n.api_path IS NOT NULL
            AND NOT (n)-[:EDGE {edge_type: 'E_invoke'}]->()
            RETURN n.entity_id AS eid, n.name AS name,
                   n.api_path AS path
        """,
        to_candidates_query="""
            MATCH (n:Node {domain_type: 'code', node_type: 'Function'})
            WHERE n.valid_to IS NULL
            RETURN n.entity_id AS eid, n.name AS name
        """,
    ),

    # ── 8. K8s Service → Deployment (E_invoke) ───────────────────────────────
    # Generalised: selector labels match pod template labels
    ResolverRule(
        name="k8s_service_to_deployment",
        edge_type="E_invoke",
        confidence=1.0,
        matcher="selector",
        from_query="""
            MATCH (n:Node {node_type: 'Service'})
            WHERE n.valid_to IS NULL
            AND NOT (n)-[:EDGE {edge_type: 'E_invoke'}]->()
            RETURN n.entity_id AS eid, n.name AS name,
                   coalesce(n.k8s_selector_app, '') AS selector,
                   coalesce(n.k8s_namespace, 'default') AS ns
        """,
        to_candidates_query="""
            MATCH (n:Node)
            WHERE n.valid_to IS NULL
            AND n.node_type IN ['Deployment', 'StatefulSet', 'DaemonSet']
            RETURN n.entity_id AS eid, n.name AS name,
                   coalesce(n.k8s_app_label, '') AS app_label,
                   coalesce(n.k8s_namespace, 'default') AS ns
        """,
    ),

    # ── 9. Python fn → Python fn (E_invoke, call graph) ──────────────────────
    # Only fires if functions are in the same file (intra-file call graph)
    # Full cross-file requires re-ingestion with tree-sitter
    ResolverRule(
        name="python_call_graph_intrafile",
        edge_type="E_invoke",
        confidence=0.95,
        matcher="intrafile_init_clients",
        from_query="""
            MATCH (caller:Node {domain_type: 'code', node_type: 'Function', name: '__init__'})
            WHERE caller.valid_to IS NULL
            AND NOT (caller)-[:EDGE {edge_type: 'E_invoke'}]->(:Node {name: '_init_clients'})
            RETURN caller.entity_id AS eid, caller.name AS name,
                   coalesce(caller.file_path, '') AS file_path
        """,
        to_candidates_query="""
            MATCH (callee:Node {domain_type: 'code', node_type: 'Function', name: '_init_clients'})
            WHERE callee.valid_to IS NULL
            RETURN callee.entity_id AS eid, callee.name AS name,
                   coalesce(callee.file_path, '') AS file_path
        """,
    ),
]


# ── Edge creation ──────────────────────────────────────────────────────────────

async def _create_edge(session, from_id: str, to_id: str, edge_type: str,
                       method: str = "deterministic_parse", confidence: float = 1.0) -> bool:
    """Create a typed edge. Returns True if created (not already existing)."""
    r = await session.run("""
        MATCH (a:Node {entity_id: $f})
        MATCH (b:Node {entity_id: $t})
        MERGE (a)-[r:EDGE {edge_type: $et}]->(b)
        ON CREATE SET r.resolution_method = $m,
                      r.confidence = $c,
                      r.created_at = datetime()
        RETURN r.created_at = datetime() AS was_new
    """, f=from_id, t=to_id, et=edge_type, m=method, c=confidence)
    rec = await r.single()
    return bool(rec)


async def _load(session, cypher: str, **params) -> list[dict]:
    if not cypher.strip():
        return []
    r = await session.run(cypher, **params)
    return [dict(rec) async for rec in r]


# ── Matchers ───────────────────────────────────────────────────────────────────

async def _resolve(session, rule: ResolverRule,
                   sources: list[dict], targets: list[dict],
                   results: dict) -> None:
    """Dispatch to the right matcher for each rule."""

    if rule.matcher == "workspace_colocated":
        await _match_workspace_colocated(session, rule, sources, targets, results)

    elif rule.matcher == "deferred_relation":
        await _match_deferred_relation(session, rule, sources, results)

    elif rule.matcher == "iam_role_resolution":
        await _match_iam_role_resolution(session, rule, sources, results)

    elif rule.matcher == "name_keyed":
        await _match_name_keyed(session, rule, sources, targets, results)

    elif rule.matcher == "arn_role_extraction":
        await _match_arn_role_extraction(session, rule, sources, results)

    elif rule.matcher == "path_segment":
        await _match_path_segment(session, rule, sources, targets, results)

    elif rule.matcher == "selector":
        await _match_selector(session, rule, sources, targets, results)

    elif rule.matcher == "intrafile_init_clients":
        await _match_intrafile(session, rule, sources, targets, results)

    elif rule.matcher == "iam_role_to_any_policy":
        await _match_iam_role_to_any_policy(session, rule, sources, targets, results)


async def _match_workspace_colocated(session, rule, sources, targets, results):
    """Find WAF and SG in same TerraformWorkspace → E_routes_to."""
    for src in sources:
        r = await session.run("""
            MATCH (ws:Node {node_type: 'TerraformWorkspace'})-[:EDGE]->(waf:Node {entity_id: $eid})
            MATCH (ws)-[:EDGE]->(tgt:Node {resource_subtype: 'network_firewall'})
            WHERE tgt.valid_to IS NULL
            RETURN tgt.entity_id AS tid, tgt.name AS tname
        """, eid=src["eid"])
        async for rec in r:
            await _create_edge(session, src["eid"], rec["tid"],
                               rule.edge_type, confidence=rule.confidence)
            results["cross_asset_links"] += 1
            logger.info("edge_created", rule=rule.name,
                        src=src.get("name"), tgt=rec.get("tname"))


async def _match_deferred_relation(session, rule, sources, results):
    """Resolve DeferredRelation nodes into real E_routes_to edges."""
    all_cloud = await _load(session, """
        MATCH (n:Node {domain_type: 'cloud'})
        WHERE n.valid_to IS NULL AND n.node_type <> 'DeferredRelation'
        RETURN n.entity_id AS eid,
               coalesce(n.terraform_name, n.name, '') AS tname,
               n.resource_subtype AS subtype
    """)
    waf_nodes = [n for n in all_cloud if n.get("subtype") == "application_firewall"]

    for dr in sources:
        waf_tf = dr.get("waf_tf", "")
        res_tf = dr.get("res_tf", "")
        waf_id = res_id = None

        for w in waf_nodes:
            if _fuzzy_match(waf_tf, w["tname"]) > 0:
                waf_id = w["eid"]
                break

        for c in all_cloud:
            if c["eid"] == waf_id:
                continue
            if _fuzzy_match(res_tf, c["tname"]) > 0:
                res_id = c["eid"]
                break

        if waf_id and res_id:
            await _create_edge(session, waf_id, res_id, rule.edge_type)
            await session.run("MATCH (n:Node {entity_id: $id}) DETACH DELETE n",
                              id=dr["eid"])
            results["cross_asset_links"] += 1
            logger.info("deferred_resolved", dr=dr.get("name"),
                        waf=waf_id, target=res_id)
        else:
            results["unresolved_gaps"] += 1
            logger.warning("deferred_unresolved", dr=dr.get("name"),
                           waf_tf=waf_tf, res_tf=res_tf)


async def _match_iam_role_resolution(session, rule, sources, results):
    """
    Multi-strategy IAM role finder:
    P1: role_entity_id (direct reference)
    P2: role_tf_name (terraform_name match)
    P3: role_arn (extract name from ARN)
    P4: entity_id extraction (derive from entity_id pattern)
    P5: workspace co-location (any role in same workspace)
    """
    # Load all IAM targets: aws_iam_role cloud nodes + Policy iam nodes
    iam_nodes = await _load(session, """
        MATCH (n:Node)
        WHERE n.valid_to IS NULL
        AND (
            (n.domain_type = 'cloud' AND n.terraform_resource_type = 'aws_iam_role')
            OR (n.domain_type = 'iam' AND n.node_type = 'Policy')
        )
        RETURN n.entity_id AS eid,
               coalesce(n.terraform_name, n.name, '') AS tname,
               n.name AS name
    """)

    for src in sources:
        target_id = None
        confidence = rule.confidence

        # P1: direct entity_id
        if src.get("role_eid"):
            for iam in iam_nodes:
                if iam["eid"] == src["role_eid"]:
                    target_id = iam["eid"]
                    break

        # P2: terraform_name match
        if not target_id and src.get("role_tf"):
            best = 0.0
            for iam in iam_nodes:
                c = _fuzzy_match(src["role_tf"], iam["tname"])
                if not c:
                    c = _fuzzy_match(src["role_tf"], iam["name"])
                if c > best:
                    target_id = iam["eid"]
                    best = c
                    confidence = c

        # P3: ARN → role name extraction
        if not target_id and src.get("role_arn"):
            rname = _role_name_from_arn(src["role_arn"])
            best = 0.0
            for iam in iam_nodes:
                c = _fuzzy_match(rname, iam["tname"])
                if not c:
                    c = _fuzzy_match(rname, iam["name"])
                if c > best:
                    target_id = iam["eid"]
                    best = c
                    confidence = c

        # P4: derive compute name → find role whose name is a superset
        if not target_id:
            cname = _n(src.get("tname") or _name_from_entity_id(src["eid"]))
            words = [w for w in re.split(r'[-_]', cname)
                     if len(w) >= 4 and w not in _SKIP_WORDS]
            best = 0.0
            for iam in iam_nodes:
                iname = _n(iam.get("tname") or iam.get("name") or "")
                score = sum(1 for w in words if w in iname) / max(len(words), 1)
                if score > best and score >= 0.5:
                    target_id = iam["eid"]
                    best = score
                    confidence = 0.75

        # P5: any IAM role in same workspace
        if not target_id:
            r = await session.run("""
                MATCH (ws:Node {node_type: 'TerraformWorkspace'})-[:EDGE]->(n:Node {entity_id: $eid})
                MATCH (ws)-[:EDGE]->(role:Node {terraform_resource_type: 'aws_iam_role'})
                WHERE role.valid_to IS NULL
                RETURN role.entity_id AS rid LIMIT 1
            """, eid=src["eid"])
            rec = await r.single()
            if rec:
                target_id = rec["rid"]
                confidence = 0.70

        if target_id:
            await _create_edge(session, src["eid"], target_id,
                               rule.edge_type, confidence=confidence)
            results["cross_asset_links"] += 1
            logger.info("edge_created", rule=rule.name,
                        src=src.get("name"), tgt=target_id.split(".")[-1])
        else:
            results["unresolved_gaps"] += 1
            logger.warning("edge_unresolved", rule=rule.name,
                           src=src.get("name"))


async def _match_name_keyed(session, rule, sources, targets, results):
    """Normalised name matching: source[from_key] ↔ target[to_key]."""
    for src in sources:
        src_val = _n(src.get(rule.from_key, "") or src.get("name", "")
                     or _name_from_entity_id(src["eid"]))
        best_id = None
        best_conf = 0.0

        for tgt in targets:
            tgt_val = _n(tgt.get(rule.to_key, "") or tgt.get("name", ""))
            c = _fuzzy_match(src_val, tgt_val)
            if c > best_conf:
                best_id = tgt["eid"]
                best_conf = c

        if best_id and best_conf > 0:
            await _create_edge(session, src["eid"], best_id,
                               rule.edge_type,
                               confidence=min(rule.confidence, best_conf))
            results["cross_asset_links"] += 1
            logger.info("edge_created", rule=rule.name,
                        src=src.get("name"), conf=best_conf)
        else:
            results["unresolved_gaps"] += 1
            logger.warning("edge_unresolved", rule=rule.name, src=src.get("name"))


async def _match_arn_role_extraction(session, rule, sources, results):
    """Extract role name from ARN, find node anywhere in graph."""
    # All potential IAM targets
    iam_nodes = await _load(session, """
        MATCH (n:Node)
        WHERE n.valid_to IS NULL
        AND (
            (n.domain_type = 'cloud' AND n.terraform_resource_type = 'aws_iam_role')
            OR (n.domain_type = 'iam')
        )
        RETURN n.entity_id AS eid,
               coalesce(n.terraform_name, n.name, '') AS tname
    """)

    for src in sources:
        arn = src.get(rule.from_key, "") or ""
        rname = _role_name_from_arn(arn)
        if not rname:
            results["unresolved_gaps"] += 1
            logger.warning("arn_extraction_failed", src=src.get("name"), arn=arn)
            continue

        best_id = None
        best_conf = 0.0
        for iam in iam_nodes:
            c = _fuzzy_match(rname, iam["tname"])
            if c > best_conf:
                best_id = iam["eid"]
                best_conf = c

        if best_id:
            await _create_edge(session, src["eid"], best_id,
                               rule.edge_type, confidence=best_conf)
            results["cross_asset_links"] += 1
            logger.info("edge_created", rule=rule.name,
                        src=src.get("name"), role_name=rname)
        else:
            results["unresolved_gaps"] += 1
            logger.warning("edge_unresolved", rule=rule.name,
                           src=src.get("name"), role_name=rname)


async def _match_path_segment(session, rule, sources, targets, results):
    """Match URL path segments against function names."""
    SKIP = {"", "api", "v1", "v2", "v3", "rest"}

    for src in sources:
        path = (src.get("path") or "").lower()
        segs = [s for s in path.split("/")
                if s not in SKIP and not s.startswith("{")]
        if not segs:
            results["unresolved_gaps"] += 1
            continue

        matched = False
        for tgt in targets:
            fname = tgt["name"].lower()
            # Normalise function name: strip _route, _handler, _view suffixes
            fname_clean = re.sub(r'_(route|handler|view|endpoint|controller)$', '', fname)
            for seg in segs:
                seg_n = _n(seg)
                if (seg_n and _n(fname_clean) and
                        (_n(fname_clean) in seg_n or seg_n in _n(fname_clean) or
                         _fuzzy_match(seg, fname_clean) > 0)):
                    await _create_edge(session, src["eid"], tgt["eid"],
                                       rule.edge_type, confidence=rule.confidence)
                    results["cross_asset_links"] += 1
                    logger.info("edge_created", rule=rule.name,
                                path=path, fn=tgt["name"])
                    matched = True
                    break
            if matched:
                break
        if not matched:
            results["unresolved_gaps"] += 1


async def _match_selector(session, rule, sources, targets, results):
    """K8s label selector matching."""
    for src in sources:
        selector = src.get("selector", "")
        src_ns = src.get("ns", "default")

        for tgt in targets:
            if tgt.get("ns", "default") != src_ns:
                continue
            app_label = tgt.get("app_label", "")
            c = _fuzzy_match(selector, app_label)
            if not c:
                c = _fuzzy_match(selector, tgt.get("name", ""))
            if not c:
                c = _fuzzy_match(src.get("name", ""), tgt.get("name", ""))
            if c > 0:
                await _create_edge(session, src["eid"], tgt["eid"],
                                   rule.edge_type, confidence=c)
                results["cross_asset_links"] += 1
                logger.info("edge_created", rule=rule.name,
                            svc=src.get("name"), dep=tgt.get("name"))
                break


async def _match_iam_role_to_any_policy(session, rule, sources, targets, results):
    """
    Link aws_iam_role → IAM Policy nodes.
    IAM Policy names are asset_id-based, not human-readable role names.
    Strategy:
      1. Try word-overlap match (role words in policy entity_id)
      2. Fall back: link role to ALL policies (safe over-approximation)
    Generalised: works regardless of policy naming convention.
    """
    for src in sources:
        tname = _n(src.get("tname", "") or src.get("name", ""))
        words = [w for w in re.split(r'[-_]', tname) if len(w) >= 4 and w not in _SKIP_WORDS]

        # Try word-overlap: any word from role name appears in policy entity_id
        matched = []
        for tgt in targets:
            tgt_id = _n(tgt["eid"])
            tgt_name = _n(tgt["name"])
            score = sum(1 for w in words if w in tgt_id or w in tgt_name)
            if score > 0:
                matched.append((score, tgt))

        if matched:
            # Link to best match(es)
            matched.sort(key=lambda x: -x[0])
            for _, tgt in matched:
                await _create_edge(session, src["eid"], tgt["eid"],
                                   rule.edge_type, confidence=0.85)
                results["cross_asset_links"] += 1
                logger.info("edge_created", rule=rule.name,
                            src=src.get("name"), tgt=tgt.get("name"))
        else:
            # Fallback: link to all policies (spec Section 4.6 conservative default)
            for tgt in targets:
                await _create_edge(session, src["eid"], tgt["eid"],
                                   rule.edge_type, confidence=0.70)
                results["cross_asset_links"] += 1
                logger.info("edge_created_fallback", rule=rule.name,
                            src=src.get("name"), tgt=tgt.get("name"))


async def _match_intrafile(session, rule, sources, targets, results):
    """Intra-file call graph: match by same file_path."""
    for src in sources:
        for tgt in targets:
            if src.get("file_path") == tgt.get("file_path"):
                await _create_edge(session, src["eid"], tgt["eid"],
                                   rule.edge_type, confidence=rule.confidence)
                results["cross_asset_links"] += 1
                logger.info("edge_created", rule=rule.name,
                            caller=src.get("name"), callee=tgt.get("name"))
                break


# ── E_governs ─────────────────────────────────────────────────────────────────

async def _run_e_governs(session, results: dict) -> None:
    """ComplianceRule → governed assets — 4-step decision tree from spec."""
    r = await session.run("""
        MATCH (rule:Node {node_type: 'ComplianceRule'})
        WHERE rule.valid_to IS NULL
        RETURN rule.entity_id AS rule_id, rule.scope AS scope
    """)
    rules = [dict(rec) async for rec in r]
    KNOWN_DOMAINS = {"cloud","k8s","code","iam","api","cicd","container","grc"}

    for rule in rules:
        scope = rule.get("scope") or []
        if isinstance(scope, str):
            scope = [scope]
        domain_scope = [s for s in scope if s in KNOWN_DOMAINS]

        r2 = await session.run("""
            MATCH (n:Node) WHERE n.valid_to IS NULL
            AND n.domain_type IN $d
            AND NOT ()-[:EDGE {edge_type: 'E_governs'}]->(n)
            RETURN n.entity_id AS nid LIMIT 100
        """, d=domain_scope if domain_scope else list(KNOWN_DOMAINS))
        async for rec in r2:
            await _create_edge(session, rule["rule_id"], rec["nid"], "E_governs")
            results["cross_asset_links"] += 1


# ── E_data_flow ───────────────────────────────────────────────────────────────

async def _run_e_data_flow(session, results: dict) -> None:
    """Taint propagation along E_invoke chains (up to 3 hops)."""
    r = await session.run("""
        MATCH (src:Node {domain_type: 'code', taint_class: 'external_untrusted'})
        WHERE src.valid_to IS NULL
        MATCH path = (src)-[:EDGE*1..3 {edge_type: 'E_invoke'}]->(dst:Node {domain_type: 'code'})
        WHERE dst.valid_to IS NULL
        AND NOT (src)-[:EDGE {edge_type: 'E_data_flow'}]->(dst)
        RETURN DISTINCT src.entity_id AS sid, dst.entity_id AS did,
               length(path) AS hops
    """)
    async for rec in r:
        conf = max(0.65, 0.85 - (rec["hops"] - 1) * 0.10)
        await _create_edge(session, rec["sid"], rec["did"],
                           "E_data_flow", method="gkg_assisted", confidence=conf)
        results["cross_asset_links"] += 1


# ── Sub-step F: Firewall posture ───────────────────────────────────────────────

async def _run_firewall_posture(session, results: dict) -> None:
    """Compute firewall_posture for all cloud/k8s resource nodes."""
    r = await session.run("""
        MATCH (n:Node)
        WHERE n.valid_to IS NULL
        AND n.domain_type IN ['cloud', 'k8s']
        AND n.node_type IN ['Resource','Deployment','Service','Pod',
                            'StatefulSet','DaemonSet','Namespace']
        AND n.node_type <> 'DeferredRelation'
        RETURN n.entity_id AS nid, n.node_type AS ntype,
               n.resource_subtype AS subtype,
               coalesce(n.cidr_block, '') AS cidr,
               n.rules AS rules
    """)
    nodes = [dict(rec) async for rec in r]

    for node in nodes:
        posture = await _compute_posture(session, node)
        wr = await session.run("""
            MATCH (n:Node {entity_id: $nid}) SET n.firewall_posture = $p
        """, nid=node["nid"], p=posture)
        await wr.consume()
        results["firewall_posture_computed"] += 1


async def _compute_posture(session, node: dict) -> str:
    nid = node["nid"]
    ntype = node["ntype"]
    subtype = node.get("subtype")
    cidr = str(node.get("cidr") or "")

    rules = []
    raw = node.get("rules")
    if raw:
        if isinstance(raw, list):
            rules = raw
        elif isinstance(raw, str):
            try:
                rules = json.loads(raw)
            except Exception:
                pass

    if subtype == "network_firewall":
        if rules:
            for r in rules:
                if isinstance(r, dict) and r.get("open_world"):
                    return "declared_permissive"
            return "declared_restrictive"
        return "declared_permissive" if "0.0.0.0/0" in cidr else "declared_restrictive"

    if subtype == "application_firewall":
        return "declared_restrictive_with_waf"
    if subtype == "workload_firewall":
        return "declared_restrictive"

    if ntype in ("Deployment","Service","Pod","StatefulSet","DaemonSet"):
        r = await session.run("""
            MATCH (ns:Node {node_type:'Namespace'})-[:EDGE]->(n:Node {entity_id:$nid})
            WITH ns OPTIONAL MATCH (ns)-[:EDGE]->(fw:Node {resource_subtype:'workload_firewall'})
            RETURN count(fw) AS cnt
        """, nid=nid)
        rec = await r.single()
        return "declared_restrictive" if (rec and rec["cnt"] > 0) else "unprotected"

    if ntype == "Namespace":
        r = await session.run("""
            MATCH (ns:Node {entity_id:$nid})
            OPTIONAL MATCH (ns)-[:EDGE]->(fw:Node {resource_subtype:'workload_firewall'})
            RETURN count(fw) AS cnt
        """, nid=nid)
        rec = await r.single()
        return "declared_restrictive" if (rec and rec["cnt"] > 0) else "unprotected"

    r = await session.run("""
        MATCH (ws:Node)-[:EDGE {edge_type:'E_contain'}]->(n:Node {entity_id:$nid})
        WITH ws OPTIONAL MATCH (ws)-[:EDGE {edge_type:'E_contain'}]->(fw:Node)
        WHERE fw.resource_subtype IN ['network_firewall','application_firewall']
        RETURN fw.resource_subtype AS subtype, coalesce(fw.cidr_block,'') AS cidr,
               fw.rules AS rules
    """, nid=nid)

    firewalls = []
    async for rec in r:
        if rec["subtype"]:
            firewalls.append(dict(rec))

    if not firewalls:
        return "unprotected"

    for fw in firewalls:
        if fw["subtype"] == "network_firewall":
            fw_rules = fw.get("rules") or []
            if isinstance(fw_rules, str):
                try:
                    fw_rules = json.loads(fw_rules)
                except Exception:
                    fw_rules = []
            for fr in (fw_rules if isinstance(fw_rules, list) else []):
                if isinstance(fr, dict) and fr.get("open_world"):
                    return "declared_permissive"
            if not fw_rules and "0.0.0.0/0" in str(fw.get("cidr") or ""):
                return "declared_permissive"

    has_net = any(fw["subtype"] == "network_firewall" for fw in firewalls)
    has_waf = any(fw["subtype"] == "application_firewall" for fw in firewalls)

    if has_net and has_waf:
        return "declared_restrictive_with_waf"
    if has_waf:
        r2 = await session.run(
            "MATCH (n:Node {entity_id:$nid}) RETURN coalesce(n.terraform_resource_type,'') AS rt",
            nid=nid)
        rec = await r2.single()
        rt = rec["rt"] if rec else ""
        lb_types = ("aws_lb","aws_alb","aws_api_gateway","aws_cloudfront")
        return ("declared_restrictive_with_waf" if any(t in rt for t in lb_types)
                else "inherited_only")
    return "declared_restrictive" if has_net else "unknown"


# ── Main entry point ───────────────────────────────────────────────────────────

async def run_linking(org_id: str = ORG_ID) -> dict:
    """
    Run the Universal Linker Engine.
    Executes all RESOLVER_RULES, then E_governs, E_data_flow, and firewall posture.
    Idempotent — safe to run multiple times.
    """
    results = {
        "identifier_links": 0,
        "cross_asset_links": 0,
        "firewall_posture_computed": 0,
        "unresolved_gaps": 0,
    }

    async with tenant_session(org_id) as session:

        # Cleanup null-name/null-domain nodes (tool lookup pollution)
        r = await session.run("""
            MATCH (n) WHERE n.name IS NULL AND n.domain_type IS NULL
            DETACH DELETE n RETURN count(*) AS cnt
        """)
        rec = await r.single()
        if rec and rec["cnt"]:
            logger.info("null_nodes_deleted", count=rec["cnt"])

        # Backfill missing terraform_resource_type / terraform_name from entity_id
        r = await session.run("""
            MATCH (n:Node {domain_type: 'cloud'})
            WHERE n.valid_to IS NULL
            AND (n.terraform_resource_type IS NULL OR n.terraform_name IS NULL)
            RETURN n.entity_id AS eid
        """)
        to_backfill = [rec["eid"] async for rec in r]
        for eid in to_backfill:
            rtype = _type_from_entity_id(eid)
            tname = _name_from_entity_id(eid)
            if rtype and rtype.startswith(("aws_", "google_", "azurerm_")):
                await session.run("""
                    MATCH (n:Node {entity_id: $eid})
                    SET n.terraform_resource_type = coalesce(n.terraform_resource_type, $rt),
                        n.terraform_name = coalesce(n.terraform_name, $tn)
                """, eid=eid, rt=rtype, tn=tname)

        # Run each resolver rule
        for rule in RESOLVER_RULES:
            logger.info("rule_start", rule=rule.name)
            sources = await _load(session, rule.from_query)
            targets = await _load(session, rule.to_candidates_query)

            if not sources:
                logger.debug("rule_skip_no_sources", rule=rule.name)
                continue

            await _resolve(session, rule, sources, targets, results)
            logger.info("rule_done", rule=rule.name,
                        links=results["cross_asset_links"])

        # Governance edges
        await _run_e_governs(session, results)

        # Taint propagation
        await _run_e_data_flow(session, results)

        # Firewall posture
        await _run_firewall_posture(session, results)

    logger.info("linking_complete", **results)
    return results
