"""
SATARK Layer 1 — Pass 2 + Pass 3 + Sub-step F

Fixes:
  - consume() on all write queries
  - Pattern predicate NOT (a)-[]->(b) instead of NOT EXISTS {}
  - cidr_block check uses 'in' substring (handles ["0.0.0.0/0"] format)
  - has_waf_association: checks terraform_resource_type CONTAINS 'association'
"""
from core.database.neo4j import tenant_session
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"


async def run_linking(org_id: str = ORG_ID) -> dict:
    results = {
        "identifier_links": 0,
        "cross_asset_links": 0,
        "firewall_posture_computed": 0,
        "unresolved_gaps": 0,
    }

    async with tenant_session(org_id) as session:

        # ── Pass 3: K8s ServiceAccount → IAM Policy ───────────────────────────
        r = await session.run("""
            MATCH (sa:Node {node_type: 'ServiceAccount'})
            MATCH (p:Node {node_type: 'Policy'})
            WHERE sa.valid_to IS NULL AND p.valid_to IS NULL
            AND NOT (sa)-[:EDGE {edge_type: 'E_trust'}]->(p)
            RETURN sa.entity_id AS said, p.entity_id AS pid,
                   sa.name AS saname, p.name AS pname,
                   sa.irsa_role_arn AS irsa_arn
        """)
        sa_pairs = [dict(rec) async for rec in r]

        for pair in sa_pairs:
            saname   = (pair.get("saname")   or "").lower()
            pname    = (pair.get("pname")    or "").lower()
            irsa_arn = (pair.get("irsa_arn") or "").lower()

            sa_base    = saname.removesuffix("-sa").removesuffix("-serviceaccount")
            name_match = bool(sa_base) and len(sa_base) > 2 and sa_base in pname
            irsa_match = bool(irsa_arn) and bool(pname) and \
                         pname.replace("-", "") in irsa_arn.replace("-", "")

            if not (name_match or irsa_match):
                results["unresolved_gaps"] += 1
                continue

            confidence = 1.0 if irsa_match else 0.85
            method     = "deterministic_parse" if irsa_match else "fuzzy_matched"
            wr = await session.run("""
                MATCH (a:Node {entity_id: $from_id})
                MATCH (b:Node {entity_id: $to_id})
                MERGE (a)-[r:EDGE {edge_type: 'E_trust'}]->(b)
                SET r.resolution_method = $method,
                    r.confidence = $confidence,
                    r.created_at = datetime()
            """, from_id=pair["said"], to_id=pair["pid"],
                 method=method, confidence=confidence)
            await wr.consume()
            results["cross_asset_links"] += 1
            logger.info("sa_policy_linked", sa=saname, policy=pname)

        # ── Pass 3: API Endpoint → Python Function ─────────────────────────────
        r = await session.run("""
            MATCH (ep:Node {node_type: 'Endpoint'})
            MATCH (f:Node {node_type: 'Function', is_entry_point: true})
            WHERE ep.valid_to IS NULL AND f.valid_to IS NULL
            AND ep.api_path IS NOT NULL
            AND NOT (ep)-[:EDGE {edge_type: 'E_invoke'}]->(f)
            RETURN ep.entity_id AS eid, f.entity_id AS fid,
                   ep.api_path AS path, f.name AS fname
        """)
        ep_pairs = [dict(rec) async for rec in r]

        SKIP = {"", "api", "v1", "v2", "v3", "rest"}
        for pair in ep_pairs:
            path  = (pair.get("path")  or "").lower()
            fname = (pair.get("fname") or "").lower()
            segs  = [s for s in path.split("/")
                     if s not in SKIP and not s.startswith("{")]

            if fname not in segs:
                results["unresolved_gaps"] += 1
                continue

            wr = await session.run("""
                MATCH (a:Node {entity_id: $from_id})
                MATCH (b:Node {entity_id: $to_id})
                MERGE (a)-[r:EDGE {edge_type: 'E_invoke'}]->(b)
                SET r.resolution_method = 'deterministic_parse',
                    r.confidence = 0.90,
                    r.created_at = datetime()
            """, from_id=pair["eid"], to_id=pair["fid"])
            await wr.consume()
            results["cross_asset_links"] += 1
            logger.info("api_fn_linked", path=pair["path"], fn=pair["fname"])

        # ── Sub-step F: Per-node firewall posture ─────────────────────────────
        r = await session.run("""
            MATCH (n:Node)
            WHERE n.valid_to IS NULL
            AND n.domain_type IN ['cloud', 'k8s']
            AND n.node_type IN ['Resource', 'Deployment', 'Service', 'Pod',
                                'StatefulSet', 'DaemonSet', 'Namespace']
            RETURN n.entity_id AS nid, n.node_type AS ntype,
                   n.resource_subtype AS subtype, n.cidr_block AS cidr
        """)
        resource_nodes = [dict(rec) async for rec in r]

        for node in resource_nodes:
            posture = await _posture_for_node(session, node)
            wr = await session.run("""
                MATCH (n:Node {entity_id: $nid})
                SET n.firewall_posture = $posture
            """, nid=node["nid"], posture=posture)
            await wr.consume()
            results["firewall_posture_computed"] += 1

    logger.info("linking_complete", **results)
    return results


async def _posture_for_node(session, node: dict) -> str:
    nid     = node["nid"]
    ntype   = node["ntype"]
    subtype = node.get("subtype")
    cidr    = str(node.get("cidr") or "")

    # Firewall nodes get posture based on their own rules
    if subtype == "network_firewall":
        # Use substring check — cidr may be stored as '["0.0.0.0/0"]'
        return "declared_permissive" if "0.0.0.0/0" in cidr else "declared_restrictive"

    if subtype == "application_firewall":
        return "declared_restrictive_with_waf"

    if subtype == "workload_firewall":
        return "declared_restrictive"

    # K8s workloads: check NetworkPolicy in same namespace
    if ntype in ("Deployment", "Service", "Pod", "StatefulSet", "DaemonSet"):
        r = await session.run("""
            MATCH (ns:Node {node_type: 'Namespace'})-[:EDGE]->(n:Node {entity_id: $nid})
            WITH ns
            OPTIONAL MATCH (ns)-[:EDGE]->(fw:Node {resource_subtype: 'workload_firewall'})
            RETURN count(fw) AS fw_count
        """, nid=nid)
        rec = await r.single()
        return "declared_restrictive" if (rec and rec["fw_count"] > 0) else "unprotected"

    if ntype == "Namespace":
        r = await session.run("""
            MATCH (ns:Node {entity_id: $nid})
            OPTIONAL MATCH (ns)-[:EDGE]->(fw:Node {resource_subtype: 'workload_firewall'})
            RETURN count(fw) AS fw_count
        """, nid=nid)
        rec = await r.single()
        return "declared_restrictive" if (rec and rec["fw_count"] > 0) else "unprotected"

    # Cloud resources: find parent workspace, check firewalls
    r = await session.run("""
        MATCH (ws:Node)-[:EDGE {edge_type: 'E_contain'}]->(n:Node {entity_id: $nid})
        WITH ws
        OPTIONAL MATCH (ws)-[:EDGE {edge_type: 'E_contain'}]->(fw:Node)
        WHERE fw.resource_subtype IN ['network_firewall', 'application_firewall']
        RETURN fw.resource_subtype AS subtype, fw.cidr_block AS cidr,
               fw.terraform_resource_type AS fw_type
    """, nid=nid)

    firewalls = []
    async for rec in r:
        if rec["subtype"]:
            firewalls.append(dict(rec))

    if not firewalls:
        return "unprotected"

    # Network firewall with permissive rules → all resources in workspace are permissive
    for fw in firewalls:
        if fw["subtype"] == "network_firewall" and "0.0.0.0/0" in str(fw.get("cidr") or ""):
            return "declared_permissive"

    has_net_fw = any(fw["subtype"] == "network_firewall"     for fw in firewalls)
    has_waf    = any(fw["subtype"] == "application_firewall" for fw in firewalls)

    # Only add _with_waf if there is an explicit WAF association resource
    # (aws_wafv2_web_acl_association) in the same workspace
    has_waf_assoc = False
    if has_waf:
        ar = await session.run("""
            MATCH (ws:Node)-[:EDGE]->(n:Node {entity_id: $nid})
            WITH ws
            MATCH (ws)-[:EDGE]->(assoc:Node)
            WHERE assoc.terraform_resource_type IS NOT NULL
            AND assoc.terraform_resource_type CONTAINS 'association'
            RETURN count(assoc) AS cnt
        """, nid=nid)
        ar_rec = await ar.single()
        has_waf_assoc = bool(ar_rec and ar_rec["cnt"] > 0)

    if has_net_fw and has_waf and has_waf_assoc:
        return "declared_restrictive_with_waf"
    if has_net_fw:
        return "declared_restrictive"
    if has_waf:
        return "declared_restrictive_with_waf"
    return "unknown"
