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

        # ── Pass 3: Cloud resource → IAM execution role (ARN-exact) ───────────
        # Lambda/EC2/ECS with role_arn → IAM Policy node
        r = await session.run("""
            MATCH (res:Node {domain_type: 'cloud'})
            WHERE res.valid_to IS NULL AND res.role_arn IS NOT NULL
            MATCH (policy:Node {node_type: 'Policy'})
            WHERE policy.valid_to IS NULL
            AND NOT (res)-[:EDGE {edge_type: 'E_trust'}]->(policy)
            RETURN res.entity_id AS rid, policy.entity_id AS pid,
                   res.name AS rname, policy.name AS pname,
                   res.role_arn AS role_arn
        """)
        role_pairs = [dict(rec) async for rec in r]
        for pair in role_pairs:
            role_arn = (pair.get("role_arn") or "").lower().replace("-","")
            pname    = (pair.get("pname")    or "").lower().replace("-policy","").replace("-","")
            if pname and role_arn and pname in role_arn:
                wr = await session.run("""
                    MATCH (a:Node {entity_id: $rid})
                    MATCH (b:Node {entity_id: $pid})
                    MERGE (a)-[r:EDGE {edge_type: 'E_trust'}]->(b)
                    SET r.resolution_method = 'deterministic_parse',
                        r.confidence = 0.90, r.created_at = datetime()
                """, rid=pair["rid"], pid=pair["pid"])
                await wr.consume()
                results["cross_asset_links"] += 1
                logger.info("lambda_iam_linked", resource=pair["rname"], policy=pair["pname"])

        # ── Pass 3: E_governs — ComplianceRule → governed assets ─────────────
        # Spec Section 4.6 4-step decision tree
        r = await session.run("""
            MATCH (rule:Node {node_type: 'ComplianceRule'})
            WHERE rule.valid_to IS NULL
            RETURN rule.entity_id AS rule_id, rule.scope AS scope
        """)
        rules = [dict(rec) async for rec in r]

        for rule in rules:
            rule_id = rule["rule_id"]
            scope   = rule.get("scope") or []
            if isinstance(scope, str):
                scope = [scope]

            KNOWN_DOMAINS = {"cloud","k8s","code","iam","api","cicd","container","grc"}
            domain_scope  = [s for s in scope if s in KNOWN_DOMAINS]

            if domain_scope:
                # Step 3: domain_type filter
                r2 = await session.run("""
                    MATCH (n:Node)
                    WHERE n.valid_to IS NULL AND n.domain_type IN $domains
                    AND NOT ()-[:EDGE {edge_type: 'E_governs'}]->(n)
                    RETURN n.entity_id AS nid LIMIT 100
                """, domains=domain_scope)
            else:
                # Step 4: no scope → all assets (safe over-approximation)
                r2 = await session.run("""
                    MATCH (n:Node)
                    WHERE n.valid_to IS NULL
                    AND n.domain_type IN ['cloud','k8s','code','iam','api','cicd','container']
                    AND NOT ()-[:EDGE {edge_type: 'E_governs'}]->(n)
                    RETURN n.entity_id AS nid LIMIT 100
                """)

            targets = [rec["nid"] async for rec in r2]
            for target_id in targets:
                wr = await session.run("""
                    MATCH (rule:Node {entity_id: $rule_id})
                    MATCH (n:Node {entity_id: $nid})
                    MERGE (rule)-[r:EDGE {edge_type: 'E_governs'}]->(n)
                    SET r.resolution_method = 'deterministic_parse',
                        r.confidence = 1.0, r.created_at = datetime()
                """, rule_id=rule_id, nid=target_id)
                await wr.consume()
                results["cross_asset_links"] += 1

                # ── Pass 2: K8s Service → Deployment (pod selector match) ─────────────
        r = await session.run("""
            MATCH (svc:Node {node_type: 'Service'})
            MATCH (dep:Node {node_type: 'Deployment'})
            WHERE svc.valid_to IS NULL AND dep.valid_to IS NULL
            AND svc.k8s_namespace = dep.k8s_namespace
            AND svc.k8s_selector_app IS NOT NULL
            AND dep.k8s_app_label IS NOT NULL
            AND svc.k8s_selector_app = dep.k8s_app_label
            AND NOT (svc)-[:EDGE {edge_type: 'E_invoke'}]->(dep)
            RETURN svc.entity_id AS sid, dep.entity_id AS did,
                   svc.name AS sname, dep.name AS dname
        """)
        svc_dep_pairs = [dict(rec) async for rec in r]
        for pair in svc_dep_pairs:
            wr = await session.run("""
                MATCH (a:Node {entity_id: $from_id})
                MATCH (b:Node {entity_id: $to_id})
                MERGE (a)-[r:EDGE {edge_type: 'E_invoke'}]->(b)
                SET r.resolution_method = 'deterministic_parse',
                    r.confidence = 1.0, r.created_at = datetime()
            """, from_id=pair["sid"], to_id=pair["did"])
            await wr.consume()
            results["cross_asset_links"] += 1
            logger.info("svc_dep_linked", svc=pair["sname"], dep=pair["dname"])

        # ── Pass 3: E_routes_to — WAF association → protected resource ─────────
        r = await session.run("""
            MATCH (assoc:Node {terraform_resource_type: 'aws_wafv2_web_acl_association'})
            WHERE assoc.valid_to IS NULL AND assoc.resource_arn IS NOT NULL
            MATCH (waf:Node {resource_subtype: 'application_firewall'})
            WHERE waf.valid_to IS NULL AND waf.terraform_resource_type = 'aws_wafv2_web_acl'
            MATCH (target:Node)
            WHERE target.valid_to IS NULL AND target.arn = assoc.resource_arn
            RETURN waf.entity_id AS waf_id, target.entity_id AS target_id,
                   waf.name AS wname, target.name AS tname
        """)
        routes_pairs = [dict(rec) async for rec in r]
        for pair in routes_pairs:
            wr = await session.run("""
                MATCH (a:Node {entity_id: $waf_id})
                MATCH (b:Node {entity_id: $target_id})
                MERGE (a)-[r:EDGE {edge_type: 'E_routes_to'}]->(b)
                SET r.resolution_method = 'deterministic_parse',
                    r.confidence = 1.0, r.created_at = datetime()
            """, waf_id=pair["waf_id"], target_id=pair["target_id"])
            await wr.consume()
            results["cross_asset_links"] += 1
            logger.info("waf_routes_to_linked", waf=pair["wname"], target=pair["tname"])

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

    # WAF only protects load balancers and API gateways directly.
    # Lambda functions and S3 buckets are NOT protected by WAF via association.
    # Check the resource type to prevent over-inheritance.
    WAF_PROTECTED_TYPES = {
        "aws_lb", "aws_alb", "aws_cloudfront_distribution",
        "aws_api_gateway_rest_api", "aws_api_gateway_v2_api",
        "azurerm_application_gateway", "google_compute_backend_service",
    }
    resource_type_r = await session.run(
        "MATCH (n:Node {entity_id: $nid}) RETURN n.terraform_resource_type AS rt",
        nid=nid
    )
    rt_rec = await resource_type_r.single()
    resource_type = rt_rec["rt"] if rt_rec else None
    is_waf_protected_type = resource_type in WAF_PROTECTED_TYPES

    if has_net_fw and has_waf and is_waf_protected_type:
        return "declared_restrictive_with_waf"
    if has_net_fw:
        return "declared_restrictive"
    if has_waf and is_waf_protected_type:
        return "declared_restrictive_with_waf"
    return "unknown"
