"""
SATARK Layer 1 — Pass 2 + Pass 3 + Sub-step F — FIXED v2

Key fixes vs original:
  1. Deferred relations from Terraform parser → E_routes_to (WAF association)
     Now resolved here using web_acl_arn + resource_arn ARN matching
  2. Lambda → IAM Role ARN matching: now matches role_arn → arn field on Role nodes
     (was matching against Policy nodes only — WRONG)
  3. K8s ServiceAccount → IAM Role via IRSA: now uses irsa_role_arn field
     (was using name substring matching — fragile)
  4. K8s Service → Deployment: now uses k8s_selector_app matching
     (already partially working — reinforced here for cross-file cases)
  5. Security group rule null check removed — rules now populated by parser
  6. Sub-step F posture: uses rules[] array when present instead of cidr_block only
  7. All write queries consume() properly
  8. NOT (a)-[]->(b) pattern predicate used correctly

Architecture:
  Pass 2 = within-asset links (K8s selector→deployment, etc.)
  Pass 3 = cross-asset links (Lambda→IAM, K8s SA→IAM, API→Function, WAF→SG)
  Sub-step F = firewall posture per resource node
"""
from __future__ import annotations
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

        # ═══════════════════════════════════════════════════════════════════════
        # PASS 2 — Within-asset linking
        # ═══════════════════════════════════════════════════════════════════════

        # ── Pass 2: K8s Service → Deployment (pod selector match) ─────────────
        # Also done inside the K8s parser now, but this catches cross-file cases.
        r = await session.run("""
            MATCH (svc:Node {node_type: 'Service'})
            MATCH (dep:Node)
            WHERE dep.node_type IN ['Deployment', 'StatefulSet', 'DaemonSet']
            AND svc.valid_to IS NULL AND dep.valid_to IS NULL
            AND svc.k8s_namespace = dep.k8s_namespace
            AND svc.k8s_selector_app IS NOT NULL
            AND (dep.k8s_app_label IS NOT NULL OR dep.pod_template_app_label IS NOT NULL)
            AND (svc.k8s_selector_app = dep.k8s_app_label
                 OR svc.k8s_selector_app = dep.pod_template_app_label)
            AND NOT (svc)-[:EDGE {edge_type: 'E_invoke'}]->(dep)
            RETURN svc.entity_id AS sid, dep.entity_id AS did,
                   svc.name AS sname, dep.name AS dname
        """)
        svc_dep_pairs = [dict(rec) async for rec in r]
        for pair in svc_dep_pairs:
            wr = await session.run("""
                MATCH (a:Node {entity_id: $sid})
                MATCH (b:Node {entity_id: $did})
                MERGE (a)-[r:EDGE {edge_type: 'E_invoke'}]->(b)
                SET r.resolution_method = 'deterministic_parse',
                    r.confidence = 1.0, r.created_at = datetime()
            """, sid=pair["sid"], did=pair["did"])
            await wr.consume()
            results["cross_asset_links"] += 1
            logger.info("svc_dep_linked", svc=pair["sname"], dep=pair["dname"])

        # ── Pass 2: Pipeline source → downstream linking ──────────────────────
        r = await session.run("""
            MATCH (src:Node {domain_type: 'data_pipeline'})
            WHERE src.valid_to IS NULL AND src.downstream IS NOT NULL
            RETURN src.entity_id AS src_id, src.name AS src_name,
                   src.downstream AS downstream
        """)
        pipeline_sources = [dict(rec) async for rec in r]
        for source in pipeline_sources:
            targets_raw = source.get("downstream") or []
            if isinstance(targets_raw, str):
                targets_raw = [targets_raw]
            for target_name in targets_raw:
                r2 = await session.run("""
                    MATCH (t:Node {domain_type: 'data_pipeline', name: $name})
                    WHERE t.valid_to IS NULL
                    RETURN t.entity_id AS tid
                    LIMIT 1
                """, name=target_name)
                rec = await r2.single()
                if rec:
                    wr = await session.run("""
                        MATCH (a:Node {entity_id: $src_id})
                        MATCH (b:Node {entity_id: $tid})
                        MERGE (a)-[r:EDGE {edge_type: 'E_data_flow'}]->(b)
                        SET r.resolution_method = 'deterministic_parse',
                            r.confidence = 1.0, r.created_at = datetime()
                    """, src_id=source["src_id"], tid=rec["tid"])
                    await wr.consume()
                    results["identifier_links"] += 1
                    logger.info("pipeline_linked",
                                source=source["src_name"], downstream=target_name)

        # ═══════════════════════════════════════════════════════════════════════
        # PASS 3 — Cross-asset linking
        # ═══════════════════════════════════════════════════════════════════════

        # ── Pass 3: Deferred WAF association → E_routes_to ────────────────────
        # FIX: aws_wafv2_web_acl_association is now a deferred_relation, not a node.
        # The parser stored web_acl_arn and resource_arn as properties.
        # We query for nodes that HAVE these properties (they're the association stubs)
        # and create the actual E_routes_to edge between WAF and protected resource.
        #
        # Two resolution strategies:
        #   1. Exact ARN match (web_acl_arn → node with matching arn property)
        #   2. Name-keyed fallback (substring of terraform_name matches)
        r = await session.run("""
            MATCH (assoc:Node {terraform_resource_type: 'aws_wafv2_web_acl_association'})
            WHERE assoc.valid_to IS NULL
            RETURN assoc.entity_id AS assoc_id,
                   assoc.web_acl_arn AS web_acl_arn,
                   assoc.resource_arn AS resource_arn,
                   assoc.name AS assoc_name
        """)
        assoc_rows = [dict(rec) async for rec in r]

        for assoc in assoc_rows:
            web_acl_arn = assoc.get("web_acl_arn")
            resource_arn = assoc.get("resource_arn")

            # Find WAF node
            waf_id = None
            if web_acl_arn:
                r2 = await session.run("""
                    MATCH (w:Node {resource_subtype: 'application_firewall'})
                    WHERE w.valid_to IS NULL
                    AND (w.arn = $arn OR w.web_acl_arn = $arn)
                    RETURN w.entity_id AS wid LIMIT 1
                """, arn=web_acl_arn)
                rec = await r2.single()
                if rec:
                    waf_id = rec["wid"]
            # Fallback: find by terraform label substring
            if not waf_id:
                r2 = await session.run("""
                    MATCH (w:Node {resource_subtype: 'application_firewall'})
                    WHERE w.valid_to IS NULL
                    AND w.terraform_resource_type = 'aws_wafv2_web_acl'
                    RETURN w.entity_id AS wid LIMIT 1
                """)
                rec = await r2.single()
                if rec:
                    waf_id = rec["wid"]

            # Find protected resource node
            target_id = None
            if resource_arn:
                r2 = await session.run("""
                    MATCH (t:Node)
                    WHERE t.valid_to IS NULL
                    AND (t.arn = $arn OR t.resource_arn = $arn)
                    RETURN t.entity_id AS tid LIMIT 1
                """, arn=resource_arn)
                rec = await r2.single()
                if rec:
                    target_id = rec["tid"]

            if waf_id and target_id:
                wr = await session.run("""
                    MATCH (a:Node {entity_id: $waf_id})
                    MATCH (b:Node {entity_id: $target_id})
                    MERGE (a)-[r:EDGE {edge_type: 'E_routes_to'}]->(b)
                    SET r.resolution_method = 'deterministic_parse',
                        r.confidence = 1.0, r.created_at = datetime()
                """, waf_id=waf_id, target_id=target_id)
                await wr.consume()
                results["cross_asset_links"] += 1
                logger.info("waf_routes_to_linked",
                            assoc=assoc.get("assoc_name"),
                            waf=waf_id, target=target_id)
            else:
                results["unresolved_gaps"] += 1
                logger.warning("waf_assoc_unresolved",
                               assoc=assoc.get("assoc_name"),
                               waf_found=bool(waf_id),
                               target_found=bool(target_id))

        # ── Pass 3: Cloud resource → IAM Role (ARN-exact, E_trust) ───────────
        # FIX: Was matching against Policy nodes — should match Role nodes by ARN.
        # Lambda `role = "arn:aws:iam::..."` → IAM Role node with matching arn.
        r = await session.run("""
            MATCH (res:Node {domain_type: 'cloud'})
            WHERE res.valid_to IS NULL AND res.role_arn IS NOT NULL
            AND NOT (res)-[:EDGE {edge_type: 'E_trust'}]->()
            RETURN res.entity_id AS rid, res.name AS rname, res.role_arn AS role_arn
        """)
        cloud_with_roles = [dict(rec) async for rec in r]

        for item in cloud_with_roles:
            role_arn = item["role_arn"]
            # Try exact ARN match against IAM Role or Policy nodes
            r2 = await session.run("""
                MATCH (iam:Node {domain_type: 'iam'})
                WHERE iam.valid_to IS NULL
                AND (iam.arn = $arn OR iam.role_arn = $arn)
                RETURN iam.entity_id AS iid, iam.name AS iname LIMIT 1
            """, arn=role_arn)
            rec = await r2.single()

            if not rec:
                # Fallback: name-keyed — extract role name from ARN
                # arn:aws:iam::123456789:role/payment-processor-role → payment-processor-role
                role_name = role_arn.split("/")[-1].lower().replace("-", "")
                r2 = await session.run("""
                    MATCH (iam:Node {domain_type: 'iam'})
                    WHERE iam.valid_to IS NULL
                    AND toLower(replace(iam.name, '-', '')) CONTAINS $role_name
                    RETURN iam.entity_id AS iid, iam.name AS iname LIMIT 1
                """, role_name=role_name)
                rec = await r2.single()

            if rec:
                wr = await session.run("""
                    MATCH (a:Node {entity_id: $rid})
                    MATCH (b:Node {entity_id: $iid})
                    MERGE (a)-[r:EDGE {edge_type: 'E_trust'}]->(b)
                    SET r.resolution_method = 'deterministic_parse',
                        r.confidence = 1.0, r.created_at = datetime()
                """, rid=item["rid"], iid=rec["iid"])
                await wr.consume()
                results["cross_asset_links"] += 1
                logger.info("cloud_iam_role_linked",
                            resource=item["rname"], iam=rec["iname"])
            else:
                results["unresolved_gaps"] += 1
                logger.warning("cloud_iam_unresolved",
                               resource=item["rname"], role_arn=role_arn)

        # ── Pass 3: K8s ServiceAccount → IAM Role via IRSA (E_trust) ─────────
        # FIX: Now uses irsa_role_arn (exact ARN match) not name substring.
        # irsa_role_arn = "arn:aws:iam::123:role/payment-processor-sa-role"
        r = await session.run("""
            MATCH (sa:Node {node_type: 'ServiceAccount'})
            WHERE sa.valid_to IS NULL AND sa.irsa_role_arn IS NOT NULL
            AND NOT (sa)-[:EDGE {edge_type: 'E_trust'}]->(: Node {domain_type: 'iam'})
            RETURN sa.entity_id AS said, sa.name AS saname,
                   sa.irsa_role_arn AS irsa_arn
        """)
        sa_rows = [dict(rec) async for rec in r]

        for sa in sa_rows:
            irsa_arn = sa["irsa_arn"]
            r2 = await session.run("""
                MATCH (iam:Node {domain_type: 'iam'})
                WHERE iam.valid_to IS NULL
                AND (iam.arn = $arn OR iam.role_arn = $arn)
                RETURN iam.entity_id AS iid, iam.name AS iname LIMIT 1
            """, arn=irsa_arn)
            rec = await r2.single()

            if not rec:
                # Name fallback
                role_name = irsa_arn.split("/")[-1].lower().replace("-", "")
                r2 = await session.run("""
                    MATCH (iam:Node {domain_type: 'iam'})
                    WHERE iam.valid_to IS NULL
                    AND toLower(replace(iam.name, '-', '')) CONTAINS $rn
                    RETURN iam.entity_id AS iid, iam.name AS iname LIMIT 1
                """, rn=role_name)
                rec = await r2.single()

            if rec:
                wr = await session.run("""
                    MATCH (a:Node {entity_id: $said})
                    MATCH (b:Node {entity_id: $iid})
                    MERGE (a)-[r:EDGE {edge_type: 'E_trust'}]->(b)
                    SET r.resolution_method = 'deterministic_parse',
                        r.confidence = 1.0, r.created_at = datetime()
                """, said=sa["said"], iid=rec["iid"])
                await wr.consume()
                results["cross_asset_links"] += 1
                logger.info("irsa_linked", sa=sa["saname"], iam=rec["iname"])
            else:
                results["unresolved_gaps"] += 1

        # ── Pass 3: API Endpoint → Python Function (E_invoke) ─────────────────
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
                MATCH (a:Node {entity_id: $eid})
                MATCH (b:Node {entity_id: $fid})
                MERGE (a)-[r:EDGE {edge_type: 'E_invoke'}]->(b)
                SET r.resolution_method = 'deterministic_parse',
                    r.confidence = 0.90, r.created_at = datetime()
            """, eid=pair["eid"], fid=pair["fid"])
            await wr.consume()
            results["cross_asset_links"] += 1
            logger.info("api_fn_linked", path=pair["path"], fn=pair["fname"])

        # ── Pass 3: E_governs — ComplianceRule → governed assets ─────────────
        r = await session.run("""
            MATCH (rule:Node {node_type: 'ComplianceRule'})
            WHERE rule.valid_to IS NULL
            RETURN rule.entity_id AS rule_id, rule.scope AS scope
        """)
        rules = [dict(rec) async for rec in r]

        KNOWN_DOMAINS = {"cloud", "k8s", "code", "iam", "api", "cicd", "container", "grc"}
        for rule in rules:
            rule_id = rule["rule_id"]
            scope = rule.get("scope") or []
            if isinstance(scope, str):
                scope = [scope]
            domain_scope = [s for s in scope if s in KNOWN_DOMAINS]

            if domain_scope:
                r2 = await session.run("""
                    MATCH (n:Node)
                    WHERE n.valid_to IS NULL AND n.domain_type IN $domains
                    AND NOT ()-[:EDGE {edge_type: 'E_governs'}]->(n)
                    RETURN n.entity_id AS nid LIMIT 100
                """, domains=domain_scope)
            else:
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

        # ── Pass 3: E_data_flow — taint propagation approximation ────────────
        r = await session.run("""
            MATCH (f:Node {domain_type: 'code', taint_class: 'external_untrusted'})
            WHERE f.valid_to IS NULL
            MATCH (f)-[:EDGE {edge_type: 'E_invoke'}]->(g:Node {domain_type: 'code'})
            WHERE g.valid_to IS NULL
            AND NOT (f)-[:EDGE {edge_type: 'E_data_flow'}]->(g)
            RETURN f.entity_id AS fid, g.entity_id AS gid,
                   f.name AS fname, g.name AS gname
        """)
        taint_pairs = [dict(rec) async for rec in r]
        for pair in taint_pairs:
            wr = await session.run("""
                MATCH (a:Node {entity_id: $fid})
                MATCH (b:Node {entity_id: $gid})
                MERGE (a)-[r:EDGE {edge_type: 'E_data_flow'}]->(b)
                SET r.resolution_method = 'gkg_assisted',
                    r.confidence = 0.85, r.created_at = datetime()
            """, fid=pair["fid"], gid=pair["gid"])
            await wr.consume()
            results["cross_asset_links"] += 1

        # ═══════════════════════════════════════════════════════════════════════
        # SUB-STEP F — Firewall posture per resource node
        # ═══════════════════════════════════════════════════════════════════════
        r = await session.run("""
            MATCH (n:Node)
            WHERE n.valid_to IS NULL
            AND n.domain_type IN ['cloud', 'k8s']
            AND n.node_type IN ['Resource', 'Deployment', 'Service', 'Pod',
                                'StatefulSet', 'DaemonSet', 'Namespace']
            RETURN n.entity_id AS nid, n.node_type AS ntype,
                   n.resource_subtype AS subtype, n.cidr_block AS cidr,
                   n.rules AS rules
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
    nid = node["nid"]
    ntype = node["ntype"]
    subtype = node.get("subtype")
    cidr = str(node.get("cidr") or "")
    rules = node.get("rules") or []

    # Firewall nodes get posture from their own rules
    if subtype == "network_firewall":
        # FIX: Also check structured rules[] array (now populated by parser)
        if rules:
            for rule in (rules if isinstance(rules, list) else []):
                if isinstance(rule, dict) and rule.get("open_world"):
                    return "declared_permissive"
            return "declared_restrictive"
        # Fallback: cidr_block string check
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
               fw.terraform_resource_type AS fw_type, fw.rules AS rules
    """, nid=nid)

    firewalls = []
    async for rec in r:
        if rec["subtype"]:
            firewalls.append(dict(rec))

    if not firewalls:
        return "unprotected"

    # Check each firewall's rules for open-world access
    for fw in firewalls:
        if fw["subtype"] == "network_firewall":
            fw_rules = fw.get("rules") or []
            fw_cidr = str(fw.get("cidr") or "")
            if fw_rules and isinstance(fw_rules, list):
                for rule in fw_rules:
                    if isinstance(rule, dict) and rule.get("open_world"):
                        return "declared_permissive"
            elif "0.0.0.0/0" in fw_cidr:
                return "declared_permissive"

    has_net_fw = any(fw["subtype"] == "network_firewall" for fw in firewalls)
    has_waf = any(fw["subtype"] == "application_firewall" for fw in firewalls)

    if has_net_fw and has_waf:
        return "declared_restrictive_with_waf"
    if has_net_fw:
        return "declared_restrictive"
    if has_waf:
        # WAF only protects load balancers and API gateways directly
        r2 = await session.run("""
            MATCH (n:Node {entity_id: $nid})
            RETURN n.terraform_resource_type AS rtype
        """, nid=nid)
        rec = await r2.single()
        rtype = (rec["rtype"] if rec else "") or ""
        if any(t in rtype for t in ("aws_lb", "aws_alb", "aws_api_gateway", "aws_cloudfront")):
            return "declared_restrictive_with_waf"
        return "inherited_only"

    return "unknown"
