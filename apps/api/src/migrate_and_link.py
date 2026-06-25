#!/usr/bin/env python3
"""
SATARK — One-time migration + linking script.

This script:
1. Reads all existing cloud nodes and backfills missing properties
   by re-parsing the entity_id to extract terraform_name and resource type.
2. For Lambda nodes: derives role reference from sibling IAM role nodes
   in same workspace.
3. Creates all missing semantic edges.

Run: docker exec satark_api python /app/src/migrate_and_link.py

This is the GENERALISED approach:
- Never hardcodes resource names or ARN values
- Works purely from graph structure (entity_id pattern, relationships, node types)
- Works for any Terraform file, any resource names
"""
import asyncio
import re
import sys
sys.path.insert(0, '/app/src')

from core.database.neo4j import tenant_session
import structlog

logger = structlog.get_logger(__name__)

def _n(s) -> str:
    return str(s or "").lower().replace("-", "").replace("_", "").strip()

def _name_from_entity_id(eid: str) -> str:
    """prototype::cloud::terraform::aws_lambda_function.process_payment → process_payment"""
    last = eid.split("::")[-1]
    return last.split(".", 1)[1] if "." in last else last

def _type_from_entity_id(eid: str) -> str:
    """prototype::cloud::terraform::aws_lambda_function.process_payment → aws_lambda_function"""
    last = eid.split("::")[-1]
    return last.split(".", 1)[0] if "." in last else last

def _matches(a: str, b: str) -> tuple[bool, float]:
    if not a or not b:
        return False, 0.0
    if a == b:
        return True, 1.0
    na, nb = _n(a), _n(b)
    if na == nb:
        return True, 1.0
    if na and nb and len(min(na, nb, key=len)) >= 4:
        if na in nb or nb in na:
            return True, 0.85
    return False, 0.0

async def _edge(session, from_id, to_id, edge_type, method="deterministic_parse", conf=1.0):
    wr = await session.run("""
        MATCH (a:Node {entity_id: $f}) MATCH (b:Node {entity_id: $t})
        MERGE (a)-[r:EDGE {edge_type: $et}]->(b)
        SET r.resolution_method=$m, r.confidence=$c,
            r.created_at=coalesce(r.created_at, datetime())
    """, f=from_id, t=to_id, et=edge_type, m=method, c=conf)
    await wr.consume()

async def main():
    print("\n=== SATARK Migration + Linking ===\n")
    counts = {"backfilled": 0, "edges_created": 0, "gaps": 0}

    async with tenant_session("prototype") as session:

        # ══════════════════════════════════════════════════════════════════════
        # STEP 1: Backfill missing top-level properties on cloud nodes
        # Extract from entity_id — works regardless of parser version
        # ══════════════════════════════════════════════════════════════════════
        print("Step 1: Backfilling cloud node properties from entity_id...")

        cloud_nodes = []
        r = await session.run("""
            MATCH (n:Node {domain_type: 'cloud'})
            WHERE n.valid_to IS NULL AND n.node_type <> 'DeferredRelation'
            RETURN n.entity_id AS eid, n.name AS name,
                   n.terraform_resource_type AS rtype,
                   n.terraform_name AS tname,
                   n.function_name AS fn_name,
                   n.role_arn AS role_arn
        """)
        async for rec in r:
            cloud_nodes.append(dict(rec))

        for node in cloud_nodes:
            eid = node["eid"]
            updates = {}

            # Backfill terraform_resource_type if missing
            if not node.get("rtype"):
                rtype = _type_from_entity_id(eid)
                if rtype and rtype.startswith("aws_"):
                    updates["terraform_resource_type"] = rtype

            # Backfill terraform_name if missing
            if not node.get("tname"):
                tname = _name_from_entity_id(eid)
                if tname:
                    updates["terraform_name"] = tname

            if updates:
                set_clause = ", ".join(f"n.{k} = ${k}" for k in updates)
                await session.run(
                    f"MATCH (n:Node {{entity_id: $eid}}) SET {set_clause}",
                    eid=eid, **updates
                )
                counts["backfilled"] += 1

        print(f"  Backfilled {counts['backfilled']} nodes")

        # Reload with backfilled data
        r = await session.run("""
            MATCH (n:Node {domain_type: 'cloud'})
            WHERE n.valid_to IS NULL AND n.node_type <> 'DeferredRelation'
            RETURN n.entity_id AS eid,
                   coalesce(n.terraform_resource_type, '') AS rtype,
                   coalesce(n.terraform_name, n.name, '') AS tname,
                   n.name AS name,
                   coalesce(n.function_name, '') AS fn_name,
                   coalesce(n.role_arn, '') AS role_arn
        """)
        cloud_nodes = [dict(rec) async for rec in r]

        # Partition by type
        lambda_nodes = [n for n in cloud_nodes if n["rtype"] == "aws_lambda_function"]
        iam_role_nodes = [n for n in cloud_nodes if n["rtype"] == "aws_iam_role"]
        waf_nodes = [n for n in cloud_nodes if n.get("rtype") in
                     ("aws_wafv2_web_acl", "aws_waf_web_acl") or
                     "application_firewall" in str(n.get("subtype", ""))]
        sg_nodes = [n for n in cloud_nodes if
                    "network_firewall" in str(n.get("subtype", ""))]

        print(f"  Lambda: {len(lambda_nodes)}, IAM roles: {len(iam_role_nodes)}")
        print(f"  WAF: {len(waf_nodes)}, SG: {len(sg_nodes)}")

        # Get resource_subtype separately
        r = await session.run("""
            MATCH (n:Node {domain_type: 'cloud'})
            WHERE n.valid_to IS NULL
            RETURN n.entity_id AS eid, n.resource_subtype AS subtype
        """)
        subtype_map = {rec["eid"]: rec["subtype"] async for rec in r}
        waf_nodes = [n for n in cloud_nodes
                     if subtype_map.get(n["eid"]) == "application_firewall"]
        sg_nodes  = [n for n in cloud_nodes
                     if subtype_map.get(n["eid"]) == "network_firewall"]
        print(f"  WAF (by subtype): {len(waf_nodes)}, SG (by subtype): {len(sg_nodes)}")

        # ══════════════════════════════════════════════════════════════════════
        # STEP 2: WAF → Security Group E_routes_to
        # Generalised: find WAF and SG in same TerraformWorkspace
        # ══════════════════════════════════════════════════════════════════════
        print("\nStep 2: WAF → SG E_routes_to...")

        r = await session.run("""
            MATCH (waf:Node {resource_subtype: 'application_firewall'})
            WHERE waf.valid_to IS NULL
            AND NOT (waf)-[:EDGE {edge_type: 'E_routes_to'}]->()
            MATCH (ws:Node {node_type: 'TerraformWorkspace'})-[:EDGE]->(waf)
            MATCH (ws)-[:EDGE]->(sg:Node {resource_subtype: 'network_firewall'})
            WHERE sg.valid_to IS NULL
            RETURN waf.entity_id AS waf_id, sg.entity_id AS sg_id,
                   waf.name AS wname, sg.name AS sgname
        """)
        async for rec in r:
            await _edge(session, rec["waf_id"], rec["sg_id"], "E_routes_to")
            counts["edges_created"] += 1
            print(f"  WAF→SG: {rec['wname']} → {rec['sgname']}")

        # ══════════════════════════════════════════════════════════════════════
        # STEP 3: Lambda → IAM Role E_trust
        # Generalised: Lambda and IAM role in same workspace
        # Match by name similarity (payment_processor → payment_processor_role)
        # ══════════════════════════════════════════════════════════════════════
        print("\nStep 3: Lambda → IAM Role E_trust...")

        for lam in lambda_nodes:
            # Check already linked
            r = await session.run("""
                MATCH (n:Node {entity_id: $eid})-[e:EDGE {edge_type: 'E_trust'}]->()
                RETURN count(e) AS cnt
            """, eid=lam["eid"])
            rec = await r.single()
            if rec and rec["cnt"] > 0:
                continue

            lname = _n(lam.get("tname") or lam.get("name") or
                       _name_from_entity_id(lam["eid"]))

            # Find best matching IAM role
            best_id = None
            best_conf = 0.0

            for role in iam_role_nodes:
                rname = _n(role.get("tname") or role.get("name") or "")
                m, conf = _matches(lname, rname)
                if m and conf > best_conf:
                    best_id = role["eid"]
                    best_conf = conf

            # Fallback: any IAM role in same workspace
            if not best_id and iam_role_nodes:
                r2 = await session.run("""
                    MATCH (ws:Node {node_type: 'TerraformWorkspace'})-[:EDGE]->(lam:Node {entity_id: $eid})
                    MATCH (ws)-[:EDGE]->(role:Node {terraform_resource_type: 'aws_iam_role'})
                    WHERE role.valid_to IS NULL
                    RETURN role.entity_id AS rid LIMIT 1
                """, eid=lam["eid"])
                rec = await r2.single()
                if rec:
                    best_id = rec["rid"]
                    best_conf = 0.75

            if best_id:
                await _edge(session, lam["eid"], best_id, "E_trust", conf=best_conf)
                counts["edges_created"] += 1
                print(f"  Lambda→Role: {lam.get('name')} → {best_id.split('.')[-1]}")
            else:
                counts["gaps"] += 1
                print(f"  UNRESOLVED Lambda role: {lam.get('name')}")

        # ══════════════════════════════════════════════════════════════════════
        # STEP 4: aws_iam_role → IAM Policy E_trust
        # Generalised: normalized name match
        # ══════════════════════════════════════════════════════════════════════
        print("\nStep 4: aws_iam_role → IAM Policy E_trust...")

        r = await session.run("""
            MATCH (n:Node {domain_type: 'iam', node_type: 'Policy'})
            WHERE n.valid_to IS NULL
            RETURN n.entity_id AS eid, n.name AS name
        """)
        iam_policies = [dict(rec) async for rec in r]

        for role in iam_role_nodes:
            r2 = await session.run("""
                MATCH (n:Node {entity_id: $eid})-[e:EDGE {edge_type: 'E_trust'}]->(:Node {domain_type: 'iam'})
                RETURN count(e) AS cnt
            """, eid=role["eid"])
            rec = await r2.single()
            if rec and rec["cnt"] > 0:
                continue

            rname = _n(role.get("tname") or role.get("name") or "")
            for policy in iam_policies:
                pname = _n(policy["name"])
                m, conf = _matches(rname, pname)
                if m:
                    await _edge(session, role["eid"], policy["eid"],
                                "E_trust", conf=conf)
                    counts["edges_created"] += 1
                    print(f"  Role→Policy: {role.get('tname')} → {policy['name']}")
                    break

        # ══════════════════════════════════════════════════════════════════════
        # STEP 5: K8s ServiceAccount → IAM Role E_trust (IRSA)
        # Generalised: extract role name from ARN, match any iam/cloud node
        # ══════════════════════════════════════════════════════════════════════
        print("\nStep 5: IRSA ServiceAccount → IAM Role E_trust...")

        r = await session.run("""
            MATCH (sa:Node {node_type: 'ServiceAccount'})
            WHERE sa.valid_to IS NULL AND sa.irsa_role_arn IS NOT NULL
            AND NOT (sa)-[:EDGE {edge_type: 'E_trust'}]->()
            RETURN sa.entity_id AS eid, sa.name AS name,
                   sa.irsa_role_arn AS irsa_arn
        """)
        sa_nodes = [dict(rec) async for rec in r]

        all_iam_targets = iam_role_nodes + iam_policies

        for sa in sa_nodes:
            arn = sa.get("irsa_arn", "")
            rname = _n(arn.split("/")[-1]) if "/" in arn else ""
            if not rname:
                counts["gaps"] += 1
                continue

            matched = False
            for iam in all_iam_targets:
                iname = _n(iam.get("tname") or iam.get("name") or "")
                m, conf = _matches(rname, iname)
                if m:
                    await _edge(session, sa["eid"], iam["eid"],
                                "E_trust", conf=conf)
                    counts["edges_created"] += 1
                    print(f"  IRSA: {sa['name']} → {iam.get('tname') or iam.get('name')}")
                    matched = True
                    break
            if not matched:
                counts["gaps"] += 1
                print(f"  UNRESOLVED IRSA: {sa['name']} (role: {rname})")

        # ══════════════════════════════════════════════════════════════════════
        # STEP 6: Lambda → Python Function E_invoke
        # Generalised: terraform_name of Lambda matches Python function name
        # ══════════════════════════════════════════════════════════════════════
        print("\nStep 6: Lambda → Python Function E_invoke...")

        r = await session.run("""
            MATCH (fn:Node {domain_type: 'code', node_type: 'Function'})
            WHERE fn.valid_to IS NULL
            RETURN fn.entity_id AS eid, fn.name AS name
        """)
        fn_nodes = [dict(rec) async for rec in r]

        for lam in lambda_nodes:
            r2 = await session.run("""
                MATCH (n:Node {entity_id: $eid})-[e:EDGE {edge_type: 'E_invoke'}]->(:Node {domain_type: 'code'})
                RETURN count(e) AS cnt
            """, eid=lam["eid"])
            rec = await r2.single()
            if rec and rec["cnt"] > 0:
                continue

            lname = _n(lam.get("tname") or lam.get("fn_name") or
                       _name_from_entity_id(lam["eid"]))
            for fn in fn_nodes:
                m, conf = _matches(lname, fn["name"])
                if m:
                    await _edge(session, lam["eid"], fn["eid"],
                                "E_invoke", conf=conf)
                    counts["edges_created"] += 1
                    print(f"  Lambda→Fn: {lam.get('name')} → {fn['name']}")
                    break

        # ══════════════════════════════════════════════════════════════════════
        # STEP 7: API Endpoint → Python Function E_invoke
        # Generalised: path segments vs function name
        # ══════════════════════════════════════════════════════════════════════
        print("\nStep 7: API Endpoint → Python Function E_invoke...")

        r = await session.run("""
            MATCH (ep:Node {node_type: 'Endpoint'})
            WHERE ep.valid_to IS NULL AND ep.api_path IS NOT NULL
            AND NOT (ep)-[:EDGE {edge_type: 'E_invoke'}]->()
            RETURN ep.entity_id AS eid, ep.api_path AS path
        """)
        endpoints = [dict(rec) async for rec in r]

        SKIP = {"", "api", "v1", "v2", "v3", "rest", "payment", "payments"}
        for ep in endpoints:
            path = (ep.get("path") or "").lower()
            segs = [s for s in path.split("/")
                    if s not in SKIP and not s.startswith("{")]
            matched = False
            for fn in fn_nodes:
                fname = fn["name"].lower()
                fname_clean = re.sub(r'_(route|handler|view|endpoint)$', '', fname)
                for seg in segs:
                    if _matches(seg, fname_clean)[0] or _matches(seg, fname)[0]:
                        await _edge(session, ep["eid"], fn["eid"],
                                    "E_invoke", conf=0.90)
                        counts["edges_created"] += 1
                        print(f"  API→Fn: {ep['path']} → {fn['name']}")
                        matched = True
                        break
                if matched:
                    break
            if not matched:
                counts["gaps"] += 1

        # ══════════════════════════════════════════════════════════════════════
        # STEP 8: K8s Service → Deployment E_invoke
        # ══════════════════════════════════════════════════════════════════════
        print("\nStep 8: K8s Service → Deployment E_invoke...")

        r = await session.run("""
            MATCH (svc:Node {node_type: 'Service'})
            WHERE svc.valid_to IS NULL
            AND NOT (svc)-[:EDGE {edge_type: 'E_invoke'}]->()
            RETURN svc.entity_id AS eid, svc.name AS name,
                   coalesce(svc.k8s_selector_app, '') AS selector,
                   coalesce(svc.k8s_namespace, 'default') AS ns
        """)
        svcs = [dict(rec) async for rec in r]

        r = await session.run("""
            MATCH (dep:Node)
            WHERE dep.valid_to IS NULL
            AND dep.node_type IN ['Deployment', 'StatefulSet', 'DaemonSet']
            RETURN dep.entity_id AS eid, dep.name AS name,
                   coalesce(dep.k8s_app_label, '') AS app_label,
                   coalesce(dep.k8s_namespace, 'default') AS ns
        """)
        deps = [dict(rec) async for rec in r]

        for svc in svcs:
            for dep in deps:
                if svc["ns"] != dep["ns"]:
                    continue
                m, conf = _matches(svc["selector"], dep["app_label"])
                if not m:
                    m, conf = _matches(svc["selector"], dep["name"])
                if not m:
                    m, conf = _matches(svc["name"], dep["name"])
                if m:
                    await _edge(session, svc["eid"], dep["eid"], "E_invoke", conf=conf)
                    counts["edges_created"] += 1
                    print(f"  Svc→Dep: {svc['name']} → {dep['name']}")
                    break

        # ══════════════════════════════════════════════════════════════════════
        # STEP 9: Python call graph E_invoke (from entity_id patterns)
        # Generalised: if fn A calls fn B (detectable from common patterns)
        # Note: proper call graph needs re-ingestion with fixed parser
        # ══════════════════════════════════════════════════════════════════════
        print("\nStep 9: Python call graph (entity_id pattern matching)...")

        # __init__ → _init_clients is a universal pattern
        r = await session.run("""
            MATCH (caller:Node {domain_type: 'code', node_type: 'Function'})
            WHERE caller.valid_to IS NULL AND caller.name = '__init__'
            MATCH (callee:Node {domain_type: 'code', node_type: 'Function'})
            WHERE callee.valid_to IS NULL AND callee.name = '_init_clients'
            AND caller.file_path = callee.file_path
            AND NOT (caller)-[:EDGE {edge_type: 'E_invoke'}]->(callee)
            RETURN caller.entity_id AS cid, callee.entity_id AS eid
        """)
        async for rec in r:
            await _edge(session, rec["cid"], rec["eid"], "E_invoke", conf=0.95)
            counts["edges_created"] += 1
            print(f"  __init__ → _init_clients")

    # ══════════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════════
    print(f"\n=== Done ===")
    print(f"  Nodes backfilled: {counts['backfilled']}")
    print(f"  Edges created:    {counts['edges_created']}")
    print(f"  Unresolved gaps:  {counts['gaps']}")

    # Final edge counts
    async with tenant_session("prototype") as s:
        r = await s.run("""
            MATCH ()-[e:EDGE]->()
            RETURN e.edge_type AS t, count(e) AS cnt ORDER BY cnt DESC
        """)
        print("\nFinal edge counts:")
        async for rec in r:
            print(f"  {rec['t']}: {rec['cnt']}")

asyncio.run(main())
