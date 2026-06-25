#!/usr/bin/env python3
"""
SATARK Layer 1 — Diagnostic Validation Script
Run this after ingestion to verify that all fixes are working correctly.

Usage:
    python validate_graph.py

Expected output after fixes:
    [PASS] E_trust edges exist (IAM)
    [PASS] E_routes_to edges exist (WAF)
    [PASS] E_invoke edges exist (Service→Deployment)
    [PASS] Security group rules populated
    [PASS] No WAF association nodes (they should be DeferredRelation or resolved)
    [PASS] IRSA links exist (SA→IAM)
    [PASS] Lambda IAM links exist
    [PASS] Firewall posture computed on cloud nodes
"""
import asyncio
import sys
from core.database.neo4j import tenant_session

ORG_ID = "prototype"
PASS = "✅ PASS"
FAIL = "❌ FAIL"
WARN = "⚠️  WARN"


async def run_checks():
    results = []
    async with tenant_session(ORG_ID) as session:

        # ── 1. E_trust edges (IAM) ─────────────────────────────────────────
        r = await session.run("""
            MATCH ()-[e:EDGE {edge_type: 'E_trust'}]->()
            RETURN count(e) AS cnt
        """)
        rec = await r.single()
        cnt = rec["cnt"] if rec else 0
        status = PASS if cnt > 0 else FAIL
        results.append(f"{status} E_trust edges: {cnt} (IAM permission relationships)")

        # ── 2. E_routes_to edges (WAF → protected resource) ────────────────
        r = await session.run("""
            MATCH ()-[e:EDGE {edge_type: 'E_routes_to'}]->()
            RETURN count(e) AS cnt
        """)
        rec = await r.single()
        cnt = rec["cnt"] if rec else 0
        status = PASS if cnt > 0 else FAIL
        results.append(f"{status} E_routes_to edges: {cnt} (WAF → protected resource)")

        # ── 3. E_invoke edges (Service → Deployment) ───────────────────────
        r = await session.run("""
            MATCH (s:Node {node_type: 'Service'})-[e:EDGE {edge_type: 'E_invoke'}]->(d:Node)
            RETURN count(e) AS cnt
        """)
        rec = await r.single()
        cnt = rec["cnt"] if rec else 0
        status = PASS if cnt > 0 else FAIL
        results.append(f"{status} E_invoke edges (K8s Service→Deployment): {cnt}")

        # ── 4. E_invoke edges (API → Function) ─────────────────────────────
        r = await session.run("""
            MATCH (ep:Node {node_type: 'Endpoint'})-[e:EDGE {edge_type: 'E_invoke'}]->(f:Node {node_type: 'Function'})
            RETURN count(e) AS cnt
        """)
        rec = await r.single()
        cnt = rec["cnt"] if rec else 0
        status = PASS if cnt > 0 else WARN
        results.append(f"{status} E_invoke edges (API Endpoint→Function): {cnt}")

        # ── 5. E_invoke code call graph ────────────────────────────────────
        r = await session.run("""
            MATCH (f:Node {domain_type: 'code', node_type: 'Function'})-[e:EDGE {edge_type: 'E_invoke'}]->()
            RETURN count(e) AS cnt
        """)
        rec = await r.single()
        cnt = rec["cnt"] if rec else 0
        status = PASS if cnt > 0 else WARN
        results.append(f"{status} E_invoke edges (code call graph): {cnt}")

        # ── 6. Security group rules populated ──────────────────────────────
        r = await session.run("""
            MATCH (n:Node {resource_subtype: 'network_firewall'})
            WHERE n.valid_to IS NULL
            RETURN count(n) AS total,
                   sum(CASE WHEN n.rules IS NOT NULL THEN 1 ELSE 0 END) AS with_rules
        """)
        rec = await r.single()
        total = rec["total"] if rec else 0
        with_rules = rec["with_rules"] if rec else 0
        status = PASS if (total > 0 and with_rules == total) else (WARN if with_rules > 0 else FAIL)
        results.append(f"{status} Security group rules: {with_rules}/{total} nodes have rules populated")

        # ── 7. No stale WAF association nodes ──────────────────────────────
        r = await session.run("""
            MATCH (n:Node {terraform_resource_type: 'aws_wafv2_web_acl_association'})
            WHERE n.node_type <> 'DeferredRelation'
            RETURN count(n) AS cnt
        """)
        rec = await r.single()
        cnt = rec["cnt"] if rec else 0
        status = PASS if cnt == 0 else FAIL
        results.append(f"{status} WAF association stale nodes: {cnt} (should be 0 — must be DeferredRelation)")

        # ── 8. IRSA links (K8s SA → IAM Role) ─────────────────────────────
        r = await session.run("""
            MATCH (sa:Node {node_type: 'ServiceAccount'})-[e:EDGE {edge_type: 'E_trust'}]->(iam:Node {domain_type: 'iam'})
            RETURN count(e) AS cnt
        """)
        rec = await r.single()
        cnt = rec["cnt"] if rec else 0
        status = PASS if cnt > 0 else WARN
        results.append(f"{status} IRSA links (ServiceAccount→IAM Role): {cnt}")

        # ── 9. Lambda → IAM Role links ─────────────────────────────────────
        r = await session.run("""
            MATCH (res:Node {domain_type: 'cloud'})-[e:EDGE {edge_type: 'E_trust'}]->(iam:Node {domain_type: 'iam'})
            RETURN count(e) AS cnt
        """)
        rec = await r.single()
        cnt = rec["cnt"] if rec else 0
        status = PASS if cnt > 0 else WARN
        results.append(f"{status} Cloud→IAM E_trust links (Lambda/EC2→Role): {cnt}")

        # ── 10. Firewall posture computed ──────────────────────────────────
        r = await session.run("""
            MATCH (n:Node {domain_type: 'cloud', node_type: 'Resource'})
            WHERE n.valid_to IS NULL
            RETURN count(n) AS total,
                   sum(CASE WHEN n.firewall_posture IS NOT NULL THEN 1 ELSE 0 END) AS with_posture
        """)
        rec = await r.single()
        total = rec["total"] if rec else 0
        with_posture = rec["with_posture"] if rec else 0
        status = PASS if (total > 0 and with_posture == total) else (WARN if with_posture > 0 else FAIL)
        results.append(f"{status} Firewall posture: {with_posture}/{total} cloud nodes computed")

        # ── 11. No generic EDGE type (all edges should have typed edge_type) ─
        r = await session.run("""
            MATCH ()-[e:EDGE]->()
            WHERE e.edge_type IS NULL OR e.edge_type = 'EDGE'
            RETURN count(e) AS cnt
        """)
        rec = await r.single()
        cnt = rec["cnt"] if rec else 0
        status = PASS if cnt == 0 else FAIL
        results.append(f"{status} Generic untyped edges: {cnt} (should be 0)")

        # ── 12. IAM edges are E_trust not generic ──────────────────────────
        r = await session.run("""
            MATCH (a:Node {domain_type: 'iam'})-[e:EDGE]->(b:Node)
            WHERE e.edge_type NOT IN ['E_trust', 'E_contain']
            RETURN count(e) AS cnt
        """)
        rec = await r.single()
        cnt = rec["cnt"] if rec else 0
        status = PASS if cnt == 0 else FAIL
        results.append(f"{status} IAM edges with wrong type: {cnt} (should be 0, all must be E_trust/E_contain)")

        # ── 13. Node count by domain ────────────────────────────────────────
        r = await session.run("""
            MATCH (n:Node)
            WHERE n.valid_to IS NULL AND n.node_type <> 'DeferredRelation'
            RETURN n.domain_type AS domain, count(n) AS cnt
            ORDER BY cnt DESC
        """)
        domain_counts = {rec["domain"]: rec["cnt"] async for rec in r}

        results.append("\n── Node counts by domain ──────────────────────────────")
        for domain, cnt in sorted(domain_counts.items(), key=lambda x: -x[1]):
            results.append(f"   {domain}: {cnt} nodes")

        # ── 14. Edge counts by type ────────────────────────────────────────
        r = await session.run("""
            MATCH ()-[e:EDGE]->()
            RETURN e.edge_type AS etype, count(e) AS cnt
            ORDER BY cnt DESC
        """)
        results.append("\n── Edge counts by type ────────────────────────────────")
        async for rec in r:
            results.append(f"   {rec['etype']}: {rec['cnt']} edges")

    return results


async def main():
    print("\n═══════════════════════════════════════════════════════")
    print("  SATARK Layer 1 — Graph Validation Report")
    print("═══════════════════════════════════════════════════════\n")

    try:
        results = await run_checks()
        for line in results:
            print(line)
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n═══════════════════════════════════════════════════════")
    fails = [r for r in results if "❌" in r]
    if fails:
        print(f"\n{len(fails)} checks FAILED. Fix these before proceeding to Pass 3.\n")
        sys.exit(1)
    else:
        print("\n✅ All critical checks passed. Graph is structurally sound.\n")


if __name__ == "__main__":
    asyncio.run(main())
