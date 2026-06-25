#!/usr/bin/env python3
"""
SATARK — Node Property Inspector
Run this FIRST to understand what's actually in Neo4j before the linker runs.

Usage:
  docker exec satark_api python /app/src/inspect_nodes.py

This tells you EXACTLY why edges aren't being created.
"""
import asyncio
import sys
sys.path.insert(0, '/app/src')

from core.database.neo4j import tenant_session

async def main():
    async with tenant_session("prototype") as s:

        print("\n=== CLOUD NODES (first 5, all props) ===")
        r = await s.run("""
            MATCH (n:Node {domain_type: 'cloud'})
            WHERE n.valid_to IS NULL AND n.node_type <> 'DeferredRelation'
            RETURN n LIMIT 5
        """)
        async for rec in r:
            n = dict(rec["n"])
            # Show only the keys relevant to linking
            keys = ['entity_id','name','node_type','terraform_resource_type',
                    'terraform_name','role_arn','role_tf_name','role_entity_id',
                    'function_name','resource_subtype']
            print({k: n.get(k) for k in keys if n.get(k)})

        print("\n=== IAM NODES (first 5, all props) ===")
        r = await s.run("""
            MATCH (n:Node {domain_type: 'iam'})
            WHERE n.valid_to IS NULL
            RETURN n LIMIT 5
        """)
        async for rec in r:
            n = dict(rec["n"])
            keys = ['entity_id','name','node_type','arn']
            print({k: n.get(k) for k in keys if n.get(k)})

        print("\n=== K8S SERVICEACCOUNT NODES ===")
        r = await s.run("""
            MATCH (n:Node {node_type: 'ServiceAccount'})
            WHERE n.valid_to IS NULL
            RETURN n
        """)
        async for rec in r:
            n = dict(rec["n"])
            keys = ['entity_id','name','irsa_role_arn','k8s_namespace']
            print({k: n.get(k) for k in keys if n.get(k)})

        print("\n=== DEFERRED RELATION NODES ===")
        r = await s.run("""
            MATCH (n:Node {node_type: 'DeferredRelation'})
            WHERE n.valid_to IS NULL
            RETURN n
        """)
        async for rec in r:
            n = dict(rec["n"])
            print(dict(n))

        print("\n=== AWS_IAM_ROLE NODES (cloud domain) ===")
        r = await s.run("""
            MATCH (n:Node {domain_type: 'cloud'})
            WHERE n.valid_to IS NULL
            AND (n.terraform_resource_type = 'aws_iam_role' OR n.name CONTAINS 'role')
            RETURN n LIMIT 5
        """)
        async for rec in r:
            n = dict(rec["n"])
            print({k: n.get(k) for k in n if n.get(k)})

        print("\n=== LAMBDA NODES ===")
        r = await s.run("""
            MATCH (n:Node {domain_type: 'cloud'})
            WHERE n.valid_to IS NULL
            AND (n.terraform_resource_type = 'aws_lambda_function'
                 OR n.name CONTAINS 'lambda' OR n.name CONTAINS 'payment')
            RETURN n LIMIT 5
        """)
        async for rec in r:
            n = dict(rec["n"])
            keys = ['entity_id','name','terraform_resource_type','terraform_name',
                    'role_arn','role_tf_name','function_name']
            print({k: n.get(k) for k in keys if n.get(k)})

        print("\n=== PYTHON FUNCTION NODES ===")
        r = await s.run("""
            MATCH (n:Node {domain_type: 'code', node_type: 'Function'})
            WHERE n.valid_to IS NULL
            RETURN n.entity_id AS eid, n.name AS name,
                   n.is_entry_point AS ep, n.taint_class AS tc
            LIMIT 10
        """)
        async for rec in r:
            print(dict(rec))

        print("\n=== ALL EDGE TYPES CURRENTLY IN GRAPH ===")
        r = await s.run("""
            MATCH ()-[e:EDGE]->()
            RETURN e.edge_type AS etype, count(*) AS cnt
            ORDER BY cnt DESC
        """)
        async for rec in r:
            print(f"  {rec['etype']}: {rec['cnt']}")

        print("\n=== SAMPLE: what props does a cloud node have? ===")
        r = await s.run("""
            MATCH (n:Node {domain_type: 'cloud'})
            WHERE n.valid_to IS NULL AND n.node_type = 'Resource'
            RETURN keys(n) AS props LIMIT 1
        """)
        rec = await r.single()
        if rec:
            print("Cloud Resource props:", sorted(rec["props"]))

asyncio.run(main())
