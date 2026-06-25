#!/usr/bin/env python3
"""
SATARK Layer 1 Diagnostic Script
Runs verification queries against Neo4j and exports results to JSON.
"""

import json
import os
from datetime import datetime
from neo4j import GraphDatabase

# =========== CONFIGURATION ===========
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "satark123")  # Change this!
OUTPUT_FILE = "diagnostic_results.json"
# =====================================

# Define all diagnostic queries with labels
QUERIES = [
    {
        "label": "1. Domain counts (non-null domain_type)",
        "query": """
            MATCH (n)
            WHERE n.domain_type IS NOT NULL
            RETURN n.domain_type, count(n) AS count
            ORDER BY count DESC
        """
    },
    {
        "label": "2. resource_subtype nodes",
        "query": """
            MATCH (n)
            WHERE n.resource_subtype IS NOT NULL
            RETURN n.name, n.resource_subtype, n.domain_type
            ORDER BY n.resource_subtype
        """
    },
    {
        "label": "3. E_routes_to edges",
        "query": """
            MATCH (a)-[r:E_routes_to]->(b)
            RETURN a.name, b.name, r.resolution_method
        """
    },
    {
        "label": "4. E_trust from IAM Role (domain_type: iam, node_type: Resource, terraform_resource_type: aws_iam_role)",
        "query": """
            MATCH (a:Node {domain_type: "iam"})-[r:E_trust]->(b)
            WHERE a.node_type = "Resource" AND a.terraform_resource_type = "aws_iam_role"
            RETURN a.name, b.name, r.resolution_method
        """
    },
    {
        "label": "5. E_trust from ServiceAccount (IRSA) to IAM Role",
        "query": """
            MATCH (a:ServiceAccount)-[r:E_trust]->(b:Resource)
            WHERE a.irsa_role_arn IS NOT NULL
            RETURN a.name, a.irsa_role_arn, b.name, r.resolution_method
        """
    },
    {
        "label": "6. E_invoke edges from payments_app.py",
        "query": """
            MATCH (a:Function)-[r:E_invoke]->(b:Function)
            WHERE a.file_path = "payments_app.py"
            RETURN a.name, b.name, r.resolution_method
        """
    },
    {
        "label": "7. Duplicate nodes (same name, multiple entity_ids)",
        "query": """
            MATCH (n)
            WITH n.name AS name, collect(n.entity_id) AS eids, count(n) AS cnt
            WHERE cnt > 1
            RETURN name, eids, cnt
            ORDER BY cnt DESC
        """
    },
    {
        "label": "8. Existence of payments_waf_assoc node (should be 0)",
        "query": """
            MATCH (n)
            WHERE n.name = "payments_waf_assoc"
            RETURN n
        """
    },
    {
        "label": "9. Count of nodes with domain_type = null (should be 0 after cleanup)",
        "query": """
            MATCH (n)
            WHERE n.domain_type IS NULL
            RETURN count(n) AS null_domain_count
        """
    }
]

def run_diagnostics():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    results = []
    timestamp = datetime.utcnow().isoformat()

    with driver.session() as session:
        for q in QUERIES:
            print(f"Running: {q['label']} ...")
            try:
                result = session.run(q['query'])
                records = [record.data() for record in result]
                results.append({
                    "label": q['label'],
                    "query": q['query'],
                    "records": records,
                    "count": len(records)
                })
                print(f"  -> {len(records)} records")
            except Exception as e:
                print(f"  ERROR: {str(e)}")
                results.append({
                    "label": q['label'],
                    "query": q['query'],
                    "error": str(e)
                })

    driver.close()

    # Build final output
    output = {
        "timestamp": timestamp,
        "neo4j_uri": NEO4J_URI,
        "results": results
    }

    # Write to JSON
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n✅ Results saved to {OUTPUT_FILE}")
    return output

if __name__ == "__main__":
    print("🔍 SATARK Layer 1 Diagnostic Tool")
    print(f"Connecting to: {NEO4J_URI}")
    print(f"User: {NEO4J_USER}")
    run_diagnostics()