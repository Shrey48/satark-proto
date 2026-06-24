# SATARK — VARG+  Layer 1

Ground Truth · Knowledge Graph · Normalised Finding Pool

## Architecture

See `docs/SATARK_Layer1_v7_FINAL.docx` for the complete specification.

Two parallel tracks:
- **Track 1**: Ground truth assets → Master Knowledge Graph (Neo4j, one DB per tenant)
- **Track 2**: Vulnerability claims → Normalised Finding Pool

## Development

```bash
cp .env.example .env        # configure environment
make dev                    # start all infrastructure
make seed-taxonomy          # seed CWE taxonomy (Phase 0)
make seed-gkg               # seed General Knowledge Graph (Phase 0)
make create-tenant TENANT=acme-corp
```

## Phase 0 (Foundation) is the entry point.
## Start with: apps/api/src/core/ then apps/api/src/components/
