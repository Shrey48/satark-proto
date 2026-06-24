"""SATARK Layer 1 — Tenant management routes (P0-03)"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from core.auth import require_admin, CurrentUser
from core.database import provision_tenant_db
from core.models.tenants import Tenant
import structlog

router = APIRouter()
logger = structlog.get_logger(__name__)


class TenantCreate(BaseModel):
    org_id: str
    org_name: str


class TenantResponse(BaseModel):
    org_id: str
    org_name: str
    neo4j_db_name: str
    status: str
    schema_version: int


@router.post("/", response_model=TenantResponse)
async def create_tenant(
    body: TenantCreate,
    admin: CurrentUser = Depends(require_admin),
):
    """Provision a new tenant. Creates the Neo4j tenant database with all required indexes."""
    from core.database.postgres import AsyncSessionFactory
    from models.tenants import Tenant
    from models.entity_id import EntityId
    from core.database.neo4j import tenant_db_name
    import sqlalchemy as sa

    db_name = tenant_db_name(body.org_id)

    async with AsyncSessionFactory() as session:
        existing = await session.execute(
            sa.select(Tenant).where(Tenant.org_id == body.org_id)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail=f"Tenant '{body.org_id}' already exists")

        # Provision the Neo4j database (creates DB + all 7 indexes from spec Section 9.4)
        await provision_tenant_db(body.org_id)

        # Record in PostgreSQL
        tenant = Tenant(
            org_id=body.org_id,
            org_name=body.org_name,
            neo4j_db_name=db_name,
        )
        session.add(tenant)
        await session.commit()

    logger.info("tenant_created", org_id=body.org_id, neo4j_db=db_name)
    return TenantResponse(
        org_id=body.org_id,
        org_name=body.org_name,
        neo4j_db_name=db_name,
        status="active",
        schema_version=1,
    )
