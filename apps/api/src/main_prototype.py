"""
SATARK Layer 1 — Prototype Entry Point
"""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import get_settings
from core.database.neo4j import get_driver, close_driver, setup_prototype_schema
from core.database.postgres import engine, create_tables
from core.database.redis_client import get_redis, close_redis
from core.components.tool_lookup import seed_tool_registry
from core.gkg.loader import load_gkg_fixtures

from api.v1.ingestion_routes import router as ingestion_router
from api.v1.graph_routes import router as graph_router
from api.v1.findings_routes import router as findings_router
from api.v1.review_routes import router as review_router
from api.v1.health_routes import router as health_router

logger = structlog.get_logger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("satark_prototype_starting", llm=settings.llm_provider, model=settings.active_llm_model)
    await get_driver()
    await get_redis()
    await create_tables()
    await seed_tool_registry()
    await load_gkg_fixtures()
    await setup_prototype_schema()
    logger.info("satark_prototype_ready")
    yield
    await close_driver()
    await close_redis()


app = FastAPI(
    title="SATARK Layer 1 — Prototype",
    version="0.1.0-prototype",
    docs_url="/docs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, tags=["health"])
app.include_router(ingestion_router, prefix="/api/v1/ingestion", tags=["ingestion"])
app.include_router(graph_router, prefix="/api/v1/graph", tags=["graph"])
app.include_router(findings_router, prefix="/api/v1/findings", tags=["findings"])
app.include_router(review_router, prefix="/api/v1/review", tags=["review"])
