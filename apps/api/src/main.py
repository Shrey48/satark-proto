"""
SATARK Layer 1 — FastAPI Application Entry Point (P0-02)

Boots the API, registers all routers, configures middleware, and handles
application lifecycle (startup/shutdown of Neo4j driver, Redis, Celery).

Everything in this file is infrastructure wiring — no business logic lives here.
"""
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from core.config import get_settings
from core.database.neo4j import get_driver, close_driver
from core.database.postgres import engine, create_tables
from core.database.redis_client import get_redis, close_redis
from core.middleware.tenant import TenantMiddleware
from core.middleware.logging import LoggingMiddleware

# API routers (v1)
from api.v1 import ingestion, graph, findings, review, tenants, health

logger = structlog.get_logger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    # ── Startup ────────────────────────────────────────────
    logger.info("satark_api_starting", env=settings.app_env, llm_provider=settings.llm_provider)

    # Initialise Neo4j driver (connection pool)
    await get_driver()
    logger.info("neo4j_connected", uri=settings.neo4j_uri)

    # Initialise Redis connection
    await get_redis()
    logger.info("redis_connected")

    # Create PostgreSQL tables if they don't exist
    await create_tables()
    logger.info("postgres_tables_ready")

    logger.info(
        "satark_api_ready",
        llm_provider=settings.llm_provider,
        llm_model=settings.active_llm_model,
    )

    yield   # ← Application runs here

    # ── Shutdown ───────────────────────────────────────────
    logger.info("satark_api_shutting_down")
    await close_driver()
    await close_redis()
    logger.info("satark_api_stopped")


def create_app() -> FastAPI:
    app = FastAPI(
        title="SATARK Layer 1 API",
        description="Ground Truth · Knowledge Graph · Normalised Finding Pool",
        version="1.0.0",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ── Middleware (order matters — outermost runs first) ───
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(TenantMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"] if not settings.is_production else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routers ─────────────────────────────────────────────
    app.include_router(health.router, tags=["health"])
    app.include_router(tenants.router, prefix="/api/v1/tenants", tags=["tenants"])
    app.include_router(ingestion.router, prefix="/api/v1/ingestion", tags=["ingestion"])
    app.include_router(graph.router, prefix="/api/v1/graph", tags=["graph"])
    app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
    app.include_router(review.router, prefix="/api/v1/review", tags=["review"])

    return app


app = create_app()
