"""
SATARK Layer 1 — PostgreSQL Connection (P0-04)
Application metadata: tenants, users, sessions, audit logs.
NOT for graph data — that lives in Neo4j.
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from core.config import get_settings
import structlog

logger = structlog.get_logger(__name__)
settings = get_settings()

# Convert postgresql:// to postgresql+asyncpg:// for async support
_uri = settings.postgres_uri.replace("postgresql://", "postgresql+asyncpg://", 1)

engine = create_async_engine(_uri, echo=False, pool_pre_ping=True, pool_size=10)
AsyncSessionFactory = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def create_tables():
    """Create all tables if they don't exist. Called at startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("postgres_tables_created_or_verified")


async def get_db_session() -> AsyncSession:
    """FastAPI dependency: yields a database session."""
    async with AsyncSessionFactory() as session:
        yield session
