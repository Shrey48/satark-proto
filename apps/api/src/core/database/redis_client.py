"""
SATARK Layer 1 — Redis Client
Used for: Component 3 tool lookup cache, Celery broker, rate limiting.
"""
from typing import Optional
import redis.asyncio as aioredis
from core.config import get_settings
import structlog

logger = structlog.get_logger(__name__)
_redis: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        settings = get_settings()
        _redis = aioredis.from_url(settings.redis_uri, encoding="utf-8", decode_responses=True)
        await _redis.ping()
        logger.info("redis_connected")
    return _redis


async def close_redis():
    global _redis
    if _redis:
        await _redis.aclose()
        _redis = None
