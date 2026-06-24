"""SATARK Layer 1 — Health endpoint"""
from fastapi import APIRouter
from core.config import get_settings

router = APIRouter()
settings = get_settings()


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "env": settings.app_env,
        "llm_provider": settings.llm_provider,
        "llm_model": settings.active_llm_model,
    }
