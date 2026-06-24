from fastapi import APIRouter
from core.config import get_settings

router = APIRouter()
settings = get_settings()

@router.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0-prototype", "llm": settings.llm_provider}
