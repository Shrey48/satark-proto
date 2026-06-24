from fastapi import APIRouter
router = APIRouter()

@router.get("/queue")
async def review_queue():
    return {"items": [], "count": 0}
