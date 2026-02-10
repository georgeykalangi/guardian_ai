"""Health check endpoints."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "dataguard"}


@router.get("/ready")
async def ready():
    return {"status": "ready"}
