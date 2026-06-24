"""
app/api/health.py — GET /health Liveness Probe
"""

from fastapi import APIRouter

router = APIRouter()

@router.get("/health", tags=["Operations"])
async def health_check():
    return {"status": "operational", "engine": "SentinelMark Forensic Verifier v3.0"}
