"""
app/api/ingest.py — POST /ingest Telemetry Ingestion Endpoint
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.telemetry import TelemetryEvent
from app.schemas.verdicts import ForensicVerdict
from app.verification.integrity_pipeline import run_pipeline

router = APIRouter()


@router.post("/ingest", response_model=ForensicVerdict, tags=["Forensic Ingestion"])
async def ingest_telemetry(event: TelemetryEvent, db: Session = Depends(get_db)):
    """
    Primary forensic ingestion endpoint.
    Executes the 4-stage verification pipeline and persists the verdict.
    """
    return await run_pipeline(event, db)


@router.post("/verify", response_model=ForensicVerdict, tags=["Forensic Ingestion"])
async def verify_telemetry(event: TelemetryEvent, db: Session = Depends(get_db)):
    """
    Stateless-style verification endpoint (still persists for audit).
    Semantically equivalent to /ingest for MVP.
    """
    return await run_pipeline(event, db)
