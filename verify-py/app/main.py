import logging
import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from app.schemas.telemetry import TelemetryEvent, ForensicVerdict
from app.verification.pipeline import process_telemetry

# ─── Logging Configuration ───────────────────────────────────────────────────
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/sentinel_cloud.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("sentinel_cloud")

# ─── FastAPI Scaffolding ─────────────────────────────────────────────────────
app = FastAPI(
    title="SentinelMark Verification Authority",
    description="Forensic telemetry ingestion and cryptographically secure verification.",
    version="0.1.0"
)

@app.get("/health")
async def health_check():
    """Liveness probe for the verification engine."""
    return {"status": "operational", "crypto_engine": "online"}

@app.post("/verify", response_model=ForensicVerdict)
async def verify_telemetry(event: TelemetryEvent):
    """
    Stateless Adjudication Endpoint.
    Deserializes the canonical JSON payload and runs the BEW pipeline.
    """
    logger.info(f"Verification requested for event: {event.event_id}")
    try:
        verdict = process_telemetry(event)
        return verdict
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail="Malformed telemetry payload")

@app.post("/ingest", response_model=ForensicVerdict)
async def ingest_telemetry(event: TelemetryEvent):
    """
    Stateful Ingestion Endpoint.
    Evaluates the telemetry. If fully verified, prepares it for database persistence.
    """
    verdict = process_telemetry(event)
    
    if verdict.verified:
        # TODO: Advanced persistence optimization (SQLAlchemy)
        logger.info(f"Ingested valid event: {event.event_id}")
    else:
        logger.warning(f"Rejected malicious/replayed event at ingestion: {event.event_id}")
        
    return verdict

@app.get("/logs")
async def get_logs():
    """Stub for retrieving recent structured logs."""
    return {"message": "Log retrieval not implemented in MVP"}

@app.get("/stats")
async def get_stats():
    """Stub for returning network trust stats."""
    return {"total_verified": 0, "total_rejected": 0}
