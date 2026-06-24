"""
app/main.py — SentinelMark Forensic Verification Authority

Phase 3: Stateful Forensic Verification Authority
- SQLite-backed persistent audit ledger
- Crash-resilient replay protection
- 4-stage forensic verification pipeline
- Statistical behavioral authenticity analysis
- Deterministic 5-dimensional trust scoring
- Network trust metrics API
"""

from fastapi import FastAPI
from contextlib import asynccontextmanager

from app.db.session import init_db
from app.logging.config import configure_logging
from app.api import ingest, health, metrics


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup: configure logging, initialize database."""
    configure_logging()
    init_db()
    yield
    # Cleanup on shutdown (if needed in future)


app = FastAPI(
    title="SentinelMark Verification Authority",
    description=(
        "Phase 3 Forensic Telemetry Authority: stateful replay defense, "
        "behavioral authenticity validation, adversarial telemetry evaluation, "
        "and reproducible forensic benchmarking."
    ),
    version="3.0.0",
    lifespan=lifespan,
)

# Register routers
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(metrics.router)
