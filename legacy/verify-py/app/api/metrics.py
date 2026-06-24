"""
app/api/metrics.py — GET /dashboard/metrics Aggregated Network Trust Statistics
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.repositories import TelemetryRepository
from app.schemas.metrics import NetworkMetrics

router = APIRouter()


@router.get("/dashboard/metrics", response_model=NetworkMetrics, tags=["Analytics"])
def get_metrics(db: Session = Depends(get_db)):
    """
    Returns aggregated forensic telemetry statistics over the full audit ledger.
    
    network_trust_index: ratio of fully verified events to total processed.
    """
    repo = TelemetryRepository(db)

    total = repo.count_logs()
    tamper = repo.count_tamper_events()
    replay = repo.count_replay_events()
    anomaly = repo.count_anomaly_events()
    avg_trust = repo.average_trust_score()
    devices = repo.count_distinct_devices()

    # Network Trust Index: fraction of fully verified events
    violations = tamper + replay + anomaly
    nti = round(1.0 - (violations / total), 4) if total > 0 else 1.0

    return NetworkMetrics(
        total_logs_processed=total,
        integrity_violations_count=tamper,
        replay_attempts_count=replay,
        anomaly_detection_count=anomaly,
        average_trust_score=avg_trust,
        network_trust_index=max(0.0, nti),
        device_count=devices,
    )
