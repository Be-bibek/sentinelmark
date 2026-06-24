"""
app/schemas/metrics.py — Network Trust Metrics Response Schema
"""

from pydantic import BaseModel, Field


class NetworkMetrics(BaseModel):
    """Aggregated forensic telemetry statistics returned by GET /dashboard/metrics."""
    total_logs_processed: int
    integrity_violations_count: int
    replay_attempts_count: int
    anomaly_detection_count: int
    average_trust_score: float = Field(..., ge=0.0, le=1.0)
    network_trust_index: float = Field(..., ge=0.0, le=1.0)
    device_count: int
