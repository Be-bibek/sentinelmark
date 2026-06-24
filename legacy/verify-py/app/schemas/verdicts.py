"""
app/schemas/verdicts.py — Forensic Verdict and Metrics Schema Contracts

ForensicVerdict is the authoritative API response. Every field is deterministic —
the same telemetry event always produces the same verdict (given the same db state).
"""

from typing import Optional
from pydantic import BaseModel, Field


class ForensicVerdict(BaseModel):
    """Complete forensic adjudication result for a single telemetry event."""
    verified: bool
    trust_score: float = Field(..., ge=0.0, le=1.0)
    replay_detected: bool
    tamper_detected: bool
    behavior_anomaly: bool
    chain_valid: bool
    timestamp_valid: bool
    z_score_cpu: Optional[float] = None
    z_score_memory: Optional[float] = None
    z_score_jitter: Optional[float] = None
    reason: str
