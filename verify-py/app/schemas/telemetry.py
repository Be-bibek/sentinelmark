from typing import Any, Dict
from pydantic import BaseModel, Field, UUID4
from datetime import datetime

class BehaviorSnapshot(BaseModel):
    """
    Python representation of the Rust BehaviorSnapshot.
    Must perfectly match the field layout of the Rust struct for deterministic digestion.
    """
    cpu_usage_pct_x100: int = Field(..., ge=0, le=10000)
    virtual_memory_bytes: int = Field(..., ge=0)
    physical_memory_bytes: int = Field(..., ge=0)
    thread_count: int = Field(..., ge=0)
    jitter_ns: int = Field(..., ge=0)
    captured_at_unix_secs: int = Field(..., ge=0)

class TelemetryPayload(BaseModel):
    """
    The dynamic payload contained within the event.
    We assume the Rust client embeds the BehaviorSnapshot inside the payload
    so the verifier can reconstruct the BEW watermark.
    """
    behavior_snapshot: BehaviorSnapshot
    # Application-specific payload data can follow
    data: Dict[str, Any] | None = None

class TelemetryEvent(BaseModel):
    """
    Canonical Telemetry Event Schema.
    Strictly validates the 256-bit hex constraints emitted by the Rust core.
    """
    schema_version: int = Field(..., eq=1)
    event_id: UUID4
    sequence_number: int = Field(..., ge=1)
    captured_at: datetime
    device_id: str
    
    # 256-bit Hex Strings (64 chars)
    nonce: str = Field(..., min_length=64, max_length=64)
    prev_hash: str = Field(..., min_length=64, max_length=64)
    watermark: str = Field(..., min_length=64, max_length=64)
    current_hash: str = Field(..., min_length=64, max_length=64)
    
    payload: TelemetryPayload

class ForensicVerdict(BaseModel):
    """
    The deterministic adjudication output for a single telemetry event.
    """
    verified: bool
    trust_score: float
    replay_detected: bool
    tamper_detected: bool
    chain_valid: bool
    timestamp_valid: bool
    behavior_anomaly: bool
    reason: str
