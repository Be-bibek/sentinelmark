"""
app/db/models.py — SQLAlchemy ORM Models for SentinelMark Forensic Persistence

ARCHITECTURE RATIONALE
======================

Two tables. Two distinct forensic purposes.

  TelemetryLog:
    Append-only evidence ledger. Every ingest attempt — verified OR rejected —
    is persisted with its full verdict and z-scores. This table is the forensic
    audit trail. It MUST never be updated or deleted post-write.
    
    Indexed by (device_id, timestamp_utc, nonce) for efficient:
      - per-device longitudinal analysis
      - chronological ordering
      - replay deduplication queries

  NonceCache:
    Stateful replay guard. The MVP in-memory set was ephemeral — restarting
    the verifier re-opened a full replay window. SQLite persistence closes
    this gap. Rows are pruned eagerly after expiry.

DATABASE DESIGN PRINCIPLE:
  NEVER MUTATE FORENSIC EVIDENCE.
  All inserts are terminal. No update/delete paths on TelemetryLog.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Float, Boolean, DateTime,
    Text, Index, UniqueConstraint
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


class TelemetryLog(Base):
    """
    Append-only forensic audit ledger.

    Every event ingested — verified or rejected — produces exactly one row.
    This row is the immutable forensic verdict. No UPDATE or DELETE operations
    are permitted on this table post-insertion.

    Fields:
        id:                 UUID primary key (string form for SQLite compatibility)
        device_id:          Source device identifier
        event_id:           Original UUID from the Rust event
        timestamp_utc:      Event capture time (UTC, from Rust event.captured_at)
        nonce:              256-bit hex nonce (64 chars) — used for replay dedup
        trust_score:        Deterministic float [0.0, 1.0]
        replay_detected:    True if this event is a replay attempt
        tamper_detected:    True if BEW watermark verification failed
        behavior_anomaly:   True if statistical Z-score exceeded threshold
        chain_valid:        True if prev_hash chain linkage is correct
        timestamp_valid:    True if event was within ±30s drift window
        z_score_cpu:        Z-score of cpu_usage_pct_x100 relative to device history
        z_score_memory:     Z-score of physical_memory_bytes
        z_score_jitter:     Z-score of jitter_ns
        verification_reason: Human-readable summary of the verdict decision
        raw_payload:        Full canonical JSON payload (immutable forensic evidence)
        created_at:         DB insertion timestamp (server-side UTC)
    """
    __tablename__ = "telemetry_log"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String(255), nullable=False)
    event_id = Column(String(36), nullable=False)
    timestamp_utc = Column(DateTime(timezone=True), nullable=False)
    nonce = Column(String(64), nullable=False)
    trust_score = Column(Float, nullable=False)
    replay_detected = Column(Boolean, nullable=False, default=False)
    tamper_detected = Column(Boolean, nullable=False, default=False)
    behavior_anomaly = Column(Boolean, nullable=False, default=False)
    chain_valid = Column(Boolean, nullable=False, default=False)
    timestamp_valid = Column(Boolean, nullable=False, default=False)
    z_score_cpu = Column(Float, nullable=True)
    z_score_memory = Column(Float, nullable=True)
    z_score_jitter = Column(Float, nullable=True)
    verification_reason = Column(Text, nullable=False)
    raw_payload = Column(Text, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        # Composite index for fast per-device chronological queries (behavioral analysis)
        Index("ix_telemetry_device_time", "device_id", "timestamp_utc"),
        # Fast nonce lookup for replay deduplication
        Index("ix_telemetry_nonce", "nonce"),
    )

    def __repr__(self) -> str:
        return (
            f"<TelemetryLog id={self.id[:8]}... device={self.device_id} "
            f"trust={self.trust_score:.2f} tamper={self.tamper_detected}>"
        )


class NonceCache(Base):
    """
    Stateful sliding-window replay guard.

    Each row represents a nonce that has been seen within the valid replay window.
    Rows are pruned eagerly once expires_at < UTC_NOW.

    This table provides crash-resilient replay protection. Without it, restarting
    the verifier process re-opens a full ~30-second replay window. SQLite persistence
    closes this attack surface.

    Fields:
        nonce:       256-bit hex nonce (primary key — enforces uniqueness)
        device_id:   The device that generated this nonce
        received_at: When this nonce first arrived (UTC)
        expires_at:  Eviction deadline — nonces expire after 60s (2× drift window)
    """
    __tablename__ = "nonce_cache"

    nonce = Column(String(64), primary_key=True)
    device_id = Column(String(255), nullable=False)
    received_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        # Fast expiry pruning: DELETE WHERE expires_at < NOW()
        Index("ix_nonce_expires", "expires_at"),
    )

    def __repr__(self) -> str:
        return f"<NonceCache nonce={self.nonce[:16]}... expires={self.expires_at}>"
