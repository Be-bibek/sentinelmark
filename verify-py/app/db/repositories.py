"""
app/db/repositories.py — Forensic Data Access Layer

ARCHITECTURE RATIONALE
======================
The repository pattern decouples the verification pipeline from SQLAlchemy internals.
Callers (pipeline, behavioral analyzer) interact only with high-level methods,
never with raw SQL or ORM queries directly.

This boundary is forensically important because:
  - All writes are centralized — easy to audit for accidental mutations.
  - Query logic for behavioral windows is co-located and testable in isolation.
  - The in-memory nonce cache from Phase 2 MVP is replaced with DB-backed persistence,
    making the replay guard crash-resilient.

REPLAY GUARD SEMANTICS:
  A nonce is valid for 60 seconds (2× the ±30s drift window). After 60s, the event
  could not have arrived in a legitimate delivery scenario, so its nonce is safe to evict.
  Eviction is eager: called on every ingest to prevent unbounded table growth.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import select, delete, func

from app.db.models import TelemetryLog, NonceCache

# Nonce expiry window: 60 seconds (2× the ±30s timestamp drift window)
NONCE_EXPIRY_SECONDS = 60


class TelemetryRepository:
    """
    Append-only forensic audit ledger accessor.
    All methods that write are INSERT-only. No UPDATE/DELETE on TelemetryLog.
    """

    def __init__(self, db: Session):
        self.db = db

    def persist_verdict(
        self,
        *,
        device_id: str,
        event_id: str,
        sequence_number: int,
        timestamp_utc: datetime,
        nonce: str,
        current_hash: str,
        prev_hash: str,
        cpu_usage: int,
        memory_usage: int,
        timing_jitter: int,
        thread_count: int,
        trust_score: float,
        replay_detected: bool,
        tamper_detected: bool,
        behavior_anomaly: bool,
        chain_valid: bool,
        timestamp_valid: bool,
        z_score_cpu: Optional[float],
        z_score_memory: Optional[float],
        z_score_jitter: Optional[float],
        verification_reason: str,
        raw_payload: str,
    ) -> TelemetryLog:
        """Insert a forensic verdict row. Returns the inserted ORM object."""
        row = TelemetryLog(
            device_id=device_id,
            event_id=event_id,
            sequence_number=sequence_number,
            timestamp_utc=timestamp_utc,
            nonce=nonce,
            current_hash=current_hash,
            prev_hash=prev_hash,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            timing_jitter=timing_jitter,
            thread_count=thread_count,
            trust_score=trust_score,
            replay_detected=replay_detected,
            tamper_detected=tamper_detected,
            behavior_anomaly=behavior_anomaly,
            chain_valid=chain_valid,
            timestamp_valid=timestamp_valid,
            z_score_cpu=z_score_cpu,
            z_score_memory=z_score_memory,
            z_score_jitter=z_score_jitter,
            verification_reason=verification_reason,
            raw_payload=raw_payload,
        )
        self.db.add(row)
        self.db.flush()  # Write to DB within transaction without commit
        return row

    def get_recent_events_for_device(
        self, device_id: str, limit: int = 50
    ) -> list[TelemetryLog]:
        """
        Fetch the last `limit` verified events for a device.
        Used by BehavioralAnalyzer to build rolling statistical windows.
        Ordered by timestamp DESC so we get the most recent history.
        """
        stmt = (
            select(TelemetryLog)
            .where(TelemetryLog.device_id == device_id)
            .where(TelemetryLog.tamper_detected == False)
            .where(TelemetryLog.replay_detected == False)
            .order_by(TelemetryLog.sequence_number.desc())
            .limit(limit)
        )
        return list(self.db.execute(stmt).scalars().all())

    def count_logs(self) -> int:
        """Total number of log entries (for /metrics endpoint)."""
        return self.db.execute(select(func.count()).select_from(TelemetryLog)).scalar_one()

    def count_tamper_events(self) -> int:
        return self.db.execute(
            select(func.count())
            .select_from(TelemetryLog)
            .where(TelemetryLog.tamper_detected == True)
        ).scalar_one()

    def count_replay_events(self) -> int:
        return self.db.execute(
            select(func.count())
            .select_from(TelemetryLog)
            .where(TelemetryLog.replay_detected == True)
        ).scalar_one()

    def count_anomaly_events(self) -> int:
        return self.db.execute(
            select(func.count())
            .select_from(TelemetryLog)
            .where(TelemetryLog.behavior_anomaly == True)
        ).scalar_one()

    def average_trust_score(self) -> float:
        result = self.db.execute(
            select(func.avg(TelemetryLog.trust_score)).select_from(TelemetryLog)
        ).scalar_one()
        return round(result or 0.0, 4)

    def count_distinct_devices(self) -> int:
        return self.db.execute(
            select(func.count(func.distinct(TelemetryLog.device_id)))
            .select_from(TelemetryLog)
        ).scalar_one()


class NonceCacheRepository:
    """
    Crash-resilient sliding-window replay guard backed by SQLite.

    Replaces the ephemeral in-memory set from Phase 2 MVP with a persistent
    solution that survives process restarts and bounded by time, not memory.
    """

    def __init__(self, db: Session):
        self.db = db

    def exists(self, nonce: str) -> bool:
        """
        Check if a nonce is currently in the active replay window.
        Returns True if the nonce exists AND has not expired.
        """
        now = datetime.now(timezone.utc)
        stmt = (
            select(NonceCache)
            .where(NonceCache.nonce == nonce)
            .where(NonceCache.expires_at > now)
        )
        return self.db.execute(stmt).scalar_one_or_none() is not None

    def record(self, nonce: str, device_id: str) -> None:
        """
        Record a newly seen nonce with its expiry deadline.
        If the nonce somehow already exists (race condition edge case), silently ignore.
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=NONCE_EXPIRY_SECONDS)

        row = NonceCache(nonce=nonce, device_id=device_id, expires_at=expires_at)
        self.db.merge(row)  # merge = INSERT OR REPLACE semantics
        self.db.flush()

    def prune_expired(self) -> int:
        """
        Eagerly delete all expired nonce rows.
        Called on every ingest to maintain bounded table size.
        Returns the number of deleted rows.
        """
        now = datetime.now(timezone.utc)
        result = self.db.execute(
            delete(NonceCache).where(NonceCache.expires_at <= now)
        )
        self.db.flush()
        return result.rowcount
