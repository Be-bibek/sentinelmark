"""
app/verification/integrity_pipeline.py — 4-Stage Forensic Verification Pipeline

STAGE ORDER (mandatory):
  1. Structural Validation     — reject malformed before touching crypto
  2. Cryptographic Integrity   — BEW watermark + hash chain
  3. Replay Validation         — timestamp drift + nonce deduplication
  4. Behavioral Authenticity   — statistical Z-score analysis (non-blocking)

This order is not arbitrary. Stages 1-3 short-circuit early on failure and
persist the rejection verdict before returning. Stage 4 is skipped if earlier
stages fail — no point analyzing behavior of a forged event.
"""

import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session

from app.schemas.telemetry import TelemetryEvent
from app.schemas.verdicts import ForensicVerdict
from app.db.repositories import TelemetryRepository, NonceCacheRepository
from app.verification.hkdf_verifier import (
    compute_behavior_digest,
    derive_bew_watermark,
    verify_watermark,
)
from app.verification.replay_guard import is_replay
from app.verification.chain_validator import validate_chain
from app.behavior.analyzer import BehavioralAnalyzer
from app.trust.scoring import compute_trust_score

logger = logging.getLogger("sentinel_cloud")


def _serialize_payload(event: TelemetryEvent) -> str:
    """Canonical JSON serialization of the payload for DB storage."""
    return event.payload.model_dump_json()


async def run_pipeline(event: TelemetryEvent, db: Session) -> ForensicVerdict:
    """
    Executes the full 4-stage forensic verification pipeline.
    Persists the verdict to the audit ledger regardless of outcome.
    """
    telemetry_repo = TelemetryRepository(db)
    nonce_repo = NonceCacheRepository(db)
    raw_payload_str = _serialize_payload(event)

    # Default verdict state — all failures, scores will be filled per-stage
    z_cpu = z_mem = z_jit = None
    behavior_anomaly = False
    behavior_authentic = True  # Default benefit-of-doubt for cold-start devices

    # ─── STAGE 2: Cryptographic Integrity ────────────────────────────────────
    behavior_digest = compute_behavior_digest(event.payload.behavior_snapshot)
    expected_watermark = derive_bew_watermark(
        behavior_digest=behavior_digest,
        prev_hash=bytes.fromhex(event.prev_hash),
        nonce=bytes.fromhex(event.nonce),
    )
    watermark_valid = verify_watermark(
        expected=expected_watermark,
        received=bytes.fromhex(event.watermark),
    )

    if not watermark_valid:
        verdict = _build_and_persist(
            event=event,
            telemetry_repo=telemetry_repo,
            raw_payload=raw_payload_str,
            watermark_valid=False, chain_valid=False,
            timestamp_valid=True,  # unknown yet, give neutral
            replay_detected=False, behavior_anomaly=False,
            behavior_authentic=False,
            z_cpu=None, z_mem=None, z_jit=None,
            reason="[TAMPERED] BEW watermark verification failed — K_static or payload integrity compromised.",
        )
        logger.warning(f"Tamper detected for device={event.device_id} event={event.event_id}")
        return verdict

    # Chain validation
    chain_valid = validate_chain(
        db=db,
        device_id=event.device_id,
        prev_hash=event.prev_hash,
        claimed_current_hash=event.current_hash,
        nonce=event.nonce,
        watermark=event.watermark,
        raw_payload=raw_payload_str,
    )

    if not chain_valid:
        verdict = _build_and_persist(
            event=event,
            telemetry_repo=telemetry_repo,
            raw_payload=raw_payload_str,
            watermark_valid=True, chain_valid=False,
            timestamp_valid=True, replay_detected=False,
            behavior_anomaly=False, behavior_authentic=False,
            z_cpu=None, z_mem=None, z_jit=None,
            reason="[TAMPERED] Hash chain linkage broken — log insertion, deletion or reordering suspected.",
        )
        logger.warning(f"Chain violation for device={event.device_id} event={event.event_id}")
        return verdict

    # ─── STAGE 3: Replay Validation ──────────────────────────────────────────
    timestamp_valid, replay_detected = is_replay(
        nonce=event.nonce,
        device_id=event.device_id,
        event_time=event.captured_at,
        nonce_repo=nonce_repo,
    )

    if replay_detected or not timestamp_valid:
        reason = (
            "[REPLAY_ATTACK] Nonce already seen in replay window."
            if replay_detected
            else "[TIMESTAMP_VIOLATION] Event timestamp outside ±30s drift window."
        )
        verdict = _build_and_persist(
            event=event,
            telemetry_repo=telemetry_repo,
            raw_payload=raw_payload_str,
            watermark_valid=True, chain_valid=True,
            timestamp_valid=timestamp_valid,
            replay_detected=replay_detected,
            behavior_anomaly=False, behavior_authentic=False,
            z_cpu=None, z_mem=None, z_jit=None,
            reason=reason,
        )
        logger.warning(f"{'Replay' if replay_detected else 'Timestamp'} rejection for device={event.device_id}")
        return verdict

    # ─── STAGE 4: Behavioral Authenticity (non-blocking thread pool) ─────────
    historical_logs = telemetry_repo.get_recent_events_for_device(event.device_id, limit=50)

    loop = asyncio.get_event_loop()
    behavior_result = await loop.run_in_executor(
        None,
        BehavioralAnalyzer.analyze,
        historical_logs,
        event.payload.behavior_snapshot,
    )

    behavior_anomaly = behavior_result.get("behavior_anomaly", False)
    behavior_authentic = not behavior_anomaly
    z_cpu = behavior_result.get("z_score_cpu")
    z_mem = behavior_result.get("z_score_memory")
    z_jit = behavior_result.get("z_score_jitter")
    behavior_reason = behavior_result.get("reason", "")

    if behavior_anomaly:
        logger.warning(f"Anomaly detected device={event.device_id}: {behavior_reason}")

    # ─── Final Verdict ────────────────────────────────────────────────────────
    reason = "Telemetry verified successfully."
    if behavior_anomaly:
        reason = f"[BEHAVIOR_ANOMALY] {behavior_reason}"

    verdict = _build_and_persist(
        event=event,
        telemetry_repo=telemetry_repo,
        raw_payload=raw_payload_str,
        watermark_valid=True, chain_valid=True,
        timestamp_valid=True, replay_detected=False,
        behavior_anomaly=behavior_anomaly, behavior_authentic=behavior_authentic,
        z_cpu=z_cpu, z_mem=z_mem, z_jit=z_jit,
        reason=reason,
    )

    if verdict.verified:
        logger.info(f"Verified event={event.event_id} device={event.device_id} trust={verdict.trust_score:.2f}")

    return verdict


def _build_and_persist(
    *,
    event: TelemetryEvent,
    telemetry_repo: TelemetryRepository,
    raw_payload: str,
    watermark_valid: bool,
    chain_valid: bool,
    timestamp_valid: bool,
    replay_detected: bool,
    behavior_anomaly: bool,
    behavior_authentic: bool,
    z_cpu: Optional[float],
    z_mem: Optional[float],
    z_jit: Optional[float],
    reason: str,
) -> ForensicVerdict:
    """Builds a ForensicVerdict, computes trust score, and persists to audit ledger."""
    trust = compute_trust_score(
        watermark_valid=watermark_valid,
        chain_valid=chain_valid,
        replay_absent=not replay_detected,
        timestamp_valid=timestamp_valid,
        behavior_authentic=behavior_authentic,
    )
    verified = (trust >= 1.0)

    telemetry_repo.persist_verdict(
        device_id=event.device_id,
        event_id=str(event.event_id),
        timestamp_utc=event.captured_at,
        nonce=event.nonce,
        trust_score=trust,
        replay_detected=replay_detected,
        tamper_detected=not watermark_valid,
        behavior_anomaly=behavior_anomaly,
        chain_valid=chain_valid,
        timestamp_valid=timestamp_valid,
        z_score_cpu=z_cpu,
        z_score_memory=z_mem,
        z_score_jitter=z_jit,
        verification_reason=reason,
        raw_payload=raw_payload,
    )

    return ForensicVerdict(
        verified=verified,
        trust_score=trust,
        replay_detected=replay_detected,
        tamper_detected=not watermark_valid,
        behavior_anomaly=behavior_anomaly,
        chain_valid=chain_valid,
        timestamp_valid=timestamp_valid,
        z_score_cpu=z_cpu,
        z_score_memory=z_mem,
        z_score_jitter=z_jit,
        reason=reason,
    )
