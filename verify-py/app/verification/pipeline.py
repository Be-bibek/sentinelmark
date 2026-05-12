import logging
from datetime import datetime, timezone
from app.schemas.telemetry import TelemetryEvent, ForensicVerdict
from app.verification.watermark import (
    compute_behavior_digest,
    derive_bew_watermark,
    verify_watermark_constant_time,
    K_STATIC
)
from app.trust.scoring import compute_trust_score

logger = logging.getLogger("sentinel_cloud")

# For MVP replay detection, we simulate a global set.
# Advanced implementation will use SQLite + SQLAlchemy and a Sliding Window.
SEEN_NONCES = set()

def verify_timestamp(event_time: datetime) -> bool:
    """ Checks if timestamp is within ±30s of server UTC time. """
    now = datetime.now(timezone.utc)
    drift = abs((now - event_time).total_seconds())
    return drift <= 30.0

def process_telemetry(event: TelemetryEvent) -> ForensicVerdict:
    """
    End-to-End Forensic Adjudication Pipeline.
    """
    # 1. Timestamp Drift Validation
    timestamp_valid = verify_timestamp(event.captured_at)
    
    # 2. Replay Detection (Nonce deduplication)
    replay_detected = event.nonce in SEEN_NONCES
    if not replay_detected and timestamp_valid:
        SEEN_NONCES.add(event.nonce)
        
    # 3. BEW Watermark Recomputation
    behavior_digest = compute_behavior_digest(event.payload.behavior_snapshot)
    
    expected_watermark = derive_bew_watermark(
        k_static=K_STATIC,
        behavior_digest=behavior_digest,
        prev_hash=bytes.fromhex(event.prev_hash),
        nonce=bytes.fromhex(event.nonce)
    )
    
    # 4. Constant-Time Authentication
    watermark_valid = verify_watermark_constant_time(
        expected=expected_watermark,
        received=bytes.fromhex(event.watermark)
    )
    tamper_detected = not watermark_valid

    # 5. Chain Validation
    # MVP: Assume chain is valid if watermark is valid and no replay occurred.
    # Advanced logic requires querying SQLite for the previous event's current_hash.
    chain_valid = watermark_valid and not replay_detected

    # 6. Trust Scoring
    trust_score = compute_trust_score(
        watermark_valid=watermark_valid,
        chain_valid=chain_valid,
        replay_absent=not replay_detected,
        timestamp_valid=timestamp_valid
    )

    # 7. Final Verdict Generation
    is_verified = (trust_score == 1.0)
    
    if not is_verified:
        reason = "Verification Failed: "
        if tamper_detected: reason += "[Forged Watermark] "
        if replay_detected: reason += "[Replayed Nonce] "
        if not timestamp_valid: reason += "[Timestamp Drift] "
    else:
        reason = "Telemetry verified successfully."
        
    verdict = ForensicVerdict(
        verified=is_verified,
        trust_score=trust_score,
        replay_detected=replay_detected,
        tamper_detected=tamper_detected,
        chain_valid=chain_valid,
        timestamp_valid=timestamp_valid,
        behavior_anomaly=False, # Stubbed until BehaviorAnalyzer is built
        reason=reason.strip()
    )
    
    if is_verified:
        logger.info(f"Verified event {event.event_id}")
    else:
        logger.warning(f"Rejected event {event.event_id} - {verdict.reason}")
        
    return verdict
