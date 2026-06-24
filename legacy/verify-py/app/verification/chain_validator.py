"""
app/verification/chain_validator.py — Hash Chain Integrity Verification

FORENSIC RATIONALE
==================
The Rust core maintains an append-only hash chain where each event commits to
its predecessor via H_prev. This makes log deletion or reordering detectable —
any gap corrupts all downstream hash commitments.

The Python verifier validates chain linkage by:
  1. Querying the last persisted event for this device_id.
  2. Verifying that event.prev_hash == last_persisted.current_hash.

EDGE CASES:
  - Genesis event: If no history exists for a device, prev_hash must equal
    GENESIS_HASH (all-zero 64-char hex). This bootstraps the chain.
  - First event per device on a fresh verifier: treated as genesis.
  - Chain gaps: If prev_hash does not match the stored current_hash, the event
    is flagged as TAMPERED — either an insertion or deletion occurred.
"""

import hashlib
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.models import TelemetryLog

# All-zero 32-byte genesis anchor — matches Rust's GENESIS_HASH constant
GENESIS_HASH = "0" * 64


def compute_current_hash(
    device_id: str,
    nonce: str,
    prev_hash: str,
    watermark: str,
    raw_payload: str,
) -> str:
    """
    Recomputes the SHA-256 current_hash for this event's canonical pre-image.
    
    The pre-image is:  device_id || nonce || prev_hash || watermark || payload
    This matches the TelemetryPreimage layout in Rust's telemetry/mod.rs.
    
    All inputs are UTF-8 encoded before hashing.
    """
    pre_image = (
        device_id.encode() +
        bytes.fromhex(nonce) +
        bytes.fromhex(prev_hash) +
        bytes.fromhex(watermark) +
        raw_payload.encode()
    )
    return hashlib.sha256(pre_image).hexdigest()


def validate_chain(
    db: Session,
    device_id: str,
    prev_hash: str,
    claimed_current_hash: str,
    nonce: str,
    watermark: str,
    raw_payload: str,
) -> bool:
    """
    Validates that:
      1. The event's prev_hash matches the last persisted current_hash for this device.
      2. The event's claimed current_hash matches our local recomputation.
    
    Returns True if both checks pass (chain integrity maintained).
    """
    # Look up the causally latest verified, non-tampered event for this device
    stmt = (
        select(TelemetryLog)
        .where(TelemetryLog.device_id == device_id)
        .where(TelemetryLog.tamper_detected == False)
        .where(TelemetryLog.replay_detected == False)
        .order_by(TelemetryLog.sequence_number.desc())
        .limit(1)
    )
    last_event: Optional[TelemetryLog] = db.execute(stmt).scalar_one_or_none()

    if last_event is None:
        # First event for this device — prev_hash must be GENESIS_HASH
        expected_prev = GENESIS_HASH
    else:
        # Extract current_hash directly from the normalized column (O(1))
        expected_prev = last_event.current_hash

    # Check 1: prev_hash linkage
    if prev_hash.lower() != expected_prev.lower():
        return False

    # Check 2: claimed current_hash correctness
    recomputed = compute_current_hash(device_id, nonce, prev_hash, watermark, raw_payload)
    return recomputed.lower() == claimed_current_hash.lower()
