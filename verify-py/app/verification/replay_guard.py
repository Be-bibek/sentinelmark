"""
app/verification/replay_guard.py — Stateful Sliding-Window Replay Protection

ARCHITECTURE RATIONALE
======================
The Phase 2 MVP used an in-memory set for nonce deduplication. This was ephemeral —
restarting the verifier process re-opened a full 30-second replay window.

Phase 3 replaces this with SQLite-backed persistence via NonceCacheRepository,
closing the restart-replay attack surface completely.

TIMESTAMP DRIFT SEMANTICS:
  - Valid window: ±30 seconds from server UTC time
  - Nonce expiry: 60 seconds (2× drift window)
  - Any event arriving outside the ±30s window is immediately rejected, regardless
    of nonce uniqueness — an attacker cannot legitimately claim an old event is fresh.

PRUNE POLICY:
  Expired nonces are eagerly pruned on every call to is_replay(). This prevents
  unbounded table growth even under adversarial load (e.g., a flood of unique nonces).
"""

from datetime import datetime, timezone
from typing import Tuple

from app.db.repositories import NonceCacheRepository

TIMESTAMP_DRIFT_SECONDS = 30


def is_replay(
    nonce: str,
    device_id: str,
    event_time: datetime,
    nonce_repo: NonceCacheRepository,
) -> Tuple[bool, bool]:
    """
    Performs both timestamp drift validation and nonce uniqueness check.
    
    Returns:
        (timestamp_valid: bool, replay_detected: bool)
    
    Pipeline logic:
        1. Prune expired nonces (maintenance, bounded table size).
        2. Check timestamp drift — reject immediately if outside ±30s.
        3. Check nonce uniqueness in the active replay window.
        4. If valid, record the nonce for future deduplication.
    """
    # 1. Eagerly prune expired nonces
    nonce_repo.prune_expired()

    # 2. Timestamp drift check
    now = datetime.now(timezone.utc)
    # Ensure event_time is timezone-aware
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    drift_seconds = abs((now - event_time).total_seconds())
    timestamp_valid = drift_seconds <= TIMESTAMP_DRIFT_SECONDS

    if not timestamp_valid:
        return False, False  # timestamp_valid=False, replay_detected=False (not a replay, just stale)

    # 3. Nonce uniqueness check
    already_seen = nonce_repo.exists(nonce)
    if already_seen:
        return True, True  # timestamp_valid=True, replay_detected=True

    # 4. Record fresh nonce
    nonce_repo.record(nonce, device_id)
    return True, False
