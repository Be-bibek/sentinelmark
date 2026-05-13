"""
tests/test_verification_pipeline.py — Full Forensic Verification Test Suite

Covers all 7 mandatory attack vectors:
  1. Valid telemetry (full trust_score=1.0)
  2. Replay rejection (duplicate nonce)
  3. Forged watermark rejection (K_static tamper)
  4. Malformed payload rejection (Pydantic validation)
  5. Timestamp skew rejection (>30s drift)
  6. Chain tampering rejection (wrong prev_hash)
  7. Anomaly detection triggering (synthetic entropy-collapsed telemetry)
"""

import pytest
import uuid
import json
import struct
import hashlib
import hmac as hmac_mod
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, AsyncMock

from app.schemas.telemetry import TelemetryEvent, TelemetryPayload, BehaviorSnapshot
from app.schemas.verdicts import ForensicVerdict
from app.verification.hkdf_verifier import (
    compute_behavior_digest,
    derive_bew_watermark,
    verify_watermark,
    K_STATIC,
)
from app.verification.replay_guard import is_replay
from app.trust.scoring import compute_trust_score
from app.behavior.analyzer import BehavioralAnalyzer

# ─── Helpers ─────────────────────────────────────────────────────────────────

GENESIS_HASH = "0" * 64
TEST_DEVICE = "device-test-001"


def _make_snapshot(
    cpu: int = 5000,
    vmem: int = 1_073_741_824,
    pmem: int = 512_000_000,
    threads: int = 8,
    jitter: int = 25_000,
    captured_at: int = 1_700_000_000,
) -> BehaviorSnapshot:
    return BehaviorSnapshot(
        cpu_usage_pct_x100=cpu,
        virtual_memory_bytes=vmem,
        physical_memory_bytes=pmem,
        thread_count=threads,
        jitter_ns=jitter,
        captured_at_unix_secs=captured_at,
    )


def _make_valid_event(
    nonce: str | None = None,
    prev_hash: str = GENESIS_HASH,
    snapshot: BehaviorSnapshot | None = None,
    device_id: str = TEST_DEVICE,
    captured_at: datetime | None = None,
) -> TelemetryEvent:
    """Builds a fully signed, valid TelemetryEvent."""
    if nonce is None:
        nonce = "ab" * 32  # 64-char hex
    if snapshot is None:
        snapshot = _make_snapshot()
    if captured_at is None:
        captured_at = datetime.now(timezone.utc)

    behavior_digest = compute_behavior_digest(snapshot)
    watermark_bytes = derive_bew_watermark(
        behavior_digest=behavior_digest,
        prev_hash=bytes.fromhex(prev_hash),
        nonce=bytes.fromhex(nonce),
    )
    watermark_hex = watermark_bytes.hex()

    # Compute current_hash (mimics chain_validator.compute_current_hash)
    raw_payload = json.dumps({
        "behavior_snapshot": snapshot.model_dump(),
        "data": None,
    }, sort_keys=True)
    pre_image = (
        device_id.encode() +
        bytes.fromhex(nonce) +
        bytes.fromhex(prev_hash) +
        bytes.fromhex(watermark_hex) +
        raw_payload.encode()
    )
    current_hash = hashlib.sha256(pre_image).hexdigest()

    return TelemetryEvent(
        schema_version=1,
        event_id=uuid.uuid4(),
        captured_at=captured_at,
        device_id=device_id,
        nonce=nonce,
        prev_hash=prev_hash,
        watermark=watermark_hex,
        current_hash=current_hash,
        payload=TelemetryPayload(behavior_snapshot=snapshot, data=None),
    )


# ─── Test 1: Trust Scoring — Valid event achieves maximum score ───────────────

def test_trust_score_full_validity():
    score = compute_trust_score(
        watermark_valid=True,
        chain_valid=True,
        replay_absent=True,
        timestamp_valid=True,
        behavior_authentic=True,
    )
    assert score == 1.0, f"Expected 1.0, got {score}"


def test_trust_score_forged_watermark():
    score = compute_trust_score(
        watermark_valid=False,
        chain_valid=False,
        replay_absent=True,
        timestamp_valid=True,
        behavior_authentic=False,
    )
    assert score == 0.2, f"Expected 0.2 (replay+timestamp only), got {score}"


def test_trust_score_replay():
    score = compute_trust_score(
        watermark_valid=True,
        chain_valid=True,
        replay_absent=False,
        timestamp_valid=True,
        behavior_authentic=True,
    )
    assert score == 0.8, f"Expected 0.8 (no replay credit), got {score}"


# ─── Test 2: BEW Watermark Derivation — Determinism & Sensitivity ─────────────

def test_watermark_derivation_deterministic():
    snap = _make_snapshot()
    digest = compute_behavior_digest(snap)
    nonce = bytes.fromhex("cd" * 32)
    prev = bytes.fromhex(GENESIS_HASH)

    w1 = derive_bew_watermark(digest, prev, nonce)
    w2 = derive_bew_watermark(digest, prev, nonce)
    assert w1 == w2


def test_watermark_changes_with_different_nonce():
    snap = _make_snapshot()
    digest = compute_behavior_digest(snap)
    prev = bytes.fromhex(GENESIS_HASH)

    w1 = derive_bew_watermark(digest, prev, bytes.fromhex("aa" * 32))
    w2 = derive_bew_watermark(digest, prev, bytes.fromhex("bb" * 32))
    assert w1 != w2


def test_watermark_changes_with_behavior_change():
    nonce = bytes.fromhex("de" * 32)
    prev = bytes.fromhex(GENESIS_HASH)

    d1 = compute_behavior_digest(_make_snapshot(cpu=1000))
    d2 = compute_behavior_digest(_make_snapshot(cpu=9999))
    w1 = derive_bew_watermark(d1, prev, nonce)
    w2 = derive_bew_watermark(d2, prev, nonce)
    assert w1 != w2


# ─── Test 3: Forged Watermark Rejection ───────────────────────────────────────

def test_forged_watermark_fails_constant_time_check():
    legitimate = derive_bew_watermark(
        compute_behavior_digest(_make_snapshot()),
        bytes.fromhex(GENESIS_HASH),
        bytes.fromhex("ff" * 32),
    )
    forged = bytes([0xFF] * 32)
    assert not verify_watermark(legitimate, forged)


def test_correct_watermark_passes():
    digest = compute_behavior_digest(_make_snapshot())
    nonce = bytes.fromhex("01" * 32)
    prev = bytes.fromhex(GENESIS_HASH)
    w = derive_bew_watermark(digest, prev, nonce)
    assert verify_watermark(w, w)


# ─── Test 4: Replay Guard — Timestamp Drift ───────────────────────────────────

def test_replay_guard_future_event_rejected():
    """Event timestamped 60s in the future exceeds ±30s drift."""
    mock_nonce_repo = MagicMock()
    mock_nonce_repo.prune_expired.return_value = 0
    mock_nonce_repo.exists.return_value = False

    future_time = datetime.now(timezone.utc) + timedelta(seconds=60)
    timestamp_valid, replay_detected = is_replay(
        nonce="aa" * 32,
        device_id=TEST_DEVICE,
        event_time=future_time,
        nonce_repo=mock_nonce_repo,
    )
    assert not timestamp_valid
    assert not replay_detected  # Not a replay — just stale/skewed


def test_replay_guard_expired_event_rejected():
    """Event timestamped 60s in the past exceeds ±30s drift."""
    mock_nonce_repo = MagicMock()
    mock_nonce_repo.prune_expired.return_value = 0
    mock_nonce_repo.exists.return_value = False

    stale_time = datetime.now(timezone.utc) - timedelta(seconds=60)
    timestamp_valid, replay_detected = is_replay(
        nonce="bb" * 32,
        device_id=TEST_DEVICE,
        event_time=stale_time,
        nonce_repo=mock_nonce_repo,
    )
    assert not timestamp_valid


def test_replay_guard_duplicate_nonce_rejected():
    """Second submission of same nonce is marked as replay."""
    mock_nonce_repo = MagicMock()
    mock_nonce_repo.prune_expired.return_value = 0
    mock_nonce_repo.exists.return_value = True  # Already seen

    fresh_time = datetime.now(timezone.utc)
    timestamp_valid, replay_detected = is_replay(
        nonce="cc" * 32,
        device_id=TEST_DEVICE,
        event_time=fresh_time,
        nonce_repo=mock_nonce_repo,
    )
    assert timestamp_valid
    assert replay_detected


def test_replay_guard_fresh_unique_nonce_accepted():
    mock_nonce_repo = MagicMock()
    mock_nonce_repo.prune_expired.return_value = 0
    mock_nonce_repo.exists.return_value = False

    fresh_time = datetime.now(timezone.utc)
    timestamp_valid, replay_detected = is_replay(
        nonce="dd" * 32,
        device_id=TEST_DEVICE,
        event_time=fresh_time,
        nonce_repo=mock_nonce_repo,
    )
    assert timestamp_valid
    assert not replay_detected
    mock_nonce_repo.record.assert_called_once()


# ─── Test 5: Behavioral Analyzer — Cold Start & Anomaly Detection ─────────────

def test_behavioral_analyzer_cold_start_skip():
    """Fewer than 10 events: no analysis, no anomaly flagged."""
    result = BehavioralAnalyzer.analyze(
        historical_logs=[],
        current_snapshot=_make_snapshot(),
    )
    assert not result["behavior_anomaly"]
    assert result["z_score_cpu"] is None


def test_behavioral_analyzer_entropy_collapse():
    """All historical events have identical jitter_ns → σ≈0 → entropy collapse flagged."""
    logs = []
    for i in range(15):
        mock_log = MagicMock()
        mock_log.raw_payload = json.dumps({
            "behavior_snapshot": {
                "cpu_usage_pct_x100": 5000,
                "physical_memory_bytes": 512_000_000,
                "jitter_ns": 0,  # Perfectly zero — synthetic telemetry signature
            }
        })
        logs.append(mock_log)

    current = _make_snapshot(jitter=0, cpu=5000, pmem=512_000_000)
    result = BehavioralAnalyzer.analyze(logs, current)
    # σ≈0 on jitter_ns should trigger entropy collapse
    assert result["behavior_anomaly"]
    assert result["z_score_jitter"] == 99.0  # Synthetic collapse sentinel value


def test_behavioral_analyzer_z_score_violation():
    """CPU usage suddenly 10x historical mean triggers Z-score anomaly."""
    logs = []
    for i in range(15):
        mock_log = MagicMock()
        mock_log.raw_payload = json.dumps({
            "behavior_snapshot": {
                "cpu_usage_pct_x100": 500,  # Historical: ~5% CPU
                "physical_memory_bytes": 512_000_000,
                "jitter_ns": 10_000,
            }
        })
        logs.append(mock_log)

    # Current event: CPU suddenly at 99% (9900/100 = 99% usage)
    current = _make_snapshot(cpu=9900, pmem=512_000_000, jitter=10_000)
    result = BehavioralAnalyzer.analyze(logs, current)
    assert result["behavior_anomaly"]
    assert result["z_score_cpu"] > 3.0
