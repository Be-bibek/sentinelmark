"""
app/trust/scoring.py — Deterministic Trust Scoring Engine

FORENSIC RATIONALE
==================
Trust scores are deterministic scalar evaluations of four cryptographic and
statistical dimensions. This is NOT probabilistic ML — the same inputs always
produce the same score, making it reproducible in forensic reports.

Weighting rationale:
  0.40 — Watermark validity is the strongest security guarantee. Forgery here
          means K_static is compromised (catastrophic).
  0.25 — Chain integrity catches deletion, reordering, and injection attacks.
  0.20 — Replay absence prevents event recycling attacks.
  0.10 — Timestamp validity prevents time-skew and delayed delivery attacks.
  0.05 — Behavioral authenticity is a softer signal — statistical, not cryptographic.
          Weighted lowest since cold-start devices cannot be analyzed.

Total weight: 1.00
Output range: 0.0 → 1.0
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class TrustWeights:
    watermark: float = 0.40
    chain: float = 0.25
    replay: float = 0.20
    timestamp: float = 0.10
    behavior: float = 0.05


WEIGHTS = TrustWeights()


def compute_trust_score(
    watermark_valid: bool,
    chain_valid: bool,
    replay_absent: bool,
    timestamp_valid: bool,
    behavior_authentic: bool,
) -> float:
    """
    Computes a deterministic trust score in [0.0, 1.0].
    
    All inputs are boolean — deliberately coarse to prevent gaming the scorer
    with marginal float manipulations.
    """
    score = 0.0
    if watermark_valid:
        score += WEIGHTS.watermark
    if chain_valid:
        score += WEIGHTS.chain
    if replay_absent:
        score += WEIGHTS.replay
    if timestamp_valid:
        score += WEIGHTS.timestamp
    if behavior_authentic:
        score += WEIGHTS.behavior

    return round(score, 4)
