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
    watermark: int = 400
    chain: int = 250
    replay: int = 200
    timestamp: int = 100
    behavior: int = 50


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
    score_x1000 = 0
    if watermark_valid:
        score_x1000 += WEIGHTS.watermark
    if chain_valid:
        score_x1000 += WEIGHTS.chain
    if replay_absent:
        score_x1000 += WEIGHTS.replay
    if timestamp_valid:
        score_x1000 += WEIGHTS.timestamp
    if behavior_authentic:
        score_x1000 += WEIGHTS.behavior

    return score_x1000 / 1000.0
