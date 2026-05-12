def compute_trust_score(
    watermark_valid: bool,
    chain_valid: bool,
    replay_absent: bool,
    timestamp_valid: bool
) -> float:
    """
    Deterministic trust scoring engine for telemetry evaluation.
    
    Weights:
    - Valid Watermark: +0.4
    - Valid Hash Chain: +0.3
    - Replay Absent: +0.2
    - Timestamp Valid: +0.1
    
    Total Range: 0.0 -> 1.0
    """
    score = 0.0
    
    if watermark_valid:
        score += 0.4
    if chain_valid:
        score += 0.3
    if replay_absent:
        score += 0.2
    if timestamp_valid:
        score += 0.1
        
    # Floating point precision safety
    return round(score, 1)
