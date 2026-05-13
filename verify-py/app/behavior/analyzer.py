"""
app/behavior/analyzer.py — Statistical Behavioral Authenticity Validation

ARCHITECTURE RATIONALE
======================
Analyzes a sliding window of historical telemetry to detect entropy collapse
or synthetic forgery attempts.

STATISTICAL METHODOLOGY
=======================
Uses Z-score outlier detection: Z = |x - μ| / σ
Threshold: 3.0 (99.7% confidence interval)

If σ ≈ 0, we detect "Entropy Collapse". True hardware exhibits scheduler
jitter and memory fluctuation. Synthetic generation scripts usually hardcode
static values, leading to zero variance.
"""

import numpy as np
from typing import List, Tuple, Dict, Any
from app.db.models import TelemetryLog
from app.schemas.telemetry import BehaviorSnapshot

# Configuration
MIN_EVENTS_FOR_ANALYSIS = 10
Z_SCORE_THRESHOLD = 3.0
ENTROPY_COLLAPSE_SIGMA = 1e-4

class BehavioralAnalyzer:
    
    @staticmethod
    def extract_metric(logs: List[TelemetryLog], current_val: int, metric_name: str) -> Tuple[np.ndarray, float]:
        """Extracts historical array + current value for a metric."""
        for log in logs:
            val = getattr(log, metric_name, None)
            if val is not None:
                history.append(val)
                
        return np.array(history, dtype=np.float64), float(current_val)

    @classmethod
    def analyze(cls, historical_logs: List[TelemetryLog], current_snapshot: BehaviorSnapshot) -> Dict[str, Any]:
        """
        Runs the Z-score analysis across the telemetry window.
        Returns a dictionary containing the calculated z-scores and the anomaly flag.
        """
        # Cold Start Bypass
        if len(historical_logs) < MIN_EVENTS_FOR_ANALYSIS:
            return {
                "behavior_anomaly": False,
                "z_score_cpu": None,
                "z_score_memory": None,
                "z_score_jitter": None,
                "reason": "Insufficient history for statistical analysis"
            }

        anomaly = False
        reasons = []
        
        metrics_to_check = [
            ("cpu_usage", current_snapshot.cpu_usage_pct_x100, "z_score_cpu"),
            ("memory_usage", current_snapshot.physical_memory_bytes, "z_score_memory"),
            ("timing_jitter", current_snapshot.jitter_ns, "z_score_jitter"),
        ]
        
        results = {"behavior_anomaly": False, "z_score_cpu": 0.0, "z_score_memory": 0.0, "z_score_jitter": 0.0, "reason": ""}

        for field_name, current_val, out_key in metrics_to_check:
            history_arr, val = cls.extract_metric(historical_logs, current_val, field_name)
            
            if len(history_arr) < MIN_EVENTS_FOR_ANALYSIS:
                results[out_key] = 0.0
                continue
                
            mean = np.mean(history_arr)
            std = np.std(history_arr)
            
            # Check for Entropy Collapse (variance approaching zero)
            if std < ENTROPY_COLLAPSE_SIGMA:
                anomaly = True
                results[out_key] = 99.0  # Synthetic high z-score for collapse
                reasons.append(f"Entropy collapse on {field_name} (σ={std:.6f})")
                continue
                
            # Compute Z-Score
            z_score = abs(val - mean) / std
            results[out_key] = round(float(z_score), 4)
            
            if z_score > Z_SCORE_THRESHOLD:
                anomaly = True
                reasons.append(f"Z-Score violation on {field_name} (z={z_score:.2f})")

        results["behavior_anomaly"] = anomaly
        if anomaly:
            results["reason"] = " | ".join(reasons)
        else:
            results["reason"] = "Behavior statistically consistent."
            
        return results
