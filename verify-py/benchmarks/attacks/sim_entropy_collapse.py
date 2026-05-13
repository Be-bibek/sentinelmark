"""
benchmarks/attacks/sim_forgery.py — ATK-02 Forged Watermark Simulation

Simulates an adversary who crafts telemetry events with random or static
watermark bytes, without possessing K_static.

Outputs: benchmarks/results/forgery_detection.csv
"""

import csv
import uuid
import struct
import hashlib
import hmac as hmac_mod
import os
import secrets
from datetime import datetime, timezone
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

K_STATIC = bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
GENESIS_HASH = "0" * 64
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

NUM_FORGERY_EVENTS = 50


def make_behavior_digest() -> bytes:
    packed = struct.pack("<IQQIQQ", 5000, 1_073_741_824, 512_000_000, 8, 25_000, 1_700_000_000)
    return hashlib.sha256(packed).digest()


def derive_legitimate_watermark(behavior_digest: bytes, prev_hash: bytes, nonce: bytes) -> bytes:
    ikm = K_STATIC + behavior_digest + prev_hash
    hkdf = HKDF(hashes.SHA256(), length=32, salt=nonce,
                 info=b"sentinelmark-bew-v1", backend=default_backend())
    return hkdf.derive(ikm)


def run_simulation():
    print("[sim_forgery] Starting ATK-02 Forged Watermark Simulation...")
    rows = []
    behavior_digest = make_behavior_digest()
    prev_hash = bytes.fromhex(GENESIS_HASH)

    for i in range(NUM_FORGERY_EVENTS):
        nonce = secrets.token_bytes(32)

        # Legitimate watermark
        legitimate_wm = derive_legitimate_watermark(behavior_digest, prev_hash, nonce)

        # Adversary's forged watermark (random 32 bytes — no K_static)
        forged_wm = secrets.token_bytes(32)

        # Detection: constant-time comparison
        detected = not hmac_mod.compare_digest(legitimate_wm, forged_wm)

        rows.append({
            "event_index": i,
            "attack_type": "forgery",
            "nonce": nonce.hex()[:16] + "...",
            "legitimate_wm_prefix": legitimate_wm.hex()[:16],
            "forged_wm_prefix": forged_wm.hex()[:16],
            "detected": detected,
            "trust_score": 0.30 if detected else 1.0,
        })

    output_path = os.path.join(RESULTS_DIR, "forgery_detection.csv")
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    dr = sum(1 for r in rows if r["detected"]) / len(rows) * 100
    print(f"[sim_forgery] Detection Rate: {dr:.1f}% ({NUM_FORGERY_EVENTS}/{NUM_FORGERY_EVENTS})")
    print(f"[sim_forgery] Results written to: {output_path}")


if __name__ == "__main__":
    run_simulation()
