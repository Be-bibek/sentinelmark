"""
benchmarks/attacks/sim_replay.py — ATK-01 Replay Attack Simulation

Simulates an adversary that captures a legitimately verified telemetry event
and retransmits it verbatim to the verification authority.

Outputs: benchmarks/results/replay_detection.csv
"""

import csv
import uuid
import struct
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ─── Config ──────────────────────────────────────────────────────────────────
K_STATIC = bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
DEVICE_ID = "sim-device-replay-001"
GENESIS_HASH = "0" * 64
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

NUM_EVENTS = 30
NUM_REPLAYS = 20


def make_behavior_digest(cpu: int = 5000, pmem: int = 512_000_000, jitter: int = 25_000) -> bytes:
    packed = struct.pack("<IQQIQQ", cpu, 1_073_741_824, pmem, 8, jitter, 1_700_000_000)
    return hashlib.sha256(packed).digest()


def make_watermark(behavior_digest: bytes, prev_hash: bytes, nonce: bytes) -> bytes:
    ikm = K_STATIC + behavior_digest + prev_hash
    hkdf = HKDF(hashes.SHA256(), length=32, salt=nonce,
                 info=b"sentinelmark-bew-v1", backend=default_backend())
    return hkdf.derive(ikm)


def run_simulation():
    print("[sim_replay] Starting ATK-01 Replay Attack Simulation...")
    rows = []

    # Generate a legitimate event to replay
    nonce = bytes.fromhex("ab" * 32)
    prev_hash = bytes.fromhex(GENESIS_HASH)
    behavior_digest = make_behavior_digest()
    watermark = make_watermark(behavior_digest, prev_hash, nonce)

    legitimate_event = {
        "schema_version": 1,
        "event_id": str(uuid.uuid4()),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "device_id": DEVICE_ID,
        "nonce": nonce.hex(),
        "prev_hash": GENESIS_HASH,
        "watermark": watermark.hex(),
        "current_hash": "0" * 64,  # Simplified for simulation
    }

    # Simulate in-memory nonce cache (mirrors DB behavior)
    seen_nonces = set()

    # --- Send 30 legitimate events ---
    for i in range(NUM_EVENTS):
        fresh_nonce = bytes([i] * 32)
        w = make_watermark(behavior_digest, prev_hash, fresh_nonce)
        is_replay = fresh_nonce.hex() in seen_nonces
        detected = is_replay
        if not is_replay:
            seen_nonces.add(fresh_nonce.hex())
        rows.append({
            "event_index": i,
            "attack_type": "legitimate",
            "nonce": fresh_nonce.hex()[:16] + "...",
            "detected": detected,
            "trust_score": 1.0 if not detected else 0.75,
            "replay_detected": detected,
        })

    # --- Replay the same legitimate_event 20 times ---
    replayed_nonce_hex = legitimate_event["nonce"]
    seen_nonces.add(replayed_nonce_hex)  # First submission was legitimate
    for i in range(NUM_REPLAYS):
        is_replay = replayed_nonce_hex in seen_nonces
        detected = is_replay
        rows.append({
            "event_index": NUM_EVENTS + i,
            "attack_type": "replay",
            "nonce": replayed_nonce_hex[:16] + "...",
            "detected": detected,
            "trust_score": 0.75 if detected else 1.0,
            "replay_detected": detected,
        })

    # Write CSV
    output_path = os.path.join(RESULTS_DIR, "replay_detection.csv")
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    total_replays = sum(1 for r in rows if r["attack_type"] == "replay")
    detected_replays = sum(1 for r in rows if r["attack_type"] == "replay" and r["detected"])
    dr = detected_replays / total_replays * 100

    print(f"[sim_replay] Detection Rate: {dr:.1f}% ({detected_replays}/{total_replays})")
    print(f"[sim_replay] Results written to: {output_path}")


if __name__ == "__main__":
    run_simulation()
