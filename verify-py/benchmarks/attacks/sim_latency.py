"""
benchmarks/attacks/sim_latency.py — Ingestion Latency Baseline

Measures the p50/p95/p99 latency of the verification pipeline components
in isolation (no network I/O — pure computation latency).

Outputs: benchmarks/results/latency_baseline.csv
"""

import csv
import struct
import hashlib
import time
import os
import numpy as np
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

K_STATIC = bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)
ITERATIONS = 1000


def time_behavior_digest() -> float:
    packed = struct.pack("<IQQIQQ", 5000, 1_073_741_824, 512_000_000, 8, 25_000, 1_700_000_000)
    t0 = time.perf_counter_ns()
    hashlib.sha256(packed).digest()
    return (time.perf_counter_ns() - t0) / 1_000_000  # ms


def time_hkdf_derivation() -> float:
    behavior_digest = hashlib.sha256(b"\x00" * 40).digest()
    prev_hash = b"\x00" * 32
    nonce = b"\xab" * 32
    ikm = K_STATIC + behavior_digest + prev_hash
    t0 = time.perf_counter_ns()
    hkdf = HKDF(hashes.SHA256(), length=32, salt=nonce,
                 info=b"sentinelmark-bew-v1", backend=default_backend())
    hkdf.derive(ikm)
    return (time.perf_counter_ns() - t0) / 1_000_000  # ms


def run_simulation():
    print(f"[sim_latency] Running {ITERATIONS} iterations...")
    rows = []

    bd_times = [time_behavior_digest() for _ in range(ITERATIONS)]
    hkdf_times = [time_hkdf_derivation() for _ in range(ITERATIONS)]
    total_times = [a + b for a, b in zip(bd_times, hkdf_times)]

    def stats(data, label):
        arr = np.array(data)
        return {
            "component": label,
            "p50_ms": round(float(np.percentile(arr, 50)), 4),
            "p95_ms": round(float(np.percentile(arr, 95)), 4),
            "p99_ms": round(float(np.percentile(arr, 99)), 4),
            "mean_ms": round(float(np.mean(arr)), 4),
            "std_ms": round(float(np.std(arr)), 4),
        }

    rows.append(stats(bd_times, "behavior_digest_sha256"))
    rows.append(stats(hkdf_times, "hkdf_sha256_derivation"))
    rows.append(stats(total_times, "total_crypto_pipeline"))

    for r in rows:
        print(f"  [{r['component']}] p50={r['p50_ms']}ms p95={r['p95_ms']}ms p99={r['p99_ms']}ms")

    output_path = os.path.join(RESULTS_DIR, "latency_baseline.csv")
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"[sim_latency] Results written to: {output_path}")


if __name__ == "__main__":
    run_simulation()
