"""
app/verification/hkdf_verifier.py — BEW Watermark Recomputation (HKDF-SHA256)

Maps exactly to the Rust WatermarkEngine::derive() method.
Cross-language binary parity is enforced via:
  - struct.pack("<IQQIQQ") matching Rust's .to_le_bytes()
  - HKDF-SHA256 via OpenSSL C-bindings (cryptography library)
  - info=b"sentinelmark-bew-v1" matching HKDF_INFO in crypto/mod.rs
  - constant-time comparison via hmac.compare_digest()
"""

import hmac
import struct
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from app.schemas.telemetry import BehaviorSnapshot

# K_static — loaded from environment. Must be 32 bytes.
# Production: inject via OS secret manager or HSM.
import os
_K_STATIC_HEX = os.getenv(
    "SENTINEL_K_STATIC",
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
)
K_STATIC: bytes = bytes.fromhex(_K_STATIC_HEX)

HKDF_INFO = b"sentinelmark-bew-v1"
WATERMARK_LEN = 32


def compute_behavior_digest(snap: BehaviorSnapshot) -> bytes:
    """
    Deterministic SHA-256 of the BehaviorSnapshot.
    
    Matches Rust's BehaviorSnapshot::to_digest() exactly:
      struct.pack("<IQQIQQ") ↔ u32.to_le_bytes() || u64.to_le_bytes() * 4 || u32.to_le_bytes() || u64.to_le_bytes()
    
    Field order is fixed by the Rust struct definition and MUST NOT change without
    a schema_version bump on both sides.
    """
    packed = struct.pack(
        "<IQQIQQ",
        snap.cpu_usage_pct_x100,       # u32 (I)
        snap.virtual_memory_bytes,      # u64 (Q)
        snap.physical_memory_bytes,     # u64 (Q)
        snap.thread_count,              # u32 (I)
        snap.jitter_ns,                 # u64 (Q)
        snap.captured_at_unix_secs,     # u64 (Q)
    )
    return hashlib.sha256(packed).digest()


def derive_bew_watermark(
    behavior_digest: bytes,
    prev_hash: bytes,
    nonce: bytes,
) -> bytes:
    """
    W_i = HKDF-SHA256(
        IKM  = K_static || BehaviorFingerprint_i || H_prev,
        salt = nonce_i,
        info = b"sentinelmark-bew-v1"
    )
    """
    ikm = K_STATIC + behavior_digest + prev_hash
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=WATERMARK_LEN,
        salt=nonce,
        info=HKDF_INFO,
        backend=default_backend(),
    )
    return hkdf.derive(ikm)


def verify_watermark(expected: bytes, received: bytes) -> bool:
    """Constant-time comparison. Neutralizes timing oracle attacks on K_static."""
    return hmac.compare_digest(expected, received)
