import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from app.schemas.telemetry import BehaviorSnapshot

# For MVP, we load K_static from environment/config. Must be 32 bytes.
# In a real system, this is fetched securely via HSM or secure vault.
K_STATIC_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
K_STATIC = bytes.fromhex(K_STATIC_HEX)

def compute_behavior_digest(snap: BehaviorSnapshot) -> bytes:
    """
    Deterministically computes the BehaviorFingerprint_i.
    
    Matches Rust's binary packing logic:
    - Fixed field ordering
    - Little-endian encoding ("<")
    - Types: u32 (I), u64 (Q), u64 (Q), u32 (I), u64 (Q), u64 (Q)
    """
    packed_bytes = struct.pack(
        "<IQQIQQ",
        snap.cpu_usage_pct_x100,
        snap.virtual_memory_bytes,
        snap.physical_memory_bytes,
        snap.thread_count,
        snap.jitter_ns,
        snap.captured_at_unix_secs,
    )
    return hashlib.sha256(packed_bytes).digest()

def derive_bew_watermark(
    k_static: bytes,
    behavior_digest: bytes,
    prev_hash: bytes,
    nonce: bytes
) -> bytes:
    """
    Derives the Behavior-Entangled Watermark (W_i).
    
    W_i = HKDF-SHA256(
        IKM = K_static || BehaviorFingerprint_i || H_prev,
        salt = nonce_i,
        info = b"sentinelmark-bew-v1"
    )
    """
    ikm = k_static + behavior_digest + prev_hash
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce,
        info=b"sentinelmark-bew-v1",
        backend=default_backend()
    )
    
    return hkdf.derive(ikm)

def verify_watermark_constant_time(expected: bytes, received: bytes) -> bool:
    """
    Constant-time comparison to prevent timing side-channel oracle attacks.
    """
    return hmac.compare_digest(expected, received)
