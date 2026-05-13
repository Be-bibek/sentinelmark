# TRUST PIPELINE — Verification Architecture Specification

**Project:** SentinelMark / ProofTrace  
**Author:** Bibek Das — B.Tech ECE, Guru Nanak Institute of Technology

---

## 1. Pipeline Overview

Every telemetry event submitted to `POST /ingest` traverses a **strictly ordered**, **fail-fast** 4-stage verification pipeline. Stages execute sequentially. Failure at any stage triggers immediate verdict persistence and response — subsequent stages do not execute.

```
POST /ingest
     │
     ▼
┌─────────────────────────────────────┐
│ STAGE 1: Structural Validation      │  Pydantic schema enforcement
│  - UUID format                      │  256-bit hex length validation
│  - 64-char hex constraints          │  BehaviorSnapshot field bounds
│  - schema_version = 1               │
└────────────────┬────────────────────┘
                 │ ✓
                 ▼
┌─────────────────────────────────────┐
│ STAGE 2: Cryptographic Integrity    │
│  - Recompute BehaviorFingerprint_i  │  struct.pack("<IQQIQQ") → SHA-256
│  - Derive W_i via HKDF-SHA256       │  IKM = K_static || BehFP || H_prev
│  - Constant-time watermark compare  │  hmac.compare_digest()
│  - Validate chain linkage           │  DB prev_hash lookup
│  - Validate current_hash            │  SHA-256 pre-image recomputation
└────────────────┬────────────────────┘
                 │ ✓
                 ▼
┌─────────────────────────────────────┐
│ STAGE 3: Replay Validation          │
│  - Timestamp drift check ±30s       │  datetime.now(UTC) comparison
│  - Nonce existence check            │  NonceCache DB lookup (O(1))
│  - Prune expired nonces             │  DELETE WHERE expires_at < NOW
│  - Record fresh nonce               │  INSERT with 60s expiry
└────────────────┬────────────────────┘
                 │ ✓
                 ▼
┌─────────────────────────────────────┐
│ STAGE 4: Behavioral Analysis        │  Skipped if < 10 historical events
│  - Fetch 50-event rolling window    │
│  - Compute Z-scores (CPU, mem, jit) │  Z = |x - μ| / σ
│  - Entropy collapse detection       │  σ < 1e-4 → anomaly flag
│  - Runs in thread executor          │  Non-blocking asyncio
└────────────────┬────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│ Trust Score Computation             │
│  watermark_valid:  × 0.40           │
│  chain_valid:      × 0.25           │
│  replay_absent:    × 0.20           │
│  timestamp_valid:  × 0.10           │
│  behavior_auth:    × 0.05           │
│  ─────────────────────────          │
│  trust_score ∈ [0.0, 1.0]          │
└────────────────┬────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│ Persist ForensicVerdict             │  Append-only TelemetryLog INSERT
│ Return JSON Response                │  ForensicVerdict schema
└─────────────────────────────────────┘
```

---

## 2. Stage Failure Behavior

| Stage | Failure Condition | verdict.verified | Pipeline continues? |
|-------|------------------|-----------------|---------------------|
| Stage 1 | Pydantic ValidationError | — (422 HTTP) | No (framework rejects) |
| Stage 2 | Watermark mismatch | False | No |
| Stage 2 | Chain linkage broken | False | No |
| Stage 3 | Timestamp drift > 30s | False | No |
| Stage 3 | Nonce already in cache | False | No |
| Stage 4 | Z-score > 3.0 | False | Yes (verdict degraded) |
| Stage 4 | Entropy collapse | False | Yes (verdict degraded) |
| All Pass | — | True (score=1.0) | — |

---

## 3. BEW Watermark Derivation (Cross-Language Parity)

The Python verifier must produce identical output to the Rust `WatermarkEngine::derive()` method.

**Rust implementation:**
```rust
// IKM = K_static (32B) || BehaviorFingerprint (32B) || H_prev (32B)
let mut ikm = Vec::with_capacity(96);
ikm.extend_from_slice(self.static_key.as_ref());
ikm.extend_from_slice(behavior.as_ref());
ikm.extend_from_slice(prev_hash.as_ref());
// HKDF-SHA256(IKM, salt=nonce, info=b"sentinelmark-bew-v1")
let secret = hkdf_derive(&ikm, nonce, HKDF_INFO)?;
```

**Python implementation:**
```python
# BehaviorFingerprint: struct.pack("<IQQIQQ") → sha256 digest
# Matches Rust's to_le_bytes() field-by-field encoding
packed = struct.pack("<IQQIQQ",
    snap.cpu_usage_pct_x100,    # u32 → I
    snap.virtual_memory_bytes,   # u64 → Q
    snap.physical_memory_bytes,  # u64 → Q
    snap.thread_count,           # u32 → I
    snap.jitter_ns,              # u64 → Q
    snap.captured_at_unix_secs,  # u64 → Q
)
behavior_digest = hashlib.sha256(packed).digest()

# HKDF-SHA256 via OpenSSL C-bindings
ikm = K_STATIC + behavior_digest + prev_hash
hkdf = HKDF(SHA256(), length=32, salt=nonce, info=b"sentinelmark-bew-v1")
watermark = hkdf.derive(ikm)
```

**Parity guarantee:** Both implementations produce identical 32-byte outputs for identical inputs. This is validated by the `test_known_good_output_vector` Rust test.

---

## 4. Forensic Persistence Invariant

> **TelemetryLog rows are never updated or deleted.**

Every call to `POST /ingest` produces exactly one `TelemetryLog` row, regardless of verdict. This guarantees:
- Complete, tamper-evident audit history.
- Replay attack patterns are visible in the ledger even if rejected.
- Forensic investigators can reconstruct the full event timeline.
