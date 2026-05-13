# FORENSIC EVALUATION — Protocol Security Guarantees

**Project:** SentinelMark / ProofTrace  
**Author:** Bibek Das — B.Tech ECE, Guru Nanak Institute of Technology

---

## 1. Security Claim Summary

SentinelMark provides the following verifiable security guarantees under the stated threat model:

| Claim | Guarantee | Mechanism |
|-------|-----------|-----------|
| **C1** | Forged telemetry is rejected with probability ≥ `1 - 2^{-256}` | HKDF-SHA256 watermark; 256-bit output space |
| **C2** | Replayed events are always rejected within the 60s window | SQLite-backed nonce cache; eager pruning |
| **C3** | Deleted or reordered events break chain integrity detectably | SHA-256 append-only hash chain linkage |
| **C4** | Entropy-collapsed synthetic telemetry is flagged after 10 events | Z-score > 3.0 or σ < 1e-4 detection |
| **C5** | Timing oracle attacks on `K_static` are neutralized | `hmac.compare_digest()` constant-time comparison |
| **C6** | Partial forensic writes cannot corrupt the audit ledger | SQLAlchemy transaction atomicity; rollback on failure |

---

## 2. Formal Claim Proofs (Informal)

### C1 — Forgery Resistance
An attacker without `K_static` must guess `W_i ∈ {0,1}^{256}`. By the PRF security of HKDF-SHA256 (under HMAC-SHA256), the probability of a successful guess is bounded by `q / 2^{256}` for `q` guesses. For any computationally bounded adversary, this is negligible.

### C2 — Replay Resistance
The `NonceCache` stores all nonces seen within a `[t - 60s, t]` sliding window. A replayed event carries an identical nonce. The `exists()` check returns `True`, immediately flagging `replay_detected = True`. The only bypass is generating a fresh nonce — but this requires `K_static` to derive a valid watermark (reduces to C1).

### C3 — Chain Integrity
SHA-256 is collision-resistant. Altering, deleting, or inserting any event `e_i` changes `H_i = SHA256(pre_image_i)`. Since `H_i` is embedded as `prev_hash` in `e_{i+1}`, all downstream events fail chain validation. An adversary cannot forge a valid `H_i` without a SHA-256 collision (computationally infeasible).

### C5 — Constant-Time Guarantee
Python's `hmac.compare_digest()` is implemented in CPython using a loop that always runs for the full length of both operands regardless of where the first difference occurs. This prevents timing-based byte-by-byte oracle attacks.

---

## 3. Trust Score Calibration

The 5-dimensional trust score is designed so that:

| Scenario | Expected Score |
|---------|---------------|
| Fully verified, no anomaly | `1.00` |
| Verified but behavioral anomaly | `0.95` |
| Replay detected | `0.75` (watermark+chain+timestamp) |
| Timestamp drift violation | `0.65` (watermark+chain+replay) |
| Chain broken | `0.55` (watermark+replay+timestamp+behavior) |
| Forged watermark | `0.30` (replay+timestamp only) |
| Forged watermark + replay | `0.10` (timestamp only) |
| Complete failure | `0.00` |

---

## 4. Network Trust Index (NTI)

```
NTI = 1.0 - (tamper_count + replay_count + anomaly_count) / total_processed
```

NTI is a network-level health metric ranging from `0.0` (fully compromised network) to `1.0` (all telemetry verified clean). It is exposed at `GET /dashboard/metrics` and intended for aggregate monitoring rather than per-event decisions.

---

## 5. Identified Limitations and Mitigations

| Limitation | Severity | Mitigation Path |
|-----------|----------|----------------|
| `K_static` exfiltration enables full forgery | Critical | Hardware attestation (TPM 2.0, SGX enclave) |
| SQLite single-writer bottleneck at high ingestion rates | Medium | Migrate to PostgreSQL asyncpg for production |
| Behavioral analysis vulnerable to informed mimicry | Low | Add entropy source diversification (network timing, disk I/O jitter) |
| Cold-start window (< 10 events) has no behavioral coverage | Low | Accept as engineering tradeoff; log warning level |
