# ATTACK MODEL — SentinelMark Adversarial Threat Analysis

**Project:** SentinelMark / ProofTrace  
**Author:** Bibek Das — B.Tech ECE, Guru Nanak Institute of Technology  
**Classification:** Research Documentation — Phase 3 Forensic Evaluation

---

## 1. Threat Scope

SentinelMark defends against adversaries who have achieved **partial compromise** of the telemetry-emitting device — meaning they can observe network traffic, read process memory, or inject events into the pipeline, but do **not** yet possess `K_static` (the long-term hardware secret).

The system assumes a **Dolev-Yao network model**: the adversary controls the communication channel between the Rust telemetry client and the Python verification authority.

---

## 2. Attack Taxonomy

### ATK-01 — Replay Attack
**Description:** Attacker captures a legitimately verified telemetry event and retransmits it verbatim to the verification authority at a later time.

**Objective:** Make the verifier accept a stale or duplicated event as fresh, potentially concealing a gap in genuine telemetry (e.g., masking downtime after compromise).

**Detection Mechanism:**
- **Nonce deduplication**: Each event carries a 256-bit CSPRNG nonce. The `NonceCache` table stores all nonces seen within a 60-second sliding window. A replayed packet carries an already-seen nonce → immediately rejected as `REPLAY_ATTACK`.
- **Timestamp drift validation**: All events must arrive within ±30 seconds of the verifier's UTC clock. Delayed replays that exceed this window are rejected as `TIMESTAMP_VIOLATION`.

**Trust Score Impact:** `replay_absent` dimension loses 0.20 weight → trust drops to maximum 0.80.

---

### ATK-02 — Forged Watermark Attack
**Description:** Attacker fabricates a telemetry event without possessing `K_static`, using guessed or static bytes for the `watermark` field.

**Objective:** Inject false telemetry (e.g., fake "device healthy" signals) to mislead the forensic authority.

**Detection Mechanism:**
- **BEW Recomputation**: The verifier independently derives `W_i = HKDF-SHA256(K_static || BehaviorFingerprint_i || H_prev, salt=nonce)`.
- **Constant-time comparison**: `hmac.compare_digest(expected, received)` ensures a timing oracle cannot be used to guess `K_static` byte-by-byte.
- A forged watermark produces a different 256-bit output with probability `1 - 2^{-256}`.

**Trust Score Impact:** `watermark_valid` dimension fails → trust drops to maximum 0.30.

---

### ATK-03 — Hash Chain Tampering
**Description:** Attacker deletes, reorders, or inserts events in the telemetry log between the Rust client and the Python authority.

**Objective:** Remove incriminating events from the forensic record or inject false historical context.

**Detection Mechanism:**
- **Chain linkage validation**: Every event commits to its predecessor's `current_hash` via the `prev_hash` field. The verifier queries its last persisted `current_hash` for the device and compares.
- Deleting any event breaks the chain permanently — all subsequent events fail `prev_hash` linkage.

**Trust Score Impact:** `chain_valid` dimension fails → trust drops to maximum 0.65.

---

### ATK-04 — Timestamp Forgery
**Description:** Attacker manipulates the `captured_at` timestamp of an event to bypass the drift window (e.g., setting it to the current UTC time on a replayed old event).

**Objective:** Allow stale or replayed events to pass timestamp validation.

**Detection Mechanism:**
- Even with a forged timestamp, the **nonce remains the same**. The `NonceCache` will reject the duplicate nonce before timestamp checks can be bypassed.
- Additionally, the BEW watermark binds `H_prev` to the event — changing `captured_at` in the JSON does not affect the watermark, but it **is** included in the `current_hash` pre-image, causing chain validation to fail.

**Trust Score Impact:** Either `replay_detected=True` or `chain_valid=False`.

---

### ATK-05 — Synthetic Behavioral Replay (Mimicry Attack)
**Description:** Attacker who possesses `K_static` (post-compromise scenario) generates fresh telemetry with hardcoded behavioral metrics, attempting to appear as a healthy device while the actual device is offline or compromised.

**Objective:** Maintain an apparently healthy telemetry stream post-compromise.

**Detection Mechanism:**
- **Z-score anomaly detection**: Real hardware exhibits stochastic variance in CPU scheduling jitter (`jitter_ns`), memory usage, and CPU load. Synthetically generated telemetry typically hardcodes these values, leading to:
  - **Entropy collapse** (σ ≈ 0 across jitter_ns): flagged when `std < 1e-4`.
  - **Z-score violation**: If the synthetic values differ statistically from the device's own historical baseline (`Z > 3.0`), `behavior_anomaly=True`.

**Trust Score Impact:** `behavior_authentic` dimension fails → trust drops to maximum 0.95.

> **Note:** Behavioral analysis is a _soft_ signal. It cannot substitute for cryptographic controls but provides an orthogonal detection layer against sophisticated adversaries.

---

### ATK-06 — Entropy Collapse Attack
**Description:** Special case of ATK-05 where the adversary sends identical behavioral snapshots across multiple events (e.g., all values = 0 or all values = constant).

**Detection:** Standard deviation across the behavioral rolling window collapses to `σ ≈ 0`. The analyzer flags this with a synthetic sentinel `z_score = 99.0` and sets `behavior_anomaly=True`.

---

## 3. Defense-in-Depth Summary

| Attack | Primary Defense | Secondary Defense | Trust Dimension Lost |
|--------|----------------|------------------|----------------------|
| ATK-01 Replay | Nonce cache | Timestamp drift | replay_absent (−0.20) |
| ATK-02 Forgery | HKDF-SHA256 recomputation | Constant-time compare | watermark_valid (−0.40) |
| ATK-03 Chain Tamper | DB-backed chain linkage | prev_hash comparison | chain_valid (−0.25) |
| ATK-04 Timestamp Forge | Nonce cache (still catches replay) | current_hash includes timestamp | replay/chain |
| ATK-05 Mimicry | Z-score behavioral analysis | Entropy collapse detection | behavior_authentic (−0.05) |
| ATK-06 Entropy Collapse | σ ≈ 0 detection | Sentinel z-score = 99.0 | behavior_authentic (−0.05) |

---

## 4. Out-of-Scope Threats

- Compromise of the OS CSPRNG source (`/dev/urandom` or Windows `BCryptGenRandom`).
- Physical side-channel attacks on `K_static` storage (DPA, bus probing).
- Vulnerabilities in the underlying `cryptography` / `ring` crate implementations.
- Multi-device collusion attacks (out of scope for single-node MVP).
