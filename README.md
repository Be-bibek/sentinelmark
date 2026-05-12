# SentinelMark Cryptographic Engine 🛡️

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![E2E Tests](https://img.shields.io/badge/tests-36%2F36%20passed-success.svg)]()

**SentinelMark** is the core cryptographic trust primitive and forensic telemetry subsystem for the **ProofTrace** cybersecurity infrastructure platform. It introduces a highly resilient, research-grade implementation of **Behavior-Entangled Watermarking (BEW)**.

By cryptographically fusing long-term static hardware secrets with live, continuous behavioral entropy snapshots, SentinelMark ensures that emitted telemetry cannot be forged, replayed, or fabricated post-compromise.

---

## 🔬 Core Derivation Primitive

Valid watermark tokens require the strict mathematical intersection of both the secret key and the instantaneous runtime behavioral state of the host device.

The derivation equation is defined as:

$$W_i = \text{HKDF-SHA256}(K_{\text{static}} \parallel \text{BehaviorFingerprint}_i \parallel H_{\text{prev}})$$

Where:
* **$K_{\text{static}}$**: The long-term static device secret (zeroized securely from stack/heap post-derivation).
* **$\text{BehaviorFingerprint}_i$**: A deterministic serialization of the live rolling behavioral entropy snapshot (CPU scheduling jitter, thread allocations, virtual/physical memory boundaries).
* **$H_{\text{prev}}$**: The SHA-256 hash commitment linking the current event to its immediate predecessor, establishing an unforgeable, append-only chronological hash chain.

---

## 🚀 Subsystem Architecture

The architecture is fully modularized and split across highly specialized sub-engines built entirely in safe Rust (with strictly audited constant-time FFI primitives).

```text
sentinelmark_core
+-- behavior  -- Runtime behavioral entropy capture (CPU, virtual/physical memory, OS Jitter)
+-- crypto    -- Core audited wrappers (HKDF-SHA256, SHA-256 via ring, constant-time comparisons via subtle)
+-- watermark -- BEW Derivation engine enforcing StaticKey drop-zeroization
+-- chain     -- Append-only cryptographic hash chain manager & link verifier
+-- telemetry -- Dual-serialization schema (serde JSON + zero-copy rkyv) & pre-image projection logic
+-- verifier  -- Remote validation logic incorporating sliding-window replay detection
+-- transport -- Resilient async dispatch queue with immutable envelopes & exponential backoff
```

### Phase 1 Features
* **Behavioral Entropy Sampler**: Captures live metrics using `sysinfo` v0.30+ alongside high-resolution OS scheduler jitter measurement. Jitter acts as a stochastic anti-tampering constraint.
* **Append-Only Hash Chaining**: Prevents log reordering, deletion, or insertion attacks. Any structural manipulation permanently corrupts subsequent chain linkages.
* **Deterministic Dual-Serialization**: Canonical JSON (`serde_json`) for human-inspectable REST delivery; zero-copy deserialization archives (`rkyv`) for extreme throughput benchmarking.
* **Pre-Image Projection Fix**: Eliminates cryptographic circularity by projecting the event schema to exclude `current_hash` during its own pre-image calculation, guaranteeing exact verification determinism.

### Phase 2 Features
* **Hardened Replay Protection Engine**:
  * **O(1) Nonce Cache**: Eagerly flags exact payload collisions using 256-bit CSPRNG nonces.
  * **Timestamp Drift Validation**: Enforces tight arrival windows ($\pm 30\text{s}$) to reject delayed re-transmissions and future-skewed packets.
  * **O(log N) Priority Queue Eviction**: Maintains a self-pruning `BTreeSet` keyed by timestamp to automatically garbage collect stale nonces, eliminating arbitrary memory expansion (OOM resilience).
* **Async Telemetry Transport Layer**:
  * **Immutable Envelopes**: Pre-serializes canonical payloads at the exact moment of event finalization. Retries never invoke `serde` routines, protecting nonces and timestamps from shifting across TCP reattempts.
  * **Resilient Worker Queue**: Non-blocking `tokio::sync::mpsc` queue decoupling generation loops from network bottlenecks.
  * **Deterministic Backoff**: Applies base-multiplied exponential retry delays strictly on transient backend status codes (`5xx`, `429`).

---

## 🛡️ Security Best Practices Enforced

1. **Constant-Time Verification**: All security-critical array and digest comparisons pass directly through `subtle::ConstantTimeEq` to completely neutralize timing side-channel attacks.
2. **Key Material Zeroization**: Static secret arrays implement `zeroize::ZeroizeOnDrop` ensuring sensitive key material is wiped directly from register arrays and stack pointers immediately upon scope exit.
3. **Immutability Boundaries**: Payloads are locked into immutable arrays prior to dispatch. Network transport cannot modify context states.

---

## 📦 Getting Started

### Prerequisites
* Rust Toolchain `1.75` or higher.
* Platform compilation tools (Windows MSVC, Linux GNU, or macOS LLVM).

### Testing & Verification
Execute the entire hardened test suite covering unit validation, behavioral anti-tampering bounds, integration execution, and network retry exhaustion simulations:

```bash
cargo test --workspace
```

Run Criterion evaluation targets (requires enabling compilation feature flags):

```bash
cargo bench --features "bench-mode"
```

---

## 📜 Usage Example

```rust
use sentinelmark_core::{
    behavior::BehaviorSnapshot,
    chain::{ChainManager, GENESIS_HASH},
    telemetry::TelemetryEvent,
    watermark::{StaticKey, WatermarkEngine},
};

// 1. Initialize Long-Term Secrets
let secret_key = StaticKey::from_bytes([0xAA; 32]);
let mut engine = WatermarkEngine::new(secret_key);
let mut chain = ChainManager::new();

// 2. Generate and Watermark Telemetry Payload
let payload = serde_json::json!({"action": "kernel_auth", "user_id": 1024});
let mut event = TelemetryEvent::new("device-host-001", GENESIS_HASH, payload).unwrap();

// Derive BEW Watermark binding current entropy and historical hash commitments
let snapshot = BehaviorSnapshot::capture().unwrap();
let watermark = engine.derive(&snapshot, &event.prev_hash);
event.set_watermark(watermark.into_bytes());

// 3. Finalize Hash Linkage
event.finalize().unwrap();
chain.append(&event).unwrap();

// Payload is ready for immutable transport dispatch!
```

---

## 🎓 Author & Attribution

**Bibek Das**  
* B.Tech Scholar, **Electronics and Communication Engineering (ECE)**  
* **Guru Nanak Institute of Technology**  
* Email: [bibekdas1055@gmail.com](mailto:bibekdas1055@gmail.com)  
* GitHub: [@Be-bibek](https://github.com/Be-bibek)  

---

## ⚖️ License

This project is open-sourced under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for complete details and patent grant conditions.
