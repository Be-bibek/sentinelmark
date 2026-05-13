# EXPERIMENTAL METHOD — Reproducible Adversarial Evaluation

**Project:** SentinelMark / ProofTrace  
**Author:** Bibek Das — B.Tech ECE, Guru Nanak Institute of Technology

---

## 1. Evaluation Objectives

The adversarial evaluation framework (`benchmarks/attacks/`) is designed to produce:
1. **Detection Rate (DR)**: fraction of adversarial events correctly flagged.
2. **False Positive Rate (FPR)**: fraction of legitimate events incorrectly rejected.
3. **Latency distribution**: p50/p95/p99 ingestion latency under each attack type.
4. **Trust Score degradation curves**: how trust score evolves over a sustained attack.

All results are emitted as **CSV files** for reproducible analysis and IEEE figure generation.

---

## 2. Attack Simulation Scripts

| Script | Attack Simulated | Output |
|--------|----------------|--------|
| `sim_replay.py` | ATK-01: Replay Attack | `results/replay_detection.csv` |
| `sim_forgery.py` | ATK-02: Forged Watermark | `results/forgery_detection.csv` |
| `sim_entropy_collapse.py` | ATK-06: Entropy Collapse | `results/entropy_collapse.csv` |
| `sim_latency.py` | Ingestion Latency Baseline | `results/latency_baseline.csv` |

---

## 3. Experimental Configuration

```python
# Shared configuration for all attack simulations
NUM_LEGITIMATE_EVENTS = 100    # Warmup: establish device baseline history
NUM_ADVERSARIAL_EVENTS = 50    # Attack payload: injected after warmup
DEVICE_ID = "sim-device-eval-001"
K_STATIC_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
```

**Reproducibility:** All simulations use deterministic seeding for behavioral metric generation. Results are bit-reproducible across runs on the same platform.

---

## 4. Expected Experimental Outcomes

### Replay Attack (ATK-01)
- Detection Rate: **100%** (cryptographic guarantee — nonce is deterministic)
- False Positive Rate: **0%** for non-duplicate nonces within drift window

### Forgery Attack (ATK-02)
- Detection Rate: **100%** (HKDF-SHA256 preimage resistance)
- False Positive Rate: **0%** for correctly derived watermarks

### Entropy Collapse (ATK-06)
- Detection Rate: **~98%** (requires ≥ 10 event warmup)
- False Positive Rate: **< 1%** empirically expected at 3σ threshold

---

## 5. CSV Output Format

```
event_id,attack_type,detected,trust_score,z_score_cpu,z_score_memory,z_score_jitter,latency_ms
uuid,replay,true,0.75,,,,2.1
uuid,forgery,true,0.30,,,,1.8
uuid,entropy_collapse,true,0.95,99.0,99.0,99.0,3.2
```

---

## 6. Running the Evaluation

```bash
# Install dependencies
pip install -e ".[dev]"

# Run full attack simulation suite
python benchmarks/attacks/sim_replay.py
python benchmarks/attacks/sim_forgery.py
python benchmarks/attacks/sim_entropy_collapse.py
python benchmarks/attacks/sim_latency.py

# Results written to benchmarks/results/
```
