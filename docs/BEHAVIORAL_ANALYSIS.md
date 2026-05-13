# BEHAVIORAL ANALYSIS — Statistical Authenticity Methodology

**Project:** SentinelMark / ProofTrace  
**Author:** Bibek Das — B.Tech ECE, Guru Nanak Institute of Technology

---

## 1. Motivation

Cryptographic watermarks prove that `K_static` was present during event generation. They cannot prove that the **host device itself** is operating authentically. An attacker who exfiltrates `K_static` can generate cryptographically valid telemetry from a virtual machine with artificially constructed behavioral metrics.

The **BehavioralAnalyzer** provides an orthogonal, statistical authenticity layer based on the observation that real hardware exhibits **continuous stochastic variation** — entropy — in its behavioral metrics. Synthetic generators typically produce either:

1. **Entropy Collapse**: identical values repeated across events (zero variance).
2. **Distribution Shift**: values statistically inconsistent with the device's established behavioral baseline.

---

## 2. Tracked Metrics

| Metric | Rust Field | Physical Meaning | Units |
|--------|-----------|-----------------|-------|
| CPU Load | `cpu_usage_pct_x100` | CPU utilization × 100 | Integer, [0, 10000] |
| Physical Memory | `physical_memory_bytes` | RSS memory usage | Bytes |
| OS Jitter | `jitter_ns` | Scheduler wake-up latency | Nanoseconds |

---

## 3. Rolling Window Architecture

```
Historical Window (last 50 verified events per device_id)
┌────┬────┬────┬────┬────┬────┬────┬────┬────┬────┐
│ e₁ │ e₂ │ e₃ │ .. │ e₄₈│ e₄₉│ e₅₀│ NEW│    │    │
└────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘
                                         ↑
                                  Current event being analyzed
```

- Only **verified, non-tampered, non-replayed** events contribute to the window.
- Window is bounded at 50 to prevent quadratic growth in analysis latency.
- Fetched via indexed DB query `ORDER BY timestamp_utc DESC LIMIT 50`.

---

## 4. Z-Score Anomaly Detection

### 4.1 Mathematical Definition

For each metric `x` (current event value):

$$Z = \frac{|x - \mu|}{\sigma}$$

Where:
- `μ` = arithmetic mean of the historical window
- `σ` = sample standard deviation of the historical window
- `|·|` = absolute value (two-tailed test)

### 4.2 Threshold

**Threshold = 3.0** (3-sigma rule)

Under a normal distribution, values within 3σ of the mean encompass **99.73%** of observations. A Z-score exceeding 3.0 indicates the current value falls in the extreme 0.27% tail — statistically unrealistic for genuine hardware behavior.

### 4.3 Entropy Collapse Detection

If `σ < 1e-4` (standard deviation approaches zero), the metric is considered **entropically collapsed**. This condition indicates:
- All historical values are identical (synthetic constant generation).
- The device's behavioral fingerprint is artificially frozen.

When entropy collapse is detected, a synthetic sentinel value `z_score = 99.0` is assigned to mark the anomaly clearly in the forensic verdict.

---

## 5. Cold Start Handling

| Historical Events | Analysis Mode | anomaly_score |
|-----------------|---------------|---------------|
| `< 5` | Skipped completely | `None` |
| `5 – 9` | Reduced confidence (logged as warning) | Computed but flagged |
| `≥ 10` | Full analysis | Normal |

**Rationale:** With fewer than 10 events, `σ` estimates are highly sensitive to individual outliers. The 10-event minimum ensures the Central Limit Theorem provides reasonable approximation guarantees for the mean and standard deviation estimates.

**Division-by-zero protection:** `σ < 1e-4` check is performed before Z-score computation, entirely preventing a divide-by-zero exception.

---

## 6. Performance Characteristics

- **Computation model**: CPU-bound NumPy operations on arrays of max 50 floats.
- **Execution context**: `asyncio.get_event_loop().run_in_executor(None, ...)` — runs in the default thread pool, preventing blocking of the FastAPI async event loop.
- **Latency estimate**: < 1ms for N=50 window on commodity hardware (NumPy is BLAS-accelerated).
- **Memory bound**: O(50) per device per request — constant. No accumulating state in-process; window is always fetched fresh from DB.

---

## 7. Known Limitations

1. **K_static theft + historical mimicry**: An adversary who steals both `K_static` and a full historical telemetry dump can craft behaviorally consistent synthetic events that pass Z-score thresholds. This is a known limitation of statistical-only behavioral analysis. Mitigation requires hardware attestation (TPM, SGX) at the endpoint.
2. **Behavioral drift over time**: Legitimate devices can exhibit genuine Z-score spikes during OS upgrades, memory pressure events, or scheduled workloads. The threshold of 3.0 is empirically chosen to minimize false positives while detecting synthetic generation.
3. **Bootstrap period**: New devices operate in cold-start mode for their first 10 events with reduced coverage.
