# Security Policy 🔒

## Supported Versions

Only the current active release stream receives security updates and constant-time algorithmic audits.

| Version | Supported | Notes |
| ------- | --------- | ----- |
| **0.1.x** | ✅ Yes | Active development and pre-publication branch. |
| **< 0.1.0** | ❌ No | Deprecated proof-of-concept drafts. |

---

## Reporting a Vulnerability

We treat our research and production infrastructure security with absolute urgency. If you discover a cryptographic side-channel, timing leakage, memory safety gap, or protocol authentication bypass within SentinelMark, please report it privately.

**Do NOT open a public GitHub issue.**

### Contact Information
Please email your findings directly to **Bibek Das** at:
📧 **[bibekdas1055@gmail.com](mailto:bibekdas1055@gmail.com)**

### Disclosure Process
1. **Acknowledgement**: You will receive confirmation of receipt within 48 hours.
2. **Triage & Patch**: We will analyze the submission, reproduce the side-channel or vector, and develop a constant-time or memory-safe mitigation.
3. **Notification**: Once the patch is merged into our upstream security branch, coordinated public disclosure will take place with full attribution to the researcher.

---

## 🛡️ Scope & Threat Model Covered

SentinelMark's protocol architecture actively guarantees protection against the following adversarial vectors:

### 1. Replay Attacks
* **Vector**: An attacker intercepts a previously verified telemetry packet over the wire and retransmits it verbatim.
* **Mitigation**: Bounded sliding-window nonce caching combined with arrival timestamp drift verification ($\pm 30\text{s}$) guarantees immediate rejection (`DuplicateNonce` or `Expired`).

### 2. Forged Telemetry
* **Vector**: A compromised node or man-in-the-middle attempts to fabricate an arbitrary telemetry event without possessing the static hardware secret.
* **Mitigation**: The watermark $W_i$ binds directly to the payload's content via HKDF-SHA256. Altering a single bit of the payload changes the internal canonical pre-image, invalidating the derived signature.

### 3. Log Reordering & Deletion
* **Vector**: An internal adversary selectively drops specific forensic events to conceal malicious access.
* **Mitigation**: Strict append-only hash chains ensure every single event's commitment relies on its predecessor's output. A dropped event permanently breaks all future evaluations (`PrevHashMismatch`).

### 4. Memory/Stack Scraping
* **Vector**: Post-compromise memory dumps attempting to pull long-term static signing keys.
* **Mitigation**: All secret arrays explicitly implement the `zeroize` trait to actively overwrite registers and stack bounds immediately after watermarking.

---

## Out of Scope
* Physical hardware level side-channel attacks (e.g., differential power analysis or direct bus-probing) on the static key storage module before it is ingested by the Rust Engine.
* Compromise of the OS Kernel CSPRNG source (`/dev/urandom` or Windows `BCryptGenRandom`). If the operating system's root entropy is poisoned, CSPRNG assumptions fail globally.
