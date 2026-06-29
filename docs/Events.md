# Events & Evaluation

The core of SentinelMark is the Trust Engine, which analyzes real-time `Events` to detect fraud, anomalies, or malicious intent. An event represents any interaction a user or system has with your platform (e.g. a login attempt, a medical scan upload, a 5G network handshake, or a financial transaction).

When you send an event to `.evaluate()`, SentinelMark assigns it two unique scores:

## Risk Score (0.0 to 1.0)
The Risk Score represents the probability that the event is anomalous, malicious, or violates established behavioral baselines.
- `0.0 - 0.3`: Low Risk (Normal behavior).
- `0.4 - 0.7`: Medium Risk (Suspicious, potentially requires step-up authentication).
- `0.8 - 1.0`: High Risk (Highly anomalous, active threat).

## Trust Score (0.0 to 1.0)
The Trust Score evaluates the historical reputation of the actor (user, device, or network) performing the event. High trust reduces the friction applied by the Risk Score.
- `0.0 - 0.3`: Untrusted (New devices, previous bad behavior, tor nodes).
- `0.4 - 0.7`: Established (Known users with normal patterns).
- `0.8 - 1.0`: Highly Trusted (Long-standing, verified, multi-factor authenticated users).

## The Action Policy
Based on the combination of Risk and Trust, the Policy Engine returns a definitive `ActionPolicy` string:
- `ALLOW`: Proceed normally.
- `BLOCK`: Reject the request immediately.
- `MFA`: Prompt for Multi-Factor Authentication.
- `REVIEW`: Send to a human analyst (useful in fintech).
