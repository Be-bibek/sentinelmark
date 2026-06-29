# Getting Started with SentinelMark

SentinelMark is a developer-first Trust Infrastructure platform. It allows you to rapidly embed Enterprise-grade Risk and Trust engines into your products without managing the underlying machine learning models or behavioral telemetry yourself.

## How it works

SentinelMark sits between your backend applications and your users.

1. **Ingest**: Your servers send a specialized JSON `EventIngestRequest` to SentinelMark containing product-specific metadata (e.g. DICOM watermarks, 5G signal patterns, or Ethereum transactions).
2. **Analyze**: SentinelMark's Trust Engine evaluates the event in real-time against your historical telemetry and configured policies.
3. **Decide**: SentinelMark synchronously returns an `ActionPolicy` (e.g., `ALLOW`, `BLOCK`, `MFA`, `REVIEW`) alongside a calculated Risk and Trust score.

## First Steps
1. **Create an Organization** in the [Dashboard](https://app.sentinelmark.ai).
2. **Generate an API Key** for your project.
3. **Install an Official SDK** (Python, Node.js, Rust, or Go).
4. **Send your first Event**.

```python
from sentinelmark import SentinelMark

client = SentinelMark(api_key="sm_live_...")
response = client.events.evaluate(
    product_slug="dicom-trace",
    event_type="scan",
    payload={ "modality": "CT" }
)
print(response["data"]["decision"])
```
