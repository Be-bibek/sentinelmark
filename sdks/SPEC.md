# SentinelMark SDK Core Specification

This document defines the strict, language-agnostic contract that all official SentinelMark SDKs MUST adhere to.
This ensures a uniform developer experience (DX) across Python, Node.js, Rust, and Go.

## 1. Instantiation
All SDKs must expose a main `SentinelMark` client object with the following configuration options:

```text
api_key (string, required)
base_url (string, default: "https://api.sentinelmark.ai")
timeout (int, default: 30) // in seconds
max_retries (int, default: 3) // maximum number of retries for transient errors
debug (bool, default: false) // enables verbose logging
```

## 2. Default Headers
Every API request made by the SDK MUST include:
- `Authorization: Bearer <api_key>`
- `Content-Type: application/json`
- `X-SentinelMark-SDK: <language>` (e.g. `python`, `node`)
- `X-SentinelMark-Version: <sdk_version>` (e.g. `1.0.0`)
- `User-Agent: sentinelmark-<language>/<sdk_version>`
- `X-Request-Id: <uuid>` (Auto-generated per request if not provided)

## 3. Retries & Exponential Backoff
All SDKs must implement automatic retries for the following HTTP status codes:
- `429` (Too Many Requests)
- `500` (Internal Server Error)
- `502` (Bad Gateway)
- `503` (Service Unavailable)
- `504` (Gateway Timeout)

Retry strategy: Exponential backoff with jitter. (e.g. `0.5s`, `1s`, `2s`).

## 4. Resource Namespaces
The SDK MUST expose the following resource namespaces as properties on the main client:

- `client.events`
  - `.evaluate(product_slug, event_type, payload, [idempotency_key])` -> `POST /api/v1/events`
  - `.list()` -> `GET /api/v1/events-explorer`
- `client.telemetry`
  - `.send(payload)` -> `POST /api/v1/telemetry`
- `client.products`
  - `.list()` -> `GET /api/v1/products`
- `client.projects`
  - `.list()` -> `GET /api/v1/projects/current`
- `client.api_keys`
  - `.list()` -> `GET /api/v1/api-keys`
- `client.audit`
  - `.list()` -> `GET /api/v1/audit/{user_id}`
- `client.usage`
  - `.current()` -> `GET /api/v1/usage`
- `client.health`
  - `.check()` -> `GET /api/v1/health`

## 5. Error Handling
All SDKs must map HTTP errors to structured native Exceptions/Errors.
- `SentinelMarkAuthError` (401, 403)
- `SentinelMarkValidationError` (400)
- `SentinelMarkRateLimitError` (429)
- `SentinelMarkApiError` (500+)
Every exception must expose `error_code`, `request_id`, and `message`.
