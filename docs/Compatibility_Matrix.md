# SDK Compatibility Matrix

This table shows which SentinelMark API versions each SDK version supports.

| SDK | Language | Version | API Version | Min Runtime | Status |
|-----|----------|---------|-------------|-------------|--------|
| `sentinelmark` | Python | 1.0.0 | v1 | Python 3.9+ | ✅ Stable |
| `sentinelmark` | Node.js | 1.0.0 | v1 | Node 18+ LTS | ✅ Stable |
| `sentinelmark` | Rust | 1.0.0 | v1 | Rust stable | ✅ Stable |
| `sentinelmark` | Go | 1.0.0 | v1 | Go 1.22+ | ✅ Stable |

## API Version Lifecycle
| API Version | Status | Sunset Date |
|-------------|--------|-------------|
| v1 | ✅ Current | — |

## Required Secrets for Publishing (GitHub Repository Secrets)

| Secret | Used By | Description |
|--------|---------|-------------|
| `NPM_TOKEN` | `publish-node.yml` | npm access token |
| `CARGO_REGISTRY_TOKEN` | `publish-rust.yml` | crates.io API token |
| `PYPI_API_TOKEN` | `publish-python.yml` | PyPI API token (or use Trusted Publishing) |
