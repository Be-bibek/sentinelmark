# Changelog

All notable changes to SentinelMark are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Phase 4.5: Package publishing to PyPI, npm, crates.io, pkg.go.dev
- Phase 4.4: Disaster recovery runbook, backup/restore scripts, env validation
- Phase 4.3: Criterion benchmark suite (P50/P95/P99), integration test scaffold
- Phase 4.2: Prometheus metrics registry, Loki + Promtail log aggregation, Grafana dashboard
- Phase 4.1: Multi-stage Dockerfiles (non-root), full Docker Compose stack with Redis, 8 GitHub Actions workflows
- Phase 3.3: Developer documentation (Getting Started, Auth, Events, Errors, Idempotency, Rate Limits), Examples (Flask, Express), Postman Collection
- Phase 3.2: Official Rust SDK and Go SDK with exponential backoff and native error types
- Phase 3.1: Official Python SDK and Node.js SDK with automatic retry and structured exceptions
- Phase 3.0: `sdks/SPEC.md` core SDK specification
- Phase 2.5: OpenAPI/Swagger UI, standardized `ApiResponse<T>`, `PlatformError` system, idempotency
- Phase 2: Multi-tenancy, Organizations, Projects, API Keys, Team management, Developer Portal
- Phase 1: Rust Trust Engine (Behavior, Risk, Policy, Audit engines), Axum API Gateway, PostgreSQL storage

---

## [2.0.0] - 2026-06-28

### Added
- Multi-tenant Developer Portal with Organization/Project/API Key management
- OpenAPI v3 spec auto-generated via `utoipa`
- Idempotency key support for safe retries
- WebSocket live event streaming
- Prometheus `/metrics` endpoint

### Changed
- API versioned to `v2` with full backwards compatibility layer

---

## [1.0.0] - 2026-05-14

### Added
- Initial Rust Trust Engine with behavioral biometrics
- Axum HTTP API Gateway
- PostgreSQL via sqlx
- Multi-product adapter architecture (StellarFlow, DICOM-Trace, ProofTrace)
- React/Next.js Dashboard with real-time analytics
