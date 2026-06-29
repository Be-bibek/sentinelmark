# ─── Build Stage ───────────────────────────────────────────────────────────────
FROM rust:1.78-slim-bullseye AS builder

WORKDIR /app

# Install OS build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Pre-cache dependencies (layer cache trick)
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY services/ ./services/
COPY sdk-rust/ ./sdk-rust/

# Build in release mode
RUN cargo build --release -p api-gateway

# ─── Runtime Stage ─────────────────────────────────────────────────────────────
FROM debian:bullseye-slim AS runtime

WORKDIR /app

# Install only runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    # Create a non-root user
    && groupadd --system --gid 1001 sentinelmark \
    && useradd --system --uid 1001 --gid sentinelmark sentinelmark

COPY --from=builder /app/target/release/api-gateway /usr/local/bin/api-gateway

# Run as non-root
USER sentinelmark

ENV ENVIRONMENT=production
ENV RUST_LOG=info
ENV PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["api-gateway"]
