FROM rust:1-slim-bullseye AS builder

WORKDIR /app
COPY . .
RUN cargo build --release -p api-gateway

FROM debian:bullseye-slim

WORKDIR /app
RUN apt-get update && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/api-gateway /usr/local/bin/

ENV ENVIRONMENT=production
ENV RUST_LOG=info
ENV PORT=8080

EXPOSE 8080
ENTRYPOINT ["api-gateway"]
