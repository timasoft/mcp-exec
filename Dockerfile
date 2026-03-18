# Stage 1: Build application
FROM rust:1.91-bullseye AS builder

RUN apt-get update \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs

RUN cargo fetch --locked

COPY src/ ./src/
# COPY locales/ ./locales/

RUN cargo build --release --locked

# Stage 2: Final runtime image
FROM debian:bullseye-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY --from=builder --chown=appuser:appuser /app/target/release/mcp-secure-exec /usr/local/bin/

RUN mkdir -p /data && \
    chown -R appuser:appuser /data

WORKDIR /app
RUN chown appuser:appuser /app

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:3344/health || exit 1

LABEL org.opencontainers.image.source="https://github.com/timasoft/mcp-secure-exec"
LABEL org.opencontainers.image.description="MCP server for executing user-defined shell commands via templates"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="timasoft"

USER appuser

ENTRYPOINT ["/usr/local/bin/mcp-secure-exec"]
