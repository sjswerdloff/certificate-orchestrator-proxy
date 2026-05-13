# EST Adapter - Docker image for hackathon deployment
# Multi-stage build using uv for fast, reproducible installs

FROM python:3.13-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock README.md ./

# Install production dependencies only (no dev)
RUN uv sync --no-dev --no-install-project

# Copy source code
COPY est_adapter/ est_adapter/

# Install the project itself
RUN uv sync --no-dev


FROM python:3.13-slim AS runtime

# OpenSSL needed for healthcheck and cert operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the virtual environment and source from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/est_adapter /app/est_adapter
COPY --from=builder /app/pyproject.toml /app/pyproject.toml

# Put venv on PATH
ENV PATH="/app/.venv/bin:$PATH"

# Default config location inside container
ENV EST_ADAPTER_CONFIG="/data/est-adapter/config.yaml"

# Create data directories (will be overridden by mount)
RUN mkdir -p /data/est-adapter/certs/ca \
             /data/est-adapter/certs/tls \
             /data/est-adapter/certs/trust \
             /data/est-adapter/db \
             /data/est-adapter/logs

# EST default port
EXPOSE 8443
# Admin API port
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f -k https://localhost:8443/health || curl -f http://localhost:8443/health || exit 1

ENTRYPOINT ["est-adapter"]
