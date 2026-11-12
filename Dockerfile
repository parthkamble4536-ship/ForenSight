# ==============================================================================
# ForenSight — Multi-Stage Hardened Dockerfile
# Base: Debian-slim Python 3.13
# Security: Non-root 'forensic' user, read-only rootfs compatible, minimal attack surface
# ==============================================================================

# --- Stage 1: Build Dependencies ---
FROM python:3.13-slim-bookworm AS builder

WORKDIR /build

# Install system build dependencies required for compiling wheels if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install dependencies into a separate virtual environment wheel root
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    python -m pip install --no-cache-dir --prefix=/install -r requirements.txt


# --- Stage 2: Final Minimal Runtime Image ---
FROM python:3.13-slim-bookworm AS runner

LABEL maintainer="ForenSight Engineering Team" \
      description="Advanced Digital Forensics & Evidence Intelligence Platform" \
      version="0.2.0"

# Install minimal runtime libraries (libmagic for file identification, curl for container health check)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python dependencies from builder
COPY --from=builder /install /usr/local

# Create dedicated non-root user and group with explicit UID/GID
RUN groupadd -g 10001 forensight && \
    useradd -u 10001 -g forensight -m -s /sbin/nologin -d /app forensight

WORKDIR /app

# Create necessary persistent directory tree with correct permissions
RUN mkdir -p /app/data/evidence /app/data/reports /app/data/keys && \
    chown -R forensight:forensight /app/data

# Copy application source code
COPY --chown=forensight:forensight forensight /app/forensight
COPY --chown=forensight:forensight .env.example /app/.env.example

# Drop privileges to non-root
USER forensight

# Environmental configuration
# Default host 0.0.0.0 inside container so Docker port mapping can bind to 127.0.0.1 on host
ENV FORENSIGHT_HOST=0.0.0.0 \
    FORENSIGHT_PORT=8000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Expose internal application port
EXPOSE 8000

# Docker healthcheck querying the local REST API /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/v1/health || exit 1

# Launch uvicorn ASGI server
CMD ["python", "-m", "uvicorn", "forensight.main:app", "--host", "0.0.0.0", "--port", "8000"]
