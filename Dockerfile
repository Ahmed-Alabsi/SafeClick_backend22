# ==============================================================================
# SafeClick Backend — Production Hardened Dockerfile
# Multi-stage security, non-root user, health checks, entrypoint orchestration
# ==============================================================================

FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Set work directory
WORKDIR /app

# Install system dependencies (including netcat for DB waiting and curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    curl \
    netcat-openbsd \
    libgomp1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create non-root user for container security (OWASP Docker Benchmark)
RUN groupadd -r appuser && useradd -r -g appuser -u 1000 -d /app -s /sbin/nologin appuser

# Create directories for runtime data
RUN mkdir -p /app/logs /app/staticfiles /app/media

# Copy project files
COPY . .

# Copy entrypoint script and set execution permissions
RUN chmod +x /app/docker-entrypoint.sh && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose Django port
EXPOSE 8000

# Container healthcheck
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/admin/login/ || exit 1

# Safe entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]

# Production Gunicorn application server
CMD ["gunicorn", "safeclick.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-"]
