# Dockerfile — Production-Hardened Container for Linktic SGDA & Claims AI Portal
# Remediated for Wiz CLI & Google Cloud Run (Project: jmaciasc / 599979914124)

FROM python:3.11-slim

LABEL org.opencontainers.image.title="Linktic SGDA & Claims AI Portal" \
      org.opencontainers.image.description="End-to-End Agentic DevSecOps Demo (Antigravity 2.0 + CodeMender + Wiz + Model Armor + SecOps)" \
      org.opencontainers.image.vendor="Linktic & Google Cloud Security" \
      security.codemender.verified="true" \
      security.wiz.hardened="non-root-uid-10001"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    DEFAULT_SECURITY_MODE="v2-secure" \
    GCP_PROJECT_ID="jmaciasc" \
    GCP_PROJECT_NUMBER="599979914124" \
    GCP_REGION="us-central1" \
    AUTH_MODE="ADC_ZERO_API_KEYS"

WORKDIR /app

# Create dedicated non-root user and group (UID/GID 10001) to satisfy Wiz Container Policy (WIZ-DOCKER-001)
RUN groupadd -g 10001 appuser && \
    useradd -u 10001 -g appuser -m -s /usr/sbin/nologin appuser && \
    mkdir -p /tmp/linktic_docs /app/artifacts && \
    chown -R appuser:appuser /tmp/linktic_docs /app

# Install Python dependencies first for layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# Copy application code, frontend, static security artifacts, and semantic context
COPY --chown=appuser:appuser backend/ /app/backend/
COPY --chown=appuser:appuser frontend/ /app/frontend/
COPY --chown=appuser:appuser artifacts/ /app/artifacts/
COPY --chown=appuser:appuser CONTEXT.md /app/CONTEXT.md

# Enforce non-root execution (UID 10001)
USER 10001:10001

EXPOSE 8080

# Built-in container healthcheck using Python stdlib (no extra curl/wget attack surface)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request, sys; r = urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3); sys.exit(0 if r.getcode() == 200 else 1)"

CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8080"]
