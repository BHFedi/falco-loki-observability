FROM python:3.12-slim

LABEL maintainer="sigma-container"
LABEL description="Sigma rule watcher, normalizer, and deployer for Loki/Grafana"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./src/

# Create required runtime directories
RUN mkdir -p /app/rules /app/state /app/failed /app/config

# Default environment — all overridable via docker-compose or .env
ENV SIGMA_RULES_DIR=/app/rules \
    SIGMA_STATE_DIR=/app/state \
    SIGMA_FAILED_DIR=/app/failed \
    SIGMA_POLL_INTERVAL=5 \
    SIGMA_DEDUP_STRATEGY=sha256 \
    SIGMA_FAIL_ON_INVALID=true \
    SIGMA_OUTPUT_FORMAT=ruler \
    SIGMA_ADD_LINE_FILTERS=true \
    SIGMA_CASE_SENSITIVE=false \
    NORMALIZATION_PROFILE=falco_loki \
    SIGMA_FIELD_MAP_FILE=/app/config/field_mapping.json \
    SIGMA_LABEL_MAP_FILE=/app/config/label_mapping.json \
    LOKI_URL=http://loki:3100 \
    LOKI_RULER_PATH=/loki/api/v1/rules \
    GRAFANA_URL=http://grafana:3000 \
    GRAFANA_DATASOURCE_UID=loki \
    GRAFANA_FOLDER=security \
    GRAFANA_ORG_ID=1 \
    GRAFANA_INTERVAL=1m \
    GRAFANA_CONTACT_POINT=default \
    LOKI_GROUP_BY_FIELD=hostname \
    GRAFANA_API_KEY_FILE=""

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python /app/src/healthcheck.py

CMD ["python", "-u", "/app/src/watcher.py"]
