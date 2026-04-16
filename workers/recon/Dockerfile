# ---------------------------------------------------------------------------
# Recon worker image — Python + subfinder + amass (ARM64)
#
# Multi-stage: copy binaries from official images.
# ---------------------------------------------------------------------------
# Pin to specific version — update deliberately after testing
FROM --platform=linux/arm64 ghcr.io/projectdiscovery/subfinder:v2.6.6 AS subfinder-src
FROM --platform=linux/arm64 ghcr.io/owasp-amass/amass:latest AS amass-src

FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=subfinder-src /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=amass-src /usr/local/bin/amass /usr/local/bin/amass

WORKDIR /app

COPY workers/common /app/common
COPY workers/recon/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY workers/recon/worker.py .
COPY workers/recon/entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /data/db /data/output /logs

ENTRYPOINT ["/app/entrypoint.sh"]
