# ---------------------------------------------------------------------------
# Recon worker image — Python + subfinder (ARM64)
#
# Multi-stage: copy the subfinder binary from the official ProjectDiscovery
# image.  The binary lives at /usr/local/bin/subfinder in that image.
# If a future release moves it, run:
#   docker run --rm --platform=linux/arm64 ghcr.io/projectdiscovery/subfinder:latest which subfinder
# and update the COPY path below.
# ---------------------------------------------------------------------------
FROM --platform=linux/arm64 ghcr.io/projectdiscovery/subfinder:latest AS subfinder-src

FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=subfinder-src /usr/local/bin/subfinder /usr/local/bin/subfinder

WORKDIR /app

COPY workers/common /app/common
COPY workers/recon/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY workers/recon/worker.py .
COPY workers/recon/entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /data/db /data/output /logs

ENTRYPOINT ["/app/entrypoint.sh"]
