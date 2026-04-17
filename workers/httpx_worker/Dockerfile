# ---------------------------------------------------------------------------
# HTTP worker image — Python + httpx binary (ARM64)
# "httpx" here is the ProjectDiscovery CLI tool, not the Python library.
# Binary lives at /usr/local/bin/httpx in the PD image.
# ---------------------------------------------------------------------------
# Pin to specific version — update deliberately after testing
FROM --platform=linux/arm64 projectdiscovery/httpx:v1.6.10 AS httpx-src

FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates musl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=httpx-src /usr/local/bin/httpx /usr/local/bin/httpx

WORKDIR /app

COPY workers/common /app/common
COPY workers/httpx_worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY workers/httpx_worker/worker.py .
COPY workers/httpx_worker/entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /data/db /data/output /logs

ENTRYPOINT ["/app/entrypoint.sh"]
