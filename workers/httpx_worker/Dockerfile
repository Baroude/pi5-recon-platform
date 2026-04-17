# ---------------------------------------------------------------------------
# HTTP worker image — Python + httpx binary (ARM64)
# "httpx" here is the ProjectDiscovery CLI tool, not the Python library.
# Binary lives at /usr/local/bin/httpx in the PD image.
# ---------------------------------------------------------------------------
# Pin to specific version — update deliberately after testing
FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip musl \
    && ln -s /usr/lib/aarch64-linux-musl/libc.so /usr/lib/libc.musl-aarch64.so.1 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_arm64.zip \
        -o /tmp/httpx.zip \
    && unzip -j /tmp/httpx.zip httpx -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm /tmp/httpx.zip

WORKDIR /app

COPY workers/common /app/common
COPY workers/httpx_worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY workers/httpx_worker/worker.py .
COPY workers/httpx_worker/entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /data/db /data/output /logs

ENTRYPOINT ["/app/entrypoint.sh"]
