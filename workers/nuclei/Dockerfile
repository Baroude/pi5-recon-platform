# ---------------------------------------------------------------------------
# Nuclei worker image — Python + nuclei binary (ARM64)
# Templates are bind-mounted at /templates and updated at container start.
# ---------------------------------------------------------------------------
# Pin to specific version — update deliberately after testing
FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip musl \
    && ln -s /usr/lib/aarch64-linux-musl/libc.so /usr/lib/libc.musl-aarch64.so.1 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_arm64.zip \
        -o /tmp/nuclei.zip \
    && unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

WORKDIR /app

ARG CACHE_BUST=1
COPY workers/common /app/common
COPY workers/nuclei/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY workers/nuclei/worker.py .
COPY workers/nuclei/entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /data/db /data/output /logs /templates

ENTRYPOINT ["/app/entrypoint.sh"]
