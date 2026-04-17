# ---------------------------------------------------------------------------
# Nuclei worker image — Python + nuclei binary (ARM64)
# Templates are bind-mounted at /templates and updated at container start.
# ---------------------------------------------------------------------------
# Pin to specific version — update deliberately after testing
FROM --platform=linux/arm64 projectdiscovery/nuclei:v3.2.9 AS nuclei-src

FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates musl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nuclei-src /usr/local/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app

COPY workers/common /app/common
COPY workers/nuclei/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY workers/nuclei/worker.py .
COPY workers/nuclei/entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /data/db /data/output /logs /templates

ENTRYPOINT ["/app/entrypoint.sh"]
