# ---------------------------------------------------------------------------
# Intel worker image — Python only (no amass binary)
# ---------------------------------------------------------------------------
FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ARG CACHE_BUST=1
COPY workers/common /app/common
COPY workers/intel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY workers/intel/worker.py .
COPY workers/intel/entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /data/db /logs

ENTRYPOINT ["/app/entrypoint.sh"]
